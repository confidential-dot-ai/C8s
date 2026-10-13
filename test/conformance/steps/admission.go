package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences of the container-admission vocabulary
// (features/enforcement/container-admission.feature and its siblings), in
// the terms of the admission enforcement specification: the admission
// plugin, entries, argv, denials.
func registerAdmission(sc *godog.ScenarioContext) {
	sc.Step(`^the admission plugin on node "([^"]*)" (?:has applied|applies) the served allowlist$`, pluginApplied)
	sc.Step(`^no workload entry declares image "([^"]*)"$`, noEntryDeclares)
	sc.Step(`^a pod "([^"]*)" whose only container runs image "([^"]*)"$`, podRunsImage)
	sc.Step(`^a pod "([^"]*)" whose containers run images "([^"]*)" and "([^"]*)"$`, podRunsImages)
	sc.Step(`^a pod "([^"]*)" whose only container names image "([^"]*)" without a digest$`, podNamesImageByTag)
	sc.Step(`^the image store on node "([^"]*)" resolves that name to the digest of "([^"]*)"$`, storeResolves)
	sc.Step(`^the argv of that container is "([^"]*)"$`, argv)
	sc.Step(`^"([^"]*)" is deployed on node "([^"]*)"$`, deployOnNode)
	sc.Step(`^the container of "([^"]*)" is not created$`, containerNotCreated)
	sc.Step(`^(?:the container|both containers) of "([^"]*)" (?:is|are) created$`, containersCreated)
	sc.Step(`^"([^"]*)" keeps running$`, keepsRunning)
	sc.Step(`^the admission plugin on node "([^"]*)" denies a container running image "([^"]*)"$`, pluginDenies)
	sc.Step(`^the admission plugin on node "([^"]*)" admits a container running image "([^"]*)"$`, pluginAdmits)
	sc.Step(`^a container on node "([^"]*)" is running image "([^"]*)"$`, containerRunning)
	sc.Step(`^the container running image "([^"]*)" is killed$`, runningContainerKilled)
	sc.Step(`^the container running image "([^"]*)" keeps running$`, runningContainerKeepsRunning)
	sc.Step(`^no process from image "([^"]*)" runs on node "([^"]*)"$`, noProcessFromImage)
	sc.Step(`^the denial names image "([^"]*)"$`, denialNamesImage)
	sc.Step(`^the denial does not contain "([^"]*)"$`, denialOmits)
	sc.Step(`^the denial says the launch specification, not the image digest, was not admitted$`, denialIsLaunchNotAdmitted)
}

// observe bounds how long a step waits for the runtime to act or deny. The
// kubelet backs off after a failed create, doubling from 10s, so a container
// created once the plugin is back can take over a minute to appear.
const observe = 150 * time.Second

// pluginApplied: the plugin on node is registered and ready, and holds what
// CDS serves now, including whatever the scenario has described so far.
func pluginApplied(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	if _, err := w.be.call("plugin_ready", k8sNode); err != nil {
		return err
	}
	return w.sync()
}

// noEntryDeclares checks a precondition on the served allowlist; a cluster
// that does not meet it is a broken harness, not a result.
func noEntryDeclares(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	s, err := w.served()
	if err != nil {
		return err
	}
	if s.declares(digest) {
		return fmt.Errorf("harness precondition: a served entry declares %s (%s)", image, digest)
	}
	return nil
}

func podRunsImage(ctx context.Context, name, image string) error {
	return describePod(ctx, name, image)
}

func podRunsImages(ctx context.Context, name, first, second string) error {
	return describePod(ctx, name, first, second)
}

// describePod records a pod with one container per image. godog binds only
// fixed-arity handlers, so the two sentences above wrap it.
func describePod(ctx context.Context, name string, images ...string) error {
	w := getWorld(ctx)
	refs, err := w.refs(images...)
	if err != nil {
		return err
	}
	w.describe(name, refs...)
	return nil
}

func podNamesImageByTag(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	// Unique per scenario: a name an earlier run aliased must not resolve here.
	w.describe(name, "docker.io/library/conformance-"+image+":"+w.namespace)
	return nil
}

func storeResolves(ctx context.Context, node, image string) error {
	w := getWorld(ctx)
	if w.lastPod == nil {
		return errors.New("no pod names an image yet")
	}
	// The alias is store-wide; node_name still checks the node exists here.
	if _, err := w.be.call("node_name", node); err != nil {
		return err
	}
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return err
	}
	_, err = w.be.call("image_alias", ref, w.lastPod.last().ref)
	return err
}

// argv sets the container's command; the manifests here leave args empty, so
// this is the whole argv the runtime executes.
func argv(ctx context.Context, line string) error {
	w := getWorld(ctx)
	if w.lastPod == nil {
		return errors.New("no container has been described yet")
	}
	w.lastPod.last().command = strings.Fields(line)
	return nil
}

// deployOnNode applies the pod. The entries the scenario described must have
// reached the plugin first, which only the applied sentence promises.
func deployOnNode(ctx context.Context, name, node string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	for entry := range w.entries {
		if !w.written[w.writtenName(entry)] {
			return fmt.Errorf("entry %q is described but not written; the scenario must say the plugin has applied the served allowlist before deploying", entry)
		}
	}
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	ns := w.nsOf(p)
	var args []string
	if len(p.opts) > 0 {
		args = append(append(args, p.opts...), "--")
	}
	args = append(args, p.name, ns, k8sNode, p.containers[0].ref)
	for i, c := range p.containers {
		if i > 0 {
			args = append(args, "+", c.ref)
		}
		args = append(args, c.command...)
	}
	renderer := "pod_manifest"
	if p.workloadID {
		renderer = "cw_pod_manifest"
	}
	manifest, err := w.be.call(renderer, args...)
	if err != nil {
		return err
	}
	if ns != w.namespace {
		// Deleting the scenario namespace will not take this one.
		w.onUndo(func() error {
			_, err := kubectl(nil, "-n", ns, "delete", "pod", p.name, "--ignore-not-found", "--wait=false")
			return err
		})
	}
	p.deployed = true
	_, err = kubectl([]byte(manifest), "apply", "-f", "-")
	return err
}

type containerStatus struct {
	id, denial string
	running    bool
	restarts   int
}

// statuses reads every container's id (empty until the runtime has created
// it), the denial reason the create check returned, if any, and its running
// state in one call. A pull failure or a crash is not a denial.
func (w *world) statuses(p *pod) []containerStatus {
	out, _ := kubectl(nil, "-n", w.namespace, "get", "pod", p.name, "-o", "json")
	var doc struct {
		Status struct {
			ContainerStatuses []struct {
				ContainerID  string `json:"containerID"`
				RestartCount int    `json:"restartCount"`
				State        struct {
					Waiting *struct {
						Reason  string `json:"reason"`
						Message string `json:"message"`
					} `json:"waiting"`
					Running *struct{} `json:"running"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
	}
	var st []containerStatus
	for _, c := range doc.Status.ContainerStatuses {
		s := containerStatus{id: c.ContainerID, running: c.State.Running != nil, restarts: c.RestartCount}
		if c.State.Waiting != nil && c.State.Waiting.Reason == "CreateContainerError" {
			s.denial = strings.TrimSpace(c.State.Waiting.Message)
		}
		st = append(st, s)
	}
	return st
}

// created is the id of a created container, or empty.
func created(st []containerStatus) string {
	for _, s := range st {
		if s.id != "" {
			return s.id
		}
	}
	return ""
}

// denials joins the denial reasons recorded so far.
func denials(st []containerStatus) string {
	var texts []string
	for _, s := range st {
		if s.denial != "" {
			texts = append(texts, s.denial)
		}
	}
	return strings.Join(texts, "; ")
}

// decided: the runtime has created or denied a container.
func decided(st []containerStatus) bool { return created(st) != "" || denials(st) != "" }

// allCreated reports whether every container of the pod has an id.
func (p *pod) allCreated(st []containerStatus) bool {
	if len(st) != len(p.containers) {
		return false
	}
	for _, s := range st {
		if s.id == "" {
			return false
		}
	}
	return true
}

// await polls the deployed pod's statuses every second until the condition
// holds or observe runs out, and returns the last statuses seen.
func (w *world) await(p *pod, until func([]containerStatus) bool) ([]containerStatus, error) {
	if !p.deployed {
		return nil, fmt.Errorf("pod %q has not been deployed", p.name)
	}
	for deadline := time.Now().Add(observe); ; time.Sleep(time.Second) {
		if st := w.statuses(p); until(st) || !time.Now().Before(deadline) {
			return st, nil
		}
	}
}

func containerNotCreated(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if p.workloadID {
		// A pod carrying a workload ID is held back by its requester's wait
		// for a leaf, not by the admission plugin, so no denial is recorded;
		// the scenario's leaf step says how long the leaf was waited for.
		if !p.deployed {
			return fmt.Errorf("pod %q has not been deployed", name)
		}
		if id := created(w.statuses(p)); id != "" {
			return fmt.Errorf("the container of %q was created (%s)", name, id)
		}
		return nil
	}
	st, err := w.await(p, decided)
	switch {
	case err != nil:
		return err
	case created(st) != "":
		return fmt.Errorf("the container of %q was created (%s)", name, created(st))
	case denials(st) == "":
		return fmt.Errorf("no denial recorded for %q within %s, and no container either", name, observe)
	}
	return nil
}

func containersCreated(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	st, err := w.await(p, p.allCreated)
	switch {
	case err != nil:
		return err
	case !p.allCreated(st):
		return fmt.Errorf("not every container of %q was created within %s; denials: %s", name, observe, denials(st))
	}
	return nil
}

// keepsRunning: a deployed pod's containers are all running and none has
// restarted. The scenario says when to look; this reads once.
func keepsRunning(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if !p.deployed {
		return fmt.Errorf("pod %q has not been deployed", name)
	}
	st := w.statuses(p)
	if len(st) != len(p.containers) {
		return fmt.Errorf("%q reports %d containers, want %d", name, len(st), len(p.containers))
	}
	for i, s := range st {
		if !s.running || s.restarts > 0 {
			return fmt.Errorf("container %d of %q is not running as it was (running=%v, restarts=%d)", i+1, name, s.running, s.restarts)
		}
	}
	return nil
}

// pluginDenies deploys a probe pod running image on the node and expects the
// create check to deny it.
func pluginDenies(ctx context.Context, node, image string) error {
	w := getWorld(ctx)
	name := fmt.Sprintf("probe-%d", len(w.pods))
	if err := podRunsImage(ctx, name, image); err != nil {
		return err
	}
	if err := deployOnNode(ctx, name, node); err != nil {
		return err
	}
	return containerNotCreated(ctx, name)
}

// pluginAdmits deploys a probe pod running image on the node and expects its
// container to be created.
func pluginAdmits(ctx context.Context, node, image string) error {
	w := getWorld(ctx)
	name := fmt.Sprintf("probe-%d", len(w.pods))
	if err := podRunsImage(ctx, name, image); err != nil {
		return err
	}
	if err := deployOnNode(ctx, name, node); err != nil {
		return err
	}
	return containersCreated(ctx, name)
}

// containerRunning starts a container of image on the node and waits for it
// to run; later sentences refer to it by its image.
func containerRunning(ctx context.Context, node, image string) error {
	w := getWorld(ctx)
	name := fmt.Sprintf("running-%d", len(w.pods))
	if err := podRunsImage(ctx, name, image); err != nil {
		return err
	}
	if err := deployOnNode(ctx, name, node); err != nil {
		return err
	}
	p := w.pods[name]
	st, err := w.await(p, func(st []containerStatus) bool { return len(st) == 1 && st[0].running })
	switch {
	case err != nil:
		return err
	case len(st) != 1 || !st[0].running:
		return fmt.Errorf("the container of %s is not running within %s; denials: %s", image, observe, denials(st))
	}
	w.running[image] = p
	return nil
}

func (w *world) runningPod(image string) (*pod, error) {
	p, ok := w.running[image]
	if !ok {
		return nil, fmt.Errorf("the scenario started no container running image %q", image)
	}
	return p, nil
}

// runningContainerKilled: the container the scenario started is no longer
// the one running. The kubelet recreates a killed container, and the plugin
// decides that create anew, so a restart count or a denial is the trace.
func runningContainerKilled(ctx context.Context, image string) error {
	w := getWorld(ctx)
	p, err := w.runningPod(image)
	if err != nil {
		return err
	}
	killed := func(st []containerStatus) bool {
		return len(st) == 1 && (!st[0].running || st[0].restarts > 0 || st[0].denial != "")
	}
	st, err := w.await(p, killed)
	switch {
	case err != nil:
		return err
	case !killed(st):
		return fmt.Errorf("the container running %s is still the one that was started, %s later", image, observe)
	}
	return nil
}

func runningContainerKeepsRunning(ctx context.Context, image string) error {
	p, err := getWorld(ctx).runningPod(image)
	if err != nil {
		return err
	}
	return keepsRunning(ctx, p.name)
}

func noProcessFromImage(ctx context.Context, image, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	ids, err := w.be.call("node_containers", k8sNode, digest)
	if err != nil {
		return err
	}
	if ids != "" {
		return fmt.Errorf("node %q holds containers from %s: %s", node, image, ids)
	}
	return nil
}

func denialNamesImage(ctx context.Context, image string) error {
	w := getWorld(ctx)
	p, text, err := w.lastDenial()
	if err != nil {
		return err
	}
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	ref := p.containers[0].ref
	if !strings.Contains(text, ref) && !strings.Contains(text, digest) {
		return fmt.Errorf("the denial names neither %s nor %s: %s", ref, digest, text)
	}
	return nil
}

// denialIsLaunchNotAdmitted: the denial is the one for a digest the served
// allowlist lists whose launch specification no entry admits (C1 step 4,
// launch_not_admitted), not the one for a digest no entry declares.
func denialIsLaunchNotAdmitted(ctx context.Context) error {
	w := getWorld(ctx)
	_, text, err := w.lastDenial()
	if err != nil {
		return err
	}
	switch {
	case strings.Contains(text, "not in allowlist"):
		return fmt.Errorf("the denial says the image is not in the allowlist: %s", text)
	case !strings.Contains(text, "allowlisted"):
		return fmt.Errorf("the denial does not say the image is allowlisted: %s", text)
	}
	return nil
}

func denialOmits(ctx context.Context, secret string) error {
	w := getWorld(ctx)
	_, text, err := w.lastDenial()
	if err != nil {
		return err
	}
	if strings.Contains(text, secret) {
		return fmt.Errorf("the denial repeats %q: %s", secret, text)
	}
	return nil
}

// lastDenial waits for the last deployed pod's denial and returns its reason.
func (w *world) lastDenial() (*pod, string, error) {
	p := w.lastPod
	if p == nil {
		return nil, "", errors.New("no pod has been described")
	}
	st, err := w.await(p, decided)
	switch {
	case err != nil:
		return nil, "", err
	case created(st) != "":
		return nil, "", fmt.Errorf("the container of %q was created (%s); no denial to inspect", p.name, created(st))
	case denials(st) == "":
		return nil, "", fmt.Errorf("no denial recorded for %q within %s", p.name, observe)
	}
	return p, denials(st), nil
}
