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
// (features/enforcement/container-admission.feature and its siblings).
func registerAdmission(sc *godog.ScenarioContext) {
	sc.Step(`^the policy enforcer on node "([^"]*)" has synced the allowlist$`, enforcerSynced)
	sc.Step(`^the floor does not contain the digest of "([^"]*)"$`, floorLacks)
	sc.Step(`^the floor contains the digest of "([^"]*)"$`, floorHas)
	sc.Step(`^no workload entry declares image "([^"]*)"$`, noEntryDeclares)
	sc.Step(`^a pod "([^"]*)" whose only container runs image "([^"]*)"$`, podRunsImage)
	sc.Step(`^a pod "([^"]*)" whose containers run images "([^"]*)" and "([^"]*)"$`, podRunsImages)
	sc.Step(`^a pod "([^"]*)" whose only container names image "([^"]*)" without a digest$`, podNamesImageByTag)
	sc.Step(`^the image store on node "([^"]*)" resolves that name to the digest of "([^"]*)"$`, storeResolves)
	sc.Step(`^the command line of that container is "([^"]*)"$`, commandLine)
	sc.Step(`^"([^"]*)" is deployed on node "([^"]*)"$`, deployOnNode)
	sc.Step(`^the container of "([^"]*)" is not created$`, containerNotCreated)
	sc.Step(`^(?:the container|both containers) of "([^"]*)" (?:is|are) created$`, containersCreated)
	sc.Step(`^"([^"]*)" keeps running$`, keepsRunning)
	sc.Step(`^the policy enforcer on node "([^"]*)" does not admit image "([^"]*)"$`, enforcerDoesNotAdmit)
	sc.Step(`^no process from image "([^"]*)" runs on node "([^"]*)"$`, noProcessFromImage)
	sc.Step(`^the refusal names image "([^"]*)"$`, refusalNamesImage)
	sc.Step(`^the refusal does not contain "([^"]*)"$`, refusalOmits)
	sc.Step(`^the refusal states that the image is allowlisted but its command line is not$`, refusalSaysLaunchNotAdmitted)
}

// observe bounds how long a step waits for the runtime to act or refuse.
const observe = 90 * time.Second

// enforcerSynced: the enforcer is enforcing and holds what CDS serves now,
// including whatever the scenario has described so far.
func enforcerSynced(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	if _, err := w.be.call("enforcer_ready", k8sNode); err != nil {
		return err
	}
	return w.sync()
}

func floorLacks(ctx context.Context, image string) error {
	return requireFloor(ctx, image, false)
}

func floorHas(ctx context.Context, image string) error {
	return requireFloor(ctx, image, true)
}

// requireFloor checks a precondition the backend fixed at install; a cluster
// that does not meet it is a broken harness, not a result.
func requireFloor(ctx context.Context, image string, want bool) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	s, err := w.served()
	if err != nil {
		return err
	}
	if s.admitsAnyArgv(digest) != want {
		return fmt.Errorf("harness precondition: floor admits %s (%s) = %v, want %v", image, digest, !want, want)
	}
	return nil
}

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
		return fmt.Errorf("harness precondition: an allowlist entry declares %s (%s)", image, digest)
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

func commandLine(ctx context.Context, line string) error {
	w := getWorld(ctx)
	if w.lastPod == nil {
		return errors.New("no container has been described yet")
	}
	w.lastPod.last().command = strings.Fields(line)
	return nil
}

// deployOnNode applies the pod. The entries the scenario described must have
// reached the enforcer first, which only the sync sentence promises.
func deployOnNode(ctx context.Context, name, node string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	for entry := range w.entries {
		if !w.wrote(w.writtenName(entry)) {
			return fmt.Errorf("entry %q is described but not written; the scenario must say the enforcer has synced the allowlist before deploying", entry)
		}
	}
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	args := []string{p.name, w.namespace, k8sNode, p.containers[0].ref}
	for i, c := range p.containers {
		if i > 0 {
			args = append(args, "+", c.ref)
		}
		args = append(args, c.command...)
	}
	manifest, err := w.be.call("pod_manifest", args...)
	if err != nil {
		return err
	}
	p.deployed = true
	_, err = kubectl([]byte(manifest), "apply", "-f", "-")
	return err
}

type containerStatus struct {
	id, refusal string
	running     bool
	restarts    int
}

// statuses reads every container's id (empty until the runtime has created
// it), its container-create refusal, if any, and its running state in one
// call. A pull failure or a crash is not a refusal.
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
			s.refusal = strings.TrimSpace(c.State.Waiting.Message)
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

// refusals joins the refusals recorded so far.
func refusals(st []containerStatus) string {
	var texts []string
	for _, s := range st {
		if s.refusal != "" {
			texts = append(texts, s.refusal)
		}
	}
	return strings.Join(texts, "; ")
}

// decided: the runtime has created or refused a container.
func decided(st []containerStatus) bool { return created(st) != "" || refusals(st) != "" }

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
	st, err := w.await(p, decided)
	switch {
	case err != nil:
		return err
	case created(st) != "":
		return fmt.Errorf("the container of %q was created (%s)", name, created(st))
	case refusals(st) == "":
		return fmt.Errorf("no refusal recorded for %q within %s, and no container either", name, observe)
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
		return fmt.Errorf("not every container of %q was created within %s; refusals: %s", name, observe, refusals(st))
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

// enforcerDoesNotAdmit deploys a probe pod running image on the node and
// expects the refusal.
func enforcerDoesNotAdmit(ctx context.Context, node, image string) error {
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

func refusalNamesImage(ctx context.Context, image string) error {
	w := getWorld(ctx)
	p, text, err := w.lastRefusal()
	if err != nil {
		return err
	}
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	ref := p.containers[0].ref
	if !strings.Contains(text, ref) && !strings.Contains(text, digest) {
		return fmt.Errorf("the refusal names neither %s nor %s: %s", ref, digest, text)
	}
	return nil
}

// refusalSaysLaunchNotAdmitted: the refusal is the one for a digest the
// allowlist lists whose launch no entry admits, not the one for an unknown
// digest.
func refusalSaysLaunchNotAdmitted(ctx context.Context) error {
	w := getWorld(ctx)
	_, text, err := w.lastRefusal()
	if err != nil {
		return err
	}
	switch {
	case strings.Contains(text, "not in allowlist"):
		return fmt.Errorf("the refusal says the image is not allowlisted: %s", text)
	case !strings.Contains(text, "allowlisted"):
		return fmt.Errorf("the refusal does not say the image is allowlisted: %s", text)
	}
	return nil
}

func refusalOmits(ctx context.Context, secret string) error {
	w := getWorld(ctx)
	_, text, err := w.lastRefusal()
	if err != nil {
		return err
	}
	if strings.Contains(text, secret) {
		return fmt.Errorf("the refusal repeats %q: %s", secret, text)
	}
	return nil
}

// lastRefusal waits for the last deployed pod's refusal and returns its text.
func (w *world) lastRefusal() (*pod, string, error) {
	p := w.lastPod
	if p == nil {
		return nil, "", errors.New("no pod has been described")
	}
	st, err := w.await(p, decided)
	switch {
	case err != nil:
		return nil, "", err
	case created(st) != "":
		return nil, "", fmt.Errorf("the container of %q was created (%s); no refusal to inspect", p.name, created(st))
	case refusals(st) == "":
		return nil, "", fmt.Errorf("no refusal recorded for %q within %s", p.name, observe)
	}
	return p, refusals(st), nil
}
