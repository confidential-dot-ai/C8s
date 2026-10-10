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
	sc.Step(`^a pod "([^"]*)" whose only container names image "([^"]*)" without a digest$`, podNamesImageByTag)
	sc.Step(`^a pod "([^"]*)" with two containers$`, podWithTwoContainers)
	sc.Step(`^the first container of "([^"]*)" runs image "([^"]*)"$`, firstContainerRuns)
	sc.Step(`^the second container of "([^"]*)" runs image "([^"]*)"$`, secondContainerRuns)
	sc.Step(`^the image store on node "([^"]*)" resolves that name to the digest of "([^"]*)"$`, storeResolves)
	sc.Step(`^the command line of that container is "([^"]*)"$`, commandLine)
	sc.Step(`^"([^"]*)" is deployed on node "([^"]*)"$`, deployOnNode)
	sc.Step(`^the container of "([^"]*)" is not created$`, containerNotCreated)
	sc.Step(`^the container of "([^"]*)" is created$`, containerCreated)
	sc.Step(`^both containers of "([^"]*)" are created$`, bothContainersCreated)
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
// including whatever the scenario has written so far.
func enforcerSynced(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	if _, err := w.be.call("enforcer_ready", k8sNode); err != nil {
		return err
	}
	if err := w.writeEntries(); err != nil {
		return err
	}
	return w.awaitApplied()
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
	doc, err := w.servedAllowlist()
	if err != nil {
		return err
	}
	if doc.floorAdmits(digest) != want {
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
	doc, err := w.servedAllowlist()
	if err != nil {
		return err
	}
	if doc.declares(digest) {
		return fmt.Errorf("harness precondition: an allowlist entry declares %s (%s)", image, digest)
	}
	return nil
}

func podRunsImage(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return err
	}
	w.named(image)
	w.describe(name, ref)
	return nil
}

func podNamesImageByTag(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	// Unique per scenario: a name an earlier run aliased must not resolve here.
	w.describe(name, "docker.io/library/conformance-"+image+":"+w.namespace)
	return nil
}

// podWithTwoContainers describes the pod; the next two steps fill it.
func podWithTwoContainers(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p := &pod{name: name}
	w.pods[name], w.lastPod = p, p
	return nil
}

func firstContainerRuns(ctx context.Context, name, image string) error {
	return nthContainerRuns(ctx, name, image, 0)
}

func secondContainerRuns(ctx context.Context, name, image string) error {
	return nthContainerRuns(ctx, name, image, 1)
}

func nthContainerRuns(ctx context.Context, name, image string, n int) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if len(p.containers) != n {
		return fmt.Errorf("%q has %d containers; the ordinal is %d", name, len(p.containers), n+1)
	}
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return err
	}
	w.named(image)
	p.add(ref)
	return nil
}

func storeResolves(ctx context.Context, node, image string) error {
	w := getWorld(ctx)
	if w.lastPod == nil || len(w.lastPod.containers) == 0 {
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
	if w.lastPod == nil || len(w.lastPod.containers) == 0 {
		return errors.New("no container has been described yet")
	}
	w.lastPod.last().command = strings.Fields(line)
	return nil
}

// deployOnNode writes the entries the scenario described, waits for the
// enforcer on the node to hold them, and applies the pod.
func deployOnNode(ctx context.Context, name, node string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if len(p.containers) == 0 {
		return fmt.Errorf("%q has no containers", name)
	}
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	pending := false
	for _, e := range w.entries {
		pending = pending || !e.written
	}
	if pending {
		if err := w.writeEntries(); err != nil {
			return err
		}
		if err := w.awaitApplied(); err != nil {
			return err
		}
	}
	manifest, err := w.manifest(p, k8sNode)
	if err != nil {
		return err
	}
	p.deployed = true
	_, err = kubectl(manifest, "apply", "-f", "-")
	return err
}

// manifest renders the backend's pod for the first container and adds the
// rest as copies of it, so every container carries the same security context.
func (w *world) manifest(p *pod, k8sNode string) ([]byte, error) {
	first := p.containers[0]
	rendered, err := w.be.call("pod_manifest", append([]string{p.name, w.namespace, k8sNode, first.ref}, first.command...)...)
	if err != nil {
		return nil, err
	}
	if len(p.containers) == 1 {
		return []byte(rendered), nil
	}
	var whole map[string]json.RawMessage
	var spec map[string]any
	if err := json.Unmarshal([]byte(rendered), &whole); err != nil {
		return nil, fmt.Errorf("pod manifest is not JSON: %w", err)
	}
	if err := json.Unmarshal(whole["spec"], &spec); err != nil {
		return nil, fmt.Errorf("pod manifest spec: %w", err)
	}
	list, _ := spec["containers"].([]any)
	if len(list) != 1 {
		return nil, fmt.Errorf("pod manifest has %d containers, want 1", len(list))
	}
	template, _ := list[0].(map[string]any)
	containers := make([]any, 0, len(p.containers))
	for i, c := range p.containers {
		copyOf := make(map[string]any, len(template)+3)
		for k, v := range template {
			copyOf[k] = v
		}
		copyOf["name"] = fmt.Sprintf("c%d", i+1)
		copyOf["image"] = c.ref
		copyOf["command"] = c.command
		containers = append(containers, copyOf)
	}
	spec["containers"] = containers
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	whole["spec"] = specJSON
	return json.Marshal(whole)
}

// status reads, in one call, the container's id (empty until the runtime has
// created it) and its container-create refusal, if any. A pull failure or a
// crash is not a refusal.
func (w *world) status(p *pod) (id, refusal string) {
	st := w.statuses(p)
	if len(st) == 0 {
		return "", ""
	}
	return st[0].id, st[0].refusal
}

type containerStatus struct {
	id, refusal string
	running     bool
	restarts    int
}

// statuses reads every container's id, refusal and running state in one call.
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

// await polls the deployed pod's status every second until the condition
// holds or observe runs out, and returns the last status seen.
func (w *world) await(p *pod, until func(id, refusal string) bool) (id, refusal string, err error) {
	if !p.deployed {
		return "", "", fmt.Errorf("pod %q has not been deployed", p.name)
	}
	for deadline := time.Now().Add(observe); ; time.Sleep(time.Second) {
		if id, refusal = w.status(p); until(id, refusal) || !time.Now().Before(deadline) {
			return id, refusal, nil
		}
	}
}

func containerNotCreated(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	id, refusal, err := w.await(p, func(id, refusal string) bool { return id != "" || refusal != "" })
	switch {
	case err != nil:
		return err
	case id != "":
		return fmt.Errorf("the container of %q was created (%s)", name, id)
	case refusal == "":
		return fmt.Errorf("no refusal recorded for %q within %s, and no container either", name, observe)
	}
	return nil
}

func containerCreated(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	id, refusal, err := w.await(p, func(id, _ string) bool { return id != "" })
	switch {
	case err != nil:
		return err
	case id == "":
		return fmt.Errorf("the container of %q was not created within %s; refusal: %s", name, observe, refusal)
	}
	return nil
}

// bothContainersCreated waits until every container of the pod has an id.
func bothContainersCreated(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if !p.deployed {
		return fmt.Errorf("pod %q has not been deployed", name)
	}
	var last []containerStatus
	for deadline := time.Now().Add(observe); time.Now().Before(deadline); time.Sleep(time.Second) {
		last = w.statuses(p)
		created := len(last) == len(p.containers)
		for _, s := range last {
			created = created && s.id != ""
		}
		if created {
			return nil
		}
	}
	var refusals []string
	for _, s := range last {
		if s.refusal != "" {
			refusals = append(refusals, s.refusal)
		}
	}
	return fmt.Errorf("not every container of %q was created within %s; refusals: %s", name, observe, strings.Join(refusals, "; "))
}

// keepsRunning: a deployed pod's containers are all running and none has
// restarted, checked after a pull interval has passed, which is when a change
// at CDS would have reached the enforcer.
func keepsRunning(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if !p.deployed {
		return fmt.Errorf("pod %q has not been deployed", name)
	}
	interval, err := w.pullInterval()
	if err != nil {
		return err
	}
	time.Sleep(2 * interval)
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
// digest, and it still names the image.
func refusalSaysLaunchNotAdmitted(ctx context.Context) error {
	w := getWorld(ctx)
	p, text, err := w.lastRefusal()
	if err != nil {
		return err
	}
	ref := p.containers[0].ref
	switch {
	case strings.Contains(text, "not in allowlist"):
		return fmt.Errorf("the refusal says the image is not allowlisted: %s", text)
	case !strings.Contains(text, "allowlisted"):
		return fmt.Errorf("the refusal does not say the image is allowlisted: %s", text)
	case !strings.Contains(text, ref):
		return fmt.Errorf("the refusal does not name %s: %s", ref, text)
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
	id, refusal, err := w.await(p, func(id, refusal string) bool { return id != "" || refusal != "" })
	switch {
	case err != nil:
		return nil, "", err
	case id != "":
		return nil, "", fmt.Errorf("the container of %q was created (%s); no refusal to inspect", p.name, id)
	case refusal == "":
		return nil, "", fmt.Errorf("no refusal recorded for %q within %s", p.name, observe)
	}
	return p, refusal, nil
}
