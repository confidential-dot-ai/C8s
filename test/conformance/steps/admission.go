package steps

import (
	"context"
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
	sc.Step(`^the image store on node "([^"]*)" resolves that name to the digest of "([^"]*)"$`, storeResolves)
	sc.Step(`^the command line of that container is "([^"]*)"$`, commandLine)
	sc.Step(`^"([^"]*)" is deployed on node "([^"]*)"$`, deployOnNode)
	sc.Step(`^the container of "([^"]*)" is not created$`, containerNotCreated)
	sc.Step(`^the container of "([^"]*)" is created$`, containerCreated)
	sc.Step(`^no process from image "([^"]*)" runs on node "([^"]*)"$`, noProcessFromImage)
	sc.Step(`^the refusal names image "([^"]*)"$`, refusalNamesImage)
	sc.Step(`^the refusal does not contain "([^"]*)"$`, refusalOmits)
}

// observe bounds how long a step waits for the runtime to act or refuse.
const observe = 90 * time.Second

func enforcerSynced(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	_, err = w.be.call("enforcer_ready", k8sNode)
	return err
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
	w.describe(name, ref)
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
	_, err = w.be.call("image_alias", ref, w.lastPod.ref)
	return err
}

func commandLine(ctx context.Context, line string) error {
	w := getWorld(ctx)
	if w.lastPod == nil {
		return errors.New("no container has been described yet")
	}
	w.lastPod.command = strings.Fields(line)
	return nil
}

func deployOnNode(ctx context.Context, name, node string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	manifest, err := w.be.call("pod_manifest", append([]string{p.name, w.namespace, k8sNode, p.ref}, p.command...)...)
	if err != nil {
		return err
	}
	p.deployed = true
	_, err = kubectl([]byte(manifest), "apply", "-f", "-")
	return err
}

// status reads, in one call, the container's id (empty until the runtime has
// created it) and its container-create refusal, if any. A pull failure or a
// crash is not a refusal.
func (w *world) status(p *pod) (id, refusal string) {
	out, _ := kubectl(nil, "-n", w.namespace, "get", "pod", p.name, "-o",
		"jsonpath={.status.containerStatuses[0].containerID}{\"\\n\"}{.status.containerStatuses[0].state.waiting.reason}{\"\\n\"}{.status.containerStatuses[0].state.waiting.message}")
	fields := strings.SplitN(out, "\n", 3)
	for len(fields) < 3 {
		fields = append(fields, "")
	}
	if fields[1] == "CreateContainerError" {
		refusal = strings.TrimSpace(fields[2])
	}
	return strings.TrimSpace(fields[0]), refusal
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
	if !strings.Contains(text, p.ref) && !strings.Contains(text, digest) {
		return fmt.Errorf("the refusal names neither %s nor %s: %s", p.ref, digest, text)
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
