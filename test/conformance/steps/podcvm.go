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

// Sentences about the Pod CVM provider: what admission does with the opt-in
// and the routing, the virtual node, and the record and status reason the
// provider gives a pod bound to that node. A backend whose cluster runs no
// provider skips them.
func registerPodCVM(sc *godog.ScenarioContext) {
	sc.Step(`^"([^"]*)" opts into a pod CVM$`, shapes(func(s *cvmSpec) { s.optIn = "true" }))
	sc.Step(`^"([^"]*)" carries the opt-in key with the value "([^"]*)"$`, carriesOptIn)
	sc.Step(`^"([^"]*)" names the virtual node$`, shapes(func(s *cvmSpec) { s.namesNode = true }))
	sc.Step(`^"([^"]*)" selects the virtual node$`, shapes(func(s *cvmSpec) { s.selectsNode = true }))
	sc.Step(`^"([^"]*)" tolerates every taint$`, shapes(func(s *cvmSpec) { s.toleratesAll = true }))
	sc.Step(`^"([^"]*)" mounts its service account token$`, shapes(func(s *cvmSpec) { s.mountsToken = true }))
	sc.Step(`^"([^"]*)" reads an environment variable from a secret$`, shapes(func(s *cvmSpec) { s.secretEnv = true }))
	sc.Step(`^"([^"]*)" has an exec readiness probe$`, shapes(func(s *cvmSpec) { s.execProbe = true }))
	sc.Step(`^"([^"]*)" requests more memory than one pod CVM has$`, shapes(func(s *cvmSpec) { s.oversize = true }))
	sc.Step(`^"([^"]*)" is created$`, podCreated)
	sc.Step(`^the opt-in of "([^"]*)" is removed$`, optInRemoved)
	sc.Step(`^the image of "([^"]*)" is changed to "([^"]*)"$`, imageChanged)

	sc.Step(`^admission refuses "([^"]*)"$`, admissionRefusesPod)
	sc.Step(`^admission refuses the update$`, admissionRefusesUpdate)
	sc.Step(`^"([^"]*)" carries the routing$`, carriesRouting)
	sc.Step(`^"([^"]*)" is bound to the virtual node$`, boundToVirtualNode)
	sc.Step(`^"([^"]*)" reports the reason "([^"]*)"$`, func(ctx context.Context, name, reason string) error { return reportsReason(ctx, name, "", reason) })
	sc.Step(`^"([^"]*)" has failed with the reason "([^"]*)"$`, func(ctx context.Context, name, reason string) error {
		return reportsReason(ctx, name, "Failed", reason)
	})
	sc.Step(`^"([^"]*)" is pending$`, podPending)
	sc.Step(`^the provider holds (a|no) record for "([^"]*)"$`, providerHoldsRecord)

	sc.Step(`^the virtual node is labelled and tainted with the opt-in key$`, virtualNodeCarriesOptIn)
	sc.Step(`^the virtual node has a pod capacity of max-pods$`, virtualNodeCapacity)
	sc.Step(`^the provider renews the heartbeat of the virtual node$`, heartbeatRenewed)
}

const (
	optInKey = "confidential.ai/pod-cvm"
	// cvmContainer is the name of the one container these pods have.
	cvmContainer = "app"
	// cvmSettle bounds what the provider does in one or two reconciliations;
	// it re-reads a pod that waits every ten seconds.
	cvmSettle = 90 * time.Second
	// heartbeatWindow is longer than the virtual node's lease, so a renewal
	// time unchanged across it is a heartbeat that stopped.
	heartbeatWindow = 45 * time.Second
)

// podCVMState is what the scenario shaped and what admission last answered.
type podCVMState struct {
	specs map[string]*cvmSpec
	// refusal is admission's answer to the last create or update, empty when
	// it admitted the request.
	refusal string
	cleanup bool
}

// cvmSpec is how a pod of these scenarios differs from the plain one: its
// opt-in value and the fields admission or the provider judges. uid is set
// once the API server holds the pod.
type cvmSpec struct {
	optIn        string
	namesNode    bool
	selectsNode  bool
	toleratesAll bool
	mountsToken  bool
	secretEnv    bool
	execProbe    bool
	oversize     bool
	uid          string
}

func (w *world) cvm(name string) (*pod, *cvmSpec, error) {
	p, err := w.pod(name)
	if err != nil {
		return nil, nil, err
	}
	if w.podCVM.specs == nil {
		w.podCVM.specs = map[string]*cvmSpec{}
	}
	s, ok := w.podCVM.specs[name]
	if !ok {
		s = &cvmSpec{}
		w.podCVM.specs[name] = s
	}
	return p, s, nil
}

func shapes(set func(*cvmSpec)) func(context.Context, string) error {
	return func(ctx context.Context, name string) error {
		_, s, err := getWorld(ctx).cvm(name)
		if err == nil {
			set(s)
		}
		return err
	}
}

func carriesOptIn(ctx context.Context, name, value string) error {
	return shapes(func(s *cvmSpec) { s.optIn = value })(ctx, name)
}

// tidy puts the provider back after the scenario: no pod of the scenario
// left, and no record left counting against the provider's pod budget for
// the next one.
func (w *world) tidy() {
	if w.podCVM.cleanup {
		return
	}
	w.podCVM.cleanup = true
	w.onUndo(func() error {
		var errs []error
		for name, s := range w.podCVM.specs {
			if s.uid == "" {
				continue
			}
			p := w.pods[name]
			_, _ = kubectl(nil, "-n", p.namespace, "delete", "pod", p.name, "--ignore-not-found", "--force", "--grace-period=0", "--wait=false")
			released, err := poll(2*time.Minute, func() (bool, error) {
				held, err := w.recordHeld(s)
				return !held, err
			})
			if err == nil && !released {
				err = fmt.Errorf("the provider still holds the record of %q", name)
			}
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	})
}

// manifest renders the pod without the harness fixture, which pins a pod to
// a node: admission refuses that on an opted pod.
func (w *world) cvmManifest(p *pod, s *cvmSpec) ([]byte, error) {
	app := map[string]any{
		"name": cvmContainer, "image": p.containers[0].ref, "command": p.containers[0].command,
		"securityContext": map[string]any{"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []string{"ALL"}}},
	}
	spec := map[string]any{
		"containers":      []any{app},
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 1000, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
	}
	meta := map[string]any{"name": p.name, "namespace": p.namespace}
	if s.optIn != "" {
		meta["annotations"] = map[string]string{optInKey: s.optIn}
		if !s.mountsToken {
			spec["automountServiceAccountToken"] = false
		}
	}
	if s.namesNode {
		node, err := w.be.call("pod_cvm_node")
		if err != nil {
			return nil, err
		}
		spec["nodeName"] = node
	}
	if s.selectsNode {
		spec["nodeSelector"] = map[string]string{optInKey: "true"}
	}
	if s.toleratesAll {
		spec["tolerations"] = []any{map[string]string{"operator": "Exists"}}
	}
	if s.secretEnv {
		app["env"] = []any{map[string]any{"name": "TOKEN", "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "absent", "key": "token"}}}}
	}
	if s.execProbe {
		app["readinessProbe"] = map[string]any{"exec": map[string]any{"command": []string{"true"}}}
	}
	if s.oversize {
		memory, err := w.be.call("pod_cvm_oversize_memory")
		if err != nil {
			return nil, err
		}
		app["resources"] = map[string]any{"requests": map[string]string{"memory": memory}}
	}
	return json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec})
}

// admitted records admission's answer to a write: a refusal is the
// scenario's to assert, any other failure is the harness's.
func (w *world) admitted(err error) error {
	w.podCVM.refusal = ""
	if err != nil && strings.Contains(err.Error(), "admission webhook") {
		w.podCVM.refusal = err.Error()
		return nil
	}
	return err
}

func podCreated(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, s, err := w.cvm(name)
	if err != nil {
		return err
	}
	// The backend answers for the provider's node or skips: a cluster
	// without a provider cannot run any of these scenarios.
	if _, err := w.be.call("pod_cvm_node"); err != nil {
		return err
	}
	manifest, err := w.cvmManifest(p, s)
	if err != nil {
		return err
	}
	w.tidy()
	_, err = kubectl(manifest, "create", "-f", "-")
	if err := w.admitted(err); err != nil || w.podCVM.refusal != "" {
		return err
	}
	s.uid, err = kubectl(nil, "-n", p.namespace, "get", "pod", p.name, "-o", "jsonpath={.metadata.uid}")
	return err
}

func optInRemoved(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	_, err = kubectl(nil, "-n", p.namespace, "annotate", "pod", p.name, optInKey+"-")
	return w.admitted(err)
}

func imageChanged(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	refs, err := w.refs(image)
	if err != nil {
		return err
	}
	patch := fmt.Sprintf(`[{"op":"replace","path":"/spec/containers/0/image","value":%q}]`, refs[0])
	_, err = kubectl(nil, "-n", p.namespace, "patch", "pod", p.name, "--type=json", "-p", patch)
	return w.admitted(err)
}

func admissionRefusesPod(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if w.podCVM.refusal == "" {
		return fmt.Errorf("admission admitted %q", p.name)
	}
	return nil
}

func admissionRefusesUpdate(ctx context.Context) error {
	if getWorld(ctx).podCVM.refusal == "" {
		return errors.New("admission admitted the update")
	}
	return nil
}

// podObject is the part of a pod these sentences read.
type podObject struct {
	Spec struct {
		NodeName     string            `json:"nodeName"`
		NodeSelector map[string]string `json:"nodeSelector"`
		Tolerations  []struct {
			Key      string `json:"key"`
			Operator string `json:"operator"`
			Value    string `json:"value"`
			Effect   string `json:"effect"`
		} `json:"tolerations"`
	} `json:"spec"`
	Status struct {
		Phase  string `json:"phase"`
		Reason string `json:"reason"`
	} `json:"status"`
}

func (w *world) podObject(name string) (*podObject, error) {
	p, err := w.pod(name)
	if err != nil {
		return nil, err
	}
	out, err := kubectl(nil, "-n", p.namespace, "get", "pod", p.name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var obj podObject
	return &obj, json.Unmarshal([]byte(out), &obj)
}

func carriesRouting(ctx context.Context, name string) error {
	obj, err := getWorld(ctx).podObject(name)
	if err != nil {
		return err
	}
	if obj.Spec.NodeSelector[optInKey] != "true" {
		return fmt.Errorf("%q has the node selector %v", name, obj.Spec.NodeSelector)
	}
	for _, t := range obj.Spec.Tolerations {
		if t.Key == optInKey && t.Operator == "Equal" && t.Value == "true" && t.Effect == "NoSchedule" {
			return nil
		}
	}
	return fmt.Errorf("%q does not tolerate the opt-in key: %+v", name, obj.Spec.Tolerations)
}

func boundToVirtualNode(ctx context.Context, name string) error {
	w := getWorld(ctx)
	node, err := w.be.call("pod_cvm_node")
	if err != nil {
		return err
	}
	var bound string
	ok, err := poll(cvmSettle, func() (bool, error) {
		obj, err := w.podObject(name)
		if err != nil {
			return false, err
		}
		bound = obj.Spec.NodeName
		return bound == node, nil
	})
	if err == nil && !ok {
		err = fmt.Errorf("%q is bound to %q, not to the virtual node %q", name, bound, node)
	}
	return err
}

// reportsReason waits for the pod's status reason, and its phase when one is
// named. A reason the provider replaces before the wait ends still counts
// while it shows; a terminal one stays.
func reportsReason(ctx context.Context, name, phase, reason string) error {
	w := getWorld(ctx)
	var last podObject
	ok, err := poll(cvmSettle, func() (bool, error) {
		obj, err := w.podObject(name)
		if err != nil {
			return false, err
		}
		last = *obj
		return obj.Status.Reason == reason && (phase == "" || obj.Status.Phase == phase), nil
	})
	if err == nil && !ok {
		err = fmt.Errorf("%q is %s with the reason %q, bound to %q", name, last.Status.Phase, last.Status.Reason, last.Spec.NodeName)
	}
	return err
}

func podPending(ctx context.Context, name string) error {
	obj, err := getWorld(ctx).podObject(name)
	if err != nil {
		return err
	}
	if obj.Status.Phase != "Pending" {
		return fmt.Errorf("%q is %s", name, obj.Status.Phase)
	}
	return nil
}

// allocation is the allocation identity the backend's provider derives for
// the pod.
func (w *world) allocation(s *cvmSpec) (string, error) {
	if s.uid == "" {
		return "", errors.New("the pod was never created, so it has no allocation identity")
	}
	return w.be.call("pod_cvm_allocation", s.uid)
}

func (w *world) recordHeld(s *cvmSpec) (bool, error) {
	allocation, err := w.allocation(s)
	if err != nil {
		return false, err
	}
	out, err := w.be.call("pod_cvm_record", allocation)
	return out == "yes", err
}

func providerHoldsRecord(ctx context.Context, which, name string) error {
	w := getWorld(ctx)
	_, s, err := w.cvm(name)
	if err != nil {
		return err
	}
	want := which == "a"
	ok, err := poll(cvmSettle, func() (bool, error) {
		held, err := w.recordHeld(s)
		return held == want, err
	})
	if err == nil && !ok {
		err = fmt.Errorf("the provider holds %s record for %q", map[bool]string{true: "no", false: "a"}[want], name)
	}
	return err
}

// virtualNode reads one field of the provider's node.
func (w *world) virtualNode(jsonpath string) (string, error) {
	node, err := w.be.call("pod_cvm_node")
	if err != nil {
		return "", err
	}
	return kubectl(nil, "get", "node", node, "-o", "jsonpath="+jsonpath)
}

func virtualNodeCarriesOptIn(ctx context.Context) error {
	key := strings.ReplaceAll(optInKey, ".", `\.`)
	got, err := getWorld(ctx).virtualNode(`{.metadata.labels.` + key + `} {.spec.taints[?(@.key=="` + optInKey + `")].effect}`)
	if err == nil && got != "true NoSchedule" {
		err = fmt.Errorf("the virtual node's opt-in label and taint effect are %q", got)
	}
	return err
}

func virtualNodeCapacity(ctx context.Context) error {
	w := getWorld(ctx)
	limit, err := w.be.call("pod_cvm_max_pods")
	if err != nil {
		return err
	}
	got, err := w.virtualNode("{.status.capacity.pods}")
	if err == nil && got != limit {
		err = fmt.Errorf("the virtual node has a pod capacity of %s; max-pods is %s", got, limit)
	}
	return err
}

// heartbeat is the time the virtual node's lease was last renewed.
func (w *world) heartbeat() (string, error) {
	node, err := w.be.call("pod_cvm_node")
	if err != nil {
		return "", err
	}
	return kubectl(nil, "-n", "kube-node-lease", "get", "lease", node, "-o", "jsonpath={.spec.renewTime}")
}

func heartbeatRenewed(ctx context.Context) error {
	w := getWorld(ctx)
	first, err := w.heartbeat()
	if err != nil {
		return err
	}
	ok, err := poll(heartbeatWindow, func() (bool, error) {
		now, err := w.heartbeat()
		return now != first, err
	})
	if err == nil && !ok {
		err = fmt.Errorf("the virtual node's heartbeat stayed at %s", first)
	}
	return err
}
