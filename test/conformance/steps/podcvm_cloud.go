package steps

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about what the Pod CVM provider asks of the cloud API and how a
// pod and its instance end. The backend's cloud API is one whose answers the
// scenario sets and whose received calls it reads (cloud_behaviour,
// cloud_calls, cloud_instances); a backend with a real cloud skips them.
func registerPodCVMCloud(sc *godog.ScenarioContext) {
	sc.Step(`^"([^"]*)" is deleted with no grace period$`, func(ctx context.Context, name string) error { return podDeleted(ctx, name, 0) })
	sc.Step(`^"([^"]*)" is deleted with a grace period of (\d+) seconds$`, podDeleted)
	sc.Step(`^"([^"]*)" is removed without the provider's release$`, removedWithoutRelease)
	sc.Step(`^the verification deadline of "([^"]*)" passes$`, deadlinePasses)
	sc.Step(`^max-pods opted pods have failed and their instances are not destroyed$`, maxPodsAwaitDestruction)

	sc.Step(`^the cloud API fails every create$`, behaves("create", cloudProblem{Status: 500, Code: "internal_error"}))
	sc.Step(`^the cloud API throttles every create$`, behaves("create", cloudProblem{Status: 429, Code: "rate_limited", RetryAfter: "5"}))
	sc.Step(`^the cloud API refuses every create with "([^"]*)"$`, refusesCreates)
	sc.Step(`^the cloud API reports every instance as "([^"]*)"$`, func(ctx context.Context, status string) error { return getWorld(ctx).cloudBehaves("status", status) })
	sc.Step(`^the cloud API reports that every instance has booted (\d+) times$`, func(ctx context.Context, n int) error { return getWorld(ctx).cloudBehaves("bootCount", n) })
	sc.Step(`^the cloud API knows no instance$`, behaves("gone", true))
	sc.Step(`^the cloud API reports every instance under another provider's label$`, behaves("foreignLabels", true))
	sc.Step(`^the cloud API answers no request$`, behaves("outage", true))
	sc.Step(`^the cloud API does not finish destroying an instance$`, behaves("lingering", true))

	sc.Step(`^"([^"]*)" is (gone|not gone)$`, podGone)
	sc.Step(`^the cloud API received a create under the allocation identity of "([^"]*)"$`, func(ctx context.Context, name string) error { _, err := getWorld(ctx).createFor(name); return err })
	sc.Step(`^the cloud API received no (create|call) for "([^"]*)"$`, cloudReceivedNothing)
	sc.Step(`^the create for "([^"]*)" is labelled with the provider's identity and the allocation identity of "([^"]*)"$`, createLabelled)
	sc.Step(`^the pod document in the create for "([^"]*)" names neither "([^"]*)" nor its image$`, documentNamesNoPod)
	sc.Step(`^the cloud API holds an instance for "([^"]*)"$`, func(ctx context.Context, name string) error {
		_, err := getWorld(ctx).awaitInstance(name, "")
		return err
	})
	sc.Step(`^the instance of "([^"]*)" is destroyed$`, func(ctx context.Context, name string) error {
		_, err := getWorld(ctx).awaitInstance(name, "terminated")
		return err
	})
	sc.Step(`^the cloud API received a delete for the instance of "([^"]*)"$`, cloudReceivedDelete)
	sc.Step(`^the cloud API receives no delete for the instance of "([^"]*)" within (\d+) seconds$`, cloudReceivesNoDelete)
	sc.Step(`^the provider stops renewing the heartbeat of the virtual node$`, heartbeatStopped)
}

type cloudProblem struct {
	Status     int    `json:"status"`
	Code       string `json:"code"`
	RetryAfter string `json:"retryAfter,omitempty"`
}

type cloudCall struct {
	Method         string          `json:"method"`
	Path           string          `json:"path"`
	IdempotencyKey string          `json:"idempotencyKey"`
	Body           json.RawMessage `json:"body"`
}

type cloudInstance struct {
	ID     string            `json:"id"`
	Status string            `json:"status"`
	Labels map[string]string `json:"labels"`
}

// cloudBehaves adds one answer to those the scenario already set.
func (w *world) cloudBehaves(key string, value any) error {
	w.tidy()
	if w.podCVM.behaviour == nil {
		w.podCVM.behaviour = map[string]any{}
	}
	w.podCVM.behaviour[key] = value
	body, err := json.Marshal(w.podCVM.behaviour)
	if err != nil {
		return err
	}
	_, err = w.be.call("cloud_behaviour", string(body))
	return err
}

func behaves(key string, value any) func(context.Context) error {
	return func(ctx context.Context) error { return getWorld(ctx).cloudBehaves(key, value) }
}

func refusesCreates(ctx context.Context, code string) error {
	return getWorld(ctx).cloudBehaves("create", cloudProblem{Status: 409, Code: code})
}

func podDeleted(ctx context.Context, name string, grace int) error {
	p, err := getWorld(ctx).pod(name)
	if err != nil {
		return err
	}
	args := []string{"-n", p.namespace, "delete", "pod", p.name, "--wait=false", fmt.Sprintf("--grace-period=%d", grace)}
	if grace == 0 {
		args = append(args, "--force")
	}
	_, err = kubectl(nil, args...)
	return err
}

// removedWithoutRelease takes the pod out of the cluster past the hold the
// provider put on its deletion, as a forced removal by an administrator does.
func removedWithoutRelease(ctx context.Context, name string) error {
	p, err := getWorld(ctx).pod(name)
	if err != nil {
		return err
	}
	if _, err := kubectl(nil, "-n", p.namespace, "patch", "pod", p.name, "--type=merge", "-p", `{"metadata":{"finalizers":null}}`); err != nil {
		return err
	}
	return podDeleted(ctx, name, 0)
}

func deadlinePasses(ctx context.Context, _ string) error {
	seconds, err := getWorld(ctx).backendInt("pod_cvm_deadline")
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

func (w *world) backendInt(fn string) (int, error) {
	out, err := w.be.call(fn)
	if err != nil {
		return 0, err
	}
	var n int
	if _, err := fmt.Sscanf(out, "%d", &n); err != nil {
		return 0, fmt.Errorf("backend %s answered %q, not a number", fn, out)
	}
	return n, nil
}

// maxPodsAwaitDestruction fills the provider's pod budget with pods that no
// longer occupy the virtual node: each has failed because its instance
// stopped, and its record still counts while the cloud API has not finished
// destroying that instance.
func maxPodsAwaitDestruction(ctx context.Context) error {
	w := getWorld(ctx)
	limit, err := w.backendInt("pod_cvm_max_pods")
	if err != nil {
		return err
	}
	if err := w.cloudBehaves("status", "stopped"); err != nil {
		return err
	}
	for i := range limit {
		name := fmt.Sprintf("ended-%d", i+1)
		w.describe(name, w.lastPod.containers[0].ref)
		if err := carriesOptIn(ctx, name, "true"); err != nil {
			return err
		}
		if err := podCreated(ctx, name); err != nil {
			return err
		}
		if err := reportsReason(ctx, name, "Failed", "InstanceEnded"); err != nil {
			return err
		}
		if err := cloudReceivedDelete(ctx, name); err != nil {
			return err
		}
	}
	delete(w.podCVM.behaviour, "status")
	return w.cloudBehaves("lingering", true)
}

func podGone(ctx context.Context, name, which string) error {
	p, err := getWorld(ctx).pod(name)
	if err != nil {
		return err
	}
	exists := func() (bool, error) {
		out, err := kubectl(nil, "-n", p.namespace, "get", "pod", p.name, "--ignore-not-found", "-o", "name")
		return strings.TrimSpace(out) != "", err
	}
	if which == "not gone" {
		there, err := exists()
		if err == nil && !there {
			err = fmt.Errorf("%q is gone", name)
		}
		return err
	}
	ok, err := poll(cvmSettle, func() (bool, error) {
		there, err := exists()
		return !there, err
	})
	if err == nil && !ok {
		err = fmt.Errorf("%q is still in the cluster", name)
	}
	return err
}

func (w *world) cloudCalls() ([]cloudCall, error) {
	out, err := w.be.call("cloud_calls")
	if err != nil {
		return nil, err
	}
	var calls []cloudCall
	return calls, json.Unmarshal([]byte(out), &calls)
}

// createFor waits for the create the cloud API received under the pod's
// allocation identity.
func (w *world) createFor(name string) (*cloudCall, error) {
	_, s, err := w.cvm(name)
	if err != nil {
		return nil, err
	}
	allocation, err := w.allocation(s)
	if err != nil {
		return nil, err
	}
	var found *cloudCall
	ok, err := poll(cvmSettle, func() (bool, error) {
		calls, err := w.cloudCalls()
		for i, c := range calls {
			if c.Method == "POST" && c.IdempotencyKey == allocation {
				found = &calls[i]
			}
		}
		return found != nil, err
	})
	if err == nil && !ok {
		err = fmt.Errorf("the cloud API received no create under %s, the allocation identity of %q", allocation, name)
	}
	return found, err
}

// instanceOf is the instance the cloud API holds under the labels of the
// pod's allocation, nil when it holds none.
func (w *world) instanceOf(s *cvmSpec) (*cloudInstance, error) {
	want, err := w.instanceLabels(s)
	if err != nil {
		return nil, err
	}
	out, err := w.be.call("cloud_instances")
	if err != nil {
		return nil, err
	}
	var instances []cloudInstance
	if err := json.Unmarshal([]byte(out), &instances); err != nil {
		return nil, err
	}
	for i, in := range instances {
		if maps.Equal(in.Labels, want) {
			return &instances[i], nil
		}
	}
	return nil, nil
}

func (w *world) instanceLabels(s *cvmSpec) (map[string]string, error) {
	allocation, err := w.allocation(s)
	if err != nil {
		return nil, err
	}
	out, err := w.be.call("pod_cvm_labels", allocation)
	if err != nil {
		return nil, err
	}
	var labels map[string]string
	return labels, json.Unmarshal([]byte(out), &labels)
}

// awaitInstance waits for the pod's instance, in the named state when one
// is given.
func (w *world) awaitInstance(name, status string) (*cloudInstance, error) {
	_, s, err := w.cvm(name)
	if err != nil {
		return nil, err
	}
	var in *cloudInstance
	ok, err := poll(cvmSettle, func() (bool, error) {
		in, err = w.instanceOf(s)
		return in != nil && (status == "" || in.Status == status), err
	})
	switch {
	case err != nil:
		return nil, err
	case in == nil:
		return nil, fmt.Errorf("the cloud API holds no instance for %q", name)
	case !ok:
		return nil, fmt.Errorf("the instance of %q is %s, not %s", name, in.Status, status)
	}
	return in, nil
}

// cloudReceivedNothing reads the calls once: the sentence follows one that
// waited for the provider to settle the pod.
func cloudReceivedNothing(ctx context.Context, what, name string) error {
	w := getWorld(ctx)
	_, s, err := w.cvm(name)
	if err != nil {
		return err
	}
	if s.uid == "" {
		return nil
	}
	allocation, err := w.allocation(s)
	if err != nil {
		return err
	}
	calls, err := w.cloudCalls()
	if err != nil {
		return err
	}
	for _, c := range calls {
		if c.IdempotencyKey == allocation || (what == "call" && strings.Contains(c.Path, allocation)) {
			return fmt.Errorf("the cloud API received %s %s for %q", c.Method, c.Path, name)
		}
	}
	return nil
}

func createLabelled(ctx context.Context, name, _ string) error {
	w := getWorld(ctx)
	call, err := w.createFor(name)
	if err != nil {
		return err
	}
	want, err := w.instanceLabels(w.podCVM.specs[name])
	if err != nil {
		return err
	}
	var body struct {
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(call.Body, &body); err != nil {
		return err
	}
	if !maps.Equal(body.Labels, want) {
		return fmt.Errorf("the create for %q is labelled %v, not %v", name, body.Labels, want)
	}
	return nil
}

func documentNamesNoPod(ctx context.Context, name, _ string) error {
	w := getWorld(ctx)
	call, err := w.createFor(name)
	if err != nil {
		return err
	}
	var body struct {
		Trust struct {
			InitData struct {
				Document string `json:"document"`
			} `json:"initData"`
		} `json:"trust"`
	}
	if err := json.Unmarshal(call.Body, &body); err != nil {
		return err
	}
	document, err := base64.StdEncoding.DecodeString(body.Trust.InitData.Document)
	if err != nil || len(document) == 0 {
		return fmt.Errorf("the create for %q carries no pod document (%v)", name, err)
	}
	p, s := w.pods[name], w.podCVM.specs[name]
	for what, value := range map[string]string{"UID": s.uid, "namespace": p.namespace, "image": p.containers[0].ref} {
		if bytes.Contains(document, []byte(value)) {
			return fmt.Errorf("the pod document names the %s of %q, %s", what, name, value)
		}
	}
	return nil
}

// deletesFor counts the deletes the cloud API received for the pod's instance.
func (w *world) deletesFor(name string) (int, error) {
	in, err := w.awaitInstance(name, "")
	if err != nil {
		return 0, err
	}
	calls, err := w.cloudCalls()
	n := 0
	for _, c := range calls {
		if c.Method == "DELETE" && strings.HasSuffix(c.Path, "/"+in.ID) {
			n++
		}
	}
	return n, err
}

func cloudReceivedDelete(ctx context.Context, name string) error {
	w := getWorld(ctx)
	ok, err := poll(cvmSettle, func() (bool, error) {
		n, err := w.deletesFor(name)
		return n > 0, err
	})
	if err == nil && !ok {
		err = fmt.Errorf("the cloud API received no delete for the instance of %q", name)
	}
	return err
}

func cloudReceivesNoDelete(ctx context.Context, name string, seconds int) error {
	w := getWorld(ctx)
	deleted, err := poll(time.Duration(seconds)*time.Second, func() (bool, error) {
		n, err := w.deletesFor(name)
		return n > 0, err
	})
	if err == nil && deleted {
		err = fmt.Errorf("the cloud API received a delete for the instance of %q within %d seconds", name, seconds)
	}
	return err
}

// heartbeatStopped lets a renewal already under way land, then requires
// the renewal time to stand still for longer than the lease.
func heartbeatStopped(ctx context.Context) error {
	w := getWorld(ctx)
	time.Sleep(15 * time.Second)
	first, err := w.heartbeat()
	if err != nil {
		return err
	}
	time.Sleep(heartbeatWindow)
	last, err := w.heartbeat()
	if err == nil && last != first {
		err = fmt.Errorf("the virtual node's heartbeat moved from %s to %s", first, last)
	}
	return err
}

// awaitVirtualNodeReady waits out the outage a scenario caused: the node
// takes pods again only once the cluster sees its heartbeat.
func (w *world) awaitVirtualNodeReady() error {
	if err := heartbeatRenewed(context.WithValue(context.Background(), worldKey{}, w)); err != nil {
		return err
	}
	ok, err := poll(2*time.Minute, func() (bool, error) {
		ready, err := w.virtualNode(`{.status.conditions[?(@.type=="Ready")].status} {.spec.taints[*].key}`)
		return ready == "True "+optInKey, err
	})
	if err == nil && !ok {
		err = errors.New("the virtual node did not become ready again")
	}
	return err
}
