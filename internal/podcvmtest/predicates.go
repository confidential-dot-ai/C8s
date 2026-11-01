// Package podcvmtest holds the common authenticated acceptance predicates.
package podcvmtest

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"
)

const meshContainerName = "c8s-mesh"

type containerStatus struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restartCount"`
	State        struct {
		Running *struct {
			StartedAt string `json:"startedAt"`
		} `json:"running"`
		Terminated *struct {
			ExitCode  int    `json:"exitCode"`
			StartedAt string `json:"startedAt"`
		} `json:"terminated"`
	} `json:"state"`
}

func (c containerStatus) startedAt() string {
	if c.State.Running != nil {
		return c.State.Running.StartedAt
	}
	if c.State.Terminated != nil {
		return c.State.Terminated.StartedAt
	}
	return ""
}

// PodState is what the attested Pod status says about the signed workloads
// and the injected mesh endpoint.
type PodState struct {
	Ready, Complete, Running bool
	Starts                   map[string]string
}

func PodStateFrom(status json.RawMessage, uid string) (PodState, error) {
	var doc struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Status struct {
			ContainerStatuses     []containerStatus `json:"containerStatuses"`
			InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal(status, &doc); err != nil {
		return PodState{}, errors.New("unreadable attested Pod status")
	}
	if doc.Metadata.UID != uid {
		return PodState{}, errors.New("attested Pod UID differs")
	}
	states := map[string]containerStatus{}
	for _, c := range doc.Status.ContainerStatuses {
		states[c.Name] = c
	}
	if len(states) == 0 {
		return PodState{Starts: map[string]string{}}, nil
	}
	if _, app := states["app"]; !app || len(states) != 2 || states["checker"].Name != "checker" {
		return PodState{}, errors.New("unexpected signed workload container")
	}
	endpoints := map[string]containerStatus{}
	for _, c := range doc.Status.InitContainerStatuses {
		endpoints[c.Name] = c
	}
	if len(endpoints) != 1 || endpoints[meshContainerName].Name != meshContainerName {
		return PodState{}, errors.New("expected measured mesh endpoint is missing")
	}
	states[meshContainerName] = endpoints[meshContainerName]
	for _, c := range states {
		if c.RestartCount != 0 {
			return PodState{}, errors.New("workload restarted")
		}
	}
	for _, name := range []string{"app", meshContainerName} {
		if states[name].State.Terminated != nil {
			return PodState{}, errors.New("application or mesh endpoint exited")
		}
	}
	ended := states["checker"].State.Terminated
	if ended != nil && ended.ExitCode != 0 {
		return PodState{}, errors.New("network acceptance checker failed")
	}
	starts, running := map[string]string{}, true
	for name, c := range states {
		starts[name] = c.startedAt()
		running = running && c.State.Running != nil && starts[name] != ""
	}
	ready := true
	for _, name := range []string{"app", meshContainerName} {
		ready = ready && states[name].Ready && states[name].State.Running != nil
	}
	return PodState{Ready: ready, Complete: ended != nil, Running: running, Starts: starts}, nil
}

// Leaf is the public certificate probe's view of one Pod's mesh identity.
type Leaf struct {
	SandboxID string          `json:"sandboxID"`
	Serial    string          `json:"serial"`
	SPKI      string          `json:"spki"`
	Workload  string          `json:"workload"`
	Denied    bool            `json:"denied"`
	NotBefore string          `json:"notBefore"`
	NotAfter  string          `json:"notAfter"`
	Raw       json.RawMessage `json:"-"`
}

func ParseLeaf(raw []byte) (*Leaf, error) {
	l := &Leaf{Raw: raw}
	if err := json.Unmarshal(raw, l); err != nil {
		return nil, errors.New("unreadable certificate probe response")
	}
	return l, nil
}

func Renewed(initial, current *Leaf) (bool, error) {
	return renewedNamed(initial, current, "connected")
}

func renewedNamed(initial, current *Leaf, workload string) (bool, error) {
	if initial.SandboxID != current.SandboxID {
		return false, errors.New("pod identity changed during renewal")
	}
	if current.Workload != workload || !current.Denied {
		return false, errors.New("named Leaf missing or certless access succeeded")
	}
	return initial.Serial != current.Serial && initial.SPKI != current.SPKI, nil
}

// RenewalEvent is a new transition after steady runtime, not an early
// replacement still served later. The guest's one-hour timer allows
// downward jitter; forty minutes is below its floor.
func RenewalEvent(previous, current *Leaf, elapsed time.Duration) (bool, error) {
	return RenewalEventNamed(previous, current, elapsed, "connected")
}

// RenewalEventNamed applies the same renewal gate to a Cloud fixture's named workload.
func RenewalEventNamed(previous, current *Leaf, elapsed time.Duration, workload string) (bool, error) {
	changed, err := renewedNamed(previous, current, workload)
	if err != nil || !changed || elapsed < 2400*time.Second {
		return false, err
	}
	parse := func(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
	beforePrevious, err1 := parse(previous.NotBefore)
	beforeCurrent, err2 := parse(current.NotBefore)
	afterPrevious, err3 := parse(previous.NotAfter)
	afterCurrent, err4 := parse(current.NotAfter)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return false, errors.New("unreadable leaf validity")
	}
	return beforeCurrent.Sub(beforePrevious) >= 2400*time.Second && afterCurrent.After(afterPrevious), nil
}

// ReadinessCycle compresses repeats and requires ready, unready, ready.
func ReadinessCycle(values []bool) bool {
	var transitions []bool
	for i, v := range values {
		if i == 0 || v != values[i-1] {
			transitions = append(transitions, v)
		}
	}
	if len(transitions) != 0 && !transitions[0] {
		transitions = transitions[1:]
	}
	return slices.Equal(transitions, []bool{true, false, true})
}

var conditionTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$`)

type ReadinessCondition struct {
	Status             string `json:"status"`
	LastTransitionTime string `json:"lastTransitionTime"`
}

// ReadinessObservation is one verdict on an authenticated Pod status. It is
// saved whether or not the tracker accepted the sample.
type ReadinessObservation struct {
	UID                         string              `json:"uid"`
	Previous                    *ReadinessCondition `json:"previous"`
	Current                     *ReadinessCondition `json:"current,omitempty"`
	AppMeshReady                bool                `json:"appMeshReady"`
	CheckerComplete             bool                `json:"checkerComplete"`
	ExpectedCycleRecovered      bool                `json:"expectedCycleRecovered"`
	Accepted                    bool                `json:"accepted"`
	CheckerCompletionWithdrawal bool                `json:"checkerCompletionWithdrawal,omitempty"`
	Failure                     string              `json:"failure,omitempty"`
}

// ReadinessTracker retains the authenticated Ready condition transitions that
// boolean polling can miss: a Ready condition whose lastTransitionTime moved
// between two ready samples withdrew and recovered unobserved.
type ReadinessTracker struct {
	uid                             string
	starts                          map[string]string
	previous                        *ReadinessCondition
	previousTime                    time.Time
	recovered, completionWithdrawal bool
}

func NewReadinessTracker(uid string, starts map[string]string) *ReadinessTracker {
	copied := map[string]string{}
	for name, started := range starts {
		copied[name] = started
	}
	return &ReadinessTracker{uid: uid, starts: copied}
}

// ReadyCondition returns the single Ready condition of an attested status and
// its transition time; anything else fails closed.
func ReadyCondition(status json.RawMessage) (*ReadinessCondition, time.Time, error) {
	malformed := errors.New("readiness conditions are malformed")
	var doc struct {
		Status struct {
			Conditions []json.RawMessage `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal(status, &doc); err != nil || doc.Status.Conditions == nil {
		return nil, time.Time{}, malformed
	}
	type condition struct {
		Type               any `json:"type"`
		Status             any `json:"status"`
		LastTransitionTime any `json:"lastTransitionTime"`
	}
	var ready []condition
	for _, raw := range doc.Status.Conditions {
		var c condition
		if string(raw) == "null" || json.Unmarshal(raw, &c) != nil {
			return nil, time.Time{}, malformed
		}
		if c.Type == "Ready" {
			ready = append(ready, c)
		}
	}
	if len(ready) != 1 {
		return nil, time.Time{}, errors.New("readiness requires exactly one Ready condition")
	}
	state, ok := ready[0].Status.(string)
	if !ok || (state != "True" && state != "False" && state != "Unknown") {
		return nil, time.Time{}, errors.New("readiness condition status is malformed")
	}
	stamp, ok := ready[0].LastTransitionTime.(string)
	if !ok || !conditionTimestamp.MatchString(stamp) {
		return nil, time.Time{}, errors.New("readiness condition timestamp is malformed")
	}
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || at.Year() < 1 {
		return nil, time.Time{}, errors.New("readiness condition timestamp is malformed")
	}
	return &ReadinessCondition{Status: state, LastTransitionTime: stamp}, at, nil
}

// Observe judges one authenticated status against the retained condition.
// recovered says whether the boolean trace has shown the expected
// ready, unready, ready cycle.
func (r *ReadinessTracker) Observe(status json.RawMessage, state PodState, recovered bool) ReadinessObservation {
	o := ReadinessObservation{UID: r.uid, Previous: r.previous, AppMeshReady: state.Ready, CheckerComplete: state.Complete, ExpectedCycleRecovered: recovered}
	current, at, err := r.verdict(status, state, recovered, &o)
	if err != nil {
		o.Failure = err.Error()
		return o
	}
	r.previous, r.previousTime, o.Accepted = current, at, true
	return o
}

func (r *ReadinessTracker) verdict(status json.RawMessage, state PodState, recovered bool, o *ReadinessObservation) (*ReadinessCondition, time.Time, error) {
	var doc struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(status, &doc); err != nil || doc.Metadata.UID != r.uid {
		return nil, time.Time{}, errors.New("readiness Pod UID changed")
	}
	if !SameStarts(state.Starts, r.starts) {
		return nil, time.Time{}, errors.New("readiness container starts changed")
	}
	current, at, err := ReadyCondition(status)
	if err != nil {
		return nil, time.Time{}, err
	}
	o.Current = current
	if r.previous != nil {
		if at.Before(r.previousTime) {
			return nil, time.Time{}, errors.New("readiness condition timestamp moved backwards")
		}
		if r.previous.Status == "True" && current.Status == "True" && at.After(r.previousTime) {
			return nil, time.Time{}, errors.New("unexpected readiness condition transition between True samples")
		}
	}
	switch {
	case r.recovered:
		if !state.Ready {
			return nil, time.Time{}, errors.New("unexpected readiness withdrawal after recovery")
		}
		if *current != *r.previous {
			// A successful checker exit may withdraw aggregate Pod Ready later
			// than its container status; app and mesh must remain ready.
			completion := state.Complete && !r.completionWithdrawal && r.previous.Status == "True" && current.Status == "False"
			if !completion {
				return nil, time.Time{}, errors.New("unexpected readiness condition transition after recovery")
			}
			r.completionWithdrawal, o.CheckerCompletionWithdrawal = true, true
		}
	case recovered:
		if current.Status != "True" || !state.Ready {
			return nil, time.Time{}, errors.New("readiness recovery condition differs")
		}
		r.recovered = true
	}
	return current, at, nil
}

func SameStarts(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (r *ReadinessTracker) Recovered() bool { return r.recovered }
