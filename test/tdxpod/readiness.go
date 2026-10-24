package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"time"
)

var conditionTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$`)

type readinessCondition struct {
	Status             string `json:"status"`
	LastTransitionTime string `json:"lastTransitionTime"`
}

// readinessObservation is one verdict on an authenticated Pod status. It is
// saved whether or not the tracker accepted the sample.
type readinessObservation struct {
	UID                         string              `json:"uid"`
	Previous                    *readinessCondition `json:"previous"`
	Current                     *readinessCondition `json:"current,omitempty"`
	AppMeshReady                bool                `json:"appMeshReady"`
	CheckerComplete             bool                `json:"checkerComplete"`
	ExpectedCycleRecovered      bool                `json:"expectedCycleRecovered"`
	Accepted                    bool                `json:"accepted"`
	CheckerCompletionWithdrawal bool                `json:"checkerCompletionWithdrawal,omitempty"`
	Failure                     string              `json:"failure,omitempty"`
}

// readinessTracker retains the authenticated Ready condition transitions that
// boolean polling can miss: a Ready condition whose lastTransitionTime moved
// between two ready samples withdrew and recovered unobserved.
type readinessTracker struct {
	uid                             string
	starts                          map[string]string
	previous                        *readinessCondition
	previousTime                    time.Time
	recovered, completionWithdrawal bool
}

func newReadinessTracker(uid string, starts map[string]string) *readinessTracker {
	copied := map[string]string{}
	for name, started := range starts {
		copied[name] = started
	}
	return &readinessTracker{uid: uid, starts: copied}
}

// readyCondition returns the single Ready condition of an attested status and
// its transition time; anything else fails closed.
func readyCondition(status json.RawMessage) (*readinessCondition, time.Time, error) {
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
	if err != nil {
		return nil, time.Time{}, errors.New("readiness condition timestamp is malformed")
	}
	return &readinessCondition{Status: state, LastTransitionTime: stamp}, at, nil
}

// observe judges one authenticated status against the retained condition.
// recovered says whether the boolean trace has shown the expected
// ready, unready, ready cycle.
func (r *readinessTracker) observe(status json.RawMessage, state podState, recovered bool) readinessObservation {
	o := readinessObservation{UID: r.uid, Previous: r.previous, AppMeshReady: state.Ready, CheckerComplete: state.Complete, ExpectedCycleRecovered: recovered}
	current, at, err := r.verdict(status, state, recovered, &o)
	if err != nil {
		o.Failure = err.Error()
		return o
	}
	r.previous, r.previousTime, o.Accepted = current, at, true
	return o
}

func (r *readinessTracker) verdict(status json.RawMessage, state podState, recovered bool, o *readinessObservation) (*readinessCondition, time.Time, error) {
	var doc struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(status, &doc); err != nil || doc.Metadata.UID != r.uid {
		return nil, time.Time{}, errors.New("readiness Pod UID changed")
	}
	if !sameStarts(state.Starts, r.starts) {
		return nil, time.Time{}, errors.New("readiness container starts changed")
	}
	current, at, err := readyCondition(status)
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

// recordReadiness keeps the authenticated response and its verdict as
// evidence even when the tracker refuses the sample.
func (a *acceptance) recordReadiness(r *readinessTracker, status json.RawMessage, state podState, recovered bool, name string) error {
	o := r.observe(status, state, recovered)
	if err := write(filepath.Join(a.evidence, name+".json"), map[string]any{"status": status, "observation": o}); err != nil {
		return err
	}
	if !o.Accepted {
		return errors.New(o.Failure)
	}
	return nil
}
