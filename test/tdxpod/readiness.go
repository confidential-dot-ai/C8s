package main

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/podcvmtest"
)

type readinessObservation = podcvmtest.ReadinessObservation
type readinessTracker = podcvmtest.ReadinessTracker

var newReadinessTracker = podcvmtest.NewReadinessTracker
var readyCondition = podcvmtest.ReadyCondition

// parseReadinessStatus retains an authenticated response even when Pod identity,
// restarts or container exits prevent the readiness tracker from accepting it.
func (a *acceptance) parseReadinessStatus(status json.RawMessage, name string) (podState, error) {
	state, err := podStateOf(status, a.name)
	if err != nil {
		o := readinessObservation{UID: a.name, Failure: err.Error()}
		return state, errors.Join(err, a.writeReadiness(status, o, name))
	}
	return state, nil
}

func (a *acceptance) writeReadiness(status json.RawMessage, o readinessObservation, name string) error {
	return write(filepath.Join(a.evidence, name+".json"), map[string]any{"status": status, "observation": o})
}

// recordReadiness keeps the authenticated response and its verdict as
// evidence even when the tracker refuses the sample.
func (a *acceptance) recordReadiness(r *readinessTracker, status json.RawMessage, state podState, recovered bool, name string) error {
	o := r.Observe(status, state, recovered)
	if err := a.writeReadiness(status, o, name); err != nil {
		return err
	}
	if !o.Accepted {
		return errors.New(o.Failure)
	}
	return nil
}
