package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type readinessOptions struct {
	uid               string
	complete, unready bool
}

// readinessDocument is an attested Pod status with one Ready condition.
func readinessDocument(condition, timestamp string, o readinessOptions) map[string]any {
	if o.uid == "" {
		o.uid = "pod"
	}
	container := func(name string) map[string]any {
		return map[string]any{"name": name, "ready": !o.unready || name != "app", "restartCount": 0,
			"state": map[string]any{"running": map[string]any{"startedAt": "2026-01-01T00:00:00Z"}}}
	}
	app, checker, mesh := container("app"), container("checker"), container(meshContainerName)
	if o.complete {
		checker["ready"] = false
		checker["state"] = map[string]any{"terminated": map[string]any{"exitCode": 0, "startedAt": "2026-01-01T00:00:00Z", "finishedAt": timestamp}}
	}
	return map[string]any{"metadata": map[string]any{"uid": o.uid}, "status": map[string]any{
		"conditions":            []any{map[string]any{"type": "Ready", "status": condition, "lastTransitionTime": timestamp}},
		"containerStatuses":     []any{app, checker},
		"initContainerStatuses": []any{mesh}}}
}

// sameJSON compares two documents regardless of indentation.
func sameJSON(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var x, y bytes.Buffer
	if err := errors.Join(json.Compact(&x, a), json.Compact(&y, b)); err != nil {
		t.Fatal(err)
	}
	return x.String() == y.String()
}

func rawDocument(t *testing.T, doc map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readinessStatus(t *testing.T, condition, timestamp string, o readinessOptions) json.RawMessage {
	t.Helper()
	return rawDocument(t, readinessDocument(condition, timestamp, o))
}

func observeReadiness(t *testing.T, r *readinessTracker, status json.RawMessage, recovered bool) readinessObservation {
	t.Helper()
	var doc struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(status, &doc); err != nil {
		t.Fatal(err)
	}
	state, err := podStateFrom(status, doc.Metadata.UID)
	if err != nil {
		t.Fatal(err)
	}
	return r.observe(status, state, recovered)
}

// acceptedTracker returns a tracker whose baseline observation was accepted.
func acceptedTracker(t *testing.T, status json.RawMessage, recovered bool) *readinessTracker {
	t.Helper()
	if status == nil {
		status = readinessStatus(t, "True", "2026-01-01T00:10:00Z", readinessOptions{})
	}
	state, err := podStateFrom(status, "pod")
	if err != nil {
		t.Fatal(err)
	}
	r := newReadinessTracker("pod", state.Starts)
	if o := r.observe(status, state, recovered); !o.Accepted {
		t.Fatalf("baseline rejected: %s", o.Failure)
	}
	return r
}

func TestReadinessTrackerAcceptsExpectedCycleAndStableSamples(t *testing.T) {
	r := acceptedTracker(t, readinessStatus(t, "False", "2026-01-01T00:00:00Z", readinessOptions{unready: true}), false)
	traces := []bool{false}
	for _, step := range []struct {
		condition string
		minute    int
	}{{"False", 0}, {"True", 2}, {"True", 2}, {"False", 5}, {"True", 8}, {"True", 8}} {
		ready := step.condition == "True"
		status := readinessStatus(t, step.condition, fmt.Sprintf("2026-01-01T00:%02d:00Z", step.minute), readinessOptions{unready: !ready})
		traces = append(traces, ready)
		if o := observeReadiness(t, r, status, readinessCycle(traces)); !o.Accepted {
			t.Fatalf("step %+v rejected: %s", step, o.Failure)
		}
	}
	if !r.recovered {
		t.Fatal("expected cycle did not mark recovery")
	}
}

func TestReadinessTrackerRejectsHiddenTrueTransition(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		r := acceptedTracker(t, nil, recovered)
		o := observeReadiness(t, r, readinessStatus(t, "True", "2026-01-01T00:11:00Z", readinessOptions{}), recovered)
		if o.Accepted || !strings.Contains(o.Failure, "between True samples") {
			t.Fatalf("recovered=%v: %+v", recovered, o)
		}
		if o.Previous == nil || o.Current == nil || o.Previous.Status != o.Current.Status {
			t.Fatalf("recovered=%v: previous %+v, current %+v", recovered, o.Previous, o.Current)
		}
	}
}

func TestReadinessTrackerAllowsOneDelayedCheckerCompletionWithdrawal(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		r := acceptedTracker(t, nil, true)
		if delayed {
			if o := observeReadiness(t, r, readinessStatus(t, "True", "2026-01-01T00:10:00Z", readinessOptions{complete: true}), true); !o.Accepted {
				t.Fatalf("delayed completion rejected: %s", o.Failure)
			}
		}
		ended := readinessStatus(t, "False", "2026-01-01T01:10:00Z", readinessOptions{complete: true})
		o := observeReadiness(t, r, ended, true)
		if !o.Accepted || !o.CheckerCompletionWithdrawal {
			t.Fatalf("delayed=%v: completion withdrawal %+v", delayed, o)
		}
		if o := observeReadiness(t, r, ended, true); !o.Accepted {
			t.Fatalf("delayed=%v: repeated sample rejected: %s", delayed, o.Failure)
		}
		for _, condition := range []string{"False", "True", "Unknown"} {
			extra := readinessStatus(t, condition, "2026-01-01T01:11:00Z", readinessOptions{complete: true})
			if o := observeReadiness(t, r, extra, true); o.Accepted {
				t.Fatalf("delayed=%v: accepted a second transition to %s", delayed, condition)
			}
		}
	}
}

func TestReadinessTrackerCompletionCannotHideAppOrMeshFailure(t *testing.T) {
	for _, complete := range []bool{false, true} {
		for _, failed := range []string{"app", "mesh", "condition"} {
			if failed == "condition" && complete {
				continue
			}
			doc := readinessDocument("False", "2026-01-01T01:10:00Z", readinessOptions{complete: complete})
			status := doc["status"].(map[string]any)
			switch failed {
			case "app":
				status["containerStatuses"].([]any)[0].(map[string]any)["ready"] = false
			case "mesh":
				status["initContainerStatuses"].([]any)[0].(map[string]any)["ready"] = false
			}
			if o := observeReadiness(t, acceptedTracker(t, nil, true), rawDocument(t, doc), true); o.Accepted {
				t.Fatalf("complete=%v failed=%s: accepted", complete, failed)
			}
		}
	}
}

func TestReadinessTrackerConditionsAndIdentityFailClosed(t *testing.T) {
	ready := map[string]any{"type": "Ready", "status": "True", "lastTransitionTime": "2026-01-01T00:10:00Z"}
	var bad []map[string]any
	mutate := func(change func(doc map[string]any)) {
		doc := readinessDocument("True", "2026-01-01T00:10:00Z", readinessOptions{})
		change(doc)
		bad = append(bad, doc)
	}
	status := func(doc map[string]any) map[string]any { return doc["status"].(map[string]any) }
	for _, value := range []any{nil, []any{}, []any{nil}, []any{ready, ready}} {
		mutate(func(doc map[string]any) { status(doc)["conditions"] = value })
	}
	for _, kv := range [][2]any{{"type", "ContainersReady"}, {"status", true}, {"status", "invalid"},
		{"lastTransitionTime", nil}, {"lastTransitionTime", "invalid"}, {"lastTransitionTime", "2026-13-01T00:10:00Z"},
		{"lastTransitionTime", "2026-01-01T00:10:00+00:00"}, {"lastTransitionTime", "2026-01-01T00:09:00Z"}} {
		mutate(func(doc map[string]any) {
			status(doc)["conditions"].([]any)[0].(map[string]any)[kv[0].(string)] = kv[1]
		})
	}
	mutate(func(doc map[string]any) { doc["metadata"].(map[string]any)["uid"] = "another-pod" })
	for _, key := range []string{"containerStatuses", "initContainerStatuses"} {
		mutate(func(doc map[string]any) {
			status(doc)[key].([]any)[0].(map[string]any)["state"].(map[string]any)["running"].(map[string]any)["startedAt"] = "2026-01-01T00:01:00Z"
		})
	}
	for _, doc := range bad {
		raw := rawDocument(t, doc)
		if o := observeReadiness(t, acceptedTracker(t, nil, true), raw, true); o.Accepted {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestReadyConditionRejectsYearZero(t *testing.T) {
	status := readinessStatus(t, "True", "0000-01-01T00:00:00Z", readinessOptions{})
	if _, _, err := readyCondition(status); err == nil {
		t.Fatal("accepted a timestamp outside the Ready condition date range")
	}
}

// rejectedReadinessStatus changes the authenticated fields checked before the
// condition tracker. These failures must also preserve the original response.
func rejectedReadinessStatus(t *testing.T, raw json.RawMessage, kind string) json.RawMessage {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	containers := doc["status"].(map[string]any)["containerStatuses"].([]any)
	switch kind {
	case "uid":
		doc["metadata"].(map[string]any)["uid"] = "other-pod"
	case "restart":
		containers[0].(map[string]any)["restartCount"] = 1
	case "checker", "app":
		index, code := 0, 0
		if kind == "checker" {
			index, code = 1, 1
		}
		containers[index].(map[string]any)["state"] = map[string]any{"terminated": map[string]any{
			"exitCode": code, "startedAt": "2026-01-01T00:00:00Z"}}
	}
	return rawDocument(t, doc)
}

func TestRecordReadinessSavesFailedVerdictBeforeFailing(t *testing.T) {
	a := newAcceptanceTask(t)
	status := readinessStatus(t, "True", "2026-01-01T00:11:00Z", readinessOptions{})
	state, err := podStateFrom(status, "pod")
	if err != nil {
		t.Fatal(err)
	}
	err = a.recordReadiness(acceptedTracker(t, nil, true), status, state, true, "rejected")
	if err == nil || !strings.Contains(err.Error(), "between True samples") {
		t.Fatalf("err = %v", err)
	}
	path := filepath.Join(a.evidence, "rejected.json")
	var record struct {
		Status      json.RawMessage      `json:"status"`
		Observation readinessObservation `json:"observation"`
	}
	if err := json.Unmarshal([]byte(readFile(t, path)), &record); err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, record.Status, status) || record.Observation.Accepted {
		t.Fatalf("record: %s", readFile(t, path))
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v, %v", info, err)
	}
}

func TestObserveSavesReadinessBeforeRejectionOrLeafFailure(t *testing.T) {
	for _, kind := range []string{"leaf", "condition", "uid", "restart", "checker", "app"} {
		a := newAcceptanceTask(t)
		a.runDeadline = now().Add(10 * time.Hour)
		if err := write(filepath.Join(a.evidence, "mesh-ca.pem"), []byte("public CA")); err != nil {
			t.Fatal(err)
		}
		baseline := readinessStatus(t, "True", "2026-01-01T00:10:00Z", readinessOptions{uid: a.name})
		timestamp := "2026-01-01T00:10:00Z"
		if kind == "condition" {
			timestamp = "2026-01-01T00:11:00Z"
		}
		observed := rejectedReadinessStatus(t, readinessStatus(t, "True", timestamp, readinessOptions{uid: a.name}), kind)
		a.connectFn = func(string, int) error { return nil }
		a.instanceFn = func(string, time.Time) (*object, error) { return nil, nil }
		a.warmupRoundFn = func(_ time.Time, traces map[string][]bool, states map[string]podState) (map[string]*leaf, map[string]json.RawMessage, error) {
			leaves, statuses := map[string]*leaf{}, map[string]json.RawMessage{}
			for _, side := range []string{"a", "b"} {
				traces[side] = append(traces[side], true, false, true)
				state, err := podStateFrom(baseline, a.name)
				if err != nil {
					return nil, nil, err
				}
				states[side], leaves[side], statuses[side] = state, &leaf{SandboxID: side}, baseline
			}
			return leaves, statuses, nil
		}
		a.cliReadFn = func(string, []string, time.Time, bool) (json.RawMessage, error) { return observed, nil }
		leafCalls := 0
		a.leafFn = func(string, string) (*leaf, error) { leafCalls++; return nil, errors.New("leaf unavailable") }
		err := a.observe()
		want := map[string]string{"leaf": "leaf unavailable", "condition": "between True samples",
			"uid": "UID", "restart": "restart", "checker": "checker", "app": "app"}[kind]
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("kind=%s: err = %v", kind, err)
		}
		var record struct {
			Status      json.RawMessage      `json:"status"`
			Observation readinessObservation `json:"observation"`
		}
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(a.evidence, "readiness-001-a.json"))), &record); err != nil {
			t.Fatal(err)
		}
		if !sameJSON(t, record.Status, observed) || record.Observation.Accepted != (kind == "leaf") {
			t.Fatalf("kind=%s: record %+v", kind, record.Observation)
		}
		if want := map[bool]int{true: 1, false: 0}[kind == "leaf"]; leafCalls != want {
			t.Fatalf("kind=%s: leaf calls = %d, want %d", kind, leafCalls, want)
		}
		if !exists(filepath.Join(a.evidence, "readiness-baseline-a.json")) || exists(filepath.Join(a.evidence, "result.json")) {
			t.Fatalf("kind=%s: evidence set differs", kind)
		}
	}
}

func TestReadinessGuardRemainsActiveAfterNegativeProbes(t *testing.T) {
	for _, kind := range []string{"stable", "condition", "uid"} {
		t.Run(kind, func(t *testing.T) {
			a := newAcceptanceTask(t)
			start := time.Date(2026, 10, 24, 18, 30, 0, 0, time.UTC)
			clock := start
			now = func() time.Time { return clock }
			sleep = func(d time.Duration) {
				if d == 20*time.Second {
					d = 10 * time.Minute
				}
				clock = clock.Add(d)
			}
			t.Cleanup(func() { now, sleep = time.Now, time.Sleep })
			a.runDeadline = start.Add(2 * time.Hour)
			a.connectFn = func(string, int) error { return nil }
			a.instanceFn = func(string, time.Time) (*object, error) { return &object{}, nil }
			a.caFn = func(path string, _ time.Time) error { return write(path, []byte("fixture CA")) }
			negativeStarted := false
			reads := map[string]int{}
			a.cliReadFn = func(side string, mode []string, _ time.Time, _ bool) (json.RawMessage, error) {
				if mode[0] == "pod-attest" {
					return json.RawMessage(`{}`), nil
				}
				reads[side]++
				ready, stamp := true, start.Add(20*time.Minute)
				switch reads[side] {
				case 1:
					ready, stamp = false, start
				case 2:
					stamp = start
				case 3:
					ready, stamp = false, start.Add(10*time.Minute)
				}
				condition, complete := "True", clock.Sub(start) >= soak
				if !ready {
					condition = "False"
				}
				if complete {
					condition, stamp = "False", start.Add(70*time.Minute)
				}
				if negativeStarted && kind == "condition" {
					stamp = clock
				}
				raw := readinessStatus(t, condition, stamp.Format(time.RFC3339), readinessOptions{uid: a.name, unready: !ready, complete: complete})
				if negativeStarted {
					raw = rejectedReadinessStatus(t, raw, kind)
				}
				return raw, nil
			}
			a.leafFn = func(side, mode string) (*leaf, error) {
				negativeStarted = negativeStarted || mode != "certless"
				serial, before := "initial", start
				if clock.Sub(start) >= 40*time.Minute {
					serial, before = "renewed", start.Add(40*time.Minute)
				}
				return &leaf{SandboxID: side, Workload: "connected", Denied: true, Serial: serial, SPKI: serial,
					NotBefore: before.Format(time.RFC3339), NotAfter: before.Add(time.Hour).Format(time.RFC3339), raw: json.RawMessage(`{}`)}, nil
			}
			err := a.observe()
			if (err != nil) != (kind != "stable") || !negativeStarted {
				t.Fatalf("final gate: error=%v negatives=%v", err, negativeStarted)
			}
			var receipt struct{ Observation readinessObservation }
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(a.evidence, "readiness-final-a.json"))), &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.Observation.Accepted != (kind == "stable") || exists(filepath.Join(a.evidence, "result.json")) != (kind == "stable") {
				t.Fatalf("post-negative transition verdict differs: %+v", receipt)
			}
		})
	}
}
