package main

// Offline ownership, cleanup and confidentiality gates shared by the three
// lanes; they do not substitute for a TDX run.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testRepo = "confidential-dot-ai/C8s"

type reply struct {
	body []byte
	err  error
}

// sequence answers kubectl calls in order and records them.
func sequence(t *testing.T, replies ...reply) (*[][]string, *[][]byte) {
	t.Helper()
	var calls [][]string
	var datas [][]byte
	kube = func(args []string, data []byte, _ time.Duration) ([]byte, error) {
		calls = append(calls, args)
		datas = append(datas, data)
		if len(calls) > len(replies) {
			t.Fatalf("unexpected kubectl call %v", args)
		}
		r := replies[len(calls)-1]
		return r.body, r.err
	}
	t.Cleanup(func() { kube = runKubectl })
	return &calls, &datas
}

// quiet captures progress output so tests can assert on what reaches logs.
func quiet(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	progressOut = &out
	t.Cleanup(func() { progressOut = os.Stdout })
	return &out
}

func noSleep(t *testing.T) {
	t.Helper()
	sleep = func(time.Duration) {}
	t.Cleanup(func() { sleep = time.Sleep })
}

func newOwnedTask(t *testing.T) *owned {
	t.Helper()
	o, err := newOwned(t.TempDir(), "123", "2", testRepo, "c8s-podacc", "pod-connected-acceptance")
	if err != nil {
		t.Fatal(err)
	}
	noSleep(t)
	return o
}

// ownedObject renders an owned object of this task with mutations applied.
func ownedObject(t *testing.T, o *owned, kind, suffix string, mutate func(map[string]any)) []byte {
	t.Helper()
	meta, err := o.metadata(kind, suffix)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"metadata": meta})
	var obj map[string]any
	_ = json.Unmarshal(raw, &obj)
	m := obj["metadata"].(map[string]any)
	m["uid"], m["resourceVersion"] = "owned", "9"
	if mutate != nil {
		mutate(obj)
	}
	raw, _ = json.Marshal(obj)
	return raw
}

func ledger(t *testing.T, o *owned, entries ...resource) {
	t.Helper()
	for _, e := range entries {
		if _, err := o.metadata(e.Kind, e.Suffix); err != nil {
			t.Fatal(err)
		}
	}
	if err := write(o.ledger, entries); err != nil {
		t.Fatal(err)
	}
}

func str(s string) *string { return &s }

func wantError(t *testing.T, err error, substring string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substring) {
		t.Fatalf("want error containing %q, got %v", substring, err)
	}
}

func parse(t *testing.T, raw []byte) *object {
	t.Helper()
	obj, err := parseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestScopeAndAttemptAreRequired(t *testing.T) {
	for _, c := range [][3]string{{"../123", "2", testRepo}, {"123", "", testRepo}, {"123", "2", "foreign/C8s"}} {
		if _, err := newOwned(t.TempDir(), c[0], c[1], c[2], "c8s-podacc", "x"); err == nil {
			t.Errorf("accepted identity %v", c)
		}
	}
	o := newOwnedTask(t)
	for _, c := range []struct{ field, key, value string }{
		{"metadata", "namespace", "default"}, {"labels", "ci.confidential.ai/run-attempt", "3"},
		{"labels", "ci.confidential.ai/run-id", "456"}, {"annotations", "ci.confidential.ai/repo", "foreign/C8s"}} {
		obj := parse(t, ownedObject(t, o, "vm", "-a", func(m map[string]any) {
			target := m["metadata"].(map[string]any)
			if c.field != "metadata" {
				target = target[c.field].(map[string]any)
			}
			target[c.key] = c.value
		}))
		if err := o.checkOwned(obj, "vm", "-a", "owned"); err == nil {
			t.Errorf("accepted %s %s=%s", c.field, c.key, c.value)
		}
	}
}

func TestNoExistingResourceIsAdopted(t *testing.T) {
	o := newOwnedTask(t)
	calls, _ := sequence(t, reply{body: ownedObject(t, o, "vm", "-a", nil)})
	_, err := o.create("vm", "-a", map[string]any{})
	wantError(t, err, "refusing existing")
	if len(*calls) != 1 {
		t.Fatalf("calls: %v", *calls)
	}
	if exists(o.ledger) {
		t.Fatal("ledger written for a refused create")
	}
}

func TestUnknownCreateOutcomeRequiresTheExactCreationNonce(t *testing.T) {
	o := newOwnedTask(t)
	sequence(t, reply{}, reply{err: errors.New("unknown outcome")})
	_, err := o.create("vm", "-a", map[string]any{})
	wantError(t, err, "unknown outcome")
	entries, _ := o.resources()
	if len(entries) != 1 || entries[0].Kind != "vm" || entries[0].Suffix != "-a" || entries[0].UID != nil {
		t.Fatalf("ledger: %+v", entries)
	}
	other := ownedObject(t, o, "vm", "-a", func(m map[string]any) {
		meta := m["metadata"].(map[string]any)
		meta["uid"] = "replacement"
		meta["annotations"].(map[string]any)["ci.confidential.ai/creation-nonce"] = "different-request"
	})
	calls, _ := sequence(t, reply{body: other})
	wantError(t, o.remove("vm", "-a", time.Time{}), "ownership differs")
	if len(*calls) != 1 {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestCrossKindCreationIntentsNeverShareANonce(t *testing.T) {
	o := newOwnedTask(t)
	service, _ := o.metadata("service", "-a")
	vm, _ := o.metadata("vm", "-a")
	if service.Annotations["ci.confidential.ai/creation-nonce"] == vm.Annotations["ci.confidential.ai/creation-nonce"] {
		t.Fatal("nonces are shared across kinds")
	}
	ledger(t, o, resource{Kind: "vm", Suffix: "-a"})
	copied := ownedObject(t, o, "vm", "-a", func(m map[string]any) {
		m["metadata"].(map[string]any)["annotations"].(map[string]any)["ci.confidential.ai/creation-nonce"] = service.Annotations["ci.confidential.ai/creation-nonce"]
	})
	calls, _ := sequence(t, reply{body: copied})
	wantError(t, o.remove("vm", "-a", time.Time{}), "ownership differs")
	if len(*calls) != 1 {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestCreationNonceSurvivesTheCleanupProcess(t *testing.T) {
	o := newOwnedTask(t)
	first, _ := o.metadata("vm", "-a")
	resumed, err := newOwned(o.root, "123", "2", testRepo, "c8s-podacc", "pod-connected-acceptance")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := resumed.metadata("vm", "-a")
	if again.Annotations["ci.confidential.ai/creation-nonce"] != first.Annotations["ci.confidential.ai/creation-nonce"] {
		t.Fatal("nonce did not survive a new process")
	}
}

func TestScopeOrUIDMismatchNeverDeletes(t *testing.T) {
	o := newOwnedTask(t)
	ledger(t, o, resource{Kind: "vm", Suffix: "-a", UID: str("owned")})
	for _, c := range []struct{ field, key, value string }{
		{"metadata", "uid", "other"}, {"metadata", "namespace", "default"},
		{"labels", "ci.confidential.ai/run-attempt", "3"}, {"annotations", "ci.confidential.ai/repo", "foreign/C8s"}} {
		obj := ownedObject(t, o, "vm", "-a", func(m map[string]any) {
			target := m["metadata"].(map[string]any)
			if c.field != "metadata" {
				target = target[c.field].(map[string]any)
			}
			target[c.key] = c.value
		})
		calls, _ := sequence(t, reply{body: obj})
		if err := o.remove("vm", "-a", time.Time{}); err == nil {
			t.Errorf("deleted with %s %s=%s", c.field, c.key, c.value)
		}
		if len(*calls) != 1 {
			t.Fatalf("calls: %v", *calls)
		}
	}
}

func TestDeletesAreUIDPreconditioned(t *testing.T) {
	for kind, path := range map[string]string{"vm": "/apis/kubevirt.io/v1/namespaces/confai-images/virtualmachines/c8s-podacc-123-2-a",
		"service": "/api/v1/namespaces/confai-images/services/c8s-podacc-123-2-a"} {
		o := newOwnedTask(t)
		ledger(t, o, resource{Kind: kind, Suffix: "-a", UID: str("owned")})
		calls, datas := sequence(t, reply{body: ownedObject(t, o, kind, "-a", nil)}, reply{body: []byte("{}")}, reply{})
		if err := o.remove(kind, "-a", time.Time{}); err != nil {
			t.Fatal(err)
		}
		del := (*calls)[1]
		if del[0] != "delete" || del[1] != "--raw" || del[2] != path {
			t.Fatalf("delete call: %v", del)
		}
		var options struct {
			Preconditions map[string]string `json:"preconditions"`
		}
		if err := json.Unmarshal((*datas)[1], &options); err != nil || options.Preconditions["uid"] != "owned" {
			t.Fatalf("delete options: %s (%v)", (*datas)[1], err)
		}
	}
}

func TestAllVMsRemovedBeforeDependenciesAndFailuresRetainSharedDisk(t *testing.T) {
	o := newOwnedTask(t)
	ledger(t, o, resource{Kind: "pvc", Suffix: "-root", UID: str("disk")}, resource{Kind: "vm", Suffix: "-a", UID: str("a")}, resource{Kind: "vm", Suffix: "-b", UID: str("b")})
	var removed [][2]string
	o.removeFn = func(kind, suffix string, _ time.Time) error {
		removed = append(removed, [2]string{kind, suffix})
		if suffix == "-b" {
			return errors.New("b still running")
		}
		return nil
	}
	wantError(t, o.cleanup(), "cleanup incomplete")
	if len(removed) != 2 || removed[0] != [2]string{"vm", "-b"} || removed[1] != [2]string{"vm", "-a"} {
		t.Fatalf("removed: %v", removed)
	}
	var receipt struct {
		Complete bool `json:"complete"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(o.evidence, "cleanup.json"))), &receipt); err != nil || receipt.Complete {
		t.Fatalf("cleanup receipt: %+v (%v)", receipt, err)
	}
}

func TestReplacedVMStopsCleanupBeforeDependencies(t *testing.T) {
	o := newOwnedTask(t)
	ledger(t, o, resource{Kind: "pvc", Suffix: "-root", UID: str("root")}, resource{Kind: "vm", Suffix: "-a", UID: str("owned")})
	calls, _ := sequence(t, reply{body: ownedObject(t, o, "vm", "-a", func(m map[string]any) { m["metadata"].(map[string]any)["uid"] = "replacement" })})
	wantError(t, o.cleanup(), "cleanup incomplete")
	if len(*calls) != 1 || (*calls)[0][1] != "vm" {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestInterruptedLedgerPublicationPreservesPreviousIntent(t *testing.T) {
	o := newOwnedTask(t)
	ledger(t, o, resource{Kind: "vm", Suffix: "-a", UID: str("owned")})
	before := readFile(t, o.ledger)
	rename = func(string, string) error { return errors.New("interrupted publication") }
	t.Cleanup(func() { rename = os.Rename })
	wantError(t, write(o.ledger, []resource{}), "interrupted publication")
	if readFile(t, o.ledger) != before {
		t.Fatal("ledger changed by a failed write")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(o.private, "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporaries left: %v", leftovers)
	}
}

func TestRequestBudgetDoesNotOutliveThePhase(t *testing.T) {
	t0 := time.Unix(100, 0)
	now = func() time.Time { return t0 }
	t.Cleanup(func() { now = time.Now })
	if d, err := budget(t0.Add(7*time.Second), 30*time.Second); err != nil || d != 7*time.Second {
		t.Fatalf("budget(7s) = %v, %v", d, err)
	}
	if d, err := budget(t0.Add(200*time.Second), 30*time.Second); err != nil || d != 30*time.Second {
		t.Fatalf("budget(200s) = %v, %v", d, err)
	}
	if d, err := budget(time.Time{}, 30*time.Second); err != nil || d != 30*time.Second {
		t.Fatalf("budget(none) = %v, %v", d, err)
	}
	if _, err := budget(t0, 30*time.Second); err == nil {
		t.Fatal("budget past the deadline succeeded")
	}
}

func TestMutationCommandErrorsStillHidePayloadAndStderr(t *testing.T) {
	execute = func([]string, []string, []byte, time.Duration) (processResult, error) {
		return processResult{code: 1, stderr: []byte("payload-not-for-logs")}, nil
	}
	t.Cleanup(func() { execute = runProcess })
	_, err := command([]string{"kubectl", "create"}, []byte("stdin-not-for-logs"), time.Second)
	if err == nil || err.Error() != "command failed: kubectl (exit 1)" {
		t.Fatalf("error: %v", err)
	}
}
