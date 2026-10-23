package main

// Offline ownership and cleanup gates; these do not substitute for a TDX run.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

func newTask(t *testing.T) *diagnostic {
	t.Helper()
	task, err := newDiagnostic(t.TempDir(), "123", "2", "confidential-dot-ai/C8s")
	if err != nil {
		t.Fatal(err)
	}
	sleep = func(time.Duration) {}
	t.Cleanup(func() { sleep = time.Sleep })
	return task
}

// object renders an owned object of this task with mutations applied.
func owned(t *testing.T, task *diagnostic, suffix string, mutate func(map[string]any)) []byte {
	t.Helper()
	meta, err := task.metadata(suffix)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"metadata": meta})
	var obj map[string]any
	_ = json.Unmarshal(raw, &obj)
	m := obj["metadata"].(map[string]any)
	m["uid"], m["resourceVersion"] = "owned-uid", "17"
	if mutate != nil {
		mutate(obj)
	}
	raw, _ = json.Marshal(obj)
	return raw
}

func ledger(t *testing.T, task *diagnostic, entries ...resource) {
	t.Helper()
	for _, e := range entries {
		if _, err := task.metadata(e.Suffix); err != nil {
			t.Fatal(err)
		}
	}
	if err := write(task.ledger, entries); err != nil {
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
	obj := &object{raw: raw}
	if err := json.Unmarshal(raw, obj); err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestScopeAndAttemptAreRequired(t *testing.T) {
	for _, c := range [][3]string{{"../123", "2", "confidential-dot-ai/C8s"}, {"123", "", "confidential-dot-ai/C8s"}, {"123", "2", "foreign/C8s"}} {
		if _, err := newDiagnostic(t.TempDir(), c[0], c[1], c[2]); err == nil {
			t.Errorf("accepted identity %v", c)
		}
	}
	task := newTask(t)
	for _, c := range []struct{ field, key, value string }{
		{"metadata", "namespace", "default"}, {"labels", "ci.confidential.ai/run-attempt", "1"},
		{"labels", "ci.confidential.ai/run-id", "456"}, {"annotations", "ci.confidential.ai/repo", "foreign/C8s"}} {
		obj := parse(t, owned(t, task, "", func(o map[string]any) {
			target := o["metadata"].(map[string]any)
			if c.field != "metadata" {
				target = target[c.field].(map[string]any)
			}
			target[c.key] = c.value
		}))
		if err := task.owned(obj, "", "owned-uid"); err == nil {
			t.Errorf("accepted %s %s=%s", c.field, c.key, c.value)
		}
	}
}

func TestCreateRefusesExistingEvenWithMatchingLabels(t *testing.T) {
	task := newTask(t)
	calls, _ := sequence(t, reply{body: owned(t, task, "", nil)})
	vm, _ := task.vm()
	wantError(t, func() error { _, err := task.create("vm", "", vm); return err }(), "refusing existing")
	if len(*calls) != 1 {
		t.Fatalf("calls: %v", *calls)
	}
	if _, err := os.Stat(task.ledger); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ledger written for a refused create")
	}
}

func TestCreateRecordsUnknownOutcomeForCleanup(t *testing.T) {
	task := newTask(t)
	sequence(t, reply{}, reply{err: errors.New("lost response")})
	vm, _ := task.vm()
	wantError(t, func() error { _, err := task.create("vm", "", vm); return err }(), "lost response")
	entries, _ := task.resources()
	if len(entries) != 1 || entries[0].Kind != "vm" || entries[0].Suffix != "" || entries[0].UID != nil {
		t.Fatalf("ledger: %+v", entries)
	}
}

func TestUnknownCreateOutcomeDoesNotAdoptAnotherRequest(t *testing.T) {
	task := newTask(t)
	sequence(t, reply{}, reply{err: errors.New("AlreadyExists")})
	vm, _ := task.vm()
	if _, err := task.create("vm", "", vm); err == nil {
		t.Fatal("create succeeded")
	}
	replacement := owned(t, task, "", func(o map[string]any) {
		o["metadata"].(map[string]any)["annotations"].(map[string]any)["ci.confidential.ai/creation-nonce"] = "foreign-request"
	})
	calls, _ := sequence(t, reply{body: replacement})
	wantError(t, task.remove("vm", ""), "ownership differs")
	if len(*calls) != 1 {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestCreationNonceIsPerResourceAndSurvivesCleanupProcess(t *testing.T) {
	task := newTask(t)
	first, _ := task.metadata("")
	second, _ := task.metadata("-root")
	if first.Annotations["ci.confidential.ai/creation-nonce"] == second.Annotations["ci.confidential.ai/creation-nonce"] {
		t.Fatal("nonces are shared between resources")
	}
	resumed, _ := newDiagnostic(task.root, "123", "2", "confidential-dot-ai/C8s")
	again, _ := resumed.metadata("")
	if again.Annotations["ci.confidential.ai/creation-nonce"] != first.Annotations["ci.confidential.ai/creation-nonce"] {
		t.Fatal("nonce did not survive a new process")
	}
}

func TestFailedAtomicWritePreservesTheExistingLedger(t *testing.T) {
	task := newTask(t)
	ledger(t, task, resource{Kind: "vm", Suffix: "", UID: str("owned-uid")})
	before, _ := os.ReadFile(task.ledger)
	rename = func(string, string) error { return errors.New("interrupted publication") }
	t.Cleanup(func() { rename = os.Rename })
	wantError(t, write(task.ledger, []resource{}), "interrupted publication")
	after, _ := os.ReadFile(task.ledger)
	if !bytes.Equal(before, after) {
		t.Fatal("ledger changed by a failed write")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(task.private, "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporaries left: %v", leftovers)
	}
}

func TestRequestBudgetDoesNotOutliveThePhase(t *testing.T) {
	t0 := time.Unix(100, 0)
	now = func() time.Time { return t0 }
	t.Cleanup(func() { now = time.Now })
	if d, err := budget(t0.Add(7 * time.Second)); err != nil || d != 7*time.Second {
		t.Fatalf("budget(7s) = %v, %v", d, err)
	}
	if d, err := budget(t0.Add(200 * time.Second)); err != nil || d != 30*time.Second {
		t.Fatalf("budget(200s) = %v, %v", d, err)
	}
	if d, err := budget(time.Time{}); err != nil || d != 30*time.Second {
		t.Fatalf("budget(none) = %v, %v", d, err)
	}
	if _, err := budget(t0); err == nil {
		t.Fatal("budget past the deadline succeeded")
	}
}

func TestCleanupRejectsReplacedResourceBeforeDelete(t *testing.T) {
	task := newTask(t)
	ledger(t, task, resource{Kind: "vm", Suffix: "", UID: str("owned-uid")})
	calls, _ := sequence(t, reply{body: owned(t, task, "", func(o map[string]any) { o["metadata"].(map[string]any)["uid"] = "replacement" })})
	wantError(t, task.remove("vm", ""), "UID changed")
	if len(*calls) != 1 {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestDeleteIsUIDPreconditioned(t *testing.T) {
	task := newTask(t)
	ledger(t, task, resource{Kind: "vm", Suffix: "", UID: str("owned-uid")})
	calls, datas := sequence(t, reply{body: owned(t, task, "", nil)}, reply{body: []byte("{}")}, reply{})
	if err := task.remove("vm", ""); err != nil {
		t.Fatal(err)
	}
	del := (*calls)[1]
	if del[0] != "delete" || del[1] != "--raw" || !strings.Contains(del[2], "/namespaces/confai-images/virtualmachines/c8s-poddiag-123-2") {
		t.Fatalf("delete call: %v", del)
	}
	var options struct {
		Preconditions map[string]string `json:"preconditions"`
	}
	if err := json.Unmarshal((*datas)[1], &options); err != nil || options.Preconditions["uid"] != "owned-uid" {
		t.Fatalf("delete options: %s (%v)", (*datas)[1], err)
	}
}

func TestFailedVMCleanupRetainsDependencies(t *testing.T) {
	task := newTask(t)
	ledger(t, task, resource{Kind: "pvc", Suffix: "-root", UID: str("root")}, resource{Kind: "vm", Suffix: "", UID: str("owned-uid")})
	calls, _ := sequence(t, reply{body: owned(t, task, "", func(o map[string]any) { o["metadata"].(map[string]any)["uid"] = "replacement" })})
	wantError(t, task.cleanup(), "cleanup incomplete")
	if len(*calls) != 1 || (*calls)[0][1] != "vm" {
		t.Fatalf("calls: %v", *calls)
	}
	var receipt struct {
		Complete bool `json:"complete"`
	}
	data, _ := os.ReadFile(filepath.Join(task.evidence, "cleanup.json"))
	if err := json.Unmarshal(data, &receipt); err != nil || receipt.Complete {
		t.Fatalf("cleanup receipt: %s", data)
	}
}

func TestForeignLauncherIsNotRead(t *testing.T) {
	task := newTask(t)
	ledger(t, task, resource{Kind: "vm", Suffix: "", UID: str("owned-uid")})
	vmi, _ := json.Marshal(map[string]any{"metadata": map[string]any{"uid": "vmi-owned", "ownerReferences": []map[string]any{
		{"controller": true, "kind": "VirtualMachine", "uid": "owned-uid"}}}})
	pods, _ := json.Marshal(map[string]any{"items": []map[string]any{{"metadata": map[string]any{"name": "foreign", "ownerReferences": []map[string]any{
		{"controller": true, "kind": "VirtualMachineInstance", "uid": "vmi-foreign"}}}}}})
	calls, _ := sequence(t, reply{body: owned(t, task, "", nil)}, reply{body: vmi}, reply{body: pods})
	_, err := task.capture(0, time.Time{})
	wantError(t, err, "launcher owner differs")
	if len(*calls) != 3 {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestVMHasPrivateReadonlyRootAndNoExtraHostInputs(t *testing.T) {
	task := newTask(t)
	vm, err := task.vm()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(vm)
	var got struct {
		Spec struct {
			RunStrategy string `json:"runStrategy"`
			Template    struct {
				Spec struct {
					Domain struct {
						LaunchSecurity map[string]any `json:"launchSecurity"`
						CPU            struct {
							Model string `json:"model"`
						} `json:"cpu"`
						Devices struct {
							LogSerialConsole bool `json:"logSerialConsole"`
							Disks            []struct {
								Disk struct {
									Readonly bool `json:"readonly"`
								} `json:"disk"`
							} `json:"disks"`
						} `json:"devices"`
					} `json:"domain"`
					Volumes []map[string]any `json:"volumes"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	spec := got.Spec.Template.Spec
	if got.Spec.RunStrategy != "Once" || spec.Domain.CPU.Model != "host-passthrough" || !spec.Domain.Devices.LogSerialConsole || !spec.Domain.Devices.Disks[0].Disk.Readonly {
		t.Fatalf("vm spec: %s", raw)
	}
	if _, tdx := spec.Domain.LaunchSecurity["tdx"]; !tdx || len(spec.Domain.LaunchSecurity) != 1 {
		t.Fatalf("launchSecurity: %v", spec.Domain.LaunchSecurity)
	}
	volumes, _ := json.Marshal(spec.Volumes)
	want := `[{"name":"rootdisk","persistentVolumeClaim":{"claimName":"c8s-poddiag-123-2-root"}},{"name":"opkey","secret":{"secretName":"c8s-poddiag-123-2-opkey","volumeLabel":"opkeydata"}}]`
	if string(volumes) != want {
		t.Fatalf("volumes: %s", volumes)
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestManifestRejectsChangedBytesBeforeParsing(t *testing.T) {
	p := pins{ManifestSHA256: strings.Repeat("1", 64), DiskSHA256: strings.Repeat("2", 64)}
	for _, data := range [][]byte{[]byte("{}"), bytes.Repeat([]byte("x"), 65537), []byte(`{"tdx":{"mrtd":"forged"}}`)} {
		_, err := validateManifest(data, p)
		wantError(t, err, "manifest digest differs")
	}
}

func TestManifestRequiresPairedDiskAndAllTDXRegisters(t *testing.T) {
	disk := strings.Repeat("2", 64)
	manifest := map[string]any{"inputs": map[string]any{"base_image": map[string]any{"sha256": disk}},
		"tdx": map[string]any{"mrtd": strings.Repeat("a", 96), "rtmr1": strings.Repeat("b", 96), "rtmr2": strings.Repeat("c", 96)}}
	data, _ := json.Marshal(manifest)
	if _, err := validateManifest(data, pins{ManifestSHA256: digest(data), DiskSHA256: disk}); err != nil {
		t.Fatal(err)
	}
	badDisk, _ := json.Marshal(map[string]any{"inputs": map[string]any{"base_image": map[string]any{"sha256": strings.Repeat("0", 64)}}, "tdx": manifest["tdx"]})
	missingRegister, _ := json.Marshal(map[string]any{"inputs": manifest["inputs"],
		"tdx": map[string]any{"mrtd": strings.Repeat("a", 96), "rtmr1": strings.Repeat("b", 96), "rtmr2": ""}})
	for _, bad := range [][]byte{badDisk, missingRegister} {
		if _, err := validateManifest(bad, pins{ManifestSHA256: digest(bad), DiskSHA256: disk}); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func fakeRegistry(t *testing.T, replies ...struct {
	body    []byte
	headers http.Header
}) *[]string {
	t.Helper()
	var paths []string
	registry = func(path, _, _ string) ([]byte, http.Header, error) {
		paths = append(paths, path)
		if len(paths) > len(replies) {
			t.Fatalf("unexpected registry call %s", path)
		}
		r := replies[len(paths)-1]
		return r.body, r.headers, nil
	}
	t.Cleanup(func() { registry = fetchRegistry })
	return &paths
}

type registryReply = struct {
	body    []byte
	headers http.Header
}

func TestResolveNamesTheMissingDevTag(t *testing.T) {
	source := "3eddfb9ed4909133cfc0844ad4913b3b02d6a9fe"
	_, err := resolve("3eddfb9e", "bearer")
	wantError(t, err, "full 40-hex commit")
	paths := fakeRegistry(t, registryReply{})
	_, err = resolve(source, "bearer")
	wantError(t, err, "node-guest-base:rke2-tdx-dev-3eddfb9; build it with: ")
	wantError(t, err, "c8s_ref=3eddfb9")
	if (*paths)[0] != "/manifests/rke2-tdx-dev-3eddfb9" {
		t.Fatalf("paths: %v", *paths)
	}
}

func TestResolveReadsLayersByTitleAndTheCDIDigest(t *testing.T) {
	source := "3eddfb9ed4909133cfc0844ad4913b3b02d6a9fe"
	layers := []map[string]any{
		{"digest": "sha256:" + strings.Repeat("a", 64), "annotations": map[string]string{"org.opencontainers.image.title": "disk.raw"}},
		{"digest": "sha256:" + strings.Repeat("b", 64), "annotations": map[string]string{"org.opencontainers.image.title": "manifest.json"}},
		{"digest": "sha256:" + strings.Repeat("c", 64), "annotations": map[string]string{"org.opencontainers.image.title": "roothash"}}}
	artifact, _ := json.Marshal(map[string]any{"layers": layers})
	cdi := http.Header{"Docker-Content-Digest": []string{"sha256:" + strings.Repeat("d", 64)}}
	fakeRegistry(t, registryReply{body: artifact}, registryReply{body: []byte{}, headers: cdi})
	got, err := resolve(source, "bearer")
	if err != nil {
		t.Fatal(err)
	}
	want := pins{Source: source, ArtifactTag: "rke2-tdx-dev-3eddfb9", Image: "ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + strings.Repeat("d", 64),
		ManifestSHA256: strings.Repeat("b", 64), DiskSHA256: strings.Repeat("a", 64)}
	if got != want {
		t.Fatalf("pins: %+v", got)
	}
	withoutDisk, _ := json.Marshal(map[string]any{"layers": layers[1:]})
	fakeRegistry(t, registryReply{body: withoutDisk})
	_, err = resolve(source, "bearer")
	wantError(t, err, "manifest.json and disk.raw")
	fakeRegistry(t, registryReply{body: artifact}, registryReply{})
	_, err = resolve(source, "bearer")
	wantError(t, err, "rke2-tdx-dev-cdi-3eddfb9")
}

// cluster is a stateful kubectl fake: creates land in a store with the state
// the provision loop waits for, gets read it, deletes remove from it.
func cluster(t *testing.T) (map[string]map[string]any, *[]string) {
	t.Helper()
	store := map[string]map[string]any{}
	var annotate []string
	kube = func(args []string, data []byte, _ time.Duration) ([]byte, error) {
		switch args[0] {
		case "get":
			obj, ok := store[args[2]]
			if !ok {
				return nil, nil
			}
			return json.Marshal(obj)
		case "create":
			var spec map[string]any
			if err := json.Unmarshal(data, &spec); err != nil {
				return nil, err
			}
			meta := spec["metadata"].(map[string]any)
			name := meta["name"].(string)
			meta["uid"], meta["resourceVersion"] = "uid-"+name, "17"
			switch spec["kind"] {
			case "PersistentVolumeClaim":
				annotations := meta["annotations"].(map[string]any)
				annotations["volume.kubernetes.io/selected-node"], annotations["cdi.kubevirt.io/storage.pod.phase"] = "n1", "Succeeded"
				spec["status"] = map[string]any{"phase": "Bound"}
			case "Pod":
				spec["spec"].(map[string]any)["nodeName"] = "n1"
			}
			store[name] = spec
			return json.Marshal(spec)
		case "annotate":
			annotate = args
			return []byte{}, nil
		case "delete":
			delete(store, args[2][strings.LastIndex(args[2], "/")+1:])
			return []byte("{}"), nil
		}
		t.Fatalf("unexpected kubectl call %v", args)
		return nil, nil
	}
	t.Cleanup(func() { kube = runKubectl })
	return store, &annotate
}

func TestProvisionImportsTheResolvedImage(t *testing.T) {
	task := newTask(t)
	wantError(t, task.provision(), "resolved image pins")
	task.pins = &pins{Image: "ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + strings.Repeat("d", 64)}
	bundle := filepath.Join(task.private, "bundle/pod")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pubkey", "launch.yaml", "launch.yaml.sig"} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, annotate := cluster(t)
	if err := task.provision(); err != nil {
		t.Fatal(err)
	}
	want := "cdi.kubevirt.io/storage.import.endpoint=docker://" + task.pins.Image
	if !strings.Contains(strings.Join(*annotate, " "), want) {
		t.Fatalf("annotate: %v", *annotate)
	}
	if _, binder := store["c8s-poddiag-123-2-binder"]; binder {
		t.Fatal("binder Pod was not removed before the import")
	}
	for _, name := range []string{"c8s-poddiag-123-2-root", "c8s-poddiag-123-2-opkey", "c8s-poddiag-123-2"} {
		if _, ok := store[name]; !ok {
			t.Fatalf("%s was not created", name)
		}
	}
	entries, _ := task.resources()
	if len(entries) != 4 || entries[3].Kind != "vm" || entries[3].UID == nil || *entries[3].UID != "uid-c8s-poddiag-123-2" {
		t.Fatalf("ledger: %+v", entries)
	}
}
