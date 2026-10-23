package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newBootTask(t *testing.T) *bootDiagnostic {
	t.Helper()
	d, err := newBootDiagnostic(t.TempDir(), "123", "2", testRepo)
	if err != nil {
		t.Fatal(err)
	}
	noSleep(t)
	return d
}

func TestForeignLauncherIsNotRead(t *testing.T) {
	d := newBootTask(t)
	ledger(t, d.owned, resource{Kind: "vm", Suffix: "", UID: str("owned")})
	vmi, _ := json.Marshal(map[string]any{"metadata": map[string]any{"uid": "vmi-owned", "ownerReferences": []map[string]any{
		{"controller": true, "kind": "VirtualMachine", "uid": "owned"}}}})
	pods, _ := json.Marshal(map[string]any{"items": []map[string]any{{"metadata": map[string]any{"name": "foreign", "ownerReferences": []map[string]any{
		{"controller": true, "kind": "VirtualMachineInstance", "uid": "vmi-foreign"}}}}}})
	calls, _ := sequence(t, reply{body: ownedObject(t, d.owned, "vm", "", nil)}, reply{body: vmi}, reply{body: pods})
	_, err := d.capture(0, time.Time{})
	wantError(t, err, "launcher owner differs")
	if len(*calls) != 3 {
		t.Fatalf("calls: %v", *calls)
	}
}

type vmShape struct {
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
							Serial string `json:"serial"`
							Disk   struct {
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

func shapeOf(t *testing.T, vm map[string]any) (vmShape, []byte) {
	t.Helper()
	raw, _ := json.Marshal(vm)
	var got vmShape
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got, raw
}

func TestVMHasPrivateReadonlyRootAndNoExtraHostInputs(t *testing.T) {
	d := newBootTask(t)
	got, raw := shapeOf(t, d.vm())
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

func TestBootManifestRejectsChangedBytesBeforeParsing(t *testing.T) {
	p := bootPins{ManifestSHA256: strings.Repeat("1", 64), DiskSHA256: strings.Repeat("2", 64)}
	for _, data := range [][]byte{[]byte("{}"), []byte(strings.Repeat("x", 65537)), []byte(`{"tdx":{"mrtd":"forged"}}`)} {
		wantError(t, validateBootManifest(data, p), "manifest digest differs")
	}
}

func TestBootManifestRequiresPairedDiskAndAllTDXRegisters(t *testing.T) {
	disk := strings.Repeat("2", 64)
	manifest := map[string]any{"inputs": map[string]any{"base_image": map[string]any{"sha256": disk}},
		"tdx": map[string]any{"mrtd": strings.Repeat("a", 96), "rtmr1": strings.Repeat("b", 96), "rtmr2": strings.Repeat("c", 96)}}
	data, _ := json.Marshal(manifest)
	if err := validateBootManifest(data, bootPins{ManifestSHA256: sha256Hex(data), DiskSHA256: disk}); err != nil {
		t.Fatal(err)
	}
	badDisk, _ := json.Marshal(map[string]any{"inputs": map[string]any{"base_image": map[string]any{"sha256": strings.Repeat("0", 64)}}, "tdx": manifest["tdx"]})
	missingRegister, _ := json.Marshal(map[string]any{"inputs": manifest["inputs"],
		"tdx": map[string]any{"mrtd": strings.Repeat("a", 96), "rtmr1": strings.Repeat("b", 96), "rtmr2": ""}})
	for _, bad := range [][]byte{badDisk, missingRegister} {
		if err := validateBootManifest(bad, bootPins{ManifestSHA256: sha256Hex(bad), DiskSHA256: disk}); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

type registryReply struct {
	body    []byte
	headers http.Header
}

func fakeRegistry(t *testing.T, replies ...registryReply) *[]string {
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

func TestResolveNamesTheMissingDevTag(t *testing.T) {
	source := "3eddfb9ed4909133cfc0844ad4913b3b02d6a9fe"
	_, err := resolveBootImage("3eddfb9e", "bearer")
	wantError(t, err, "full 40-hex commit")
	paths := fakeRegistry(t, registryReply{})
	_, err = resolveBootImage(source, "bearer")
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
	got, err := resolveBootImage(source, "bearer")
	if err != nil {
		t.Fatal(err)
	}
	want := bootPins{Source: source, ArtifactTag: "rke2-tdx-dev-3eddfb9", Image: "ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + strings.Repeat("d", 64),
		ManifestSHA256: strings.Repeat("b", 64), DiskSHA256: strings.Repeat("a", 64)}
	if got != want {
		t.Fatalf("pins: %+v", got)
	}
	withoutDisk, _ := json.Marshal(map[string]any{"layers": layers[1:]})
	fakeRegistry(t, registryReply{body: withoutDisk})
	_, err = resolveBootImage(source, "bearer")
	wantError(t, err, "manifest.json and disk.raw")
	fakeRegistry(t, registryReply{body: artifact}, registryReply{})
	_, err = resolveBootImage(source, "bearer")
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

func stageBundle(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pubkey", "launch.yaml", "launch.yaml.sig"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProvisionImportsTheResolvedImage(t *testing.T) {
	d := newBootTask(t)
	wantError(t, d.provision(), "resolved image pins")
	d.pins = &bootPins{Image: "ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + strings.Repeat("d", 64)}
	stageBundle(t, filepath.Join(d.private, "bundle/pod"))
	store, annotate := cluster(t)
	if err := d.provision(); err != nil {
		t.Fatal(err)
	}
	want := "cdi.kubevirt.io/storage.import.endpoint=docker://" + d.pins.Image
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
	entries, _ := d.resources()
	if len(entries) != 4 || entries[3].Kind != "vm" || entries[3].UID == nil || *entries[3].UID != "uid-c8s-poddiag-123-2" {
		t.Fatalf("ledger: %+v", entries)
	}
}
