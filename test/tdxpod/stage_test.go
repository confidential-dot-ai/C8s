package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRendererDoesNotDuplicateCLILaunchPayloads(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "manifest.json")
	raw, _ := json.Marshal(map[string]any{"build": map[string]any{"platform": "tdx"},
		"tdx": map[string]any{"mrtd": strings.Repeat("a", 96), "rtmr1": strings.Repeat("a", 96), "rtmr2": strings.Repeat("a", 96)}})
	if err := os.WriteFile(manifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	execute = func(argv, _ []string, _ []byte, _ time.Duration) (processResult, error) {
		if argv[0] != "fixture-cli" {
			t.Fatalf("unexpected executable %v", argv)
		}
		switch argv[1] {
		case "measurements":
			return processResult{stdout: []byte(`{"measurements":[{}]}`)}, nil
		case "keys":
			pub := argv[slices.Index(argv, "--pub-out")+1]
			if err := os.WriteFile(pub, []byte("fixture public key"), 0o600); err != nil {
				t.Fatal(err)
			}
		default:
			role := "pod"
			if argv[3] == "new" {
				role = "server"
			}
			dir := filepath.Join(argv[slices.Index(argv, "--out")+1], role)
			stageBundle(t, dir)
		}
		return processResult{}, nil
	}
	t.Cleanup(func() { execute = runProcess })
	endpoints := map[string]endpoint{}
	for i, side := range sides {
		endpoints[side] = endpoint{IP: "10.43.0." + string(rune('0'+i+1)) + "0", UID: side}
	}
	out := filepath.Join(root, "bundle")
	id, err := renderBundle(bundleInputs{name: "acceptance-fixture", cli: "fixture-cli", manifest: manifest, manifestSHA256: sha256Hex(raw),
		source: strings.Repeat("a", 40), meshImage: "registry/mesh@sha256:" + strings.Repeat("a", 64), out: out, endpoints: endpoints})
	if err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(out, "opkey-secrets.json")) {
		t.Fatal("renderer duplicated the launch payloads")
	}
	for _, side := range sides {
		role := "pod"
		if side == "server" {
			role = "server"
		}
		entries, err := os.ReadDir(filepath.Join(out, side, role))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if !slices.Equal(names, []string{"launch.yaml", "launch.yaml.sig", "pubkey"}) {
			t.Fatalf("%s: %v", side, names)
		}
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("bundle mode: %v, %v", info.Mode(), err)
	}
	if len(id.ExpectedDigests) != 2 || !exists(filepath.Join(out, "identity.json")) {
		t.Fatalf("identity: %+v", id)
	}
	if _, err := renderBundle(bundleInputs{manifest: manifest, manifestSHA256: sha256Hex(raw), meshImage: "registry/mesh:latest", out: filepath.Join(root, "again")}); err == nil {
		t.Fatal("accepted an unmeasured mesh image")
	}
}

func TestServiceAddressesCanBeAllocatedBeforeAVMExists(t *testing.T) {
	name := "acceptance-test"
	specs := serviceSpecs(name)
	if len(specs) != 3 {
		t.Fatalf("specs: %d", len(specs))
	}
	var objects []*object
	for i, side := range sides {
		spec := specs[side]["spec"].(map[string]any)
		if _, set := spec["clusterIP"]; set || spec["publishNotReadyAddresses"] != true {
			t.Fatalf("%s spec: %v", side, spec)
		}
		spec["clusterIP"] = "10.43.0." + string(rune('0'+i+1)) + "0"
		specs[side]["metadata"] = map[string]any{"name": name + "-" + side, "namespace": namespace, "uid": "fixture-" + side}
		raw, _ := json.Marshal(specs[side])
		objects = append(objects, parse(t, raw))
	}
	result, err := allocated(objects, name)
	if err != nil || len(result) != 3 {
		t.Fatalf("allocated: %v, %v", result, err)
	}
	for _, bad := range []string{"169.254.1.1", "10.255.254.1", "10.53.0.4", "10.52.0.4", "10.0.2.2"} {
		objects[0].Spec.ClusterIP = bad
		if _, err := allocated(objects, name); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
