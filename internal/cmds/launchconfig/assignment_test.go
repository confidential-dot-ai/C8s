package launchconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const emptyPodEntries = `{"schema":"c8s.allowlist/v1","workloads":{}}`

func TestGenericBootStagesTrustWithoutWorkloadAuthority(t *testing.T) {
	doc, key, pub := testPodDocument(t, "tdx")
	doc.Pod, doc.Workloads = nil, ""
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	staged, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil {
		t.Fatal(err)
	}
	if staged.Role != Pod || staged.Pod != nil || staged.Workloads != "" || staged.PodOperatorPublicKey != pub || staged.Server != doc.Server || staged.CDS != doc.CDS {
		t.Fatal("generic launch changed workload or trust authority")
	}
	requirePresent(t, cfg.path(podMarker))
	for _, p := range []string{Dir + "/operator-pubkey", Dir + "/peers.json"} {
		requirePresent(t, cfg.path(p))
	}
	for _, p := range []string{Dir + "/workloads.json", Dir + "/cds.json", serverMarker, agentMarker, serverTokenPath, agentTokenPath} {
		requireAbsent(t, cfg.path(p))
	}
	for _, entries := range []string{testPodWorkloads, emptyPodEntries, "null"} {
		doc.Workloads = entries
		data, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "must not carry workloads") {
			t.Fatalf("generic policy accepted: %v", err)
		}
	}
}

func TestStaticPodAllowsAbsentOrEmptyBase(t *testing.T) {
	for _, entries := range []string{"", emptyPodEntries} {
		doc, _, _ := testPodDocument(t, "tdx")
		doc.Workloads = entries
		data, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err != nil {
			t.Fatal(err)
		}
		pubPath, _ := writePodServerKey(t)
		dir := filepath.Join(t.TempDir(), "bundle")
		args := []string{"new-pod", "--out", dir, "--cluster-id", "cluster-one",
			"--image-manifest", writeManifest(t, "tdx"), "--pod-manifest", writeFile(t, "pod.json", testPodManifest("")),
			"--server-address", "10.0.0.1", "--server-public-key", pubPath,
			"--cds-address", "cds.example.org:8443", "--cds-image-policy-file", writePodCDSPin(t)}
		if entries != "" {
			args = append(args, "--workloads", writeFile(t, "workloads.json", entries))
		}
		if err := runBundleCmd(t, args...); err != nil {
			t.Fatal(err)
		}
		bundled, _ := readBundleDocument(t, dir, podDir)
		if bundled.Pod == nil || bundled.Workloads != entries || bundled.CDS.Address != "cds.example.org:8443" {
			t.Fatal("static bundle lost optional base or explicit CDS trust")
		}
	}
}

func TestAssignedPodPreservesGenericTrustAndValidatesPayload(t *testing.T) {
	doc, _, _ := testPodDocument(t, "tdx")
	doc.Pod, doc.Workloads = nil, ""
	for _, entries := range []string{testPodWorkloads, emptyPodEntries} {
		assigned, err := AssignedPod(&doc, []byte(testPodManifest("")), []byte(entries), []byte(`["192.0.2.1:15006"]`))
		if err != nil {
			t.Fatal(err)
		}
		if doc.Pod != nil || doc.Workloads != "" || assigned.Pod == nil || assigned.Pod.UID != testPodUID || assigned.Pod.Namespace != "tenant" || assigned.Pod.Name != "app" || assigned.Workloads != entries || len(assigned.Pod.MeshPeers) != 1 {
			t.Fatal("assignment mutated generic authority or lost Pod identity")
		}
		if assigned.CDS != doc.CDS || assigned.Server != doc.Server || assigned.PodOperatorPublicKey != doc.PodOperatorPublicKey || assigned.Node != doc.Node || assigned.Image.Measurement != doc.Image.Measurement {
			t.Fatal("assignment changed launch trust")
		}
		if _, err := AssignedPod(assigned, []byte(testPodManifest("")), []byte(entries), []byte("[]")); err == nil {
			t.Fatal("assigned document reassigned")
		}
	}
	cases := []struct{ name, manifest, entries, peers string }{
		{"host-network", testPodManifest(`,"hostNetwork":true`), testPodWorkloads, "[]"},
		{"unpinned-image", strings.Replace(testPodManifest(""), "busybox@sha256:"+strings.Repeat("a", 64), "busybox:latest", 1), testPodWorkloads, "[]"},
		{"missing-uid", strings.Replace(testPodManifest(""), testPodUID, "", 1), testPodWorkloads, "[]"},
		{"platform-container", strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"c8s-mesh","image"`, 1), testPodWorkloads, "[]"},
		{"platform-role", testPodManifest(""), strings.Replace(testPodWorkloads, `"digest":`, `"role":"mesh","digest":`, 1), "[]"},
		{"missing-entries", testPodManifest(""), "", "[]"},
		{"invalid-entries", testPodManifest(""), "null", "[]"},
		{"peer-null", testPodManifest(""), emptyPodEntries, "null"},
		{"peer-object", testPodManifest(""), emptyPodEntries, "{}"},
		{"peer-number", testPodManifest(""), emptyPodEntries, "[1]"},
		{"peer-trailing", testPodManifest(""), emptyPodEntries, "[] []"},
		{"peer-metadata", testPodManifest(""), emptyPodEntries, `["169.254.169.254:80"]`},
		{"oversized-manifest", strings.Repeat(" ", MaxDocumentSize+1), emptyPodEntries, "[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := AssignedPod(&doc, []byte(tc.manifest), []byte(tc.entries), []byte(tc.peers)); err == nil {
				t.Fatal("unsafe assignment accepted")
			}
			if doc.Pod != nil || doc.Workloads != "" {
				t.Fatal("refusal mutated generic launch")
			}
		})
	}
	if _, err := AssignedPod(nil, nil, nil, nil); err == nil {
		t.Fatal("nil document accepted")
	}
	doc.Role = Server
	if _, err := AssignedPod(&doc, []byte(testPodManifest("")), []byte(emptyPodEntries), []byte("[]")); err == nil {
		t.Fatal("non-Pod role assigned")
	}
}

func TestGenericPodBundleRequiresExplicitEmptyLaunch(t *testing.T) {
	pubPath, _ := writePodServerKey(t)
	manifest := writeManifest(t, "tdx")
	cdsPolicy := writePodCDSPin(t)
	unboundCDS := writeFile(t, "unbound-cds.json", testDigestOnlyPin(t))
	for _, tc := range []struct {
		name  string
		args  []string
		valid bool
	}{
		{"generic", []string{"--generic", "--name", "warm-1"}, true},
		{"missing CDS address", []string{"--generic", "--name", "warm-1", "--cds-address", ""}, false},
		{"missing CDS policy", []string{"--generic", "--name", "warm-1", "--cds-image-policy-file", ""}, false},
		{"unbound CDS policy", []string{"--generic", "--name", "warm-1", "--cds-image-policy-file", unboundCDS}, false},
		{"implicit", nil, false},
		{"no-name", []string{"--generic"}, false},
		{"pod", []string{"--generic", "--name", "warm-1", "--pod-manifest", "unused"}, false},
		{"entries", []string{"--generic", "--name", "warm-1", "--workloads", "unused"}, false},
		{"peers", []string{"--generic", "--name", "warm-1", "--mesh-peer", "192.0.2.1:80"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			args := append([]string{"new-pod", "--out", dir, "--cluster-id", "cluster-one", "--image-manifest", manifest, "--server-address", "10.0.0.1", "--server-public-key", pubPath, "--cds-address", "cds.example.org:8443", "--cds-image-policy-file", cdsPolicy}, tc.args...)
			err := runBundleCmd(t, args...)
			if (err == nil) != tc.valid {
				t.Fatalf("bundle validity: %v", err)
			}
			if !tc.valid {
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatal("refused launch left output")
				}
				return
			}
			doc, _ := readBundleDocument(t, dir, podDir)
			if doc.Pod != nil || doc.Workloads != "" || doc.Node.Name != "warm-1" || doc.CDS.Address != "cds.example.org:8443" || doc.CDS.Measurements == "" {
				t.Fatal("generic bundle carried workload state")
			}
			stageBundleNode(t, dir, podDir)
		})
	}
}
