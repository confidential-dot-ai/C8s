package launchconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const emptyPodEntries = `{"schema":"c8s.allowlist/v1","workloads":{}}`

// A generic boot stages the launch trust and no workload authority.
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
}

// An assignment validates its payload and never
// mutates the generic document it derives from.
func TestAssignedPodPreservesGenericTrustAndValidatesPayload(t *testing.T) {
	doc, _, _ := testPodDocument(t, "tdx")
	doc.Pod, doc.Workloads = nil, ""
	assigned, err := AssignedPod(&doc, []byte(testPodManifest("")), []byte(testPodWorkloads), []byte(`["192.0.2.1:15006"]`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Pod != nil || doc.Workloads != "" || assigned.Pod == nil || assigned.Pod.UID != testPodUID || assigned.Pod.Namespace != "tenant" || assigned.Pod.Name != "app" || assigned.Workloads != testPodWorkloads || len(assigned.Pod.MeshPeers) != 1 {
		t.Fatal("assignment mutated generic authority or lost Pod identity")
	}
	if assigned.CDS != doc.CDS || assigned.Server != doc.Server || assigned.PodOperatorPublicKey != doc.PodOperatorPublicKey || assigned.Node != doc.Node || assigned.Image.Measurement != doc.Image.Measurement {
		t.Fatal("assignment changed launch trust")
	}
	if _, err := AssignedPod(assigned, []byte(testPodManifest("")), []byte(testPodWorkloads), []byte("[]")); err == nil {
		t.Fatal("assigned document reassigned")
	}
	cases := []struct{ name, manifest, entries, peers string }{
		{"unpinned-image", strings.Replace(testPodManifest(""), "busybox@sha256:"+strings.Repeat("a", 64), "busybox:latest", 1), testPodWorkloads, "[]"},
		{"platform-role", testPodManifest(""), strings.Replace(testPodWorkloads, `"digest":`, `"role":"mesh","digest":`, 1), "[]"},
		{"missing-entries", testPodManifest(""), "", "[]"},
		{"peer-null", testPodManifest(""), emptyPodEntries, "null"},
		{"peer-object", testPodManifest(""), emptyPodEntries, "{}"},
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

// A generic bundle is explicit and carries no pod, entries or peers.
func TestGenericPodBundleRequiresExplicitEmptyLaunch(t *testing.T) {
	pubPath, _ := writePodServerKey(t)
	manifest := writeManifest(t, "tdx")
	cdsPolicy := writePodCDSPin(t)
	for _, tc := range []struct {
		name  string
		args  []string
		valid bool
	}{
		{"generic", []string{"--generic", "--name", "warm-1"}, true},
		{"implicit", nil, false},
		{"pod", []string{"--generic", "--name", "warm-1", "--pod-manifest", "unused"}, false},
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

// The workload ID the assignment records is the manifest's
// confidential.ai/cw annotation and nothing else; a manifest naming one the
// leaf cannot carry is refused at assignment, not at issuance.
func TestAssignedPodRecordsTheManifestWorkloadID(t *testing.T) {
	annotated := func(id string) string {
		return strings.Replace(testPodManifest(""), `"metadata":{`, `"metadata":{"annotations":{"confidential.ai/cw":"`+id+`"},`, 1)
	}
	doc, _, _ := testPodDocument(t, "tdx")
	doc.Pod, doc.Workloads = nil, ""
	assigned, err := AssignedPod(&doc, []byte(annotated("tenant-a.web")), []byte(emptyPodEntries), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if assigned.Pod.WorkloadID != "tenant-a.web" {
		t.Fatalf("workload ID = %q, want the annotation", assigned.Pod.WorkloadID)
	}
	if assigned, err := AssignedPod(&doc, []byte(testPodManifest("")), []byte(emptyPodEntries), []byte("[]")); err != nil || assigned.Pod.WorkloadID != "" {
		t.Fatalf("unannotated pod: %q, %v; want no workload ID", assigned.Pod.WorkloadID, err)
	}
	for _, bad := range []string{"tenant a", strings.Repeat("a", 64)} {
		if _, err := AssignedPod(&doc, []byte(annotated(bad)), []byte(emptyPodEntries), []byte("[]")); err == nil {
			t.Fatalf("workload ID %q the leaf cannot carry was assigned", bad)
		}
	}
	// A signed document whose workloadID disagrees with its manifest is refused.
	assigned.Pod.WorkloadID = "tenant-b.web"
	if err := assigned.Pod.validate(); err == nil {
		t.Fatal("workloadID diverging from the manifest annotation validated")
	}
}
