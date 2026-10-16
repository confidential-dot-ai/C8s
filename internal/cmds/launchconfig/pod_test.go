package launchconfig

import (
	"context"
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

const (
	testPodUID       = "0b7c6f9e-3c1a-4d3e-9a51-2f0c1d2e3f40"
	testPodWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{}}`
)

func testPodManifest(spec string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"` + testPodUID +
		`"},"spec":{"containers":[{"name":"app","image":"busybox@sha256:` + strings.Repeat("a", 64) + `"}]` + spec + `}}`
}

// testPodDocument returns a pod document, its launch key and public key.
func testPodDocument(t *testing.T, platform string) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	doc, key, pub := testDocument(t, platform, Server)
	doc.Role = Pod
	doc.RKE2 = RKE2{}
	doc.AgentOperatorPublicKeys = nil
	doc.Server.Address = ""
	doc.Workloads = testPodWorkloads
	doc.Pod = &PodSpec{UID: testPodUID, Namespace: "tenant", Name: "app", Manifest: testPodManifest("")}
	return doc, key, pub
}

func TestStagePodRole(t *testing.T) {
	for _, platform := range []string{"snp", "tdx"} {
		t.Run(platform, func(t *testing.T) {
			doc, key, pub := testPodDocument(t, platform)
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			// A stale marker from another role must not survive restaging.
			if err := os.MkdirAll(cfg.path("/run/confos"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg.path(agentMarker), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := Stage(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			requirePresent(t, cfg.path(podMarker))
			for _, path := range []string{serverMarker, agentMarker, serverTokenPath, agentTokenPath, rke2FragmentPath} {
				requireAbsent(t, cfg.path(path))
			}
			for path, want := range map[string]string{PodManifestPath: doc.Pod.Manifest, Dir + "/workloads.json": testPodWorkloads} {
				got, err := os.ReadFile(cfg.path(path))
				if err != nil || string(got) != want {
					t.Fatalf("%s = %q, %v", path, got, err)
				}
			}
			staged, err := LoadStaged(cfg.path(DefaultStagedPath))
			if err != nil {
				t.Fatal(err)
			}
			if staged.Role != Pod || staged.Pod == nil || staged.Pod.UID != testPodUID {
				t.Fatalf("staged %+v", staged)
			}
			peers, err := refvalues.Load(cfg.path(Dir + "/peers.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(peers.Images) != 1 || string(peers.Images[0].Anchor) != pub || peers.Images[0].Name != "pod" {
				t.Fatalf("pod peers = %+v", peers.Images)
			}

			if err := clearOutputs(cfg); err != nil {
				t.Fatal(err)
			}
			requireAbsent(t, cfg.path(podMarker))
			requireAbsent(t, cfg.path(PodManifestPath))
		})
	}
}

func TestVerifyRejectsPodSignedByAnotherKey(t *testing.T) {
	doc, _, _ := testPodDocument(t, "snp")
	other, otherPub := testKey(t)
	testLoader(t, doc, otherPub)
	cfg := testConfig(t, doc, other)
	err := Stage(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "pod launch key does not match") {
		t.Fatalf("got %v", err)
	}
	requireAbsent(t, cfg.path(podMarker))
}

func TestValidatePodRole(t *testing.T) {
	_, agentPub := testKey(t)
	tests := []struct {
		name   string
		change func(*Document)
		want   string
	}{
		{"agent token", func(d *Document) { d.RKE2.AgentToken = strings.Repeat("a", 64) }, "rke2 tokens"},
		{"server token", func(d *Document) { d.RKE2.ServerToken = strings.Repeat("b", 64) }, "rke2 tokens"},
		{"agent keys", func(d *Document) { d.AgentOperatorPublicKeys = []string{agentPub} }, "agentOperatorPublicKeys"},
		{"router", func(d *Document) { d.Router = &Router{} }, "server-only"},
		{"no pod", func(d *Document) { d.Pod = nil }, "requires a pod section"},
		{"no workloads", func(d *Document) { d.Workloads = "" }, "requires workloads"},
		{"bad uid", func(d *Document) { d.Pod.UID = "Not A UID" }, "pod.uid"},
		{"bad namespace", func(d *Document) { d.Pod.Namespace = "Tenant" }, "pod.namespace"},
		{"uid mismatch", func(d *Document) { d.Pod.UID = "other" }, "must match"},
		{"name mismatch", func(d *Document) { d.Pod.Name = "other" }, "must match"},
		{"not a pod", func(d *Document) { d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"Pod"`, `"Deployment"`, 1) }, "v1 Pod"},
		{"unknown field", func(d *Document) { d.Pod.Manifest = testPodManifest(`,"bogus":true`) }, "pod.manifest"},
		{"host network", func(d *Document) { d.Pod.Manifest = testPodManifest(`,"hostNetwork":true`) }, "host namespaces"},
		{"host path", func(d *Document) {
			d.Pod.Manifest = testPodManifest(`,"volumes":[{"name":"h","hostPath":{"path":"/"}}]`)
		}, "only emptyDir"},
		{"host port", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"app","ports":[{"containerPort":80,"hostPort":80}],"image"`, 1)
		}, "hostPort"},
		{"privileged", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"app","securityContext":{"privileged":true},"image"`, 1)
		}, "privileged"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testPodDocument(t, "snp")
			tc.change(&doc)
			data, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	doc, _, _ := testDocument(t, "snp", Server)
	doc.Pod = &PodSpec{}
	data, _ := yaml.Marshal(doc)
	if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "requires role pod") {
		t.Fatalf("server with pod section: %v", err)
	}
}

func TestNewPodBundleStages(t *testing.T) {
	in := t.TempDir()
	manifest := filepath.Join(in, "pod.json")
	workloads := filepath.Join(in, "workloads.json")
	if err := os.WriteFile(manifest, []byte(testPodManifest("")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workloads, []byte(testPodWorkloads), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, "new-pod", "--out", dir, "--cluster-id", "cluster-one",
		"--image-manifest", writeManifest(t, "tdx"), "--pod-manifest", manifest, "--workloads", workloads); err != nil {
		t.Fatal(err)
	}
	doc, _ := readBundleDocument(t, dir, podDir)
	if doc.Role != Pod || doc.Node.Name != "p-"+testPodUID || doc.Pod.Namespace != "tenant" {
		t.Fatalf("pod document %+v", doc)
	}
	requirePresent(t, filepath.Join(dir, podKeyFile))
	stageBundleNode(t, dir, podDir)

	again := filepath.Join(t.TempDir(), "again")
	if err := runBundleCmd(t, "new-pod", "--out", again, "--cluster-id", "cluster-one", "--image-manifest", writeManifest(t, "tdx"),
		"--pod-manifest", manifest, "--workloads", workloads, "--launch-key", filepath.Join(dir, podKeyFile)); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, filepath.Join(again, podKeyFile))
	first, _ := os.ReadFile(filepath.Join(dir, podDir, pubkeyFile))
	second, _ := os.ReadFile(filepath.Join(again, podDir, pubkeyFile))
	if string(first) != string(second) {
		t.Fatal("--launch-key did not reuse the key")
	}
}
