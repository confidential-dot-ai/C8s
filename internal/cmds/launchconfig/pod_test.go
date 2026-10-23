package launchconfig

import (
	"context"
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

const (
	testPodUID       = "0b7c6f9e-3c1a-4d3e-9a51-2f0c1d2e3f40"
	testPodWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`
)

func testPodManifest(spec string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"` + testPodUID +
		`"},"spec":{"containers":[{"name":"app","image":"busybox@sha256:` + strings.Repeat("a", 64) + `"}]` + spec + `}}`
}

// testPodDocument returns a pod document, its launch key and public key.
func testPodDocument(t *testing.T, platform string) (Document, *ecdsa.PrivateKey, string) {
	t.Helper()
	doc, _, _ := testDocument(t, platform, Server)
	key, pub := testKey(t)
	doc.Role = Pod
	doc.RKE2 = RKE2{}
	doc.AgentOperatorPublicKeys = nil
	doc.PodOperatorPublicKey = pub
	doc.Workloads = testPodWorkloads
	doc.Pod = &PodSpec{UID: testPodUID, Namespace: "tenant", Name: "app", Manifest: testPodManifest("")}
	return doc, key, pub
}

func TestStagePodRole(t *testing.T) {
	for _, platform := range []string{"tdx"} {
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
			for path, want := range map[string]string{Dir + "/workloads.json": testPodWorkloads, Dir + "/operator-pubkey": pub} {
				got, err := os.ReadFile(cfg.path(path))
				if err != nil || string(got) != want {
					t.Fatalf("%s = %q, %v", path, got, err)
				}
			}
			staged, err := LoadStaged(cfg.path(DefaultStagedPath))
			if err != nil {
				t.Fatal(err)
			}
			if staged.Role != Pod || staged.Pod == nil || staged.Pod.UID != testPodUID || staged.PodOperatorPublicKey != pub || staged.Server != doc.Server {
				t.Fatalf("staged %+v", staged)
			}
			peers, err := refvalues.Load(cfg.path(Dir + "/peers.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(peers.Images) != 2 || string(peers.Images[0].Anchor) != doc.Server.OperatorPublicKey || peers.Images[0].Name != "server" || string(peers.Images[1].Anchor) != pub || peers.Images[1].Name != "pod" {
				t.Fatalf("pod peers = %+v", peers.Images)
			}
			cds, err := refvalues.Load(cfg.path(Dir + "/cds.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(cds.Images) != 1 || cds.Images[0].Name != "server" || string(cds.Images[0].Anchor) != doc.Server.OperatorPublicKey || string(cds.Images[0].Anchor) == pub {
				t.Fatalf("pod CDS pins = %+v", cds.Images)
			}

			if err := clearOutputs(cfg); err != nil {
				t.Fatal(err)
			}
			requireAbsent(t, cfg.path(podMarker))
			requireAbsent(t, cfg.path(Dir+"/workloads.json"))
		})
	}
}

func TestVerifyRejectsPodSignedByAnotherKey(t *testing.T) {
	doc, _, _ := testPodDocument(t, "tdx")
	other, otherPub := testKey(t)
	testLoader(t, doc, otherPub)
	cfg := testConfig(t, doc, other)
	err := Stage(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "pod launch key does not match") {
		t.Fatalf("got %v", err)
	}
	requireAbsent(t, cfg.path(podMarker))
}

func TestVerifyRejectsPodSignedByItsCDSServer(t *testing.T) {
	doc, _, _ := testPodDocument(t, "tdx")
	server, pub := testKey(t)
	doc.Server.OperatorPublicKey = pub
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, server)
	if err := Stage(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "pod launch key does not match") {
		t.Fatalf("CDS authority authorized a pod launch: %v", err)
	}
	requireAbsent(t, cfg.path(podMarker))
}

func TestVerifyRequiresExactPodLaunchKeyBytes(t *testing.T) {
	doc, key, pub := testPodDocument(t, "tdx")
	doc.PodOperatorPublicKey = strings.TrimSpace(pub)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "podOperatorPublicKey bytes") {
		t.Fatalf("accepted differently encoded pod key: %v", err)
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
		{"no CDS address", func(d *Document) { d.Server.Address = "" }, "server.address"},
		{"no CDS key", func(d *Document) { d.Server.OperatorPublicKey = "" }, "server.operatorPublicKey"},
		{"no pod key", func(d *Document) { d.PodOperatorPublicKey = "" }, "podOperatorPublicKey"},
		{"invalid pod key", func(d *Document) { d.PodOperatorPublicKey = "not a key" }, "podOperatorPublicKey"},
		{"server is pod key", func(d *Document) { d.PodOperatorPublicKey = d.Server.OperatorPublicKey }, "must be distinct"},
		{"server is equivalent pod key", func(d *Document) { d.PodOperatorPublicKey = strings.TrimSpace(d.Server.OperatorPublicKey) }, "must be distinct"},
		{"agent token", func(d *Document) { d.RKE2.AgentToken = strings.Repeat("a", 64) }, "rke2 tokens"},
		{"server token", func(d *Document) { d.RKE2.ServerToken = strings.Repeat("b", 64) }, "rke2 tokens"},
		{"agent keys", func(d *Document) { d.AgentOperatorPublicKeys = []string{agentPub} }, "agentOperatorPublicKeys"},
		{"router", func(d *Document) { d.Router = &Router{} }, "server-only"},
		{"no pod", func(d *Document) { d.Pod = nil }, "requires a pod section"},
		{"no runtime register", func(d *Document) { d.Image.Platform = "snp"; d.Image.RTMRs = nil }, "runtime register"},
		{"no workloads", func(d *Document) { d.Workloads = "" }, "requires workloads"},
		{"empty workloads", func(d *Document) { d.Workloads = `{"schema":"c8s.allowlist/v1","workloads":{}}` }, "at least one workload"},
		{"bad uid", func(d *Document) { d.Pod.UID = "Not A UID" }, "pod.uid"},
		{"bad namespace", func(d *Document) { d.Pod.Namespace = "Tenant" }, "pod.namespace"},
		{"uid mismatch", func(d *Document) { d.Pod.UID = "other" }, "must match"},
		{"name mismatch", func(d *Document) { d.Pod.Name = "other" }, "must match"},
		{"not a pod", func(d *Document) { d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"Pod"`, `"Deployment"`, 1) }, "v1 Pod"},
		{"unknown field", func(d *Document) { d.Pod.Manifest = testPodManifest(`,"bogus":true`) }, "pod.manifest"},
		{"host network", func(d *Document) { d.Pod.Manifest = testPodManifest(`,"hostNetwork":true`) }, "host namespaces"},
		{"shared processes", func(d *Document) { d.Pod.Manifest = testPodManifest(`,"shareProcessNamespace":true`) }, "shareProcessNamespace"},
		{"platform container", func(d *Document) {
			d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"name":"app","image"`, `"name":"c8s-mesh","image"`, 1)
		}, "reserved"},
		{"platform volume", func(d *Document) {
			d.Pod.Manifest = testPodManifest(`,"volumes":[{"name":"c8s-certs","emptyDir":{"medium":"Memory"}}]`)
		}, "reserved"},
		{"credential mount", func(d *Document) {
			d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"name":"app","image"`, `"name":"app","volumeMounts":[{"name":"c8s-certs","mountPath":"/keys"}],"image"`, 1)
		}, "private credential volume"},
		{"router namespace", func(d *Document) {
			d.Pod.Namespace = "c8s-router"
			d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"tenant"`, `"c8s-router"`, 1)
		}, "reserved"},
		{"guest status ingress", func(d *Document) {
			d.Pod.Manifest = strings.Replace(d.Pod.Manifest, `"name":"app","image"`, `"name":"app","ports":[{"containerPort":8443}],"image"`, 1)
		}, "reserved"},
		{"local peer", func(d *Document) { d.Pod.MeshPeers = []string{"169.254.169.254:80"} }, "pod.meshPeers"},
		{"Pod subnet peer", func(d *Document) { d.Pod.MeshPeers = []string{"10.255.254.1:8400"} }, "pod.meshPeers"},
		{"IPv6 peer", func(d *Document) { d.Pod.MeshPeers = []string{"[2001:db8::1]:80"} }, "pod.meshPeers"},
		{"peer without port", func(d *Document) { d.Pod.MeshPeers = []string{"192.0.2.1"} }, "pod.meshPeers"},
		{"tag-only image", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"image":"busybox@sha256:`+strings.Repeat("a", 64)+`"`, `"image":"busybox:1.36"`, 1)
		}, "pin the image by digest"},
		{"tag-only init image", func(d *Document) {
			d.Pod.Manifest = testPodManifest(`,"initContainers":[{"name":"init","image":"busybox"}]`)
		}, "pin the image by digest"},
		{"bare digest image", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"image":"busybox@sha256:`+strings.Repeat("a", 64)+`"`, `"image":"sha256:`+strings.Repeat("a", 64)+`"`, 1)
		}, "pin the image by digest"},
		{"sha512 digest", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), "sha256:"+strings.Repeat("a", 64), "sha512:"+strings.Repeat("a", 128), 1)
		}, "not sha256"},
		{"short digest", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), strings.Repeat("a", 64), strings.Repeat("a", 63), 1)
		}, "image"},
		{"disk emptyDir", func(d *Document) {
			d.Pod.Manifest = testPodManifest(`,"volumes":[{"name":"d","emptyDir":{}}]`)
		}, "medium: Memory"},
		{"host path", func(d *Document) {
			d.Pod.Manifest = testPodManifest(`,"volumes":[{"name":"h","hostPath":{"path":"/"}}]`)
		}, "only emptyDir"},
		{"host port", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"app","ports":[{"containerPort":80,"hostPort":80}],"image"`, 1)
		}, "hostPort"},
		{"host ip", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"app","ports":[{"containerPort":80,"hostIP":"127.0.0.1"}],"image"`, 1)
		}, "hostIP"},
		{"privileged", func(d *Document) {
			d.Pod.Manifest = strings.Replace(testPodManifest(""), `"name":"app","image"`, `"name":"app","securityContext":{"privileged":true},"image"`, 1)
		}, "privileged"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testPodDocument(t, "tdx")
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
	doc, _, _ := testPodDocument(t, "tdx")
	doc.Pod.Manifest = testPodManifest(`,"volumes":[{"name":"m","emptyDir":{"medium":"Memory","sizeLimit":"64Mi"}}]`)
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("memory emptyDir refused: %v", err)
	}
	doc, _, _ = testDocument(t, "tdx", Server)
	doc.Pod = &PodSpec{}
	data, _ = yaml.Marshal(doc)
	if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "requires role pod") {
		t.Fatalf("server with pod section: %v", err)
	}
}

func TestNewPodBundleRefusesAnSNPImage(t *testing.T) {
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
	serverPubPath, _ := writePodServerKey(t)
	err := runBundleCmd(t, "new-pod", "--out", dir, "--cluster-id", "cluster-one", "--image-manifest", writeManifest(t, "snp"),
		"--vcpus", "8", "--pod-manifest", manifest, "--workloads", workloads, "--server-address", "10.0.0.1", "--server-public-key", serverPubPath)
	if err == nil || !strings.Contains(err.Error(), "runtime register") {
		t.Fatalf("got %v, want a runtime register refusal", err)
	}
	requireAbsent(t, filepath.Join(dir, podDir))
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
	serverPubPath, serverPub := writePodServerKey(t)
	if err := runBundleCmd(t, "new-pod", "--out", dir, "--cluster-id", "cluster-one",
		"--image-manifest", writeManifest(t, "tdx"), "--pod-manifest", manifest, "--workloads", workloads,
		"--server-address", "10.0.0.1", "--server-public-key", serverPubPath,
		"--mesh-peer", "192.0.2.1:15006", "--mesh-peer", "192.0.2.1:31000"); err != nil {
		t.Fatal(err)
	}
	doc, _ := readBundleDocument(t, dir, podDir)
	if !slices.Equal(doc.Pod.MeshPeers, []string{"192.0.2.1:15006", "192.0.2.1:31000"}) {
		t.Fatalf("signed mesh peers = %v", doc.Pod.MeshPeers)
	}
	if doc.Role != Pod || doc.Node.Name != "p-"+testPodUID || doc.Pod.Namespace != "tenant" {
		t.Fatalf("pod document %+v", doc)
	}
	if doc.Server.Address != "10.0.0.1" || doc.Server.OperatorPublicKey != serverPub || doc.PodOperatorPublicKey == serverPub {
		t.Fatal("pod bundle did not preserve independent CDS trust")
	}
	requirePresent(t, filepath.Join(dir, podKeyFile))
	stageBundleNode(t, dir, podDir)

	again := filepath.Join(t.TempDir(), "again")
	if err := runBundleCmd(t, "new-pod", "--out", again, "--cluster-id", "cluster-one", "--image-manifest", writeManifest(t, "tdx"),
		"--pod-manifest", manifest, "--workloads", workloads, "--launch-key", filepath.Join(dir, podKeyFile),
		"--server-address", "10.0.0.1", "--server-public-key", serverPubPath); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, filepath.Join(again, podKeyFile))
	first, _ := os.ReadFile(filepath.Join(dir, podDir, pubkeyFile))
	second, _ := os.ReadFile(filepath.Join(again, podDir, pubkeyFile))
	if string(first) != string(second) || string(first) != doc.PodOperatorPublicKey {
		t.Fatal("--launch-key did not reuse the key")
	}
	shared := filepath.Join(t.TempDir(), "shared-key")
	if err := runBundleCmd(t, "new-pod", "--out", shared, "--cluster-id", "cluster-one", "--image-manifest", writeManifest(t, "tdx"),
		"--pod-manifest", manifest, "--workloads", workloads, "--launch-key", filepath.Join(dir, podKeyFile),
		"--server-address", "10.0.0.1", "--server-public-key", filepath.Join(dir, podDir, pubkeyFile)); err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("bundle accepted shared Pod/CDS authority: %v", err)
	}
	requireAbsent(t, shared)
}

func writePodServerKey(t *testing.T) (string, string) {
	t.Helper()
	_, pub := testKey(t)
	path := filepath.Join(t.TempDir(), "server.pub")
	if err := os.WriteFile(path, []byte(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}
