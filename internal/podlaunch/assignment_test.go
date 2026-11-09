package podlaunch

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const emptyPodEntries = `{"schema":"c8s.allowlist/v1","workloads":{}}`

// An assignment validates its payload and never mutates the generic document
// it derives from. Every refusal of a manifest, entries or peer list, one row
// per check.
func TestAssignValidatesPayloadAndPreservesGenericTrust(t *testing.T) {
	doc, _, _ := testPodDocument(t, "tdx")
	before, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func() bool { after, err := yaml.Marshal(doc); return err == nil && reflect.DeepEqual(before, after) }
	assigned, err := Assign(&doc, []byte(testPodManifest("")), []byte(testPodWorkloads), []byte(`["192.0.2.1:15006"]`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !unchanged() || assigned.Pod.UID != testPodUID || assigned.Pod.Namespace != "tenant" || assigned.Pod.Name != "app" || assigned.Entries != testPodWorkloads || len(assigned.Pod.MeshPeers) != 1 {
		t.Fatal("assignment mutated generic authority or lost Pod identity")
	}
	if assigned.CDS != doc.CDS || assigned.PodOperatorPublicKey != doc.PodOperatorPublicKey || assigned.Node != doc.Node || assigned.Image.Measurement != doc.Image.Measurement {
		t.Fatal("assignment changed launch trust")
	}
	app := `"name":"app","image"`
	cases := []struct{ name, manifest, entries, peers, want string }{
		{"missing-entries", testPodManifest(""), "", "[]", "entries"},
		{"platform-role", testPodManifest(""), strings.Replace(testPodWorkloads, `"digest":`, `"role":"mesh","digest":`, 1), "[]", "entries"},
		{"peer-null", testPodManifest(""), emptyPodEntries, "null", "meshPeers"},
		{"peer-object", testPodManifest(""), emptyPodEntries, "{}", "meshPeers"},
		{"oversized-manifest", strings.Repeat(" ", MaxDocumentSize+1), emptyPodEntries, "[]", "document limit"},
		{"local peer", testPodManifest(""), emptyPodEntries, `["169.254.169.254:80"]`, "pod.meshPeers"},
		{"Pod subnet peer", testPodManifest(""), emptyPodEntries, `["10.255.254.1:8400"]`, "pod.meshPeers"},
		{"IPv6 peer", testPodManifest(""), emptyPodEntries, `["[2001:db8::1]:80"]`, "pod.meshPeers"},
		{"peer without port", testPodManifest(""), emptyPodEntries, `["192.0.2.1"]`, "pod.meshPeers"},
		{"bad uid", strings.Replace(testPodManifest(""), testPodUID, "Not A UID", 1), emptyPodEntries, "[]", "pod.uid"},
		{"bad namespace", strings.Replace(testPodManifest(""), `"namespace":"tenant"`, `"namespace":"Tenant"`, 1), emptyPodEntries, "[]", "pod.namespace"},
		{"not a pod", strings.Replace(testPodManifest(""), `"Pod"`, `"Deployment"`, 1), emptyPodEntries, "[]", "v1 Pod"},
		{"unknown field", testPodManifest(`,"bogus":true`), emptyPodEntries, "[]", "pod.manifest"},
		{"host network", testPodManifest(`,"hostNetwork":true`), emptyPodEntries, "[]", "host namespaces"},
		{"ephemeral containers", testPodManifest(`,"ephemeralContainers":[{"name":"debug","image":"busybox@sha256:` + strings.Repeat("a", 64) + `"}]`), emptyPodEntries, "[]", "ephemeral"},
		{"platform container", strings.Replace(testPodManifest(""), app, `"name":"c8s-mesh","image"`, 1), emptyPodEntries, "[]", "reserved"},
		{"guest status ingress", strings.Replace(testPodManifest(""), app, `"name":"app","ports":[{"containerPort":8443}],"image"`, 1), emptyPodEntries, "[]", "reserved"},
		{"tag-only image", strings.Replace(testPodManifest(""), `"image":"busybox@sha256:`+strings.Repeat("a", 64)+`"`, `"image":"busybox:1.36"`, 1), emptyPodEntries, "[]", "pin the image by digest"},
		{"tag-only init image", testPodManifest(`,"initContainers":[{"name":"init","image":"busybox"}]`), emptyPodEntries, "[]", "pin the image by digest"},
		{"sha512 digest", strings.Replace(testPodManifest(""), "sha256:"+strings.Repeat("a", 64), "sha512:"+strings.Repeat("a", 128), 1), emptyPodEntries, "[]", "not sha256"},
		{"disk emptyDir", testPodManifest(`,"volumes":[{"name":"d","emptyDir":{}}]`), emptyPodEntries, "[]", "medium: Memory"},
		{"host path", testPodManifest(`,"volumes":[{"name":"h","hostPath":{"path":"/"}}]`), emptyPodEntries, "[]", "only emptyDir"},
		{"host port", strings.Replace(testPodManifest(""), app, `"name":"app","ports":[{"containerPort":80,"hostPort":80}],"image"`, 1), emptyPodEntries, "[]", "hostPort"},
		{"privileged", strings.Replace(testPodManifest(""), app, `"name":"app","securityContext":{"privileged":true},"image"`, 1), emptyPodEntries, "[]", "privileged"},
		{"privilege escalation", strings.Replace(testPodManifest(""), app, `"name":"app","securityContext":{"allowPrivilegeEscalation":true},"image"`, 1), emptyPodEntries, "[]", "allowPrivilegeEscalation"},
		{"undeclarable capability", strings.Replace(testPodManifest(""), app, `"name":"app","securityContext":{"capabilities":{"add":["NET_RAW"]}},"image"`, 1), emptyPodEntries, "[]", "NET_RAW"},
		{"invalid workload annotation", strings.Replace(testPodManifest(""), `"metadata":{`, `"metadata":{"annotations":{"confidential.ai/cw":"../other"},`, 1), emptyPodEntries, "[]", "not a valid workload name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Assign(&doc, []byte(tc.manifest), []byte(tc.entries), []byte(tc.peers), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if !unchanged() {
				t.Fatal("refusal mutated generic launch")
			}
		})
	}
	if _, err := Assign(nil, nil, nil, nil, nil); err == nil {
		t.Fatal("nil document accepted")
	}
	doc.Role = "agent"
	if _, err := Assign(&doc, []byte(testPodManifest("")), []byte(emptyPodEntries), []byte("[]"), nil); err == nil {
		t.Fatal("non-Pod role assigned")
	}
}

// A pod bundle is generic: it names its node and takes no pod, entries or
// peers.
func TestPodBundleIsGeneric(t *testing.T) {
	manifest := writeManifest(t, "tdx")
	cdsPolicy := writePodCDSPin(t)
	for _, tc := range []struct {
		name  string
		args  []string
		valid bool
	}{
		{"named", []string{"--name", "p-1"}, true},
		{"unnamed", nil, false},
		{"pod manifest", []string{"--name", "p-1", "--pod-manifest", "unused"}, false},
		{"workloads", []string{"--name", "p-1", "--workloads", "unused"}, false},
		{"mesh peer", []string{"--name", "p-1", "--mesh-peer", "192.0.2.1:15006"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			args := append([]string{"new-pod", "--out", dir, "--cluster-id", "cluster-one", "--image-manifest", manifest, "--cds-address", "cds.example.org:8443", "--cds-image-policy-file", cdsPolicy}, tc.args...)
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
			if doc.Node.Name != "p-1" || doc.CDS.Address != "cds.example.org:8443" || doc.CDS.Measurements == "" {
				t.Fatal("generic bundle lost its identity or trust")
			}
			stageBundleNode(t, dir, podDir)
		})
	}
}

// The signed client document is opaque and bounded; a pod's annotation must be
// standard base64 of such a document.
func TestClientDocumentIsOpaqueAndBounded(t *testing.T) {
	doc, _, _ := testPodDocument(t, "tdx")
	document := []byte("\x00not json, not yaml")
	assigned, err := Assign(&doc, []byte(testPodManifest("")), []byte(testPodWorkloads), []byte("[]"), document)
	if err != nil || string(assigned.ClientDocument) != string(document) {
		t.Fatalf("assigned %q: %v", assigned.ClientDocument, err)
	}
	if _, err := Assign(&doc, []byte(testPodManifest("")), []byte(testPodWorkloads), []byte("[]"), make([]byte, podassign.MaxClientDocument+1)); err == nil {
		t.Fatal("oversized client document assigned")
	}
	pod := &corev1.Pod{}
	if got, err := ClientDocument(pod); err != nil || got != nil {
		t.Fatalf("a pod without the annotation has document %q: %v", got, err)
	}
	for value, ok := range map[string]bool{
		base64.StdEncoding.EncodeToString(document):                                    true,
		base64.StdEncoding.EncodeToString(make([]byte, podassign.MaxClientDocument)):   true,
		base64.StdEncoding.EncodeToString(make([]byte, podassign.MaxClientDocument+1)): false,
		base64.RawStdEncoding.EncodeToString(document):                                 false,
		"not base64!": false,
	} {
		pod.Annotations = map[string]string{workloadclaims.AnnotationClientDocument: value}
		if _, err := ClientDocument(pod); (err == nil) != ok {
			t.Fatalf("annotation %.20q: %v", value, err)
		}
	}
}
