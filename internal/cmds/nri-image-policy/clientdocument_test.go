package nriimagepolicy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"slices"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/podassign"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The configuration carries the client document as standard base64 of a
// bounded document; its digest is what the Pod claims report.
func TestPodConfigClientDocument(t *testing.T) {
	document := []byte("\x00client document")
	var pod podConfig
	if err := yaml.Unmarshal([]byte("client_document: "+base64.StdEncoding.EncodeToString(document)), &pod); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(document)
	if string(pod.ClientDocument) != string(document) || pod.ClientDocument.digest() != hex.EncodeToString(h[:]) {
		t.Fatalf("client document %q digest %q", pod.ClientDocument, pod.ClientDocument.digest())
	}
	if (clientDocument(nil)).digest() != "" {
		t.Fatal("an empty client document has a digest")
	}
	for _, value := range []string{"not base64!", base64.StdEncoding.EncodeToString(make([]byte, podassign.MaxClientDocument+1))} {
		if err := yaml.Unmarshal([]byte("client_document: "+value), &podConfig{}); err == nil {
			t.Fatalf("client_document %.20q accepted", value)
		}
	}
}

// Every container of a Pod with a client document gets it read-only at the
// one path, and admission reads that bind as the platform's own, not as a
// host path the workload's policy must allow.
func TestPodClientDocumentIsBoundIntoEveryContainer(t *testing.T) {
	previous := enforcerRuntimeDir
	enforcerRuntimeDir = t.TempDir()
	t.Cleanup(func() { enforcerRuntimeDir = previous })
	pod := sandboxedPod()
	p := &plugin{cfg: &config{Pod: &podConfig{UID: "assigned", Namespace: pod.Namespace, Name: pod.Name}}}
	if err := p.prepareClientDocument(); err != nil || p.clientDocument != "" {
		t.Fatalf("a Pod without a client document prepared %q: %v", p.clientDocument, err)
	}
	if adjust, err := p.credentialMounts(t.Context(), pod, &api.Container{Name: "app"}); err != nil || adjust != nil {
		t.Fatalf("a Pod without a client document got %v: %v", adjust, err)
	}

	p.cfg.Pod.ClientDocument = clientDocument("client document")
	if err := p.prepareClientDocument(); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(p.clientDocument)
	if err != nil || string(written) != "client document" {
		t.Fatalf("written client document %q: %v", written, err)
	}
	for _, name := range []string{"app", workloadclaims.MeshContainerName} {
		ctr := &api.Container{Name: name, PodSandboxId: pod.Id}
		adjust, err := p.credentialMounts(t.Context(), pod, ctr)
		if err != nil || adjust == nil || len(adjust.Mounts) != 1 {
			t.Fatalf("%s adjustment %v: %v", name, adjust, err)
		}
		bind := adjust.Mounts[0]
		if bind.Source != p.clientDocument || bind.Destination != workloadclaims.ClientDocumentPath || !endsReadOnly(bind) {
			t.Fatalf("%s bind = %+v", name, bind)
		}
		ctr.Mounts = adjust.Mounts
		observed := p.observedMounts(pod, ctr)
		if len(observed) != 1 || observed[0].Class != allowlist.MountPlatform || !observed[0].ReadOnly {
			t.Fatalf("%s observed %+v", name, observed)
		}
		if foreign := hostBinds(pod, ctr, p.nodeMounts(), observed, nil, cdiExpansion{}); len(foreign) != 0 {
			t.Fatalf("%s client document read as a host bind: %v", name, foreign)
		}
	}

	// A writable bind, or one from another source, is the workload's own.
	ctr := &api.Container{Name: "app", PodSandboxId: pod.Id, Mounts: []*api.Mount{{Destination: workloadclaims.ClientDocumentPath, Type: "bind", Source: "/tenant/document", Options: []string{"rbind", "ro"}}}}
	if observed := p.observedMounts(pod, ctr); slices.ContainsFunc(observed, func(m allowlist.ObservedMount) bool { return m.Class == allowlist.MountPlatform }) {
		t.Fatalf("a foreign bind at the client document path was read as the platform's: %+v", observed)
	}
}
