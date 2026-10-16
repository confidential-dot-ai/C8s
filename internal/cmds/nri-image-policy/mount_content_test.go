package nriimagepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestContentPinRejectsWritableSourceBeforeCreation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nvidia-smi")
	if err := os.WriteFile(file, []byte("reviewed bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("reviewed bytes"))
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: "/usr/bin/nvidia-smi", Kind: allowlist.MountHost, Source: file, ReadOnly: true, Provenance: allowlist.ProvenanceFSVerity, VerityDigest: hex.EncodeToString(sum[:])}}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
	p.SetReady()
	pod := makePod("default", "pod")
	pod.Uid = "pod-uid"
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
	ctr.Args = []string{"/bin/app"}
	ctr.Mounts = []*api.Mount{{Type: "bind", Source: file, Destination: "/usr/bin/nvidia-smi", Options: []string{"bind", "ro"}}}
	if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err != nil {
		t.Fatalf("preliminary admission: %v", err)
	}
	if err := p.ValidateContainerAdjustment(t.Context(), &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr}); err == nil {
		t.Fatal("admitted content pin without immutable evidence before creation")
	}
}

func TestNodeRootProvenanceRequiresFileBind(t *testing.T) {
	original := nodeRootEvidence
	nodeRootEvidence = func(string) bool { return true }
	t.Cleanup(func() { nodeRootEvidence = original })
	file := filepath.Join(t.TempDir(), "nvidia-smi")
	if err := os.WriteFile(file, []byte("reviewed bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		mount *api.Mount
		want  string
	}{
		{"read-only bind", &api.Mount{Type: "bind", Source: file, Destination: "/usr/bin/nvidia-smi", Options: []string{"rbind", "rprivate", "ro"}}, allowlist.ProvenanceNodeRoot},
		{"overlay naming the file", &api.Mount{Type: "overlay", Source: file, Destination: "/usr/bin/nvidia-smi", Options: []string{"bind", "ro", "lowerdir=/untrusted"}}, ""},
		{"bind with data option", &api.Mount{Type: "bind", Source: file, Destination: "/usr/bin/nvidia-smi", Options: []string{"bind", "ro", "upperdir=/untrusted"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := observeHostMount(tc.mount).Provenance; got != tc.want {
				t.Fatalf("observeHostMount(%v).Provenance = %q, want %q", tc.mount, got, tc.want)
			}
		})
	}
}
