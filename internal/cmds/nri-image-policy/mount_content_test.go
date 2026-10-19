package nriimagepolicy

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestNodeRootProvenanceRequiresReadOnlyFileBind(t *testing.T) {
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
		{"OCI bind form", &api.Mount{Type: "none", Source: file, Destination: "/usr/bin/nvidia-smi", Options: []string{"rbind", "ro"}}, allowlist.ProvenanceNodeRoot},
		{"writable bind", &api.Mount{Type: "bind", Source: file, Destination: "/usr/bin/nvidia-smi", Options: []string{"rbind", "rw"}}, ""},
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

func TestNodeRootProvenanceAdmitsBeforeCreation(t *testing.T) {
	const source = "/usr/bin/nvidia-smi"
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: source, Kind: allowlist.MountHost, Source: source, ReadOnly: true, Provenance: allowlist.ProvenanceNodeRoot}}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	original := nodeRootEvidence
	t.Cleanup(func() { nodeRootEvidence = original })
	for _, measured := range []bool{true, false} {
		nodeRootEvidence = func(string) bool { return measured }
		p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
		p.SetReady()
		pod := makePod("default", "pod")
		pod.Uid = "pod-uid"
		ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
		ctr.Args = []string{"/bin/app"}
		ctr.Mounts = []*api.Mount{{Type: "bind", Source: source, Destination: source, Options: []string{"rbind", "ro"}}}
		err := p.ValidateContainerAdjustment(t.Context(), &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr})
		if (err == nil) != measured {
			t.Fatalf("ValidateContainerAdjustment(measured root %t) = %v", measured, err)
		}
	}
}

func TestNodeRootMissingNamesCause(t *testing.T) {
	original := nodeRootUnavailableReason
	nodeRootUnavailableReason = func() (string, bool) { return "root filesystem is not read-only", true }
	t.Cleanup(func() { nodeRootUnavailableReason = original })
	unproven := allowlist.ObservedMount{Destination: "/usr/bin/nvidia-smi", Class: allowlist.MountHost, HostSourceDigest: "sha256:" + strings.Repeat("a", 64), ReadOnly: true}
	proven := unproven
	proven.Provenance = allowlist.ProvenanceNodeRoot
	writable := unproven
	writable.ReadOnly = false
	for _, tc := range []struct {
		name   string
		mounts []allowlist.ObservedMount
		want   string
	}{
		{"unproven read-only bind", []allowlist.ObservedMount{unproven}, "root filesystem is not read-only"},
		{"proven bind", []allowlist.ObservedMount{proven}, ""},
		{"writable bind", []allowlist.ObservedMount{writable}, ""},
	} {
		if got := nodeRootMissing(tc.mounts); got != tc.want {
			t.Fatalf("nodeRootMissing(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestNodeRootMissingOnlyForNodeRootEntries(t *testing.T) {
	original := nodeRootUnavailableReason
	nodeRootUnavailableReason = func() (string, bool) { return "root filesystem is not read-only", false }
	t.Cleanup(func() { nodeRootUnavailableReason = original })
	file := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(file, []byte("bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		provenance string
		want       bool
	}{
		{"path-only rule", "", false},
		{"node-root rule", allowlist.ProvenanceNodeRoot, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: "/opt/tool", Kind: allowlist.MountHost, Source: "/usr/bin/tool", ReadOnly: true, Provenance: tc.provenance}}}
			if err := al.Normalize(); err != nil {
				t.Fatal(err)
			}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
			var logs bytes.Buffer
			p.logger = slog.New(slog.NewTextHandler(&logs, nil))
			digest, err := allowlist.HostSourceDigest(file)
			if err != nil {
				t.Fatal(err)
			}
			mounts := []allowlist.ObservedMount{{Source: file, Destination: "/opt/tool", Class: allowlist.MountHost, ReadOnly: true, HostSourceDigest: digest}}
			verdict, _ := p.checkImagePhase(context.Background(), p.cfg, imageCheck{Namespace: "default", PodName: "pod", Container: "app", ImageRef: "registry/repo@" + pushDigestB, Argv: []string{"/bin/app"}, Mounts: mounts}, launchFinal)
			if verdict != verdictDeny {
				t.Fatalf("checkImagePhase(%s) = %d, want deny", tc.name, verdict)
			}
			if got := strings.Contains(logs.String(), "node_root_unavailable"); got != tc.want {
				t.Fatalf("checkImagePhase(%s) logged node_root_unavailable = %t, want %t: %s", tc.name, got, tc.want, logs.String())
			}
		})
	}
}
