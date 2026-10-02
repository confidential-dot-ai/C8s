package nriimagepolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A newly applied policy is checked against running containers: a removed
// entry stops its container, an addition stops nothing, and an exempt
// namespace's container survives.
func TestRecheckRunningAfterPolicyChange(t *testing.T) {
	// anyAllowlist names entries by the first 12 hex digits, which the push
	// digests share, so build one entry per digest under distinct names.
	entries := func(digests ...string) *allowlist.Allowlist {
		al := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{}}
		for i, d := range digests {
			for _, w := range anyAllowlist(map[string]string{d: "image"}).Workloads {
				al.Workloads[fmt.Sprintf("w%d", i)] = w
			}
		}
		return al
	}
	// A base allowlist turns the allowlist check on; its digest is unrelated.
	base := entries("sha256:" + strings.Repeat("9", 64))
	p, store := newCachedPlugin(&config{Allowlist: allowlistConfig{Base: base}, Policy: policyConfig{
		Mode: ModeFailClosed, EnforceExisting: true, ExemptNamespaces: []string{"kube-system"},
	}}, entries(pushDigestA, pushDigestB))
	p.SetReady()
	var killed []string
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		killed = append(killed, id)
		return nil
	}}

	pod := makePod("default", "pod1")
	sys := makePod("kube-system", "pod2")
	keep := makeCtrWithImage(pod.Id, "keep", "registry/repo@"+pushDigestA)
	removed := makeCtrWithImage(pod.Id, "removed", "registry/repo@"+pushDigestB)
	exempt := makeCtrWithImage(sys.Id, "exempt", "registry/repo@"+pushDigestB)
	p.trackRunning([]*api.PodSandbox{pod, sys}, []*api.Container{keep, removed, exempt})

	store.apply(entries(pushDigestA, pushDigestB, pushDigestC), 2)
	p.RecheckRunning(context.Background())
	if len(killed) != 0 {
		t.Fatalf("an added entry stopped containers: %v", killed)
	}

	store.apply(entries(pushDigestA), 3)
	p.RecheckRunning(context.Background())
	if !slices.Equal(killed, []string{removed.Id}) {
		t.Fatalf("stopped %v after an entry was removed, want only %s (exempt %s must survive)", killed, removed.Id, exempt.Id)
	}
}
