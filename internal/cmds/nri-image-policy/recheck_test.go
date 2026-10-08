package nriimagepolicy

import (
	"context"
	"errors"
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
	p.inventory = newAdmissionInventory("")
	var killed []string
	stopErr := error(nil)
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		if stopErr != nil {
			return stopErr
		}
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

	if ack := p.inventory.PolicyAck(); ack.Policy != store.current().digest || !ack.Clean {
		t.Fatalf("ack after an addition = %+v, want %s clean", ack, store.current().digest)
	}

	stopErr = errors.New("stop failed")
	store.apply(entries(pushDigestA), 3)
	p.RecheckRunning(context.Background())
	if ack := p.inventory.PolicyAck(); ack.Policy != store.current().digest || ack.Clean {
		t.Fatalf("ack with a denied container left running = %+v, want %s not clean", ack, store.current().digest)
	}

	stopErr = nil
	p.RecheckRunning(context.Background())
	if !slices.Equal(killed, []string{removed.Id}) {
		t.Fatalf("stopped %v after an entry was removed, want only %s (exempt %s must survive)", killed, removed.Id, exempt.Id)
	}
	if ack := p.inventory.PolicyAck(); ack.Policy != store.current().digest || !ack.Clean {
		t.Fatalf("ack after the denied container stopped = %+v, want %s clean", ack, store.current().digest)
	}
}

// A container the recheck stopped, or one containerd removed, is not checked
// again, so it cannot spoil a later acknowledgement.
func TestRecheckRunningForgetsStoppedAndRemoved(t *testing.T) {
	entries := func(digests ...string) *allowlist.Allowlist {
		al := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{}}
		for i, d := range digests {
			for _, w := range anyAllowlist(map[string]string{d: "image"}).Workloads {
				al.Workloads[fmt.Sprintf("w%d", i)] = w
			}
		}
		return al
	}
	base := entries("sha256:" + strings.Repeat("9", 64))
	p, store := newCachedPlugin(&config{Allowlist: allowlistConfig{Base: base}, Policy: policyConfig{
		Mode: ModeFailClosed, EnforceExisting: true,
	}}, entries(pushDigestA, pushDigestB, pushDigestC))
	p.SetReady()
	p.inventory = newAdmissionInventory("")
	stops := map[string]int{}
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		stops[id]++
		if stops[id] > 1 {
			return errors.New("container is not running")
		}
		return nil
	}}
	pod := makePod("default", "pod1")
	a := makeCtrWithImage(pod.Id, "a", "registry/repo@"+pushDigestA)
	b := makeCtrWithImage(pod.Id, "b", "registry/repo@"+pushDigestB)
	c := makeCtrWithImage(pod.Id, "c", "registry/repo@"+pushDigestC)
	p.trackRunning([]*api.PodSandbox{pod}, []*api.Container{a, b, c})

	store.apply(entries(pushDigestA, pushDigestC), 2)
	p.RecheckRunning(context.Background())
	if err := p.RemoveContainer(context.Background(), pod, c); err != nil {
		t.Fatal(err)
	}
	store.apply(entries(pushDigestA), 3)
	p.RecheckRunning(context.Background())
	if stops[b.Id] != 1 || stops[c.Id] != 0 {
		t.Fatalf("stops = %v, want b stopped once and the removed c never", stops)
	}
	if ack := p.inventory.PolicyAck(); !ack.Clean {
		t.Fatalf("ack after rechecks = %+v, want clean", ack)
	}
}
