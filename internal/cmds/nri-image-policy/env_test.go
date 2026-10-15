package nriimagepolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Exercise containerd's create/start lifecycle for older admission tests.
func createAndStart(p *plugin, ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	a, u, err := p.CreateContainer(ctx, pod, ctr)
	if err != nil {
		return nil, nil, err
	}
	if err = p.ValidateContainerAdjustment(ctx, &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr, Adjust: a}); err != nil {
		return nil, nil, err
	}
	if err = p.StartContainer(ctx, pod, ctr); err != nil {
		return nil, nil, err
	}
	return a, u, nil
}

func TestEnvAdmissionUsesFinalStartSpec(t *testing.T) {
	for _, tc := range []struct {
		name           string
		initial, final []string
		want           bool
	}{
		{"later injection", nil, []string{"MODE=production"}, true},
		{"later tampering", []string{"MODE=production"}, []string{"MODE=unsafe"}, false},
		{"duplicate", nil, []string{"MODE=unsafe", "MODE=production"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Env = allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: map[string]string{"MODE": "production"}}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base"})}}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			p.inventory.needsVariableEvidence = p.policy.needsVariableEvidence
			pod := makePod("default", "pod")
			ctr := makeCtrWithImage(pod.Id, "ctr", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app", "--serve"}
			ctr.Env = tc.initial
			if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err != nil {
				t.Fatal(err)
			}
			if len(p.inventory.containers) != 0 {
				t.Fatal("pre-final environment recorded")
			}
			ctr.Env = tc.final
			err := p.StartContainer(context.Background(), pod, ctr)
			if (err == nil) != tc.want {
				t.Fatalf("start=%v", err)
			}
			_, cs, _, err := p.inventory.DigestsForSandbox(pod.Id)
			if tc.want {
				if err != nil || len(cs) != 1 || !cs[0].Env.Valid() {
					t.Fatalf("missing final evidence: %v %v", cs, err)
				}
			} else if len(cs) != 0 {
				t.Fatal("denied start recorded")
			}
		})
	}
}

func TestIncompleteProcessIsNotEmptyEnv(t *testing.T) {
	if containerEnv(&api.Container{}) != nil {
		t.Fatal("missing OCI process looks like empty env")
	}
	o := containerEnv(&api.Container{Args: []string{"/app"}})
	if !o.Valid() {
		t.Fatal("observed empty OCI env lost")
	}
}

func TestEnvCreationValidatorChecksCumulativeEdits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial []string
		edits   []*api.KeyValue
		cdi     bool
		any     bool
		match   bool
		want    bool
	}{
		{name: "match adjusted", match: true, initial: []string{"MODE=production", "GPU_SERIAL=old"}, edits: []*api.KeyValue{{Key: "GPU_SERIAL", Value: "new"}}, want: true},
		{name: "match exact tamper", match: true, initial: []string{"MODE=production", "GPU_SERIAL=x"}, edits: []*api.KeyValue{{Key: "MODE", Value: "unsafe"}}},
		{name: "match extra", match: true, initial: []string{"MODE=production", "GPU_SERIAL=x"}, edits: []*api.KeyValue{{Key: "EXTRA", Value: "x"}}},
		{name: "match missing", match: true, initial: []string{"MODE=production", "GPU_SERIAL=x"}, edits: []*api.KeyValue{{Key: "-GPU_SERIAL"}}},
		{name: "match deferred CDI", match: true, initial: []string{"MODE=production", "GPU_SERIAL=x"}, cdi: true},
		{name: "unchanged", initial: []string{"MODE=production"}, want: true},
		{name: "override", initial: []string{"MODE=unsafe"}, edits: []*api.KeyValue{{Key: "MODE", Value: "production"}}, want: true},
		{name: "tamper", initial: []string{"MODE=production"}, edits: []*api.KeyValue{{Key: "MODE", Value: "unsafe"}}},
		{name: "remove extra", initial: []string{"MODE=production", "EXTRA=x"}, edits: []*api.KeyValue{{Key: "-EXTRA"}}, want: true},
		{name: "remove required", initial: []string{"MODE=production"}, edits: []*api.KeyValue{{Key: "-MODE"}}},
		{name: "extra", initial: []string{"MODE=production"}, edits: []*api.KeyValue{{Key: "EXTRA", Value: "x"}}},
		{name: "last edit", edits: []*api.KeyValue{{Key: "MODE", Value: "unsafe"}, {Key: "MODE", Value: "production"}}, want: true},
		{name: "bad original", initial: []string{"MODE=unsafe", "MODE=production"}, edits: []*api.KeyValue{{Key: "MODE", Value: "production"}}},
		{name: "bad edit", edits: []*api.KeyValue{{Key: "MODE=production", Value: ""}}},
		{name: "deferred CDI", initial: []string{"MODE=production"}, cdi: true},
		{name: "unrestricted CDI", cdi: true, any: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			policy := allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: map[string]string{"MODE": "production"}}
			if tc.match {
				policy = allowlist.EnvPolicy{}
				if err := json.Unmarshal([]byte(`{"policy":"match","variables":{"MODE":{"exact":"production"},"GPU_SERIAL":{"present":true}}}`), &policy); err != nil {
					t.Fatal(err)
				}
			}
			if tc.any {
				policy = allowlist.EnvPolicy{Policy: allowlist.PolicyAny}
			}
			al.Workloads["w"].Containers[0].Env = policy
			al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyAny}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base"})}}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			p.inventory.needsVariableEvidence = p.policy.needsVariableEvidence
			pod := makePod("default", "pod")
			ctr := makeCtrWithImageArgs(pod.Id, "ctr", "registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
			ctr.Env = tc.initial
			adjust := &api.ContainerAdjustment{Env: tc.edits}
			if tc.cdi {
				adjust.CDIDevices = []*api.CDIDevice{{Name: "vendor/device=gpu"}}
			}
			req := &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr, Adjust: adjust}
			err := p.ValidateContainerAdjustment(context.Background(), req)
			if (err == nil) != tc.want {
				t.Fatalf("validation=%v want admitted=%v", err, tc.want)
			}
			if len(p.inventory.containers) != 0 {
				t.Fatal("validator prematurely recorded an admission")
			}
			if !slices.Equal(ctr.Env, tc.initial) {
				t.Fatal("validator mutated request")
			}
			if err != nil && strings.Contains(err.Error(), "unsafe") {
				t.Fatal("denial disclosed env value")
			}
		})
	}
}

func TestMountCreationValidatorChecksCumulativeEdits(t *testing.T) {
	pod := makePod("default", "pod")
	pod.Uid = "pod-a"
	platform := &api.Mount{Source: kubeletRoot + "/pods/pod-a/etc-hosts", Destination: "/etc/hosts"}
	host := &api.Mount{Source: "/", Destination: "/etc/hosts"}
	remove := &api.Mount{Destination: "-/etc/hosts"}
	for _, tc := range []struct {
		name           string
		initial, edits []*api.Mount
		policy         string
		cdi, want      bool
	}{
		{name: "observed empty", want: true},
		{name: "platform addition", edits: []*api.Mount{platform}, want: true},
		{name: "host addition", edits: []*api.Mount{host}},
		{name: "host replaces platform", initial: []*api.Mount{platform}, edits: []*api.Mount{host}},
		{name: "platform replaces host", initial: []*api.Mount{host}, edits: []*api.Mount{platform}, want: true},
		{name: "remove host", initial: []*api.Mount{host}, edits: []*api.Mount{remove}, want: true},
		{name: "remove missing", edits: []*api.Mount{remove}, want: true},
		{name: "add then remove", edits: []*api.Mount{host, remove}, want: true},
		{name: "remove then add", initial: []*api.Mount{host}, edits: []*api.Mount{remove, host}},
		{name: "last replacement wins", edits: []*api.Mount{host, platform}, want: true},
		{name: "nil edit", edits: []*api.Mount{nil}},
		{name: "CDI deny", cdi: true},
		{name: "CDI exact", cdi: true, policy: allowlist.PolicyExact},
		{name: "CDI any", cdi: true, policy: allowlist.PolicyAny, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			mountPolicy := allowlist.MountPolicy{Policy: tc.policy}
			if tc.policy == allowlist.PolicyExact {
				mountPolicy.Rules = []allowlist.MountRule{{Destination: "/cache", Kind: allowlist.MountEmptyDir}}
			}
			al.Workloads["w"].Containers[0].Mounts = mountPolicy
			al.Workloads["w"].Containers[0].Env = allowlist.EnvPolicy{Policy: allowlist.PolicyAny}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base"})}}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			ctr := makeCtrWithImageArgs(pod.Id, "ctr", "registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
			ctr.Mounts = tc.initial
			adjust := &api.ContainerAdjustment{Mounts: tc.edits}
			if tc.cdi {
				adjust.CDIDevices = []*api.CDIDevice{{Name: "vendor/device=gpu"}}
			}
			req := &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr, Adjust: adjust}
			before := proto.Clone(req)
			if tc.cdi && adjustedMounts(req, proto.Clone(ctr).(*api.Container)) != nil {
				t.Fatal("deferred CDI produced complete mount evidence")
			}
			err := p.ValidateContainerAdjustment(context.Background(), req)
			if (err == nil) != tc.want {
				t.Fatalf("validation=%v, want admitted=%v", err, tc.want)
			}
			if !proto.Equal(req, before) {
				t.Fatal("validation mutated its request")
			}
			if len(p.inventory.containers) != 0 {
				t.Fatal("validator prematurely recorded admission")
			}
		})
	}
}

func TestMountCreationValidatorContainerdBaseline(t *testing.T) {
	for _, tc := range []struct{ name, root, state string }{
		{"containerd", "/var/lib/containerd", "/run/containerd"},
		{"rke2", "/var/lib/rancher/rke2/agent/containerd", "/run/k3s/containerd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyDeny}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base"})}}, al)
			p.SetReady()
			pod := makePod("default", "pod")
			pod.Uid = "pod-a"
			ctr := makeCtrWithImageArgs(pod.Id, "ctr", "registry/repo@"+pushDigestB, []string{"/bin/app", "--serve"})
			sandbox := "/io.containerd.grpc.v1.cri/sandboxes/" + pod.Id
			ctr.Mounts = []*api.Mount{
				{Source: tc.root + sandbox + "/hostname", Destination: "/etc/hostname"},
				{Source: tc.root + sandbox + "/resolv.conf", Destination: "/etc/resolv.conf"},
				{Source: tc.state + sandbox + "/shm", Destination: "/dev/shm"},
				{Source: kubeletRoot + "/pods/pod-a/etc-hosts", Destination: "/etc/hosts"},
			}
			req := &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr}
			if err := p.ValidateContainerAdjustment(context.Background(), req); err != nil {
				t.Fatalf("platform baseline rejected: %v", err)
			}
			for _, source := range []string{tc.root + "/io.containerd.grpc.v1.cri/sandboxes/foreign/hostname", tc.root + "-lookalike" + sandbox + "/hostname"} {
				ctr.Mounts[0].Source = source
				if err := p.ValidateContainerAdjustment(context.Background(), req); err == nil {
					t.Errorf("unowned hostname source admitted: %s", source)
				}
			}
		})
	}
}

func TestInventoryServesVariableEvidenceOnlyForMatchPolicies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy string
		want   bool
	}{
		{"match", `{"policy":"match","variables":{"MODE":{"present":true}}}`, true},
		{"exact", `{"policy":"exact","values":{"MODE":"production"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			if err := json.Unmarshal([]byte(tc.policy), &al.Workloads["w"].Containers[0].Env); err != nil {
				t.Fatal(err)
			}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base"})}}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			p.inventory.needsVariableEvidence = p.policy.needsVariableEvidence
			pod := makePod("default", "pod")
			ctr := makeCtrWithImage(pod.Id, "ctr", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app"}
			ctr.Env = []string{"MODE=production"}
			if _, _, err := createAndStart(p, context.Background(), pod, ctr); err != nil {
				t.Fatal(err)
			}
			_, cs, _, err := p.inventory.DigestsForSandbox(pod.Id)
			if err != nil || len(cs) != 1 || !cs[0].Env.Valid() {
				t.Fatalf("DigestsForSandbox() = %v, %v; want one record with an aggregate digest", cs, err)
			}
			if got := cs[0].Env.VariableDigests != nil; got != tc.want {
				t.Errorf("per-variable evidence recorded = %t, want %t", got, tc.want)
			}
		})
	}
}

// A container recorded before the plugin holds a match policy, as before Ready
// or after a failed initial pull, is served its evidence once one applies.
func TestInventoryServesEvidenceRecordedBeforeMatchPolicy(t *testing.T) {
	p, store := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}}, &allowlist.Allowlist{Schema: allowlist.Schema})
	p.inventory = newAdmissionInventory(t.TempDir())
	p.inventory.needsVariableEvidence = store.needsVariableEvidence
	pod := makePod("default", "pod")
	ctr := makeCtrWithImage(pod.Id, "ctr", "registry/repo@"+pushDigestB)
	ctr.Args = []string{"/bin/app"}
	ctr.Env = []string{"MODE=production"}
	p.recordUncheckedForInventory(pod, ctr, "registry/repo@"+pushDigestB)

	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	if err := json.Unmarshal([]byte(`{"policy":"match","variables":{"MODE":{"present":true}}}`), &al.Workloads["w"].Containers[0].Env); err != nil {
		t.Fatal(err)
	}
	if !store.apply(al, 2) {
		t.Fatal("match allowlist not applied")
	}
	_, cs, _, err := p.inventory.DigestsForSandbox(pod.Id)
	if err != nil || len(cs) != 1 || cs[0].Env == nil || cs[0].Env.VariableDigests == nil {
		t.Fatalf("DigestsForSandbox() = %+v, %v; want per-variable evidence", cs, err)
	}
}

// matchWorkloadAtLimits declares n containers, each with a match env policy at
// the per-record evidence limits, and the environment each of them runs.
func matchWorkloadAtLimits(t *testing.T, n int) ([]byte, [][]string) {
	t.Helper()
	var containers []map[string]any
	var envs [][]string
	for i := range n {
		variables := map[string]any{}
		var env []string
		for v := range 128 {
			name := fmt.Sprintf("%s%03d", strings.Repeat("V", 29), v)
			variables[name] = map[string]string{"exact": "x"}
			env = append(env, name+"=x")
		}
		containers = append(containers, map[string]any{
			"digest":  fmt.Sprintf("sha256:%064x", i+1),
			"command": map[string]any{"policy": "exact", "argv": []string{"/app"}},
			"args":    map[string]string{"policy": "deny"},
			"env":     map[string]any{"policy": "match", "variables": variables},
		})
		envs = append(envs, env)
	}
	doc, err := json.Marshal(map[string]any{"schema": allowlist.Schema, "workloads": map[string]any{"wide": map[string]any{"containers": containers}}})
	if err != nil {
		t.Fatal(err)
	}
	return doc, envs
}

// A workload the authoring check accepts keeps every container's evidence in a
// fresh sandbox, so it matches; one container more is rejected.
func TestMatchWorkloadAtEvidenceCeiling(t *testing.T) {
	probe, err := allowlist.ObserveEnv(func() []string { _, envs := matchWorkloadAtLimits(t, 1); return envs[0] }())
	if err != nil {
		t.Fatal(err)
	}
	fit := allowlist.MaxSandboxVariableEvidenceBytes / probe.VariableEvidenceBytes()
	if fit <= 16 {
		t.Fatalf("ceiling admits %d containers at the limits, want more than 16", fit)
	}
	doc, envs := matchWorkloadAtLimits(t, fit)
	al, err := allowlist.ParseJSON(doc)
	if err != nil {
		t.Fatalf("ParseJSON(%d containers) = %v", fit, err)
	}
	inv := newAdmissionInventory(t.TempDir())
	inv.needsVariableEvidence = al.BuildIndex().NeedsVariableEvidence
	for i, env := range envs {
		observation, err := allowlist.ObserveEnv(env)
		if err != nil {
			t.Fatal(err)
		}
		inv.record(fmt.Sprint("ctr-", i), "pod", "ctr", fmt.Sprintf("sha256:%064x", i+1), []string{"/app"}, observation, []allowlist.ObservedMount{}...)
	}
	_, cs, _, err := inv.DigestsForSandbox("pod")
	if err != nil {
		t.Fatal(err)
	}
	if name, _, err := al.MatchWorkload(secrets.WorkloadContainers(al, cs)); err != nil || name != "wide" {
		t.Fatalf("MatchWorkload() = %q, %v; want wide", name, err)
	}

	over, _ := matchWorkloadAtLimits(t, fit+1)
	if _, err := allowlist.ParseJSON(over); err == nil || !strings.Contains(err.Error(), fmt.Sprint(allowlist.MaxSandboxVariableEvidenceBytes)) {
		t.Fatalf("ParseJSON(%d containers) error = %v, want the evidence ceiling", fit+1, err)
	}
}

// A stopped or removed container is no longer running, so churning sidecar
// variants lose their evidence before the live main container does.
func TestInventoryEvictsExitedContainersEvidenceFirst(t *testing.T) {
	_, envs := matchWorkloadAtLimits(t, 1)
	observe := func(value string) *allowlist.EnvObservation {
		env := slices.Clone(envs[0])
		for i := range env {
			env[i] = strings.TrimSuffix(env[i], "x") + value
		}
		o, err := allowlist.ObserveEnv(env)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	pod := &api.PodSandbox{Id: "pod"}
	for _, tc := range []struct {
		name string
		exit func(p *plugin, ctr *api.Container) error
	}{
		{"stopped", func(p *plugin, ctr *api.Container) error {
			_, err := p.StopContainer(context.Background(), pod, ctr)
			return err
		}},
		{"removed", func(p *plugin, ctr *api.Container) error {
			return p.RemoveContainer(context.Background(), pod, ctr)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
			p.inventory = newAdmissionInventory(t.TempDir())
			main := observe("main")
			p.inventory.record("main", "pod", "main", pushDigestA, []string{"/app"}, main)
			for i := range allowlist.MaxSandboxVariableEvidenceBytes/main.VariableEvidenceBytes() + 2 {
				id := fmt.Sprint("sidecar-", i)
				p.inventory.record(id, "pod", "sidecar", pushDigestB, []string{"/sidecar"}, observe(fmt.Sprint(i)))
				if err := tc.exit(p, &api.Container{Id: id, PodSandboxId: "pod"}); err != nil {
					t.Fatal(err)
				}
			}
			_, cs, _, err := p.inventory.DigestsForSandbox("pod")
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cs {
				if c.Env.Digest == main.Digest && c.Env.VariableDigests == nil {
					t.Fatalf("the running main container lost its per-variable evidence to %s sidecars", tc.name)
				}
			}
		})
	}
}
