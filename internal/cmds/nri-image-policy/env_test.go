package nriimagepolicy

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

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
