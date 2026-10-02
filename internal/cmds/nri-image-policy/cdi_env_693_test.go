package nriimagepolicy

// Regression tests for issue #693.
//
// containerd appends rather than replaces when a CDI container edit sets an
// environment name the image config or pod spec already set: runtime-tools'
// generate.createEnvCacheMap keys its cache on the whole "NAME=VALUE" string
// while generate.addEnv looks up the name, so the replace path never hits.
// runc then drops the duplicate and keeps the last value, so the container runs
// with the CDI value. Every CUDA base image sets NVIDIA_VISIBLE_DEVICES and the
// NVIDIA CDI spec rewrites it to "void", so without this the launch environment
// of every such GPU workload reads as unknown and only `env: any` admits it.

import (
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// cdiDuplicateEnv is what containerd hands NRI for a CUDA image on a GPU node.
func cdiDuplicateEnv() []string {
	return []string{
		"PATH=/usr/bin",
		"NVIDIA_VISIBLE_DEVICES=all",
		"MODE=production",
		"NVIDIA_VISIBLE_DEVICES=void",
		"NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/x86_64-linux-gnu",
	}
}

// runcEnv is what runc execs: duplicates dropped, last value kept.
func runcEnv() map[string]string {
	return map[string]string{
		"PATH":                   "/usr/bin",
		"MODE":                   "production",
		"NVIDIA_VISIBLE_DEVICES": "void",
		"NVIDIA_CTK_LIBCUDA_DIR": "/usr/lib/x86_64-linux-gnu",
	}
}

// gpuContainer carries CDI evidence the way the cdi-annotations device-list
// strategy delivers it: a cdi.k8s.io annotation, no CRI CDIDevices field.
func gpuContainer(env []string) *api.Container {
	return &api.Container{
		Args:        []string{"/bin/server"},
		Env:         env,
		Annotations: map[string]string{"cdi.k8s.io/nvidia-device-plugin_abc": "nvidia.com/gpu=GPU-0"},
	}
}

func TestCDIDuplicateEnvIsObservable(t *testing.T) {
	obs := containerEnv(gpuContainer(cdiDuplicateEnv()))
	if obs == nil {
		t.Fatal("duplicate CDI env left the launch environment unobservable: exact policy can never admit a CUDA GPU workload")
	}
	if !envPolicyAdmits(allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: runcEnv()}, obs) {
		t.Error("exact policy pinning the environment runc execs did not admit it")
	}
}

func TestCDIDuplicateEnvViaCRIDeviceField(t *testing.T) {
	ctr := &api.Container{
		Args:       []string{"/bin/server"},
		Env:        cdiDuplicateEnv(),
		CDIDevices: []*api.CDIDevice{{Name: "nvidia.com/gpu=GPU-0"}},
	}
	if containerEnv(ctr) == nil {
		t.Error("cdi-cri strategy: duplicate env left the launch environment unobservable")
	}
}

// The tolerance is scoped to CDI containers. Everywhere else a duplicate stays
// unobservable, because nothing tells us which value the runtime would keep.
func TestDuplicateEnvWithoutCDIStaysUnobservable(t *testing.T) {
	ctr := &api.Container{Args: []string{"/bin/server"}, Env: []string{"MODE=unsafe", "MODE=production"}}
	if containerEnv(ctr) != nil {
		t.Error("a duplicate outside a CDI container must stay unobservable")
	}
}

func TestCDIDuplicateEnvStillRejectsTampering(t *testing.T) {
	tampered := append(cdiDuplicateEnv(), "LD_PRELOAD=/tmp/evil.so")
	obs := containerEnv(gpuContainer(tampered))
	if obs == nil {
		t.Fatal("expected observable evidence")
	}
	if envPolicyAdmits(allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: runcEnv()}, obs) {
		t.Error("an injected variable was admitted: tolerating the duplicate must not weaken exactness")
	}
}

func TestMalformedEnvStaysUnobservableUnderCDI(t *testing.T) {
	for _, bad := range [][]string{
		{"PATH=/usr/bin", "NOEQUALS"},
		{"PATH=/usr/bin", "=novalue"},
	} {
		if obs := containerEnv(gpuContainer(bad)); obs != nil {
			t.Errorf("malformed env %q must stay unobservable, got evidence", bad)
		}
	}
}

// envPolicyAdmits exercises the policy through the exported admission path.
func envPolicyAdmits(p allowlist.EnvPolicy, obs *allowlist.EnvObservation) bool {
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	d, err := types.ParseDigest(digest)
	if err != nil {
		panic(err)
	}
	a := &allowlist.Allowlist{Schema: "c8s.allowlist/v1", Workloads: map[string]allowlist.Workload{
		"w": {Containers: []allowlist.Container{{
			Digest:  d,
			Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyAny},
			Env:     p,
		}}},
	}}
	if err := a.Normalize(); err != nil {
		panic(err)
	}
	return a.BuildIndex().AdmitsContainer(allowlist.RunningContainer{Digest: digest, Env: obs})
}
