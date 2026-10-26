package nriimagepolicy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestPodImageConfigRequiresCanonicalPinsAndMeasuredEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config)
	}{
		{"missing", func(c *config) { c.Pod.Images = nil }},
		{"tag", func(c *config) { c.Pod.Images["app"] = "repo:latest" }},
		{"uppercase", func(c *config) { c.Pod.Images["app"] = "sha256:" + strings.Repeat("A", 64) }},
		{"reference", func(c *config) { c.Pod.Images["app"] = "repo@" + pushDigestA }},
		{"unnamed", func(c *config) { c.Pod.Images[""] = pushDigestA }},
		{"invalid name", func(c *config) { c.Pod.Images["../app"] = pushDigestA }},
		{"missing endpoint", func(c *config) { delete(c.Pod.Images, workloadclaims.MeshContainerName) }},
		{"replaced endpoint", func(c *config) { c.Pod.Images[workloadclaims.MeshContainerName] = pushDigestA }},
		{"no measured base", func(c *config) { c.Allowlist.Base = nil }},
		{"ambiguous endpoint", func(c *config) { c.Allowlist.Base.Workloads["other"] = c.Allowlist.Base.Workloads["role-entry"] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config{Pod: &podConfig{Images: map[string]string{"app": pushDigestA, workloadclaims.MeshContainerName: pushDigestB}}, Allowlist: allowlistConfig{Base: roleBase(t, pushDigestB, meshRole, []string{"/mesh"})}}
			if err := cfg.validatePodImages(); err != nil {
				t.Fatalf("valid pins: %v", err)
			}
			tc.change(cfg)
			if err := cfg.validatePodImages(); err == nil {
				t.Fatal("invalid Pod image binding accepted")
			}
		})
	}
}

func TestPodImageBindingIgnoresMutableRuntimeNames(t *testing.T) {
	pod := makePod("tenant", "assigned-node")
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo:latest")
	p := newTestPlugin(&config{Pod: &podConfig{UID: "signed-uid", Namespace: pod.Namespace, Name: pod.Name, Images: map[string]string{"app": pushDigestA}}})
	for _, annotation := range []string{"registry/repo:latest", "registry/repo@" + pushDigestB, "", "not an image"} {
		ctr.Annotations[annotationImageName] = annotation
		if got, err := p.containerImage(pod, ctr); err != nil || got != pushDigestA {
			t.Fatalf("annotation %q selected %q, %v", annotation, got, err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*api.PodSandbox, *api.Container)
	}{
		{"namespace", func(p *api.PodSandbox, _ *api.Container) { p.Namespace = "other" }},
		{"Pod name", func(p *api.PodSandbox, _ *api.Container) { p.Name = "other" }},
		{"sandbox", func(_ *api.PodSandbox, c *api.Container) { c.PodSandboxId = "other" }},
		{"missing sandbox", func(p *api.PodSandbox, _ *api.Container) { p.Id = "" }},
		{"missing container", func(_ *api.PodSandbox, c *api.Container) { c.Id = "" }},
		{"unknown container", func(_ *api.PodSandbox, c *api.Container) { c.Name = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p2, c2 := proto.Clone(pod).(*api.PodSandbox), proto.Clone(ctr).(*api.Container)
			tc.change(p2, c2)
			if _, err := p.containerImage(p2, c2); err == nil {
				t.Fatal("container outside its staged binding accepted")
			}
		})
	}
}

func TestPodStartVerifiesEverySelectionBeforeMeasuringAndRecording(t *testing.T) {
	reg := &fakeRegister{value: launchSeed}
	measurer, err := openMeasurer(measureFixture(t, reg), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	pod := makePod("tenant", "assigned-node")
	pod.Uid = "runtime-uid"
	p := newTestPlugin(&config{
		Pod:       &podConfig{UID: "signed-uid", Namespace: pod.Namespace, Name: pod.Name, Images: map[string]string{"app": pushDigestA}},
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "app"})},
		Policy:    policyConfig{Mode: ModeFailClosed},
		Measure:   measureConfig{RTMR3: true},
	})
	p.SetReady()
	p.measurer = measurer
	p.inventory = newAdmissionInventory(t.TempDir())
	p.inventory.recordSandbox(pod.Id)
	ctr := makeCtrWithImageArgs(pod.Id, "app", "repo:latest", []string{"/app"})
	ctr.Env = []string{}
	checks := 0
	p.containerd = &fakeContainerd{verify: func(_ context.Context, containerID, sandboxID, digest string) error {
		checks++
		if containerID != ctr.Id || sandboxID != pod.Id || digest != pushDigestA {
			t.Fatalf("wrong selected-image verification: %s/%s/%s", sandboxID, containerID, digest)
		}
		return nil
	}}
	if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	for _, annotation := range []string{"repo@" + pushDigestB, "repo:replacement"} {
		ctr.Annotations[annotationImageName] = annotation
		if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
			t.Fatalf("verified selected content with moved annotation: %v", err)
		}
	}
	if checks != 2 || reg.value != runtimemeasure.FromDigestsSeeded(launchSeed, []string{pushDigestA}) {
		t.Fatalf("checks = %d; repeated start must verify twice and extend once", checks)
	}
	digests, containers, known, err := p.inventory.DigestsForSandbox(pod.Id)
	if err != nil || !known || !slices.Equal(digests, []string{pushDigestA}) || len(containers) != 1 || containers[0].Digest != pushDigestA {
		t.Fatalf("inventory = %v/%+v, known=%v, %v", digests, containers, known, err)
	}
}

func TestPodSelectedImageFailureHasNoMeasurementHistoryOrMeshStart(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "initializing", true: "ready"}[ready], func(t *testing.T) {
			reg := &fakeRegister{value: launchSeed}
			measurer, err := openMeasurer(measureFixture(t, reg), discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			pod := meshPod("tenant", "assigned-node", testNetNS)
			p := newTestPlugin(&config{Pod: &podConfig{UID: "signed-uid", Namespace: pod.Namespace, Name: pod.Name, Images: map[string]string{workloadclaims.MeshContainerName: pushDigestB}}})
			p.measurer = measurer
			p.inventory = newAdmissionInventory(t.TempDir())
			p.inventory.recordSandbox(pod.Id)
			gate, state := gateWithPod(pod)
			p.mesh = gate
			if ready {
				p.SetReady()
			}
			p.containerd = &fakeContainerd{verify: func(context.Context, string, string, string) error { return errors.New("selected snapshot differs") }}
			ctr := makeCtrWithImage(pod.Id, workloadclaims.MeshContainerName, "repo@"+pushDigestB)
			if err := p.StartContainer(t.Context(), pod, ctr); err == nil || !strings.Contains(err.Error(), "selected snapshot differs") {
				t.Fatalf("got %v, want selected image refusal", err)
			}
			if reg.value != launchSeed || state.meshStarted || len(p.inventory.containers) != 0 || p.inventory.denial(pod.Id) == nil {
				t.Fatal("rejected selection created a measurement, admission record or mesh authority")
			}
		})
	}
}

func TestPodExistingContainersCannotReconstructImageHistory(t *testing.T) {
	pod := makePod("tenant", "assigned-node")
	p := newTestPlugin(&config{Pod: &podConfig{UID: "signed-uid", Namespace: pod.Namespace, Name: pod.Name, Images: map[string]string{"app": pushDigestA}}, Policy: policyConfig{Mode: ModeFailClosed, EnforceExisting: true}})
	p.inventory = newAdmissionInventory(t.TempDir())
	p.inventory.recordSandbox(pod.Id)
	ctr := makeCtrWithImage(pod.Id, "app", "repo:changed")
	stopped := false
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		if id != ctr.Id {
			t.Fatalf("stopping unexpected container %s", id)
		}
		stopped = true
		return nil
	}}
	p.checkExisting(t.Context(), p.cfg, []*api.PodSandbox{pod}, []*api.Container{ctr})
	if !stopped || len(p.inventory.containers) != 0 || p.inventory.denial(pod.Id) == nil {
		t.Fatal("existing container supplied reconstructed Pod image evidence")
	}
}
