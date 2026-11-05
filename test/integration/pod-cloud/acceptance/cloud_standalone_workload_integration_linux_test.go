//go:build linux && pod_cloud_integration

package acceptance

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

func TestCloudAcceptanceStandaloneWorkloadUsesHelloAppAndExactPolicy(t *testing.T) {
	r, _, _ := cloudOwnershipFixture(t)
	r.cfg.Scenario = "warm-assignment"
	pod, policy, err := r.workload("a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || pod.Spec.NodeName != "" || len(pod.Spec.SchedulingGates) != 0 {
		t.Fatal("standalone workload must be one application the launcher signs as is")
	}
	app := pod.Spec.Containers[0]
	if app.Name != "app" || app.Image != podfixture.Image || !slices.Equal(app.Command, podfixture.Command()) || !slices.Equal(app.Args, podfixture.HelloArgs()) {
		t.Fatal("timeout workload retained a connected checker/configuration or did not select the independent HTTP application")
	}
	if app.ReadinessProbe == nil || app.ReadinessProbe.HTTPGet == nil || app.ReadinessProbe.HTTPGet.Path != "/ready" || app.ReadinessProbe.HTTPGet.Port.IntVal != 8080 || app.LivenessProbe == nil || app.LivenessProbe.HTTPGet == nil || app.LivenessProbe.HTTPGet.Path != "/live" || app.LivenessProbe.HTTPGet.Port.IntVal != 8080 || len(app.Ports) != 1 || app.Ports[0].ContainerPort != 8080 {
		t.Fatal("standalone application lost its HTTP readiness/liveness probes or declared ingress")
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	allowlist, err := pkgallowlist.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	rules := allowlist.Workloads["cloud-a"].Containers
	if len(rules) != 1 || rules[0].Image != app.Image || rules[0].Digest.String() != strings.Split(app.Image, "@")[1] || rules[0].Command.Policy != pkgallowlist.PolicyExact || rules[0].Args.Policy != pkgallowlist.PolicyExact || !slices.Equal(rules[0].Command.Argv, app.Command) || !slices.Equal(rules[0].Args.Argv, app.Args) {
		t.Fatal("timeout workload policy does not bind exactly the submitted application")
	}
	if _, _, err = r.workload("b", nil); err == nil {
		t.Fatal("single-Pod timeout scenario accepted a peer workload")
	}
}

// standaloneCloudState checks a single-app lane's actual app and injected mesh;
// it deliberately has no connected checker or completion result.
func standaloneCloudState(p podstatus.PodProjection, uid string) (PodState, error) {
	if uid == "" || p.Metadata.UID != uid || (p.Status.Phase != corev1.PodPending && p.Status.Phase != corev1.PodRunning) {
		return PodState{}, errors.New("standalone guest identity or phase differs")
	}
	if len(p.Status.ContainerStatuses) != 1 || p.Status.ContainerStatuses[0].Name != "app" || len(p.Status.InitContainerStatuses) != 1 || p.Status.InitContainerStatuses[0].Name != workloadclaims.MeshContainerName {
		return PodState{}, errors.New("standalone guest must contain exactly its app and measured mesh endpoint")
	}
	out := PodState{Running: p.Status.Phase == corev1.PodRunning, Ready: true, Starts: map[string]string{}}
	for _, c := range []podstatus.ContainerStatus{p.Status.ContainerStatuses[0], p.Status.InitContainerStatuses[0]} {
		if c.RestartCount != 0 || (c.State != nil && c.State.Terminated != nil) || (c.LastState != nil && c.LastState.Terminated != nil) {
			return PodState{}, errors.New("standalone app or mesh restarted or exited")
		}
		if c.State == nil || c.State.Running == nil {
			if p.Status.Phase == corev1.PodRunning {
				return PodState{}, errors.New("running standalone guest has an incomplete container state")
			}
			out.Ready = false
			continue
		}
		if c.State.Waiting != nil || c.State.Running.StartedAt == nil || c.State.Running.StartedAt.IsZero() {
			return PodState{}, errors.New("standalone running container has malformed state or no start time")
		}
		out.Starts[c.Name] = c.State.Running.StartedAt.UTC().Format(time.RFC3339Nano)
		out.Ready = out.Ready && c.Ready
	}
	out.Ready = out.Ready && out.Running
	return out, nil
}

func TestCloudAcceptanceStandaloneStateRejectsForeignOrMalformedStatus(t *testing.T) {
	started := metav1.NewTime(time.Unix(1234, 0).UTC())
	fixture := func() podstatus.PodProjection {
		status := func(name string) podstatus.ContainerStatus {
			return podstatus.ContainerStatus{Name: name, Ready: true, State: &podstatus.ContainerState{Running: &podstatus.ContainerRunning{StartedAt: &started}}}
		}
		return podstatus.PodProjection{Metadata: podstatus.PodMetadata{UID: "owned"}, Status: podstatus.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []podstatus.ContainerStatus{status("app")}, InitContainerStatuses: []podstatus.ContainerStatus{status(workloadclaims.MeshContainerName)}}}
	}
	good := fixture()
	state, err := standaloneCloudState(good, "owned")
	if err != nil || !state.Ready || !state.Running || state.Complete || len(state.Starts) != 2 {
		t.Fatalf("valid standalone status was refused or acquired a checker result: %+v %v", state, err)
	}
	for name, mutate := range map[string]func(*podstatus.PodProjection){
		"foreign":      func(p *podstatus.PodProjection) { p.Metadata.UID = "foreign" },
		"missing-mesh": func(p *podstatus.PodProjection) { p.Status.InitContainerStatuses = nil },
		"extra-checker": func(p *podstatus.PodProjection) {
			p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, podstatus.ContainerStatus{Name: "checker"})
		},
		"app-restarted":  func(p *podstatus.PodProjection) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"mesh-restarted": func(p *podstatus.PodProjection) { p.Status.InitContainerStatuses[0].RestartCount = 1 },
		"terminated": func(p *podstatus.PodProjection) {
			p.Status.ContainerStatuses[0].State = &podstatus.ContainerState{Terminated: &podstatus.ContainerTerminated{}}
		},
		"missing-start": func(p *podstatus.PodProjection) { p.Status.InitContainerStatuses[0].State.Running.StartedAt = nil },
		"mixed-state":   func(p *podstatus.PodProjection) { p.Status.ContainerStatuses[0].State.Waiting = &struct{}{} },
		"missing-state": func(p *podstatus.PodProjection) { p.Status.ContainerStatuses[0].State = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			mutate(&p)
			if _, err := standaloneCloudState(p, "owned"); err == nil {
				t.Fatal("foreign or malformed standalone guest status was accepted")
			}
		})
	}
	pending := fixture()
	pending.Status.Phase = corev1.PodPending
	pending.Status.ContainerStatuses[0].State = &podstatus.ContainerState{Waiting: &struct{}{}}
	if state, err := standaloneCloudState(pending, "owned"); err != nil || state.Ready || state.Running || state.Complete {
		t.Fatalf("pending standalone guest did not remain a boot wait: %+v %v", state, err)
	}
}
