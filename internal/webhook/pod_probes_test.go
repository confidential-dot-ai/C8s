package webhook

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// podWithProbedApp is a pod whose application is probed the way a chart
// renders it: a readiness probe on a declared port number and a liveness probe
// on that port's name.
func podWithProbedApp() *corev1.Pod {
	pod := podWithApp()
	app := &pod.Spec.Containers[0]
	app.Ports = []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 8080,
		},
	}
	app.ReadinessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8080),
			},
		},
	}
	app.LivenessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/livez",
				Port: intstr.FromString("http"),
			},
		},
	}
	return pod
}

// appContainerNamed is one of the pod's own containers.
func appContainerNamed(t *testing.T, pod *corev1.Pod, name string) *corev1.Container {
	t.Helper()
	for _, c := range workloadProbeContainers(pod) {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("pod carries no container %q", name)
	return nil
}

// appProbePath is the path a probe of the pod's application reaches.
func appProbePath(t *testing.T, probe *corev1.Probe) string {
	t.Helper()
	if probe == nil || probe.HTTPGet == nil {
		t.Fatalf("probe %+v is not an HTTP probe", probe)
	}
	if got := probe.HTTPGet.Port; got != intstr.FromInt32(workloadclaims.MeshHealthPort) {
		t.Fatalf("probe port = %v, want the health port %d", got, workloadclaims.MeshHealthPort)
	}
	return probe.HTTPGet.Path
}

// containerEnvValue is the value of one environment variable of a container.
func containerEnvValue(c *corev1.Container, name string) string {
	for _, env := range c.Env {
		if env.Name == name {
			return env.Value
		}
	}
	return ""
}

// The pod's ruleset answers its application ports with the mesh listener, so
// an application probe is moved onto the endpoint's health port and named to
// the endpoint, which forwards it inside the pod.
func TestInjectionMovesApplicationProbesOntoTheHealthPort(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())

	mutated := admit(t, m, podWithProbedApp(), "tenant")

	app := appContainerNamed(t, mutated, "app")
	ready := appProbePath(t, app.ReadinessProbe)
	live := appProbePath(t, app.LivenessProbe)
	if want := workloadclaims.MeshProbePath(8080, "/healthz"); ready != want {
		t.Errorf("readiness probe path = %q, want %q", ready, want)
	}
	if want := workloadclaims.MeshProbePath(8080, "/livez"); live != want {
		t.Errorf("liveness probe path = %q, want %q", live, want)
	}
	mesh := containerNamed(mutated, reservedMeshContainerName)
	want := workloadclaims.JoinMeshProbePaths([]string{ready, live})
	if got := containerEnvValue(mesh, workloadclaims.MeshProbesEnv); got != want {
		t.Errorf("the endpoint is given %s=%q, want %q", workloadclaims.MeshProbesEnv, got, want)
	}
	for _, arg := range mesh.Args {
		if arg == want {
			t.Errorf("the endpoint carries its probe targets in %v, which a node's measured policy pins", mesh.Args)
		}
	}
}

// The rewrite is its own fixed point, so the validator derives the same shape
// from a stored pod as the injector built.
func TestInjectedProbesAreReinjectedUnchanged(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	injected := admit(t, m, podWithProbedApp(), "tenant")

	again := admit(t, m, injected.DeepCopy(), "tenant")

	if got, want := appContainerNamed(t, again, "app").ReadinessProbe, appContainerNamed(t, injected, "app").ReadinessProbe; !equalProbes(got, want) {
		t.Fatalf("reinjection moved the probe again: %+v, want %+v", got.HTTPGet, want.HTTPGet)
	}
	if resp := validate(t, v, defaulted(injected), "tenant"); !resp.Allowed {
		t.Fatalf("the validator denied the injected pod: %+v", resp.Result)
	}
}

func equalProbes(a, b *corev1.Probe) bool {
	return a != nil && b != nil && a.HTTPGet != nil && b.HTTPGet != nil &&
		a.HTTPGet.Path == b.HTTPGet.Path && a.HTTPGet.Port == b.HTTPGet.Port
}

// The endpoint forwards the targets the injector rendered from the pod's own
// probes, so a target added behind the injector is refused rather than
// forwarded into the pod's loopback.
func TestValidatorRefusesAProbeTargetThePodDoesNotProbe(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	injected := defaulted(admit(t, m, podWithProbedApp(), "tenant"))

	forged := injected.DeepCopy()
	mesh := containerNamed(forged, reservedMeshContainerName)
	mesh.Env = []corev1.EnvVar{
		{
			Name:  workloadclaims.MeshProbesEnv,
			Value: workloadclaims.MeshProbePath(9000, "/admin/shutdown"),
		},
	}

	denies(t, v, forged, "env")
}

// A member pod carrying a probe the endpoint cannot forward is refused: its
// probe would otherwise never pass once the ruleset is installed.
func TestInjectionRefusesAnUnforwardableProbe(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	for _, tc := range []struct {
		name  string
		probe *corev1.HTTPGetAction
		want  string
	}{
		{"https", &corev1.HTTPGetAction{
			Path:   "/healthz",
			Port:   intstr.FromInt32(8080),
			Scheme: corev1.URISchemeHTTPS,
		}, "scheme HTTPS"},
		{"undeclared named port", &corev1.HTTPGetAction{
			Path: "/healthz",
			Port: intstr.FromString("admin"),
		}, "declared by no port"},
		{"mesh port", &corev1.HTTPGetAction{
			Path: "/readyz",
			Port: intstr.FromInt32(workloadclaims.MeshHealthPort),
		}, "mesh port"},
		{"query", &corev1.HTTPGetAction{
			Path: "/healthz?verbose=1",
			Port: intstr.FromInt32(8080),
		}, "probe path"},
		{"unclean path", &corev1.HTTPGetAction{
			Path: "/healthz/../metrics",
			Port: intstr.FromInt32(8080),
		}, "probe path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := podWithApp()
			pod.Spec.Containers[0].ReadinessProbe = &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{HTTPGet: tc.probe},
			}
			raw, err := json.Marshal(pod)
			if err != nil {
				t.Fatal(err)
			}
			resp := m.Handle(context.Background(), podRequest("tenant", raw, ""))
			if resp.Allowed {
				t.Fatal("the injector admitted a pod whose probe it cannot forward")
			}
			if resp.Result == nil || !strings.Contains(resp.Result.Message, tc.want) {
				t.Fatalf("denial = %+v, want it to mention %q", resp.Result, tc.want)
			}
		})
	}
}

// Probes the kubelet does not aim into the pod's network namespace, or does not
// carry over HTTP, are left as they are: the endpoint forwards nothing for them.
func TestInjectionLeavesOtherProbesAlone(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	pod := podWithApp()
	app := &pod.Spec.Containers[0]
	app.ReadinessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Host: "sidecar.example.com",
				Path: "/healthz",
				Port: intstr.FromInt32(8080),
			},
		},
	}
	app.LivenessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{Command: []string{"/bin/true"}},
		},
	}
	app.StartupProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(8080)},
		},
	}

	mutated := admit(t, m, pod, "tenant")

	got := appContainerNamed(t, mutated, "app")
	if got.ReadinessProbe.HTTPGet.Port != intstr.FromInt32(8080) || got.ReadinessProbe.HTTPGet.Path != "/healthz" {
		t.Errorf("a probe naming a host was moved: %+v", got.ReadinessProbe.HTTPGet)
	}
	mesh := containerNamed(mutated, reservedMeshContainerName)
	if mesh.Env != nil {
		t.Errorf("the endpoint is given %+v, want no probe targets", mesh.Env)
	}
}

// The pod's own restartable init containers are probed like its containers,
// and the platform containers keep the probes the injector gives them.
func TestInjectionMovesOwnInitContainerProbesOnly(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	pod := podWithProbedApp()
	always := corev1.ContainerRestartPolicyAlways
	pod.Spec.InitContainers = []corev1.Container{
		{
			Name:          "cache",
			RestartPolicy: &always,
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/ready",
						Port: intstr.FromInt32(6379),
					},
				},
			},
		},
	}

	mutated := admit(t, m, pod, "tenant")

	cache := appProbePath(t, appContainerNamed(t, mutated, "cache").ReadinessProbe)
	if want := workloadclaims.MeshProbePath(6379, "/ready"); cache != want {
		t.Errorf("the init container's probe path = %q, want %q", cache, want)
	}
	mesh := containerNamed(mutated, reservedMeshContainerName)
	if got := containerEnvValue(mesh, workloadclaims.MeshProbesEnv); !slices.Contains(workloadclaims.SplitMeshProbePaths(got), cache) {
		t.Errorf("the endpoint is given %q, which does not name %q", got, cache)
	}
	if mesh.ReadinessProbe.HTTPGet.Path != "/readyz" || mesh.StartupProbe.HTTPGet.Path != "/startupz" {
		t.Errorf("the endpoint's own probes were moved: %+v", mesh.ReadinessProbe.HTTPGet)
	}
}
