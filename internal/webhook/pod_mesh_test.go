package webhook

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const testMeshImage = "ghcr.io/confidential-dot-ai/armtls-mesh:test"

// meshConfig is the operator's configuration as the chart renders it.
func meshConfig() Config {
	return secretsConfig().withDefaults()
}

// podRequest is a CREATE of one pod.
func podRequest(namespace string, raw []byte, subResource string) admission.Request {
	return admission.Request{
		Namespace:   namespace,
		SubResource: subResource,
		Operation:   admissionv1.Create,
		Object:      runtime.RawExtension{Raw: raw},
	}
}

// podUpdateRequest is an UPDATE from one stored pod to another.
func podUpdateRequest(namespace string, oldRaw, raw []byte) admission.Request {
	return admission.Request{
		Namespace: namespace,
		Operation: admissionv1.Update,
		Object:    runtime.RawExtension{Raw: raw},
		OldObject: runtime.RawExtension{Raw: oldRaw},
	}
}

func meshHandlers(t *testing.T, cfg Config) (*podMutator, *podValidator) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	decoder := admission.NewDecoder(scheme)
	mutator := &podMutator{
		decoder: decoder,
		cfg:     cfg,
	}
	validator := &podValidator{
		decoder: decoder,
		cfg:     cfg,
	}
	return mutator, validator
}

// admit runs the mutator over pod and applies its patch, so a test reads the
// pod the API server would store rather than a second call of the mutation.
func admit(t *testing.T, m *podMutator, pod *corev1.Pod, namespace string) *corev1.Pod {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), podRequest(namespace, raw, ""))
	if !resp.Allowed {
		t.Fatalf("mutator denied the pod: %+v", resp.Result)
	}
	patchJSON, err := json.Marshal(resp.Patches)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		t.Fatalf("decode the mutator's patch: %v", err)
	}
	patched, err := patch.Apply(raw)
	if err != nil {
		t.Fatalf("apply the mutator's patch: %v", err)
	}
	mutated := &corev1.Pod{}
	if err := json.Unmarshal(patched, mutated); err != nil {
		t.Fatal(err)
	}
	return mutated
}

// Every pod in a covered namespace is injected, annotated or not, and the mesh
// endpoint leads the platform containers.
func TestMeshInjectionOrdersEndpointFirst(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	pod := podWithApp()
	pod.Spec.InitContainers = []corev1.Container{{Name: "migrate"}}

	mutated := admit(t, m, pod, "tenant")

	want := []string{reservedMeshContainerName, reservedCertContainerName, reservedCertWaitContainerName, "migrate"}
	if got := containerNames(mutated.Spec.InitContainers); !slices.Equal(got, want) {
		t.Fatalf("init containers = %v, want %v", got, want)
	}
	if _, ok := mutated.Labels[LabelWorkload]; ok {
		t.Fatalf("unannotated pod carries the %s label: %v", LabelWorkload, mutated.Labels)
	}
	cert := containerNamed(mutated, reservedCertContainerName)
	if !hasArg(cert.Args, "--no-san") {
		t.Fatalf("c8s-cert args %v must request no SAN for an unannotated pod", cert.Args)
	}
}

// The endpoint runs as the reserved mesh role with no capabilities, probed over
// HTTP on the health port, with the credential paths the injector chose.
func TestMeshContainerShape(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	mesh := containerNamed(admit(t, m, podWithApp(), "tenant"), reservedMeshContainerName)

	if mesh.Image != testMeshImage {
		t.Fatalf("mesh image = %q, want %q", mesh.Image, testMeshImage)
	}
	if mesh.RestartPolicy == nil || *mesh.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("mesh restartPolicy = %v, want Always (native sidecar)", mesh.RestartPolicy)
	}
	for _, want := range []string{
		"--cert-path=/etc/c8s/certs/tls.crt",
		"--key-path=/etc/c8s/certs/tls.key",
		"--ca-path=/etc/c8s/certs/ca.crt",
	} {
		if !hasArg(mesh.Args, want) {
			t.Fatalf("mesh args %v missing %q", mesh.Args, want)
		}
	}
	sc := mesh.SecurityContext
	if sc == nil || sc.RunAsUser == nil || *sc.RunAsUser != int64(workloadclaims.MeshUID) {
		t.Fatalf("mesh runAsUser = %v, want the reserved %d", sc, workloadclaims.MeshUID)
	}
	if len(sc.Capabilities.Add) != 0 || !slices.Contains(sc.Capabilities.Drop, corev1.Capability("ALL")) {
		t.Fatalf("mesh capabilities = %+v, want all dropped and none added", sc.Capabilities)
	}
	if *sc.AllowPrivilegeEscalation || !*sc.ReadOnlyRootFilesystem || !*sc.RunAsNonRoot {
		t.Fatalf("mesh security context = %+v, want the non-root read-only floor", sc)
	}
	for name, probe := range map[string]*corev1.Probe{"startup": mesh.StartupProbe, "readiness": mesh.ReadinessProbe} {
		if probe == nil || probe.HTTPGet == nil {
			t.Fatalf("mesh %s probe = %+v, want an HTTP probe", name, probe)
		}
		if probe.Exec != nil {
			t.Fatalf("mesh %s probe execs: %+v", name, probe.Exec)
		}
		if got := probe.HTTPGet.Port.IntValue(); int32(got) != workloadclaims.MeshHealthPort {
			t.Fatalf("mesh %s probe port = %d, want %d", name, got, workloadclaims.MeshHealthPort)
		}
	}
	if mesh.StartupProbe.HTTPGet.Path != "/startupz" || mesh.ReadinessProbe.HTTPGet.Path != "/readyz" {
		t.Fatalf("mesh probe paths = %q and %q", mesh.StartupProbe.HTTPGet.Path, mesh.ReadinessProbe.HTTPGet.Path)
	}
}

// The credential volume reaches the platform containers only: no workload
// container holds the pod's key, CA or issuer record.
func TestMeshInjectionKeepsCredentialsOffWorkloads(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	pod := podWithApp()
	pod.Annotations = map[string]string{
		AnnotationWorkload: "api",
		AnnotationSecrets:  "token=/store/token",
	}
	cfg := meshConfig()
	cfg.WorkloadClaimsHostDir = "/run/c8s-node"
	m.cfg = cfg

	mutated := admit(t, m, pod, "tenant")

	for _, c := range mutated.Spec.Containers {
		if containerMount(&c, certVolumeName) != nil {
			t.Fatalf("workload container %q mounts the credential volume", c.Name)
		}
	}
	for _, name := range []string{
		reservedMeshContainerName,
		reservedCertContainerName,
		reservedCertWaitContainerName,
		reservedSecretContainerName,
	} {
		c := containerNamed(mutated, name)
		if c == nil {
			t.Fatalf("platform container %q missing", name)
		}
		if containerMount(c, certVolumeName) == nil {
			t.Fatalf("platform container %q has no credential mount", name)
		}
	}
	// The released secrets stay readable pod-wide: they are the workload's.
	if containerMount(&mutated.Spec.Containers[0], secretsVolumeName) == nil {
		t.Fatal("workload container lost its secrets mount")
	}
}

// A pod requesting a SAN without opting in gets injection and no SAN.
func TestMeshInjectionAdmitsSANWithoutWorkloadAnnotation(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	pod := podWithApp()
	pod.Annotations = map[string]string{AnnotationSAN: "api.tenant.svc"}

	mutated := admit(t, m, pod, "tenant")

	args := containerNamed(mutated, reservedCertContainerName).Args
	if !hasArg(args, "--no-san") {
		t.Fatalf("c8s-cert args %v must request no SAN without the cw annotation", args)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--san") {
			t.Fatalf("c8s-cert requests %q for a pod that never opted in", arg)
		}
	}
}

// The injected shape stays admissible under PodSecurity restricted: the mesh
// endpoint runs non-root with no capabilities, so a hardened namespace does not
// have to choose between the mesh and its own policy.
func TestMeshInjectionStaysRestrictedAdmissible(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   new(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: new(false),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			}},
		},
	}
	if agg := evaluateRestricted(t, pod); !agg.Allowed {
		t.Fatalf("input fixture violates PodSecurity restricted before injection: %s: %s", agg.ForbiddenReason(), agg.ForbiddenDetail())
	}

	injected := admit(t, m, pod, "tenant")

	if agg := evaluateRestricted(t, injected); !agg.Allowed {
		t.Fatalf("injected pod violates PodSecurity restricted: %s: %s", agg.ForbiddenReason(), agg.ForbiddenDetail())
	}
}

// A container parked under a platform name the pod never requested is dropped
// by the injector and refused by the validator: it would otherwise sit behind
// the real containers and mount the pod's credentials.
func TestPlatformNameImpostorIsDroppedAndRefused(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	impostor := corev1.Container{
		Name:    reservedSecretContainerName,
		Image:   "ghcr.io/attacker/shell:latest",
		Command: []string{"sleep", "infinity"},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      certVolumeName,
				MountPath: "/creds",
			},
		},
	}
	pod := podWithApp()
	pod.Spec.InitContainers = []corev1.Container{impostor}

	mutated := admit(t, m, pod, "tenant")
	if c := containerNamed(mutated, reservedSecretContainerName); c != nil {
		t.Fatalf("injector kept a container under the reserved name %q: %+v", impostor.Name, c)
	}

	smuggled := mutated.DeepCopy()
	smuggled.Spec.InitContainers = append(smuggled.Spec.InitContainers, impostor)
	denies(t, v, smuggled, "containers are")
}

// A platform container's termination message must stay its own file: a pod
// authored with the path pointing at the key, or with the log fallback, would
// copy a credential into pod status, which the control plane reads.
func TestValidatorRejectsTerminationMessageEscape(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	injected := admit(t, m, podWithApp(), "tenant")

	mesh := containerNamed(injected, reservedMeshContainerName)
	if mesh.TerminationMessagePath != corev1.TerminationMessagePathDefault {
		t.Fatalf("injected terminationMessagePath = %q, want the default", mesh.TerminationMessagePath)
	}
	if mesh.TerminationMessagePolicy != corev1.TerminationMessageReadFile {
		t.Fatalf("injected terminationMessagePolicy = %q, want %q", mesh.TerminationMessagePolicy, corev1.TerminationMessageReadFile)
	}

	cases := []struct {
		name   string
		mutate func(c *corev1.Container)
		want   string
	}{
		{"path names the key", func(c *corev1.Container) {
			c.TerminationMessagePath = "/etc/c8s/certs/tls.key"
		}, "terminationMessagePath"},
		{"log fallback", func(c *corev1.Container) {
			c.TerminationMessagePolicy = corev1.TerminationMessageFallbackToLogsOnError
		}, "terminationMessagePolicy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := injected.DeepCopy()
			tc.mutate(containerNamed(pod, reservedMeshContainerName))
			denies(t, v, pod, tc.want)
		})
	}
}

// The credential paths are the injector's, so a pod naming them is refused by
// both webhooks rather than admitted with paths nothing writes.
func TestMeshInjectionRefusesCredentialPathAnnotations(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	for _, annotation := range []string{
		AnnotationCertVolume,
		AnnotationCertDir,
		AnnotationCertFile,
		AnnotationKeyFile,
		AnnotationCAFile,
	} {
		t.Run(annotation, func(t *testing.T) {
			pod := podWithApp()
			pod.Annotations = map[string]string{AnnotationWorkload: "api", annotation: "/tmp/elsewhere"}
			raw, err := json.Marshal(pod)
			if err != nil {
				t.Fatal(err)
			}
			req := podRequest("tenant", raw, "")
			for name, resp := range map[string]admission.Response{
				"mutator":   m.Handle(context.Background(), req),
				"validator": v.Handle(context.Background(), req),
			} {
				if resp.Allowed {
					t.Fatalf("%s admitted %s", name, annotation)
				}
				if !strings.Contains(resp.Result.Message, annotation) {
					t.Fatalf("%s denial = %+v, want it to name %s", name, resp.Result, annotation)
				}
			}
		})
	}
}

// Nothing the pod carries skips injection: the webhook's scope is its own
// configuration's namespaceSelector, and no label, no role-like name and no
// pre-stamped marker is read as an exemption.
func TestMeshInjectionIgnoresPodSuppliedExemptions(t *testing.T) {
	m, _ := meshHandlers(t, meshConfig())
	cases := []struct {
		name     string
		metadata func(pod *corev1.Pod)
	}{
		{"pre-stamped injected marker", func(pod *corev1.Pod) {
			pod.Annotations = map[string]string{AnnotationInjected: "true"}
		}},
		{"platform role name", func(pod *corev1.Pod) {
			pod.Annotations = map[string]string{AnnotationWorkload: "c8s-mesh"}
		}},
		{"namespace labels on the pod", func(pod *corev1.Pod) {
			pod.Labels = map[string]string{
				"kubernetes.io/metadata.name":  "kube-system",
				"confidential.ai/c8s-exempt":   "true",
				"app.kubernetes.io/managed-by": "c8s",
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := podWithApp()
			tc.metadata(pod)

			mutated := admit(t, m, pod, "tenant")

			if containerNamed(mutated, reservedMeshContainerName) == nil {
				t.Fatalf("pod skipped mesh injection: init containers %v", containerNames(mutated.Spec.InitContainers))
			}
		})
	}
}
