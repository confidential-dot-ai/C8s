package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	psaapi "k8s.io/pod-security-admission/api"
	psapolicy "k8s.io/pod-security-admission/policy"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestMutatePodInjectsCertSidecar(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{
		WorkloadID: "api",
		SAN:        "api",
	}, Config{
		GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
		MeshImage:         testMeshImage,
		AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
	})

	if got := containerNames(pod.Spec.InitContainers); !slices.Equal(got, []string{reservedMeshContainerName, reservedCertContainerName, reservedCertWaitContainerName}) {
		t.Fatalf("init containers = %v, want the endpoint, get-cert and the credential-wait gate", got)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("containers = %d, want app container only", len(pod.Spec.Containers))
	}

	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil {
		t.Fatalf("expected injected fsGroup")
	}
	if got := *pod.Spec.SecurityContext.FSGroup; got != defaultCertFSGroup {
		t.Fatalf("fsGroup = %d, want %d", got, defaultCertFSGroup)
	}
	cert := *containerNamed(pod, reservedCertContainerName)
	for _, want := range []string{
		"--san=api",
		"--cert-path=/etc/c8s/certs/tls.crt",
		"--key-path=/etc/c8s/certs/tls.key",
		"--ca-path=/etc/c8s/certs/ca.crt",
		"--renew-interval=2h0m0s",
		"--continue-on-initial-error",
	} {
		if !hasArg(cert.Args, want) {
			t.Fatalf("c8s-cert args %v missing %s", cert.Args, want)
		}
	}
	if cert.RestartPolicy == nil || *cert.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("c8s-cert restartPolicy = %#v, want Always", cert.RestartPolicy)
	}
	// The workload is gated by the c8s-cert-wait init container, not an exec
	// startupProbe on the sidecar. The sidecar must carry no startupProbe.
	if cert.StartupProbe != nil {
		t.Fatalf("c8s-cert must NOT carry a startupProbe; got %#v", cert.StartupProbe)
	}
	wait := *containerNamed(pod, reservedCertWaitContainerName)
	if wait.RestartPolicy != nil {
		t.Fatalf("c8s-cert-wait must be a run-once init container (nil restartPolicy), got %#v", wait.RestartPolicy)
	}
	for _, want := range []string{"/c8s", "probe-file", "--wait", "/etc/c8s/certs/tls.crt"} {
		if !hasArg(wait.Command, want) {
			t.Fatalf("c8s-cert-wait command %v missing %s", wait.Command, want)
		}
	}
	if cert.SecurityContext == nil {
		t.Fatalf("missing c8s-cert security context")
	}
	if cert.SecurityContext.AllowPrivilegeEscalation == nil || *cert.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("c8s-cert allows privilege escalation")
	}
	if cert.SecurityContext.RunAsNonRoot == nil || !*cert.SecurityContext.RunAsNonRoot {
		t.Fatalf("c8s-cert does not require non-root")
	}
	// The credential role's reserved identity, which the node binds to the CDS
	// address and refuses elsewhere.
	if got := *cert.SecurityContext.RunAsUser; got != int64(workloadclaims.CredentialsUID) {
		t.Fatalf("c8s-cert runAsUser = %d, want the reserved %d", got, workloadclaims.CredentialsUID)
	}
	if got := *cert.SecurityContext.RunAsGroup; got != int64(workloadclaims.CredentialsUID) {
		t.Fatalf("c8s-cert runAsGroup = %d, want the reserved %d", got, workloadclaims.CredentialsUID)
	}
	if cert.SecurityContext.SeccompProfile == nil || cert.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("c8s-cert seccomp profile = %#v", cert.SecurityContext.SeccompProfile)
	}
	if len(cert.VolumeMounts) != 1 || cert.VolumeMounts[0].ReadOnly {
		t.Fatalf("c8s-cert mounts = %#v, want writable c8s cert mount", cert.VolumeMounts)
	}

	// The credential volume is the platform containers': a workload container
	// reads no leaf, key or CA set of its own.
	if app := pod.Spec.Containers[0]; containerMount(&app, certVolumeName) != nil {
		t.Fatalf("app mounts the credential volume: %#v", app.VolumeMounts)
	}
}

// TestMutatePodCertSidecarCarriesHostIPEnv proves the injected c8s-cert sidecar
// defines HOST_IP from status.hostIP. Under cvmMode=bare-metal the chart passes the
// operator --attestation-api-url=http://$(HOST_IP):8400 verbatim, forwarded into
// this sidecar's args; the kubelet expands $(HOST_IP) against the tenant pod's
// own node so the sidecar reaches the node-baked host attestation-api wherever
// it lands. The env is unconditional (harmless when the URL has no placeholder).
func TestMutatePodCertSidecarCarriesHostIPEnv(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "image",
		AttestationApiURL: "http://$(HOST_IP):8400",
	})

	cert := *containerNamed(pod, reservedCertContainerName)
	if !hasArg(cert.Args, "--attestation-api-url=http://$(HOST_IP):8400") {
		t.Fatalf("c8s-cert args %v missing verbatim $(HOST_IP) URL", cert.Args)
	}
	var found bool
	for _, e := range cert.Env {
		if e.Name == "HOST_IP" {
			found = true
			if e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "status.hostIP" {
				t.Fatalf("HOST_IP env = %#v, want fieldRef status.hostIP", e)
			}
		}
	}
	if !found {
		t.Fatalf("c8s-cert env %#v missing HOST_IP (tenant sidecar cannot expand $(HOST_IP))", cert.Env)
	}
}

func TestMutatePodPreservesExistingFSGroup(t *testing.T) {
	existing := int64(1234)
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{FSGroup: &existing},
			Containers:      []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "image",
		AttestationApiURL: "http://attestation-api",
	})

	if got := *pod.Spec.SecurityContext.FSGroup; got != existing {
		t.Fatalf("fsGroup = %d, want existing %d", got, existing)
	}
}

func TestMutatePodUsesConfiguredCertAndInitSecurity(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "image",
		AttestationApiURL: "http://attestation-api",
		CertFSGroup:       new(int64(4242)),
		CertRenewInterval: time.Hour,
	})

	if got := *pod.Spec.SecurityContext.FSGroup; got != 4242 {
		t.Fatalf("fsGroup = %d, want 4242", got)
	}
	if got := containerNames(pod.Spec.InitContainers); !slices.Equal(got, []string{reservedMeshContainerName, reservedCertContainerName, reservedCertWaitContainerName}) {
		t.Fatalf("init containers = %v, want the endpoint, get-cert and the credential-wait gate", got)
	}
	cert := *containerNamed(pod, reservedCertContainerName)
	if !hasArg(cert.Args, "--renew-interval=1h0m0s") {
		t.Fatalf("c8s-cert args %v missing configured renewal interval", cert.Args)
	}
}

func TestMutatePodSupportsRouterProfile(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{
			AnnotationWorkload:               "c8s-router.c8s-system.svc",
			AnnotationRenewInterval:          "1h",
			AnnotationDiscoveryVolume:        "discovery",
			AnnotationDiscoveryMountPath:     "/discovery",
			AnnotationDiscoveryOut:           "/discovery/discovery.json",
			AnnotationDiscoveryCDSCertURL:    "/.well-known/cds-cert.pem",
			AnnotationDiscoveryMeshCAURL:     "/.well-known/mesh-ca.pem",
			AnnotationDiscoveryPublicTLSMode: "webpki",
			AnnotationGetCertVerbose:         "true",
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "public-tls"},
				{Name: "discovery"},
			},
			Containers: []corev1.Container{{
				Name: "nginx",
			}},
		},
	}

	inj, err := parseAnnotations(pod, "")
	if err != nil {
		t.Fatalf("parseAnnotations: %v", err)
	}
	mutatePod(pod, inj, Config{
		GetCertImage:      "image",
		AttestationApiURL: "http://attestation-api",
	})

	// No injected container signals nginx, so the injector leaves the
	// process namespace alone.
	if pod.Spec.ShareProcessNamespace != nil {
		t.Fatalf("shareProcessNamespace = %v, want it unset", *pod.Spec.ShareProcessNamespace)
	}
	if len(pod.Spec.Volumes) != 3 {
		t.Fatalf("volumes = %#v, want the router's own plus the injected cert volume", pod.Spec.Volumes)
	}
	if got := containerNames(pod.Spec.InitContainers); !slices.Equal(got, []string{reservedMeshContainerName, reservedCertContainerName, reservedCertWaitContainerName}) {
		t.Fatalf("init containers = %v, want the endpoint, get-cert and the credential-wait gate", got)
	}
	cert := *containerNamed(pod, reservedCertContainerName)
	for _, want := range []string{
		"--cert-path=/etc/c8s/certs/tls.crt",
		"--key-path=/etc/c8s/certs/tls.key",
		"--ca-path=/etc/c8s/certs/ca.crt",
		"--renew-interval=1h0m0s",
		"--discovery-out=/discovery/discovery.json",
		"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
		"--discovery-public-tls-mode=webpki",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
		"--verbose",
	} {
		if !hasArg(cert.Args, want) {
			t.Fatalf("c8s-cert args %v missing %s", cert.Args, want)
		}
	}
	if !hasMount(cert.VolumeMounts, certVolumeName, certDir, false) {
		t.Fatalf("c8s-cert mounts %v missing the writable cert volume", cert.VolumeMounts)
	}
	if !hasMount(cert.VolumeMounts, "discovery", "/discovery", false) {
		t.Fatalf("c8s-cert mounts %v missing writable discovery", cert.VolumeMounts)
	}
}

func TestMutatePodStampsWorkloadLabel(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage: "ghcr.io/confidential-dot-ai/c8s-operator:test",
	})

	if got := pod.Labels[LabelWorkload]; got != "api" {
		t.Fatalf("label %s = %q, want %q", LabelWorkload, got, "api")
	}
}

func TestParseAnnotationsRejectsWorkloadIDInvalidAsLabelValue(t *testing.T) {
	for _, id := range []string{
		"has spaces",
		"-leading-dash",
		"waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay-too-long-for-a-label-value",
	} {
		_, err := parseAnnotations(&corev1.Pod{
			Annotations: map[string]string{
				AnnotationWorkload: id,
			},
		}, "")
		if !errors.Is(err, errInvalidInjectionAnnotation) {
			t.Fatalf("parseAnnotations(%q) error = %v, want invalid annotation", id, err)
		}
	}
}

func TestValidateWorkloadLabelRequiresMatchingAnnotation(t *testing.T) {
	cases := []struct {
		name    string
		labels  map[string]string
		ann     map[string]string
		wantErr bool
	}{
		{"no label", nil, map[string]string{AnnotationWorkload: "api"}, false},
		{"label matches annotation", map[string]string{LabelWorkload: "api"}, map[string]string{AnnotationWorkload: "api"}, false},
		{"label without annotation", map[string]string{LabelWorkload: "api"}, nil, true},
		{"label differs from annotation", map[string]string{LabelWorkload: "other"}, map[string]string{AnnotationWorkload: "api"}, true},
	}
	for _, tc := range cases {
		err := validateWorkloadLabel(&corev1.Pod{
			Labels: tc.labels, Annotations: tc.ann,
		})
		if tc.wantErr && !errors.Is(err, errInvalidInjectionAnnotation) {
			t.Fatalf("%s: err = %v, want invalid annotation", tc.name, err)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%s: err = %v, want nil", tc.name, err)
		}
	}
}

func TestParseAnnotationsRejectsInvalidRenewInterval(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		Annotations: map[string]string{
			AnnotationWorkload:      "api",
			AnnotationRenewInterval: "not-a-duration",
		},
	}, "")
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestParseAnnotationsRejectsInjectionDetailsWithoutWorkloadAnnotation(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		Annotations: map[string]string{
			AnnotationRenewInterval: "1h",
		},
	}, "")
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestParseAnnotationsRejectsIncompleteDiscovery(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		Annotations: map[string]string{
			AnnotationWorkload:            "api",
			AnnotationDiscoveryCDSCertURL: "/.well-known/cds-cert.pem",
		},
	}, "")
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestParseAnnotationsRejectsInvalidDiscoveryPublicTLSMode(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		Annotations: map[string]string{
			AnnotationWorkload:               "api",
			AnnotationDiscoveryVolume:        "discovery",
			AnnotationDiscoveryMountPath:     "/discovery",
			AnnotationDiscoveryOut:           "/discovery/discovery.json",
			AnnotationDiscoveryCDSCertURL:    "/.well-known/cds-cert.pem",
			AnnotationDiscoveryPublicTLSMode: "invalid",
		},
	}, "")
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func hasArg(args []string, want string) bool {
	return slices.Contains(args, want)
}

func hasMount(mounts []corev1.VolumeMount, name, path string, readOnly bool) bool {
	for _, mount := range mounts {
		if mount.Name == name && mount.MountPath == path && mount.ReadOnly == readOnly {
			return true
		}
	}
	return false
}

func TestWorkloadSAN(t *testing.T) {
	cases := []struct {
		name      string
		cwID      string
		namespace string
		want      string
	}{
		{"bare id gets managed service dns name", "api", "default", "c8s-api.default.svc"},
		{"dotted id passes through", "c8s-router.c8s-system.svc", "c8s-system", "c8s-router.c8s-system.svc"},
		{"empty namespace falls back to id", "api", "", "api"},
		{"id too long for a service name passes through", strings.Repeat("a", 60), "default", strings.Repeat("a", 60)},
		{"empty id stays empty", "", "default", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := workloadSAN(tc.cwID, tc.namespace); got != tc.want {
				t.Fatalf("workloadSAN(%q, %q) = %q, want %q", tc.cwID, tc.namespace, got, tc.want)
			}
		})
	}
}

// TestHandleDerivesServiceSAN proves the request namespace, not the pod
// object's (empty for template-created pods), feeds the injected --san.
func TestHandleDerivesServiceSAN(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
			MeshImage:         testMeshImage,
			AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
		},
	}
	pod := &corev1.Pod{
		Annotations: map[string]string{AnnotationWorkload: "api"},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		Namespace: "default",
		Object:    runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied: %v", resp.Result)
	}

	initContainers := initContainersPatch(t, resp)
	if len(initContainers) != 3 {
		t.Fatalf("initContainers patch = %d containers, want the endpoint, get-cert and the gate", len(initContainers))
	}
	cert := initContainers[1]
	if !hasArg(cert.Args, "--san=c8s-api.default.svc") {
		t.Fatalf("%s args %v missing --san=c8s-api.default.svc", cert.Name, cert.Args)
	}
}

// TestHandleRejectsCWHostNetwork proves a cw-annotated hostNetwork pod is
// denied: it shares the node IP so it cannot be mesh-intercepted or covered by
// the cw inbound guard, and must not onboard silently unprotected.
func TestHandleRejectsCWHostNetwork(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage: "ghcr.io/confidential-dot-ai/c8s-operator:test",
			MeshImage:    testMeshImage,
		},
	}
	pod := &corev1.Pod{
		Annotations: map[string]string{AnnotationWorkload: "api"},
		Spec:        corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		Namespace: "default",
		Object:    runtime.RawExtension{Raw: raw},
	})
	if resp.Allowed {
		t.Fatal("Handle admitted a cw hostNetwork pod; want denial")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "hostNetwork") {
		t.Fatalf("denial message = %+v, want it to mention hostNetwork", resp.Result)
	}
}

// A hostNetwork pod WITHOUT the cw annotation is untouched: the guardrail is
// scoped to opted-in workloads, not every hostNetwork pod on the cluster.
func TestHandleAllowsPlainHostNetwork(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{decoder: admission.NewDecoder(scheme), cfg: Config{}.withDefaults()}
	pod := &corev1.Pod{Spec: corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "app"}}}}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		Namespace: "default", Object: runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied a plain hostNetwork pod: %v", resp.Result)
	}
}

// initContainersPatch decodes the /spec/initContainers patch op from an
// admission response into typed containers.
func initContainersPatch(t *testing.T, resp admission.Response) []corev1.Container {
	t.Helper()
	var initContainers []corev1.Container
	for _, op := range resp.Patches {
		if op.Path != "/spec/initContainers" {
			continue
		}
		value, err := json.Marshal(op.Value)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(value, &initContainers); err != nil {
			t.Fatal(err)
		}
	}
	return initContainers
}

func TestParseAnnotationsSANOverride(t *testing.T) {
	pod := &corev1.Pod{Annotations: map[string]string{
		AnnotationWorkload: "api",
		AnnotationSAN:      "api.default.svc",
	}}
	inj, err := parseAnnotations(pod, "")
	if err != nil {
		t.Fatalf("parseAnnotations: %v", err)
	}
	if inj.SAN != "api.default.svc" {
		t.Fatalf("SAN = %q, want api.default.svc", inj.SAN)
	}

	pod.Annotations[AnnotationSAN] = "https://api.default.svc"
	if _, err := parseAnnotations(pod, ""); !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestHandleSANOverrideWinsOverDerivation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
			MeshImage:         testMeshImage,
			AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
		},
	}
	pod := &corev1.Pod{
		Annotations: map[string]string{
			AnnotationWorkload: "api",
			AnnotationSAN:      "api.default.svc",
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		Namespace: "default",
		Object:    runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied: %v", resp.Result)
	}
	initContainers := initContainersPatch(t, resp)
	if len(initContainers) != 3 {
		t.Fatalf("initContainers patch = %d containers, want the endpoint, get-cert and the gate", len(initContainers))
	}
	if cert := initContainers[1]; !hasArg(cert.Args, "--san=api.default.svc") {
		t.Fatalf("%s args %v missing --san=api.default.svc", cert.Name, cert.Args)
	}
}

// TestMutatePodReplacesPreexistingCertContainer proves injection is by
// reconstruction: a pod that pre-declares its own c8s-cert init container to
// shed the real one does not win — the operator-built sidecar replaces the
// decoy rather than being skipped.
func TestMutatePodReplacesPreexistingCertContainer(t *testing.T) {
	decoy := int64(0)
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:            "c8s-cert",
				Image:           "attacker/pause:latest",
				Command:         []string{"sleep", "infinity"},
				SecurityContext: &corev1.SecurityContext{RunAsUser: &decoy},
			}},
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{
		WorkloadID: "api",
		SAN:        "api",
	}, Config{
		GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
		MeshImage:         testMeshImage,
		AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
	})

	certs := 0
	for _, c := range pod.Spec.InitContainers {
		if c.Name == "c8s-cert" {
			certs++
		}
	}
	if certs != 1 {
		t.Fatalf("c8s-cert init containers = %d, want exactly 1 (real sidecar replaces the decoy)", certs)
	}
	got := *containerNamed(pod, reservedCertContainerName)
	if pod.Spec.InitContainers[0].Name != reservedMeshContainerName {
		t.Fatalf("init[0] = %q, want the endpoint leading the list", pod.Spec.InitContainers[0].Name)
	}
	if got.Image != "ghcr.io/confidential-dot-ai/c8s-operator:test" {
		t.Fatalf("c8s-cert image = %q, want the operator get-cert image (decoy survived)", got.Image)
	}
	if !hasArg(got.Args, "--renew-interval=2h0m0s") {
		t.Fatalf("c8s-cert args %v are not operator-built (decoy survived)", got.Args)
	}
	if got.RestartPolicy == nil || *got.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("c8s-cert restartPolicy = %#v, want Always", got.RestartPolicy)
	}
}

// TestMutatePodInjectionIsIdempotent proves a reinvocation (mutatePod applied
// twice, as reinvocationPolicy: IfNeeded can trigger) converges: one sidecar,
// one cert volume, one mount per container.
func TestMutatePodInjectionIsIdempotent(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	cfg := Config{
		GetCertImage:      "img",
		MeshImage:         testMeshImage,
		AttestationApiURL: "http://attestation-api",
	}
	mutatePod(pod, &injection{WorkloadID: "api"}, cfg)
	mutatePod(pod, &injection{WorkloadID: "api"}, cfg)

	if got := len(pod.Spec.InitContainers); got != 3 {
		t.Fatalf("init containers = %d after two injections, want the three platform containers, deduped", got)
	}
	volumes := 0
	for _, v := range pod.Spec.Volumes {
		if v.Name == "c8s-certs" {
			volumes++
		}
	}
	if volumes != 1 {
		t.Fatalf("c8s-certs volumes = %d after two injections, want 1", volumes)
	}
	for _, c := range pod.Spec.InitContainers {
		mounts := 0
		for _, mnt := range c.VolumeMounts {
			if mnt.Name == "c8s-certs" {
				mounts++
			}
		}
		if mounts != 1 {
			t.Fatalf("platform container %s c8s-certs mounts = %d, want 1", c.Name, mounts)
		}
	}
}

// TestHandleRejectsReservedCertContainerName proves an opted-in pod cannot park
// its own container under the reserved c8s-cert name (in the regular list) to
// shadow the injected sidecar — the collision is rejected at admission.
func TestHandleRejectsReservedCertContainerName(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage: "ghcr.io/confidential-dot-ai/c8s-operator:test",
			MeshImage:    testMeshImage,
		},
	}
	pod := &corev1.Pod{
		Annotations: map[string]string{AnnotationWorkload: "api"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app"},
			{Name: "c8s-cert", Image: "attacker/pause"},
		}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		Namespace: "default", Object: runtime.RawExtension{Raw: raw},
	})
	if resp.Allowed {
		t.Fatal("Handle admitted a cw pod with a reserved c8s-cert container; want denial")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "reserved") {
		t.Fatalf("denial message = %+v, want it to mention the reserved name", resp.Result)
	}
}

func TestHandleRejectsReservedCertVolumeCollision(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage: "ghcr.io/confidential-dot-ai/c8s-operator:test",
			MeshImage:    testMeshImage,
		},
	}
	// The default reserved cert volume name (see withDefaults / certsVolume).
	const certVol = "c8s-certs"
	hostPathType := corev1.HostPathDirectory

	handle := func(t *testing.T, vol corev1.Volume) admission.Response {
		t.Helper()
		pod := &corev1.Pod{
			Annotations: map[string]string{AnnotationWorkload: "api"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app"}},
				Volumes:    []corev1.Volume{vol},
			},
		}
		raw, err := json.Marshal(pod)
		if err != nil {
			t.Fatal(err)
		}
		return m.Handle(context.Background(), admission.Request{
			Namespace: "default", Object: runtime.RawExtension{Raw: raw},
		})
	}

	rejected := map[string]corev1.Volume{
		"hostPath": {Name: certVol, VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/tmp/leak", Type: &hostPathType}}},
		"disk-backed emptyDir": {Name: certVol, VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{}}}, // Medium "" == node disk
	}
	for name, vol := range rejected {
		t.Run("rejects "+name, func(t *testing.T) {
			resp := handle(t, vol)
			if resp.Allowed {
				t.Fatalf("Handle admitted a cw pod whose reserved cert volume is %s; want denial", name)
			}
			if resp.Result == nil || !strings.Contains(resp.Result.Message, "reserved") {
				t.Fatalf("denial message = %+v, want it to mention the reserved volume", resp.Result)
			}
		})
	}

	t.Run("accepts memory emptyDir", func(t *testing.T) {
		resp := handle(t, corev1.Volume{Name: certVol,
			EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}})
		if !resp.Allowed {
			t.Fatalf("Handle denied a cw pod with a correct memory-backed cert volume: %+v", resp.Result)
		}
	})
}

// TestHandleInjectsDespitePresetInjectedMarker proves the
// confidential.ai/c8s-injected marker no longer suppresses injection: a pod
// that presets it (with no real sidecar) is still given the c8s-cert sidecar,
// so the marker cannot be used to skip attestation-bound injection.
func TestHandleInjectsDespitePresetInjectedMarker(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
			MeshImage:         testMeshImage,
			AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
		},
	}
	pod := &corev1.Pod{
		Annotations: map[string]string{
			AnnotationWorkload: "api",
			AnnotationInjected: "true",
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		Namespace: "default", Object: runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied: %v", resp.Result)
	}
	inits := containerNames(initContainersPatch(t, resp))
	want := []string{reservedMeshContainerName, reservedCertContainerName, reservedCertWaitContainerName}
	if !slices.Equal(inits, want) {
		t.Fatalf("initContainers patch = %v, want %v despite the preset marker", inits, want)
	}
}

// runtimeClassPatch returns the value of the /spec/runtimeClassName patch op,
// or "" when the response carries none.
func runtimeClassPatch(t *testing.T, resp admission.Response) string {
	t.Helper()
	for _, op := range resp.Patches {
		if op.Path != "/spec/runtimeClassName" {
			continue
		}
		value, ok := op.Value.(string)
		if !ok {
			t.Fatalf("runtimeClassName patch value = %#v, want a string", op.Value)
		}
		return value
	}
	return ""
}

// Get-cert injection must not touch runtimeClassName.
func TestHandleGetCertOnlyLeavesRuntimeClassUnset(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage: "ghcr.io/confidential-dot-ai/c8s-operator:test",
			MeshImage:    testMeshImage,
		}.withDefaults(),
	}
	pod := &corev1.Pod{
		Annotations: map[string]string{AnnotationWorkload: "api"},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		Namespace: "default", Object: runtime.RawExtension{Raw: raw},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied: %v", resp.Result)
	}
	if len(initContainersPatch(t, resp)) != 3 {
		t.Fatal("expected the platform containers to be injected")
	}
	if got := runtimeClassPatch(t, resp); got != "" {
		t.Fatalf("runtimeClassName patch = %q, want none", got)
	}
}

func TestWorkloadServiceFQDN(t *testing.T) {
	tests := []struct {
		name, cwID, namespace, want string
	}{
		{"nameable id", "api", "default", "c8s-api.default.svc.cluster.local"},
		{"unnameable id", "api.v1", "default", ""},
		{"empty namespace", "api", "", ""},
		{"empty id", "", "default", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := WorkloadServiceFQDN(tc.cwID, tc.namespace); got != tc.want {
				t.Fatalf("WorkloadServiceFQDN(%q, %q) = %q, want %q", tc.cwID, tc.namespace, got, tc.want)
			}
		})
	}
}

// fsGroup 0 (root group) is a valid configuration and must still be applied;
// only negative values disable the mutation.
func TestMutatePodAppliesZeroFSGroup(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage: "image",
		CertFSGroup:  ptr.To[int64](0),
	})
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil {
		t.Fatal("fsGroup 0 was not applied")
	}
	if got := *pod.Spec.SecurityContext.FSGroup; got != 0 {
		t.Fatalf("fsGroup = %d, want 0", got)
	}
}

func TestMutatePodInitializesNilAnnotationsAndLabels(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{GetCertImage: "image"})
	if pod.Annotations[AnnotationInjected] != "true" {
		t.Fatalf("annotations = %v, want the injected marker stamped", pod.Annotations)
	}
	if pod.Labels[LabelWorkload] != "api" {
		t.Fatalf("labels = %v, want the cw label stamped", pod.Labels)
	}
}

func TestConfigWithDefaultsPreservesExplicitValues(t *testing.T) {
	def := Config{}.withDefaults()
	// Pinned against the constant, not a literal: the default must stay
	// strictly below issuer.MaxNamedLeafTTL so a named leaf always has a
	// renewal attempt left before it expires.
	if def.CertRenewInterval != defaultCertRenewInterval {
		t.Fatalf("default CertRenewInterval = %v, want %v", def.CertRenewInterval, defaultCertRenewInterval)
	}
	if def.CertRenewInterval >= issuer.MaxNamedLeafTTL {
		t.Fatalf("default CertRenewInterval %v must stay below issuer.MaxNamedLeafTTL %v",
			def.CertRenewInterval, issuer.MaxNamedLeafTTL)
	}
}

func TestEnsureSupplementalGroup(t *testing.T) {
	const gid int64 = 4242
	tests := []struct {
		name     string
		existing *corev1.PodSecurityContext
		want     []int64
	}{
		{"nil security context", nil, []int64{gid}},
		{"other groups kept", &corev1.PodSecurityContext{SupplementalGroups: []int64{7}}, []int64{7, gid}},
		{"already present is idempotent", &corev1.PodSecurityContext{SupplementalGroups: []int64{gid}}, []int64{gid}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{Spec: corev1.PodSpec{SecurityContext: tc.existing}}
			ensureSupplementalGroup(pod, gid)
			got := pod.Spec.SecurityContext.SupplementalGroups
			if len(got) != len(tc.want) {
				t.Fatalf("supplementalGroups = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("supplementalGroups = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// ensureSupplementalGroup must not replace an existing pod security context;
// mutatePod sets fsGroup first and the broker-socket group is added alongside.
func TestMutatePodKeepsFSGroupWithWorkloadClaims(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "image",
		WorkloadClaimsHostDir: "/run/c8s/workload-claims",
	})
	sc := pod.Spec.SecurityContext
	if sc == nil || sc.FSGroup == nil || *sc.FSGroup != defaultCertFSGroup {
		t.Fatalf("securityContext = %#v, want fsGroup %d kept", sc, defaultCertFSGroup)
	}
	if len(sc.SupplementalGroups) != 1 {
		t.Fatalf("supplementalGroups = %v, want the broker socket group added", sc.SupplementalGroups)
	}
}

// The wait gate's timeout must comfortably exceed get-cert's initial retry so
// a slow CDS cold start is absorbed in one wait.
func TestCertWaitContainerTimeout(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage: "image",
		MeshImage:    testMeshImage,
	})
	wait := *containerNamed(pod, reservedCertWaitContainerName)
	if !hasArg(wait.Command, "--timeout=3m0s") {
		t.Fatalf("c8s-cert-wait command %v missing --timeout=3m0s", wait.Command)
	}
}

// No injected client takes a pin as an argument: it reads the node's CDS
// policy from the path the enforcer mounts, which neither the pod nor the
// control plane can choose.
func TestInjectedClientsCarryNoCDSPins(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/var/run/nri-image-policy"
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
		Volumes:    volumesSpec{Specs: []string{"weights=/tenant-a/volumes/weights"}},
	}, cfg)

	for _, name := range []string{reservedCertContainerName, reservedSecretContainerName, reservedVolumeContainerName} {
		for _, arg := range containerNamed(pod, name).Args {
			for _, pin := range []string{"--cds-measurements", "--cds-rtmrs", "--measurements", "--rtmrs", "--image-policy"} {
				if strings.HasPrefix(arg, pin) {
					t.Errorf("%s carries %q; pins come from the node policy mount", name, arg)
				}
			}
		}
	}
}

// A node serving the inventory socket directory serves its own attestation-api
// in it, and a client reading that node's CDS pins may answer to no other
// verifier (cmdsutil.RequireNodeVerifier), so every operator endpoint renders
// as the sidecar's mount of that socket. Without an inventory directory the
// operator's endpoint stands.
func TestSidecarAttestationApiURLRebase(t *testing.T) {
	const hostDir = "/var/run/nri-image-policy"
	for _, tc := range []struct {
		name    string
		hostDir string
		url     string
		want    string
	}{
		{"socket rebased onto the sidecar mount", hostDir,
			"unix://" + hostDir + "/attestation-api.sock",
			"unix://" + workloadclaims.AttestationAPISocket},
		{"http endpoint renders the node socket", hostDir,
			"http://attestation-api.c8s-system.svc:8400",
			"unix://" + workloadclaims.AttestationAPISocket},
		{"host-IP endpoint renders the node socket", hostDir,
			"http://$(HOST_IP):8400",
			"unix://" + workloadclaims.AttestationAPISocket},
		{"socket outside the inventory dir renders the node socket", hostDir,
			"unix:///elsewhere/attest.sock",
			"unix://" + workloadclaims.AttestationAPISocket},
		{"no inventory mount leaves the URL alone", "",
			"http://attestation-api.c8s-system.svc:8400",
			"http://attestation-api.c8s-system.svc:8400"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := secretsConfig()
			cfg.WorkloadClaimsHostDir = tc.hostDir
			cfg.AttestationApiURL = tc.url
			if got := cfg.sidecarAttestationApiURL(); got != tc.want {
				t.Fatalf("sidecarAttestationApiURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The rebased endpoint must be what the injected containers actually receive.
func TestCertContainerGetsRebasedAttestationURL(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/var/run/nri-image-policy"
	cfg.AttestationApiURL = "unix:///var/run/nri-image-policy/attestation-api.sock"
	pod := podWithApp()
	mutatePod(pod, &injection{WorkloadID: "api"}, cfg)

	want := "--attestation-api-url=unix://" + workloadclaims.SidecarSocketDir + "/attestation-api.sock"
	if args := containerNamed(pod, reservedCertContainerName).Args; !hasArg(args, want) {
		t.Fatalf("c8s-cert args %v missing %q", args, want)
	}
}

// The cluster shape the chart renders where the node's attestation-api is not
// the chart's own (cvmMode=bare-metal, http://$(HOST_IP):8400): the injected
// fetchers still verify CDS through the node's socket, which is what a client
// reading the node's CDS pins must name.
func TestFetchersTakeTheNodeSocketOverAnHTTPEndpoint(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/var/run/nri-image-policy"
	cfg.AttestationApiURL = "http://$(HOST_IP):8400"
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
		Volumes:    volumesSpec{Specs: []string{"weights=/tenant-a/volumes/weights"}},
	}, cfg)

	want := "--attestation-api-url=unix://" + workloadclaims.AttestationAPISocket
	for _, name := range []string{reservedCertContainerName, reservedSecretContainerName, reservedVolumeContainerName} {
		args := containerNamed(pod, name).Args
		if !hasArg(args, want) {
			t.Errorf("%s args %v missing %q", name, args, want)
		}
	}
}

// Every injected fetcher (cert, secret, volume) must carry the rebased socket
// URL, be named so the inventory's NRI plugin mounts the socket directory into
// it (workloadclaims.IsSidecarContainer), and declare no pod-spec mount of its
// own at that path — the pod spec stays free of hostPath so PodSecurity
// restricted admits it.
func TestFetchersCarryRebasedURLAsNRIMountTargets(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/var/run/nri-image-policy"
	cfg.AttestationApiURL = "unix:///var/run/nri-image-policy/attestation-api.sock"
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
		Volumes:    volumesSpec{Specs: []string{"weights=/tenant-a/volumes/weights"}},
	}, cfg)

	// The mount contract is split across components: the webhook emits the
	// rebased URL, the inventory's NRI plugin mounts the directory into the
	// containers matching its published predicate. So the set of containers
	// carrying the rebased URL must equal the predicate's match set exactly,
	// and the pod must carry the annotation the plugin keys on.
	want := "--attestation-api-url=unix://" + workloadclaims.SidecarSocketDir + "/attestation-api.sock"
	carrying := map[string]bool{}
	for _, c := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		if hasArg(c.Args, want) {
			carrying[c.Name] = true
		}
		if workloadclaims.IsSidecarContainer(c.Name) != carrying[c.Name] {
			t.Errorf("container %q: carries rebased URL %v but IsSidecarContainer %v; the NRI mount would miss or overshoot", c.Name, carrying[c.Name], workloadclaims.IsSidecarContainer(c.Name))
		}
		if slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool {
			return m.MountPath == workloadclaims.SidecarSocketDir
		}) {
			t.Errorf("%s declares a pod-spec mount at %s; the socket directory arrives by NRI mount only, mounts %+v", c.Name, workloadclaims.SidecarSocketDir, c.VolumeMounts)
		}
	}
	for _, name := range []string{reservedCertContainerName, reservedSecretContainerName, reservedVolumeContainerName} {
		if !carrying[name] {
			t.Errorf("injected pod missing fetcher %q with the rebased URL", name)
		}
	}
	if pod.Annotations[workloadclaims.AnnotationInjected] != "true" {
		t.Errorf("pod annotation %s = %q; the NRI plugin mounts only under it", workloadclaims.AnnotationInjected, pod.Annotations[workloadclaims.AnnotationInjected])
	}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			t.Errorf("mutated pod declares hostPath volume %q; PodSecurity baseline and restricted reject it", v.Name)
		}
	}
}

// Every pod is in scope now, so one that pre-sets the injected marker and
// names a platform container itself is refused rather than passed through: the
// name is the injector's, and the marker is scoping, not a security boundary.
func TestHandleRefusesAForgedPlatformContainer(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		Annotations: map[string]string{AnnotationInjected: "true"},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: reservedCertContainerName}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg:     secretsConfig().withDefaults(),
	}

	resp := m.Handle(context.Background(), admission.Request{
		Namespace: "default", Object: runtime.RawExtension{Raw: raw},
	})

	if resp.Allowed {
		t.Fatal("a pod naming a platform container was admitted")
	}
	if !strings.Contains(resp.Result.Message, "reserved") {
		t.Fatalf("denial = %+v, want it to name the reserved container", resp.Result)
	}
}

// evaluateRestricted runs the same checks the PodSecurity admission plugin
// enforces at restricted/latest.
func evaluateRestricted(t *testing.T, pod *corev1.Pod) psapolicy.AggregateCheckResult {
	t.Helper()
	evaluator, err := psapolicy.NewEvaluator(psapolicy.DefaultChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return psapolicy.AggregateCheckResults(evaluator.EvaluatePod(
		psaapi.LevelVersion{Level: psaapi.LevelRestricted, Version: psaapi.LatestVersion()},
		&pod.ObjectMeta, &pod.Spec))
}

// The acceptance bar for hardened clusters: a restricted-compliant cw pod must
// STAY restricted-admissible after the full node-CVM mutation (cert, wait,
// secret and volume fetchers). The socket directory reaches the
// sidecars by NRI mount, so nothing the webhook adds may name a hostPath.
// Default injection shape only: a pod overriding c8s-get-cert-run-as-* to root
// fails restricted by its own choice.
func TestMutatePodStaysRestrictedAdmissible(t *testing.T) {
	pod := &corev1.Pod{
		Annotations: map[string]string{AnnotationWorkload: "api"},
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
	// Guard against a vacuous pass: the input fixture itself must be
	// restricted-admissible, and the evaluator must actually reject the old
	// injected shape (a hostPath claims volume).
	if agg := evaluateRestricted(t, pod); !agg.Allowed {
		t.Fatalf("input fixture violates PodSecurity restricted before mutation: %s: %s", agg.ForbiddenReason(), agg.ForbiddenDetail())
	}
	legacy := pod.DeepCopy()
	hpType := corev1.HostPathDirectory
	legacy.Spec.Volumes = append(legacy.Spec.Volumes, corev1.Volume{
		Name:     "c8s-workload-claims",
		HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/nri-image-policy", Type: &hpType},
	})
	if agg := evaluateRestricted(t, legacy); agg.Allowed {
		t.Fatal("evaluator admitted a hostPath claims volume; the control proves nothing")
	}

	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/var/run/nri-image-policy"
	cfg.AttestationApiURL = "unix:///var/run/nri-image-policy/attestation-api.sock"
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
		Volumes:    volumesSpec{Specs: []string{"weights=/tenant-a/volumes/weights"}},
	}, cfg)

	if agg := evaluateRestricted(t, pod); !agg.Allowed {
		t.Fatalf("mutated cw pod violates PodSecurity restricted: %s: %s", agg.ForbiddenReason(), agg.ForbiddenDetail())
	}
}

// The set of containers injection adds must equal what
// workloadclaims.IsInjectedContainerName matches: `c8s allowlist derive` drops
// exactly that set from an admitted pod, so a sixth injected container added
// here without the predicate learning its name would be silently derived into
// every workload entry.
func TestInjectedContainersMatchThePublishedNameSet(t *testing.T) {
	cfg := secretsConfig()
	pod := podWithApp()
	pod.Spec.InitContainers = []corev1.Container{{Name: "seed"}}
	authored := map[string]bool{"app": true, "seed": true}
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
		Volumes:    volumesSpec{Specs: []string{"weights=/tenant-a/volumes/weights"}},
	}, cfg)

	all := append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	if len(all) != len(authored)+5 {
		t.Fatalf("containers = %d, want the 2 authored plus 5 injected: %v", len(all), containerNames(all))
	}
	for _, c := range all {
		if workloadclaims.IsInjectedContainerName(c.Name) == authored[c.Name] {
			t.Errorf("container %q: authored %v but IsInjectedContainerName %v; derive would drop the wrong set",
				c.Name, authored[c.Name], workloadclaims.IsInjectedContainerName(c.Name))
		}
	}
}

// A pod the webhook selected no SAN for asks for none explicitly, and every
// injected sidecar watches the CDS mesh CA, so a CA renewal or replacement is
// seen inside the renewal interval.
func TestCertContainerSANAndCAWatchArgs(t *testing.T) {
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		SAN:        "api",
	}, secretsConfig())
	args := containerNamed(pod, reservedCertContainerName).Args
	if !hasArg(args, "--san=api") {
		t.Fatalf("c8s-cert args %v missing the selected SAN", args)
	}
	if !hasArg(args, "--ca-watch-interval="+caWatchInterval.String()) {
		t.Fatalf("c8s-cert args %v missing the CA watch interval", args)
	}

	sanless := podWithApp()
	mutatePod(sanless, &injection{WorkloadID: ""}, secretsConfig())
	args = containerNamed(sanless, reservedCertContainerName).Args
	if !hasArg(args, "--no-san") {
		t.Fatalf("c8s-cert args %v must ask for no SAN explicitly", args)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--san") {
			t.Fatalf("c8s-cert carries %q beside --no-san", arg)
		}
	}
}
