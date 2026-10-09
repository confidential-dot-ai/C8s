package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// A pod that declares its own mount of the secrets volume with readOnly
// omitted (defaulting to false) keeps the mount path and loses the write bit:
// the fetcher is the only writer of that directory. The credential volume is
// not in this list — no workload container may mount it at all
// (rejectCredentialMounts).
func TestPreDeclaredSecretsMountIsForcedReadOnly(t *testing.T) {
	pod := podWithApp()
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
		Name:      secretsVolumeName,
		MountPath: "/attacker/chosen/path",
	}}
	pod.Spec.Volumes = []corev1.Volume{{
		Name:     secretsVolumeName,
		EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
	}}

	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")

	m := containerMount(&pod.Spec.Containers[0], secretsVolumeName)
	if m == nil {
		t.Fatalf("workload container lost its %q mount", secretsVolumeName)
	}
	if !m.ReadOnly {
		t.Fatalf("pre-declared %q mount stayed writable: %+v", secretsVolumeName, *m)
	}
	if m.MountPath != "/attacker/chosen/path" {
		t.Fatalf("MountPath = %q, want the pod's own path", m.MountPath)
	}
}

// The fetcher is the one container that must keep write access. It is appended
// after mountAll runs and rebuilt by injectInitContainers on every call, so a
// reinvocation over an already-injected pod must not leave it read-only.
func TestFetcherKeepsWriteAccessAcrossReinvocation(t *testing.T) {
	pod := podWithApp()
	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")
	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")

	fetcher := containerNamed(pod, reservedSecretContainerName)
	if fetcher == nil {
		t.Fatal("fetcher not injected")
	}
	m := containerMount(fetcher, secretsVolumeName)
	if m == nil {
		t.Fatal("fetcher lost its secrets mount")
	}
	if m.ReadOnly {
		t.Fatal("fetcher's secrets mount went read-only; it could no longer write released values")
	}

	// The workload's mount stays read-only across the same reinvocation.
	if wm := containerMount(&pod.Spec.Containers[0], secretsVolumeName); wm == nil || !wm.ReadOnly {
		t.Fatalf("workload secrets mount = %+v, want a read-only mount", wm)
	}
}

// An ephemeral container is attached to a running pod, so it is the one way
// into the volumes the injected sidecars hold.
func TestEphemeralGuardCoversInjectedVolumes(t *testing.T) {
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
	}, secretsConfig())

	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		Name:         "debugger",
		VolumeMounts: []corev1.VolumeMount{{Name: certVolumeName, MountPath: "/x"}},
	}}

	if err := rejectEphemeralReach(pod); err == nil {
		t.Fatal("an ephemeral container mounted the volume holding the leaf key")
	}

	// The secrets volume has a fixed name, so it is reserved either way.
	pod.Spec.EphemeralContainers[0].VolumeMounts = []corev1.VolumeMount{{Name: secretsVolumeName, MountPath: "/x"}}
	if err := rejectEphemeralReach(pod); err == nil {
		t.Fatal("ephemeral container mounted the released secrets")
	}

	// A genuinely unrelated volume is still fine.
	pod.Spec.EphemeralContainers[0].VolumeMounts = []corev1.VolumeMount{{Name: "scratch", MountPath: "/x"}}
	if err := rejectEphemeralReach(pod); err != nil {
		t.Fatalf("rejected a harmless ephemeral container: %v", err)
	}
}

func TestReservedVolumeNamesCoversSidecarMounts(t *testing.T) {
	pod := podWithApp()
	pod.Spec.InitContainers = []corev1.Container{
		{Name: reservedCertContainerName, VolumeMounts: []corev1.VolumeMount{
			{Name: "my-certs"}, {Name: "sidecar-extra"},
		}},
		{Name: "user-init", VolumeMounts: []corev1.VolumeMount{{Name: "user-scratch"}}},
	}

	reserved := reservedVolumeNames(pod)
	for _, want := range []string{secretsVolumeName, certVolumeName, "my-certs", "sidecar-extra"} {
		if !reserved[want] {
			t.Errorf("%q not reserved", want)
		}
	}
	// A non-c8s init container's mounts are the pod's own business.
	if reserved["user-scratch"] {
		t.Error("a user init container's volume was reserved")
	}
}

func handleSecretsPod(t *testing.T, cfg Config) admission.Response {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		Annotations: map[string]string{
			AnnotationWorkload: "api",
			AnnotationSecrets:  "DB=/api/db",
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	m := &podMutator{decoder: admission.NewDecoder(scheme), cfg: cfg}
	return m.Handle(context.Background(), admission.Request{
		Namespace: "tenant",
		Object:    runtime.RawExtension{Raw: raw},
	})
}

// TestHandleRejectsSecretsWithoutAnyInventory covers the shape no fetcher can
// serve: no mounted socket means no inventory to redeem a sandbox token at.
// Injecting anyway produces a Running pod whose fetcher CrashLoops while the
// workload blocks forever on a file that never lands — fail at admission instead.
func TestHandleRejectsSecretsWithoutAnyInventory(t *testing.T) {
	cfg := secretsConfig() // WorkloadClaimsHostDir is unset

	resp := handleSecretsPod(t, cfg)
	if resp.Allowed {
		t.Fatal("admitted a secrets pod the fetcher could never serve")
	}
	if msg := resp.Result.Message; !strings.Contains(msg, AnnotationSecrets) {
		t.Fatalf("denial %q does not name the offending annotation", msg)
	}
}

// The same pod is admitted once the operator has the inventory socket, so the
// guard rejects only the shape that cannot work.
func TestHandleAdmitsSecretsWithInventorySocket(t *testing.T) {
	cfg := secretsConfig()
	cfg.WorkloadClaimsHostDir = "/run/c8s/nri"

	if resp := handleSecretsPod(t, cfg); !resp.Allowed {
		t.Fatalf("Handle denied a serviceable secrets pod: %v", resp.Result)
	}
}
