package webhook

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func newInjectablePod() *corev1.Pod {
	return &corev1.Pod{
		Annotations: map[string]string{},
		Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
}

func findVolume(pod *corev1.Pod, name string) *corev1.Volume {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == name {
			return &pod.Spec.Volumes[i]
		}
	}
	return nil
}

// node-CVM (inventory + host dir): get-cert dials its compiled socket path and
// the socket directory arrives as an NRI mount from the inventory plugin, so
// the pod spec must carry no volume or mount for it (a hostPath would fail
// PodSecurity restricted).
func TestWorkloadClaims_NodeCVMLeavesMountToNRI(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "img",
		AttestationApiURL:     "http://as:8400",
		WorkloadClaimsHostDir: "/var/run/nri-image-policy",
	})

	cert := pod.Spec.InitContainers[0]
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			t.Fatalf("mutated pod declares hostPath volume %q", v.Name)
		}
	}
	for _, m := range cert.VolumeMounts {
		if m.MountPath == workloadclaims.SidecarSocketDir {
			t.Fatalf("c8s-cert declares a pod-spec mount at %s; it arrives by NRI mount only", workloadclaims.SidecarSocketDir)
		}
	}
}

// The webhook passes the pod's own init-container names so get-cert can split
// / get-cert no longer classifies containers by role — CDS resolves a sandbox's
// images from the inventory — so the webhook must not pass per-init-container
// names it would reject as an unknown flag.
func TestWorkloadClaims_PassesNoInitContainerNames(t *testing.T) {
	pod := newInjectablePod()
	pod.Spec.InitContainers = []corev1.Container{{Name: "setup"}, {Name: "migrate"}}
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "img",
		AttestationApiURL:     "http://as:8400",
		WorkloadClaimsHostDir: "/var/run/nri-image-policy",
	})
	cert := pod.Spec.InitContainers[0]
	if cert.Name != "c8s-cert" {
		t.Fatalf("c8s-cert not first: %q", cert.Name)
	}
	for _, arg := range cert.Args {
		if strings.HasPrefix(arg, "--workload-init-container") {
			t.Fatalf("webhook still passes a flag get-cert does not define: %v", cert.Args)
		}
	}
}

// No host dir: the webhook injects neither a volume nor the socket group, so
// nothing in the pod spec claims to reach an inventory.
func TestWorkloadClaims_NoHostDirNoInventory(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "img",
		AttestationApiURL: "http://as:8400",
	})
	if findVolume(pod, "c8s-workload-claims") != nil {
		t.Fatal("no inventory volume expected when disabled")
	}
	if pod.Spec.SecurityContext != nil {
		for _, g := range pod.Spec.SecurityContext.SupplementalGroups {
			if g == workloadclaims.InventorySocketGID {
				t.Fatal("inventory supplemental group injected without an inventory host dir")
			}
		}
	}
}

// The inventory socket is group-owned (InventorySocketGID); the non-root sidecar can
// only reach it if the pod carries that supplemental group. Without it, connect
// fails closed and the pod hangs on its initial cert.
func TestWorkloadClaims_InjectsInventorySupplementalGroup(t *testing.T) {
	pod := newInjectablePod()
	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "img",
		AttestationApiURL:     "http://as:8400",
		WorkloadClaimsHostDir: "/var/run/nri-image-policy",
	})
	if pod.Spec.SecurityContext == nil {
		t.Fatal("pod securityContext not set")
	}
	found := false
	for _, g := range pod.Spec.SecurityContext.SupplementalGroups {
		if g == workloadclaims.InventorySocketGID {
			found = true
		}
	}
	if !found {
		t.Fatalf("pod missing inventory supplemental group %d: %v", workloadclaims.InventorySocketGID, pod.Spec.SecurityContext.SupplementalGroups)
	}
}
