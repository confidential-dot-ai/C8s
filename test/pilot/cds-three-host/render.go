//go:build ignore

// Render only: run this file from the pinned cloud/operator module to reuse
// its ConfAI SDK. No Kubernetes connection, host operation or image publishing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/confidential-dot-ai/bare-metal-infra-management/pkg/confai"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

func main() {
	run := flag.String("run", "", "cds-ha- followed by 12 random hex characters")
	slot := flag.Int("slot", -1, "owned replica slot 0..2")
	variant := flag.String("variant", "", "measured image a or b")
	platform := flag.String("platform", "snp", "snp or tdx")
	node := flag.String("node", "", "approved SNP compute worker")
	uid := flag.String("node-uid", "", "independently observed Node UID")
	launch := flag.String("launch-file", "", "fixed public probe launch bytes")
	expires := flag.String("expires", "", "RFC3339 cleanup deadline, at most 90 minutes away")
	tools := flag.String("tools-image", "", "digest-pinned existing population tools image")
	flag.Parse()
	deadline, err := time.Parse(time.RFC3339, *expires)
	if err != nil || time.Until(deadline) < 5*time.Minute || time.Until(deadline) > 90*time.Minute ||
		(*platform != "snp" && *platform != "tdx") ||
		!regexp.MustCompile(`^cds-ha-[0-9a-f]{12}$`).MatchString(*run) || *platform != "tdx" || *slot < 0 || *slot > 2 || (*variant != "a" && *variant != "b") || len(validation.IsDNS1123Subdomain(*node)) != 0 || *node == "" ||
		!regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`).MatchString(*uid) ||
		!regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`).MatchString(*tools) || flag.NArg() != 0 {
		panic("explicit owned run, node/UID, pinned tools and bounded cleanup deadline required")
	}
	data, err := os.ReadFile(*launch)
	if err != nil {
		panic(err)
	}
	if err := confai.RequireLaunchFile(data); err != nil {
		panic(err)
	}
	const namespace = "p-internal"
	group := *run
	*run = group + "-g" + strconv.Itoa(*slot) + "-" + *variant
	labels := map[string]string{"cloud.confidential.ai/cds-ha-owner": group, "cloud.confidential.ai/cds-ha-component": "cds", "cloud.confidential.ai/cds-ha-slot": strconv.Itoa(*slot)}
	selector := map[string]string{"kubernetes.io/hostname": *node, "cloud.confidential.ai.node-restriction.kubernetes.io/node-uid": *uid}
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels, Annotations: map[string]string{"cds.confidential.ai/cleanup-deadline": deadline.UTC().Format(time.RFC3339)}}
	}
	claim := func(name, size string) *corev1.PersistentVolumeClaim {
		m := meta(name)
		m.Annotations["volume.kubernetes.io/selected-node"] = *node
		return &corev1.PersistentVolumeClaim{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"}, ObjectMeta: m,
			Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, StorageClassName: new("local-path"), Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)}}}}
	}
	root, boot := *run+"-root", *run+"-boot"
	spec := confai.Spec{Name: *run, Namespace: namespace, Platform: confai.PlatformSNP, HostNode: *node,
		// Pre-provisioned owned PVC mode: no invented registry provenance. Both
		// claims and the VM are pinned to the independently checked Node UID;
		// uploaded file hashes and the separate SNP measurement bind the bytes.
		Image: confai.ImageRef{RootdiskPVC: root, IGVMPVC: boot}, CPUCores: 2, MemoryGi: 4,
		BridgePodNetwork: true, NoCloudInit: true, OperatorKeyPub: data, OperatorKeyFormat: confai.OperatorKeyFormatLaunchFile,
		ServiceType: confai.ServiceTypeClusterIP, Ports: []confai.Port{{Name: "probe", Port: 6443}}, ExactServicePorts: true, Labels: labels}
	if *platform == "tdx" {
		spec.Platform = confai.PlatformTDX
		spec.Image.IGVMPVC = ""
		spec.NoVSOCK = true
	}
	objects, err := confai.Build(spec)
	if err != nil {
		panic(err)
	}
	items := []any{claim(root, "8Gi")}
	if *platform == "snp" {
		items = append(items, claim(boot, "1Gi"))
	}
	for _, obj := range objects {
		switch value := obj.(type) {
		case *kubevirtv1.VirtualMachine:
			value.Spec.Running = nil
			// Explicit starts only: a guest's expiry poweroff must stay off.
			value.Spec.RunStrategy = new(kubevirtv1.RunStrategyManual)
			for k, v := range selector {
				value.Spec.Template.Spec.NodeSelector[k] = v
			}
			if value.Annotations == nil {
				value.Annotations = map[string]string{}
			}
			value.Annotations["cds.confidential.ai/cleanup-deadline"] = *expires
			items = append(items, value)
		case *corev1.Secret:
			items = append(items, value)
		case *corev1.Service:
			// No public or cluster Service. Only the authenticated VM tunnel.
		default:
			panic(fmt.Sprintf("unexpected SDK resource %T", obj))
		}
	}
	// Upload public disk/IGVM artifacts to NEW claims with native kubectl cp.
	// Verify their hashes, then delete this exact Pod UID BEFORE starting the VM.
	// The active deadline bounds an interrupted upload; the owner journal is
	// still required to clean claims/VMs, which Kubernetes does not TTL-delete.
	populationLabels := map[string]string{}
	for k, v := range labels {
		populationLabels[k] = v
	}
	populationLabels["cloud.confidential.ai/cds-ha-component"] = "population"
	population := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta(*run + "-populate"), Spec: corev1.PodSpec{
		NodeSelector: selector, RestartPolicy: corev1.RestartPolicyNever, ActiveDeadlineSeconds: new(int64(1800)),
		AutomountServiceAccountToken: new(false), EnableServiceLinks: new(false),
		SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: new(true), RunAsUser: new(int64(107)), RunAsGroup: new(int64(107)), FSGroup: new(int64(107)), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Containers: []corev1.Container{{Name: "populate", Image: *tools, Command: []string{"sleep", "1800"},
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: new(false), ReadOnlyRootFilesystem: new(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("256Mi")}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "root", MountPath: "/rootdisk"}, {Name: "boot", MountPath: "/bootfiles"}},
		}},
		Volumes: []corev1.Volume{{Name: "root", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: root}}}, {Name: "boot", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: boot}}}},
	}}
	population.Labels = populationLabels
	if *platform == "tdx" {
		population.Spec.Containers[0].VolumeMounts = population.Spec.Containers[0].VolumeMounts[:1]
		population.Spec.Volumes = population.Spec.Volumes[:1]
	}
	items = append(items, population)
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "items": items}); err != nil {
		panic(err)
	}
}
