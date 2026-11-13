package webhook

import (
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// rejectUnservedRequests requires the inventory socket for injected credentials.
func (cfg Config) rejectUnservedRequests(inj *injection) error {
	if cfg.WorkloadClaimsHostDir != "" {
		return nil
	}
	if len(inj.Secrets.Specs) > 0 {
		return fmt.Errorf("%w: %s needs an admission inventory, which this operator is not configured with (node inventory not configured); see docs/secrets.md",
			errInvalidInjectionAnnotation, AnnotationSecrets)
	}
	if len(inj.Volumes.Specs) > 0 {
		return fmt.Errorf("%w: %s needs a volume daemon, which this operator is not configured with (node inventory not configured); see docs/volumes.md",
			errInvalidInjectionAnnotation, AnnotationVolumes)
	}
	return fmt.Errorf("%w: get-cert needs workload-claims-host-dir (node inventory not configured)", errInvalidInjectionAnnotation)
}

// rejectReservedResources refuses a pod in scope that occupies something the
// injector owns and cannot safely reconcile: a reserved container name, a
// reserved volume under another shape, a credential mount outside the platform
// containers, a mesh port, a node selector contradicting the cluster's
// confidential nodes, or a container the privilege floor always refuses.
func rejectReservedResources(pod *corev1.Pod, inj *injection, cfg Config) error {
	if err := rejectHostNetwork(pod); err != nil {
		return err
	}
	if err := rejectNodeSelectorConflict(pod, cfg.ConfidentialNodeSelector); err != nil {
		return err
	}
	// The injected init containers are rebuilt (injectInitContainers), but a
	// regular or ephemeral collision cannot be: injection integrity is by name.
	if err := rejectReservedCertContainer(pod); err != nil {
		return err
	}
	if err := rejectReservedVolumeShapes(pod); err != nil {
		return err
	}
	if err := rejectCredentialMounts(pod, CertVolumeName); err != nil {
		return err
	}
	if err := rejectCredentialPathAnnotations(pod); err != nil {
		return err
	}
	if err := rejectUnforwardableProbes(pod); err != nil {
		return err
	}
	if err := podmesh.RefusePrivilegesAboveFloor(pod); err != nil {
		return err
	}
	if err := rejectRootContainers(pod); err != nil {
		return err
	}
	return rejectSharedNamespaces(pod)
}

// rejectCredentialPathAnnotations refuses a pod that names where its
// credentials land: the injector fixes those paths, so a pod choosing them
// would read files nothing writes.
func rejectCredentialPathAnnotations(pod *corev1.Pod) error {
	for _, name := range []string{
		AnnotationCertVolume,
		AnnotationCertDir,
		AnnotationCertFile,
		AnnotationKeyFile,
		AnnotationCAFile,
	} {
		if pod.Annotations[name] != "" {
			return fmt.Errorf("%w: %s is fixed by the injector and must not be set",
				errInvalidInjectionAnnotation, name)
		}
	}
	return nil
}

// rejectSharedNamespaces refuses a pod whose containers share a namespace with
// the platform containers: the pod's credentials are readable through
// /proc/<pid>/root of the process holding them.
func rejectSharedNamespaces(pod *corev1.Pod) error {
	if pod.Spec.ShareProcessNamespace != nil && *pod.Spec.ShareProcessNamespace {
		return sharedNamespaceError("shareProcessNamespace")
	}
	if pod.Spec.HostPID {
		return sharedNamespaceError("hostPID")
	}
	if pod.Spec.HostIPC {
		return sharedNamespaceError("hostIPC")
	}
	return nil
}

func sharedNamespaceError(field string) error {
	return fmt.Errorf("%w: a C8s pod must not set %s — it exposes the platform containers' credentials through /proc",
		errInvalidInjectionAnnotation, field)
}

// rejectNamespaceMismatch refuses a pod whose own namespace is not the one the
// request names: the injected identity derives from the request namespace.
func rejectNamespaceMismatch(pod *corev1.Pod, namespace string) error {
	if pod.Namespace == "" || pod.Namespace == namespace {
		return nil
	}
	return fmt.Errorf("%w: pod namespace %q does not match the request namespace %q",
		errInvalidInjectionAnnotation, pod.Namespace, namespace)
}

// rejectHostNetwork refuses a pod in scope that shares the node's network
// namespace: it has no pod-local namespace to seal, so its application traffic
// would leave the node in plaintext with no interception and no drop.
func rejectHostNetwork(pod *corev1.Pod) error {
	if !pod.Spec.HostNetwork {
		return nil
	}
	return fmt.Errorf("%w: a C8s pod must not set hostNetwork — it shares the node IP and cannot be mesh-intercepted or sealed",
		errInvalidInjectionAnnotation)
}

// rejectCredentialMounts refuses a pod that mounts the credential volume into a
// container outside the platform credential roles. The volume carries the pod's
// private key, its CA and its issuer record, which no workload container
// reads.
func rejectCredentialMounts(pod *corev1.Pod, certVolume string) error {
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if workloadclaims.IsInjectedContainerName(c.Name) {
			continue
		}
		if containerMount(&c, certVolume) != nil {
			return fmt.Errorf("%w: container %q may not mount %q, which holds the pod's private credentials",
				errInvalidInjectionAnnotation, c.Name, certVolume)
		}
	}
	return nil
}

// rejectEphemeralReach denies an ephemeral container that could reach C8s
// material: a volume holding it, or the namespaces of a platform container
// holding it.
//
// The release check cannot help here: it gates the fetch, and by the time an
// ephemeral container is attached the file already exists. Without this,
// `kubectl debug` with any allowlisted image reads a secret straight out of a
// live pod — through a volumeMount, or through /proc of its target.
//
// Reserved container names are checked too. The pod-CREATE path already does
// that, but Kubernetes strips spec.ephemeralContainers at CREATE, so that check
// only ever runs against an empty list.
//
// On an injected pod no container may be targeted: every one mounts C8s
// material, and a target shares its process namespace, so a same-UID process
// reads its files through /proc/<pid>/root.
func rejectEphemeralReach(pod *corev1.Pod) error {
	reserved := reservedVolumeNames(pod)
	injected := slices.ContainsFunc(pod.Spec.InitContainers, func(c corev1.Container) bool {
		return workloadclaims.IsInjectedContainerName(c.Name)
	})
	for _, c := range pod.Spec.EphemeralContainers {
		if workloadclaims.IsInjectedContainerName(c.Name) {
			return fmt.Errorf("%w: ephemeral container name %q is reserved for the injected c8s containers",
				errInvalidInjectionAnnotation, c.Name)
		}
		if injected && c.TargetContainerName != "" {
			return fmt.Errorf("%w: ephemeral container %q may not target %q: it would share that container's process namespace",
				errInvalidInjectionAnnotation, c.Name, c.TargetContainerName)
		}
		if workloadclaims.IsInjectedContainerName(c.TargetContainerName) {
			return fmt.Errorf("%w: ephemeral container %q may not target %q, whose namespaces expose c8s credentials",
				errInvalidInjectionAnnotation, c.Name, c.TargetContainerName)
		}
		for _, m := range c.VolumeMounts {
			// By prefix as well as by set: an opened volume is reserved
			// whatever the host-written annotation says its name is.
			if reserved[m.Name] || strings.HasPrefix(m.Name, volume.KubeVolumePrefix) {
				return fmt.Errorf("%w: ephemeral container %q may not mount %q, which holds c8s-released material",
					errInvalidInjectionAnnotation, c.Name, m.Name)
			}
		}
	}
	return nil
}

// reservedVolumeNames is the set of volumes holding C8s material on this pod:
// the injected volumes, plus whatever the injected sidecars mount. The mounts
// are read off spec.initContainers, immutable after CREATE, so a pod whose
// sidecars name another volume is judged by that volume too.
func reservedVolumeNames(pod *corev1.Pod) map[string]bool {
	reserved := map[string]bool{secretsVolumeName: true, CertVolumeName: true}
	for _, c := range pod.Spec.InitContainers {
		if !workloadclaims.IsInjectedContainerName(c.Name) {
			continue
		}
		for _, m := range c.VolumeMounts {
			reserved[m.Name] = true
		}
	}
	return reserved
}

// rejectUnpinnableSidecarVolumes refuses a discovery volume of a kind the
// get-cert sidecar's exact mount rules cannot admit (the chart's
// c8s.injectedShapes): discovery is an emptyDir rule. Admitting the pod would
// only have the node refuse the sidecar at container creation. A disk-backed
// emptyDir passes: the rule admits it on the measured node image, whose
// kubelet volumes sit on encrypted scratch, and the webhook cannot tell that
// node from one without it, where the node refuses the sidecar
// (docs/secrets.md#fixed-sidecar-mounts).
func rejectUnpinnableSidecarVolumes(pod *corev1.Pod, inj *injection) error {
	for _, ref := range []struct {
		annotation, name, want string
		admits                 func(corev1.VolumeSource) bool
	}{
		{AnnotationDiscoveryVolume, inj.Discovery.Volume, "an emptyDir (medium: Memory unless the node has encrypted scratch)", func(v corev1.VolumeSource) bool { return v.EmptyDir != nil }},
	} {
		if ref.name == "" {
			continue
		}
		i := slices.IndexFunc(pod.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == ref.name })
		if i < 0 {
			return fmt.Errorf("%w: %s %q names no volume of the pod", errInvalidInjectionAnnotation, ref.annotation, ref.name)
		}
		if !ref.admits(pod.Spec.Volumes[i].VolumeSource) {
			return fmt.Errorf("%w: %s %q must be %s: the get-cert sidecar's mount rules admit no other kind there, so the node would refuse it",
				errInvalidInjectionAnnotation, ref.annotation, ref.name, ref.want)
		}
	}
	return nil
}

// rejectReservedVolumeShapes denies a pod that pre-declares a volume the
// injector owns as anything but the emptyDir the injector creates. ensureVolume
// keeps an existing same-named volume rather than overwriting it, so without
// this a pod spec could point the credential or secrets volume at a hostPath
// and have a private key or a CDS-released secret written to persistent,
// host-visible storage outside the TEE boundary. Omitting a reserved volume is
// fine — the webhook injects it.
//
// The opened volumes are reserved by prefix rather than by re-deriving names
// from the annotation: the annotation is host-written, so a guard that reads it
// can be steered away from the name it is meant to protect.
func rejectReservedVolumeShapes(pod *corev1.Pod) error {
	for _, reserved := range []struct {
		matches func(name string) bool
		medium  corev1.StorageMedium
		refusal string
	}{
		{
			matches: func(name string) bool {
				return name == CertVolumeName
			},
			medium:  corev1.StorageMediumMemory,
			refusal: "reserved for the injected in-memory cert store; it must be a memory-backed emptyDir (medium: Memory) or omitted",
		},
		{
			matches: func(name string) bool {
				return name == secretsVolumeName
			},
			medium:  corev1.StorageMediumMemory,
			refusal: "reserved for released secrets; it must be a memory-backed emptyDir (medium: Memory) or omitted",
		},
		{
			matches: func(name string) bool {
				return strings.HasPrefix(name, volume.KubeVolumePrefix)
			},
			medium:  corev1.StorageMediumDefault,
			refusal: "reserved for an encrypted volume; it must be a default-medium emptyDir or omitted (see openedVolume)",
		},
	} {
		for _, v := range pod.Spec.Volumes {
			if !reserved.matches(v.Name) {
				continue
			}
			if v.EmptyDir == nil || v.EmptyDir.Medium != reserved.medium {
				return fmt.Errorf("%w: volume %q is %s", errInvalidInjectionAnnotation, v.Name, reserved.refusal)
			}
		}
	}
	return nil
}

// rejectReservedCertContainer denies an opted-in pod that parks a container
// under a name C8s injects, outside the init-container slot the webhook
// rebuilds. Such a container would survive injection and collide with the
// injected init sidecar (names are unique across all three lists), so it can
// only be an attempt to shed or impersonate it; init-container collisions are
// handled by injectInitContainers instead.
func rejectReservedCertContainer(pod *corev1.Pod) error {
	for _, c := range pod.Spec.Containers {
		if workloadclaims.IsInjectedContainerName(c.Name) {
			return fmt.Errorf("%w: container name %q is reserved for the containers c8s injects",
				errInvalidInjectionAnnotation, c.Name)
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		if workloadclaims.IsInjectedContainerName(c.Name) {
			return fmt.Errorf("%w: ephemeral container name %q is reserved for the containers c8s injects",
				errInvalidInjectionAnnotation, c.Name)
		}
	}
	return nil
}
