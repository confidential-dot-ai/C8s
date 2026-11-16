package webhook

import (
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// meshContainer is the pod's mesh endpoint: a native sidecar carrying the
// pod's captured TCP over armTLS with the credentials get-cert publishes. The
// pod's fsGroup owns the credential volume, which is how the mesh role reads a
// key get-cert's UID wrote.
func meshContainer(cfg Config, probes []string) corev1.Container {
	return podmesh.Endpoint(cfg.MeshImage, probes)
}

// certContainer is the workload's mesh-cert sidecar. It publishes the pod's
// credential generation on startup and keeps it fresh on a --renew-interval.
//
// Native sidecar (restartPolicy: Always) so it stays resident.
func certContainer(inj *injection, cfg Config) corev1.Container {
	args := []string{
		"get-cert",
		"--attestation-api-url=" + cfg.sidecarAttestationApiURL(),
		sanArg(inj.SAN),
		"--cert-path=" + certPath(certFile),
		"--key-path=" + certPath(keyFile),
		// The mesh CA alone (0644), next to the leaf+CA bundle in tls.crt: an
		// app that pins the CA as its own file (mysqld --ssl-ca, any client
		// doing VERIFY_CA against the mesh) reads it directly instead of
		// splitting the bundle in an entrypoint.
		"--ca-path=" + certPath(caFile),
		"--renew-interval=" + inj.Cert.RenewInterval.String(),
		"--continue-on-initial-error",
	}
	args = append(args, discoveryArgs(inj.Discovery)...)
	if inj.Verbose {
		args = append(args, "--verbose")
	}

	always := corev1.ContainerRestartPolicyAlways
	return corev1.Container{
		Name:            reservedCertContainerName,
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		RestartPolicy:   &always,
		Args:            args,
		Env:             getCertEnv(inj),
		VolumeMounts:    getCertVolumeMounts(inj),
		SecurityContext: getCertSecurityContext(),
		// The workload is gated on the initial cert by the c8s-cert-wait
		// init container (certWaitContainer), not a startupProbe here: a
		// native sidecar is "started" the moment its process launches.
	}
}

// sanNone is the selection of a pod that asks for no identity.
const sanNone = ""

// sanArg asks for no SAN explicitly, so an empty value can never pass for a
// choice.
func sanArg(san string) string {
	if san == sanNone {
		return "--no-san"
	}
	return "--san=" + san
}

// certWaitTimeout bounds how long c8s-cert-wait blocks before failing (and
// being restarted by the kubelet, which re-waits). Comfortably exceeds
// get-cert's own initial-fetch retry so a slow CDS cold start is absorbed in
// one wait, while a genuinely stuck bootstrap surfaces as Init:Error/CrashLoop
// rather than a silent Init hang.
const certWaitTimeout = 3 * time.Minute

// certWaitContainer gates the workload on the initial cert being written by the
// c8s-cert sidecar. It is a plain (run-once) init container that blocks on the
// cert file and exits 0 once it appears, so normal init-completion ordering
// holds the workload until the attested cert exists — fail-closed. It must be
// ordered after c8s-cert and before the workload; injectInitContainers does that.
func certWaitContainer(inj *injection, cfg Config) corev1.Container {
	return corev1.Container{
		Name:            reservedCertWaitContainerName,
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{
			"/c8s", "probe-file", "--wait",
			"--timeout=" + certWaitTimeout.String(),
			certPath(certFile),
		},
		VolumeMounts:    getCertVolumeMounts(inj),
		SecurityContext: getCertSecurityContext(),
	}
}

func certPath(name string) string {
	return filepath.Join(CertDir, name)
}

func discoveryArgs(discovery discoverySpec) []string {
	var args []string
	if discovery.Out != "" {
		args = append(args, "--discovery-out="+discovery.Out)
	}
	if discovery.CDSCertURL != "" {
		args = append(args, "--discovery-cds-cert-url="+discovery.CDSCertURL)
	}
	if discovery.PublicTLSMode != "" {
		args = append(args, "--discovery-public-tls-mode="+discovery.PublicTLSMode)
	}
	if discovery.MeshCAURL != "" {
		args = append(args, "--discovery-mesh-ca-url="+discovery.MeshCAURL)
	}
	return args
}

func getCertVolumeMounts(inj *injection) []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{Name: CertVolumeName, MountPath: CertDir},
	}
	if inj.Discovery.Volume != "" && inj.Discovery.MountPath != "" {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      inj.Discovery.Volume,
			MountPath: inj.Discovery.MountPath,
		})
	}
	return mounts
}

func getCertEnv(inj *injection) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "C8S_WORKLOAD_ID", Value: inj.WorkloadID},
		{
			Name:      "C8S_POD_NAME",
			ValueFrom: fieldRef("metadata.name"),
		},
		{
			Name:      "C8S_POD_UID",
			ValueFrom: fieldRef("metadata.uid"),
		},
		// An operator endpoint of http://$(HOST_IP):8400 reaches this arg
		// unexpanded (sidecarAttestationApiURL), and the kubelet expands it
		// against THIS tenant pod's node, so the sidecar reaches the host
		// attestation-api on whichever node it lands. Unused (harmless) where
		// the URL has no $(HOST_IP).
		{
			Name:      "HOST_IP",
			ValueFrom: fieldRef("status.hostIP"),
		},
	}
}

// fieldRef names a pod field for the kubelet to expand. The API version is
// explicit so a stored pod still matches what the injector built.
func fieldRef(path string) *corev1.EnvVarSource {
	return &corev1.EnvVarSource{
		FieldRef: &corev1.ObjectFieldSelector{
			APIVersion: "v1",
			FieldPath:  path,
		},
	}
}

// getCertSecurityContext is the credential role's floor: its reserved
// identity, and no capabilities. The identity is fixed, not a pod's to choose:
// the node binds it to the CDS address and refuses it in any other container
// (pkg/workloadclaims.CredentialsUID).
func getCertSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: new(false),
		ReadOnlyRootFilesystem:   new(true),
		RunAsNonRoot:             new(true),
		RunAsUser:                new(int64(workloadclaims.CredentialsUID)),
		RunAsGroup:               new(int64(workloadclaims.CredentialsUID)),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// secretsVolume is the memory-backed volume released values are written to.
func secretsVolume() corev1.Volume {
	return corev1.Volume{
		Name: secretsVolumeName,
		EmptyDir: &corev1.EmptyDirVolumeSource{
			Medium: corev1.StorageMediumMemory,
		},
	}
}

var hostToContainer = corev1.MountPropagationHostToContainer

// volumeNames returns the NAME of each NAME=/store/path spec, in order.
// validate has already rejected anything malformed.
func volumeNames(specs []string) []string {
	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		name, _, ok := strings.Cut(spec, "=")
		if !ok {
			continue
		}
		out = append(out, strings.TrimSpace(name))
	}
	return out
}

// openedVolume is the mount point volumed mounts a decrypted volume over. It
// holds nothing itself — the plaintext lives on the opened device mounted over
// it. The default-medium placeholder must share the pod directory's filesystem,
// because volumed resolves the target with RESOLVE_NO_XDEV.
func openedVolume(name string) corev1.Volume {
	src := &corev1.EmptyDirVolumeSource{}
	return corev1.Volume{
		Name:     volume.KubeVolumeName(name),
		EmptyDir: src,
	}
}

// replaceVolume overwrites a same-named volume rather than keeping it, which is
// what ensureVolume does. See the call site in mutatePod.
func replaceVolume(pod *corev1.Pod, v corev1.Volume) {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == v.Name {
			pod.Spec.Volumes[i] = v
			return
		}
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, v)
}

// remountAll gives every container the mount, overwriting one it already
// declares rather than keeping it, which is what mountAll does. See the call
// site in mutatePod.
func remountAll(pod *corev1.Pod, mount corev1.VolumeMount) {
	replace := func(cs []corev1.Container) []corev1.Container {
		for i := range cs {
			if existing := containerMount(&cs[i], mount.Name); existing != nil {
				*existing = mount
				continue
			}
			cs[i].VolumeMounts = append(cs[i].VolumeMounts, mount)
		}
		return cs
	}
	pod.Spec.Containers = replace(pod.Spec.Containers)
	pod.Spec.InitContainers = replace(pod.Spec.InitContainers)
}

func volumeContainer(inj *injection, cfg Config) corev1.Container {
	container := releaseSidecar(inj, cfg, reservedVolumeContainerName, "get-volume")
	for _, spec := range inj.Volumes.Specs {
		container.Args = append(container.Args, "--volume="+spec)
	}
	return container
}

func secretContainer(inj *injection, cfg Config) corev1.Container {
	container := releaseSidecar(inj, cfg, reservedSecretContainerName, "get-secret")
	container.Args = append(container.Args, "--out-dir="+inj.Secrets.Dir)
	for _, spec := range inj.Secrets.Specs {
		container.Args = append(container.Args, "--secret="+spec)
	}
	// Released secrets are writable only by this fetcher.
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      secretsVolumeName,
		MountPath: inj.Secrets.Dir,
	})
	return container
}

// Release sidecars follow c8s-cert-wait and run alongside the workload.
func releaseSidecar(
	inj *injection,
	cfg Config,
	name string,
	command string,
) corev1.Container {
	always := corev1.ContainerRestartPolicyAlways
	return corev1.Container{
		Name:            name,
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		RestartPolicy:   &always,
		Args: []string{
			command,
			"--attestation-api-url=" + cfg.sidecarAttestationApiURL(),
			"--cert=" + certPath(certFile),
			"--key=" + certPath(keyFile),
		},
		Env:             getCertEnv(inj),
		VolumeMounts:    getCertVolumeMounts(inj),
		SecurityContext: getCertSecurityContext(),
	}
}

func certsVolume(name string) corev1.Volume {
	return corev1.Volume{
		Name:     name,
		EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
	}
}

// sidecarAttestationApiURL rebases sockets inside the node's inventory directory.
func (cfg Config) sidecarAttestationApiURL() string {
	prefix := "unix://" + strings.TrimRight(cfg.WorkloadClaimsHostDir, "/") + "/"
	if cfg.WorkloadClaimsHostDir == "" || !strings.HasPrefix(cfg.AttestationApiURL, prefix) {
		return cfg.AttestationApiURL
	}
	socketPath := strings.TrimPrefix(cfg.AttestationApiURL, "unix://")
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return cfg.AttestationApiURL
	}
	relativeSocketPath := strings.TrimPrefix(cfg.AttestationApiURL, prefix)
	return "unix://" + workloadclaims.SidecarSocketDir + "/" + relativeSocketPath
}

func ensureVolume(pod *corev1.Pod, v corev1.Volume) {
	for _, existing := range pod.Spec.Volumes {
		if existing.Name == v.Name {
			return
		}
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, v)
}

func ensureFSGroup(pod *corev1.Pod, fsGroup int64) {
	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if pod.Spec.SecurityContext.FSGroup == nil {
		pod.Spec.SecurityContext.FSGroup = &fsGroup
	}
}

// ensureSupplementalGroup adds gid to the pod's supplemental groups (idempotent)
// so the non-root get-cert sidecar can reach the group-owned inventory socket. It
// is pod-level (the only place SupplementalGroups exists); the socket is mounted
// only into the sidecar, so the group is harmless to the app containers.
func ensureSupplementalGroup(pod *corev1.Pod, gid int64) {
	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if slices.Contains(pod.Spec.SecurityContext.SupplementalGroups, gid) {
		return
	}
	pod.Spec.SecurityContext.SupplementalGroups = append(pod.Spec.SecurityContext.SupplementalGroups, gid)
}

// injectInitContainers prepends the C8s-managed init containers, in the given
// order, and drops every existing init container holding a reserved name —
// including one the pod did not ask for, which could otherwise sit behind the
// injected containers and mount what they mount. Injection is therefore
// idempotent (a reinvocation rebuilds the same list) and a pre-declared
// platform container can neither shed nor shadow the real one. Order matters:
// the mesh endpoint leads, then c8s-cert, then c8s-cert-wait gates the workload
// on the initial cert (see certWaitContainer), then the pod's own init
// containers.
func injectInitContainers(existing []corev1.Container, injected ...corev1.Container) []corev1.Container {
	out := make([]corev1.Container, 0, len(existing)+len(injected))
	for _, c := range injected {
		// Explicitly the API server's defaults: a platform container's
		// termination message must stay a file of its own, or a failing
		// container would copy a credential into pod status.
		c.TerminationMessagePath = corev1.TerminationMessagePathDefault
		c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		out = append(out, c)
	}
	for _, ec := range existing {
		if !workloadclaims.IsInjectedContainerName(ec.Name) {
			out = append(out, ec)
		}
	}
	return out
}

// mountAll gives every container in pod the mount, read-only.
//
// A container that already declares the volume keeps its own mount path, but
// the mount is forced read-only: matching on the name alone and skipping would
// let a pod pre-declare `{name: c8s-secrets}` with readOnly omitted (defaulting
// to false) and keep write access to the shared directory, which is exactly the
// invariant secretContainer relies on ("the only container with write access").
// The same holds for the cert volume, where a writable mount means overwriting
// the sidecar-managed leaf key.
//
// The fetcher's own read-write mount is unaffected: mountAll runs against the
// pod's containers before the C8s sidecars are appended, and injectInitContainers
// rebuilds them from scratch afterwards, so a coerced stale copy is discarded on
// a webhook reinvocation.
func mountAll(pod *corev1.Pod, mount corev1.VolumeMount) {
	add := func(cs []corev1.Container) []corev1.Container {
		for i := range cs {
			if existing := containerMount(&cs[i], mount.Name); existing != nil {
				existing.ReadOnly = true
				continue
			}
			cs[i].VolumeMounts = append(cs[i].VolumeMounts, mount)
		}
		return cs
	}
	pod.Spec.Containers = add(pod.Spec.Containers)
	pod.Spec.InitContainers = add(pod.Spec.InitContainers)
}

// containerMount returns c's mount of the named volume, or nil. The pointer
// aliases the container's slice so callers can amend the mount in place.
func containerMount(c *corev1.Container, name string) *corev1.VolumeMount {
	for i := range c.VolumeMounts {
		if c.VolumeMounts[i].Name == name {
			return &c.VolumeMounts[i]
		}
	}
	return nil
}
