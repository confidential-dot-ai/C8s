// Package webhook contains the admission webhooks that give a pod its C8s
// shape: a mutator that injects the platform containers and a validator that
// rejects a pod in scope whose final shape is not the injected one.
//
// Every pod the webhooks are called for is injected: its own mesh endpoint
// carries its traffic, and the credential volume stays private to the platform
// containers.
//
// Which namespaces reach the webhooks is their configurations'
// namespaceSelector: control-plane data, deciding injection alone. Membership
// is the node enforcer's decision from its measured exempt set, so a pod the
// host keeps uninjected is a non-member, not an unprotected member.
//
// Pod metadata selects the details, confidential.ai/cw=<workload-id> naming
// the workload the leaf's SAN is for. The webhooks GET no CR.
package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Pod annotations that drive sidecar injection.
const (
	// AnnotationWorkload names the workload a pod belongs to and requests a
	// SAN for its leaf. Injection does not depend on it.
	AnnotationWorkload = workloadclaims.AnnotationWorkloadID

	// AnnotationInjected is stamped on pods after a successful mutation
	// so re-invocations of the webhook are no-ops. Shared with the node's
	// admission inventory, which keys its socket mount on it.
	AnnotationInjected = workloadclaims.AnnotationInjected

	// LabelWorkload mirrors AnnotationWorkload as a pod label so the
	// operator-managed headless Service (one per annotated workload) can
	// select the workload's pods — Service selectors match labels only.
	LabelWorkload = AnnotationWorkload

	// AnnotationSAN overrides the DNS SAN get-cert requests for a pod that
	// also carries AnnotationWorkload: for workloads adopted into C8s whose
	// clients already dial an existing Service name.
	AnnotationSAN = "confidential.ai/c8s-san"

	// The credential paths are the injector's. These are refused, not read
	// (rejectCredentialPathAnnotations).
	AnnotationCertVolume = "confidential.ai/c8s-cert-volume"
	AnnotationCertDir    = "confidential.ai/c8s-cert-dir"
	AnnotationCertFile   = "confidential.ai/c8s-cert-file"
	AnnotationKeyFile    = "confidential.ai/c8s-key-file"
	AnnotationCAFile     = "confidential.ai/c8s-ca-file"

	AnnotationRenewInterval          = "confidential.ai/c8s-renew-interval"
	AnnotationDiscoveryVolume        = "confidential.ai/c8s-discovery-volume"
	AnnotationDiscoveryMountPath     = "confidential.ai/c8s-discovery-mount-path"
	AnnotationDiscoveryOut           = "confidential.ai/c8s-discovery-out"
	AnnotationDiscoveryCDSCertURL    = "confidential.ai/c8s-discovery-cds-cert-url"
	AnnotationDiscoveryMeshCAURL     = "confidential.ai/c8s-discovery-mesh-ca-url"
	AnnotationDiscoveryPublicTLSMode = "confidential.ai/c8s-discovery-public-tls-mode"
	AnnotationGetCertVerbose         = "confidential.ai/c8s-get-cert-verbose"

	// AnnotationSecrets requests secrets for the pod, as a comma-separated
	// list of NAME=/store/path. NAME is the file each value is written to
	// under the secrets directory. Setting it injects the fetcher sidecar.
	AnnotationSecrets = workloadclaims.AnnotationSecrets
	// AnnotationSecretDir once moved the secrets directory. It is refused
	// unless it names the fixed one; see pinnedDestinations.
	AnnotationSecretDir = "confidential.ai/c8s-secret-dir"

	// AnnotationVolumes requests encrypted volumes for the pod, as a
	// comma-separated list of NAME=/store/path. NAME selects the node's device
	// by serial and names the directory the plaintext appears in under
	// AnnotationVolumeDir. Setting it injects the volume fetcher sidecar.
	AnnotationVolumes = "confidential.ai/c8s-volumes"
	// AnnotationVolumeDir overrides where the volumes are mounted. It must sit
	// at or below pkgallowlist.DataMountPrefix.
	AnnotationVolumeDir = "confidential.ai/c8s-volume-dir"
)

var errInvalidInjectionAnnotation = errors.New("invalid c8s injection annotation")

// defaultCertFSGroup is the shared group used for the injected EmptyDir
// when the pod does not already specify an fsGroup. The C8s image runs as
// the distroless nonroot UID/GID 65532, and get-cert creates tls.key 0640 in the setgid certificate volume.
const defaultCertFSGroup int64 = 65532

// defaultCertRenewInterval must stay strictly below issuer.MaxNamedLeafTTL, the
// shortest TTL CDS issues: a leaf carrying a matched-workload stamp is capped
// there and its NotBefore is not backdated, so an equal interval would only
// renew once the installed leaf had already expired.
const defaultCertRenewInterval = 2 * time.Hour

// reservedSecretContainerName is the injected secret fetcher. Reserved like
// the cert containers: a pod that declared the name itself would have the
// webhook's container silently replace or collide with it.
const reservedSecretContainerName = workloadclaims.SecretContainerName

// The injected credential volume, where it is mounted, and the files get-cert
// publishes in it. One pod shape, so every reader of a generation — the mesh
// endpoint, the fetchers and the workload — resolves the same three paths.
const (
	// CertVolumeName is the injected memory-backed credential volume.
	CertVolumeName = podmesh.CertVolumeName
	// CertDir is where the injected containers mount it; no other container
	// may (rejectCredentialMounts).
	CertDir  = workloadclaims.MemberCertDir
	certFile = "tls.crt"
	keyFile  = "tls.key"
	caFile   = "ca.crt"
)

// secretsVolumeName is the memory-backed volume the fetcher writes to and the
// workload reads from.
const secretsVolumeName = workloadclaims.SecretsVolumeName

// The injected sidecars' mount destinations. The allowlist pins each
// sidecar's mount table exactly (the chart's c8s.injectedShapes), so a pod
// cannot move them.
const (
	// defaultSecretDir is where the fetcher writes, matching its own default.
	defaultSecretDir = workloadclaims.SecretDir
	// discoveryMountPath is where get-cert mounts the pod's discovery volume.
	discoveryMountPath = "/run/c8s/discovery"
)

// pinnedDestinations are the annotations that used to move a sidecar mount.
// Each is refused unless it names the fixed destination.
var pinnedDestinations = []struct{ annotation, path string }{
	{AnnotationCertDir, CertDir},
	{AnnotationSecretDir, defaultSecretDir},
	{AnnotationDiscoveryMountPath, discoveryMountPath},
}

// reservedVolumeContainerName is the injected volume fetcher. Reserved like the
// cert containers.
const reservedVolumeContainerName = workloadclaims.VolumeContainerName

// reservedCertContainerName is the injected mesh-cert sidecar's name. It is
// operator-reserved: a pod may not declare its own container under it. The
// webhook rebuilds the sidecar every call (injectInitContainers) and rejects
// the name in the regular/ephemeral lists (rejectReservedCertContainer); the
// pod validator refuses a final shape without it.
const reservedCertContainerName = workloadclaims.CertContainerName

// reservedCertWaitContainerName is the injected gate init container that blocks
// the workload until c8s-cert has written the initial cert (see
// certWaitContainer). Operator-reserved like c8s-cert: a pod may not declare
// its own container under it.
const reservedCertWaitContainerName = workloadclaims.CertWaitContainerName

// reservedMeshContainerName is the injected mesh endpoint, operator-reserved
// like the credential containers.
const reservedMeshContainerName = workloadclaims.MeshContainerName

// Config tunes the injector.
type Config struct {
	// PodCVMProviderEnabled routes explicitly opted-in Pods to the virtual node.
	PodCVMProviderEnabled bool

	// GetCertImage is the c8s multi-mode binary image used for the
	// injected get-cert containers.
	GetCertImage string

	// MeshImage is the armtls-mesh image the pod's mesh endpoint runs.
	MeshImage string

	// AttestationApiURL points at the node-local attestation-api.
	AttestationApiURL string

	// CertFSGroup is applied to the pod when it does not already specify
	// fsGroup. A negative value disables fsGroup mutation.
	CertFSGroup *int64

	// CertRenewInterval is passed to the renewal sidecar. Non-positive
	// values use the default interval.
	CertRenewInterval time.Duration

	// ConfidentialNodeSelector are the chart's confidentialNodeSelector: the
	// labels this platform puts on a confidential node, which every node agent
	// selects. Every injected pod selects them too. Empty leaves placement to
	// the pod, as on the measured image, where every node is a CVM.
	ConfidentialNodeSelector map[string]string

	// WorkloadClaimsHostDir, when set (node-CVM), is the host directory holding
	// the nri-image-policy inventory socket. That plugin bind-mounts the
	// directory at workloadclaims.SidecarSocketDir into the injected sidecars
	// (an NRI mount, never a pod-spec hostPath — PodSecurity baseline and
	// restricted forbid hostPath), where get-cert redeems a sandbox token over
	// its compiled socket path (docs/armtls.md).
	WorkloadClaimsHostDir string
}

// Register wires the pod mutator and the pod validator onto the manager's
// webhook server.
func Register(mgr ctrl.Manager, cfg Config) error {
	cfg = cfg.withDefaults()
	decoder := admission.NewDecoder(mgr.GetScheme())
	server := mgr.GetWebhookServer()
	server.Register("/mutate-pods", &admission.Webhook{
		Handler: &podMutator{
			decoder: decoder,
			cfg:     cfg,
		},
	})
	server.Register("/validate-pods", &admission.Webhook{
		Handler: &podValidator{
			decoder: decoder,
			cfg:     cfg,
		},
	})
	return nil
}

type podMutator struct {
	decoder admission.Decoder
	cfg     Config
}

// injectionEnabled reports whether this operator holds the images the platform
// containers run. Register refuses a configuration with only one of them.
//
// With them it owns the shape of every pod it is called for, which is every
// pod of a namespace the webhook configurations' namespaceSelector does not
// exempt.
func (cfg Config) injectionEnabled() bool {
	return cfg.GetCertImage != "" && cfg.MeshImage != ""
}

func (m *podMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	l := log.FromContext(ctx).WithValues("pod", req.Name, "ns", req.Namespace)

	pod := &corev1.Pod{}
	if err := m.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if response, handled := handlePodCVM(req, pod, m.decoder, m.cfg, mutatingPodCVM{}); handled {
		return response
	}

	// An ephemeral container is attached to a running pod, so nothing here is
	// injected — the only decision is whether it may reach what the injected
	// containers already put on that pod.
	if req.SubResource == "ephemeralcontainers" {
		if err := rejectEphemeralReach(pod); err != nil {
			l.Info("denying ephemeral container", "reason", err.Error())
			return admission.Errored(http.StatusBadRequest, err)
		}
		return admission.Allowed("ephemeral container reaches no c8s material")
	}

	if !m.cfg.injectionEnabled() {
		return admission.Allowed("outside the injector's scope — passthrough")
	}
	if err := rejectRenderedProbeInput(pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if err := rejectNamespaceMismatch(pod, req.Namespace); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	inj, err := parseAnnotations(pod, req.Namespace)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if err := rejectReservedResources(pod, inj, m.cfg); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if err := m.cfg.rejectUnservedRequests(inj); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	var warnings []string
	if err := rejectUnpinnableSidecarVolumes(pod, inj); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	// Injection is idempotent by reconstruction (mutatePod rebuilds the
	// injected containers every call), so it does not key off the
	// confidential.ai/c8s-injected marker: an author cannot skip injection by
	// pre-setting it.
	l.Info("injecting the c8s platform containers", "workload", inj.WorkloadID)
	// Only an explicit true: an unset field is the default on nearly every
	// pod, and a controller-created pod's warning reaches the controller's
	// log, not its author.
	if pod.Spec.EnableServiceLinks != nil && *pod.Spec.EnableServiceLinks {
		warnings = append(warnings, serviceLinksWarning)
	}
	mutatePod(pod, inj, m.cfg)

	raw, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	resp := admission.PatchResponseFromRaw(req.Object.Raw, raw)
	resp.Warnings = warnings
	return resp
}

// serviceLinksWarning tells the pod's author that mutatePod turned service
// links off.
const serviceLinksWarning = "c8s: enableServiceLinks set to false; the pod no longer receives <SERVICE>_SERVICE_HOST and <SERVICE>_PORT_* variables, so resolve Services by DNS and re-derive allowlist entries that pin them; set enableServiceLinks: false in the pod template to silence this warning"

// workloadServiceNamePrefix marks the operator-managed headless Service inside
// the workload namespace and keeps it from colliding with the workload's own
// Services.
const workloadServiceNamePrefix = "c8s-"

// WorkloadServiceName derives the managed headless Service name from the cw
// id, or "" when the id is absent or cannot name a Service. Shared with the
// WorkloadServiceReconciler so the Service it provisions and the SAN get-cert
// requests stay derived from one rule.
func WorkloadServiceName(cwID string) string {
	if cwID == "" {
		return ""
	}
	name := workloadServiceNamePrefix + cwID
	if len(validation.IsDNS1035Label(name)) > 0 {
		return ""
	}
	return name
}

// workloadServiceDNS is the managed headless Service's in-cluster DNS name,
// c8s-<id>.<namespace>.svc, or "" when the id cannot name a Service. Callers add
// the ".cluster.local" suffix (or not) per their DNS-name needs.
func workloadServiceDNS(cwID, namespace string) string {
	svc := WorkloadServiceName(cwID)
	if svc == "" || namespace == "" {
		return ""
	}
	return svc + "." + namespace + ".svc"
}

// WorkloadServiceFQDN is the managed headless Service's fully-qualified DNS name,
// c8s-<id>.<namespace>.svc.cluster.local, or "" when the id cannot name a
// Service. It is the name router dials for an adopted workload upstream.
func WorkloadServiceFQDN(cwID, namespace string) string {
	dns := workloadServiceDNS(cwID, namespace)
	if dns == "" {
		return ""
	}
	return dns + ".cluster.local"
}

// workloadSAN is the DNS SAN get-cert requests for a workload. An id that
// names a managed headless Service gets that Service's in-cluster DNS name,
// which CDS's default --dns-san-pattern signs; any other id passes through
// verbatim (e.g. the <name>.<ns>.svc ids the chart's own components use).
func workloadSAN(cwID, namespace string) string {
	if dns := workloadServiceDNS(cwID, namespace); dns != "" {
		return dns
	}
	return cwID
}

// mutatePod is pure — easy to unit test.
func mutatePod(pod *corev1.Pod, inj *injection, cfg Config) {
	cfg = cfg.withDefaults()
	effective := inj.withDefaults(cfg)
	if *cfg.CertFSGroup >= 0 {
		ensureFSGroup(pod, *cfg.CertFSGroup)
	}
	selectConfidentialNodes(pod, cfg.ConfidentialNodeSelector)
	ensureVolume(pod, certsVolume(CertVolumeName))
	if cfg.WorkloadClaimsHostDir != "" {
		// The inventory socket is group-owned by InventorySocketGID and the non-root
		// get-cert sidecar connects to it; without this supplemental group the
		// connect fails closed and the pod hangs on its initial cert.
		ensureSupplementalGroup(pod, workloadclaims.InventorySocketGID)
	}

	// The injected sidecars share the C8s image's allowlist entry, whose env
	// match lists every variable by name. Service links would add one set per
	// Service in the namespace, so the sidecar's names would change whenever
	// a Service is added; the KUBERNETES_* variables stay either way.
	pod.Spec.EnableServiceLinks = new(false)
	pod.Spec.AutomountServiceAccountToken = new(false)

	podmesh.ApplyPrivilegeFloor(pod)

	probes := rewriteWorkloadProbes(pod)
	// The pod's own endpoint leads: it runs before any credential exists.
	injected := []corev1.Container{
		meshContainer(cfg, probes),
		certContainer(&effective, cfg),
		certWaitContainer(&effective, cfg),
	}
	if len(effective.Secrets.Specs) > 0 {
		ensureVolume(pod, secretsVolume())
		// Read-only for the workload, and mounted before the fetcher is built
		// so mountAll (which skips a container that already has the mount)
		// leaves the fetcher's own read-write mount alone.
		mountAll(pod, corev1.VolumeMount{
			Name:      secretsVolumeName,
			MountPath: effective.Secrets.Dir,
			ReadOnly:  true,
		})
		injected = append(injected, secretContainer(&effective, cfg))
	}
	if len(effective.Volumes.Specs) > 0 {
		// Reconstructed, not ensured: ensureVolume and mountAll are both
		// idempotent by SKIPPING what the pod already declares, so a
		// host-authored spec could pre-declare the volume or the mount and
		// choose where the decrypted plaintext lands.
		for _, name := range volumeNames(effective.Volumes.Specs) {
			replaceVolume(pod, openedVolume(name))
			remountAll(pod, corev1.VolumeMount{
				Name:      volume.KubeVolumeName(name),
				MountPath: filepath.Join(effective.Volumes.Dir, name),
				// Writability is the daemon's mount flags: read-only for an
				// immutable volume, read-write for a mutable one. A container-
				// side ReadOnly would not narrow a propagated mount anyway.
				MountPropagation: &hostToContainer,
			})
		}
		injected = append(injected, volumeContainer(&effective, cfg))
	}
	pod.Spec.InitContainers = injectInitContainers(pod.Spec.InitContainers, injected...)

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[AnnotationInjected] = "true"
	if inj.WorkloadID != "" {
		if pod.Labels == nil {
			pod.Labels = map[string]string{}
		}
		pod.Labels[LabelWorkload] = inj.WorkloadID
	}
}

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

// below reports whether path names a file strictly inside dir.
func below(path, dir string) bool {
	return filepath.IsAbs(path) && strings.HasPrefix(filepath.Clean(path), dir+"/")
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

func (inj *injection) withDefaults(cfg Config) injection {
	effective := *inj
	effective.Secrets.Dir = defaultSecretDir
	if effective.Discovery.Volume != "" {
		effective.Discovery.MountPath = discoveryMountPath
	}
	if effective.Cert.RenewInterval <= 0 {
		effective.Cert.RenewInterval = cfg.CertRenewInterval
	}
	if effective.Volumes.Dir == "" {
		effective.Volumes.Dir = volume.DefaultDir
	}
	return effective
}

func (cfg Config) withDefaults() Config {
	if cfg.CertFSGroup == nil {
		cfg.CertFSGroup = new(defaultCertFSGroup)
	}
	if cfg.CertRenewInterval <= 0 {
		cfg.CertRenewInterval = defaultCertRenewInterval
	}
	return cfg
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
