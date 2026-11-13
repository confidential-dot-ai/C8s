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
