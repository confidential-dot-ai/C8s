// Package webhook contains the mutating admission webhook that injects
// the C8s get-cert containers into pods opted in by annotation.
//
// The webhook reads one annotation on the pod (not its owning workload,
// not any CR — pod metadata only):
//
//	confidential.ai/cw=<workload-id>     required to opt in
//
// Pod-to-pod mTLS is handled by the node-level armtls-mesh DaemonSet
// (cmd/armtls-mesh/), so the webhook does not inject any mesh sidecar.
// Its only job is to add get-cert containers that fetch and renew the
// workload's own identity cert when the pod opts in.
//
// Pods without confidential.ai/cw pass through unchanged. The webhook does
// not GET any CR — sidecar injection runs whether or not a ConfidentialWorkload
// CR exists.
package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Pod annotations that drive sidecar injection.
const (
	// AnnotationWorkload opts a pod in to C8s injection. Required.
	AnnotationWorkload = "confidential.ai/cw"

	// AnnotationInjected is stamped on pods after a successful mutation
	// so re-invocations of the webhook are no-ops. Shared with the node's
	// admission inventory, which keys its socket mount on it.
	AnnotationInjected = workloadclaims.AnnotationInjected

	// LabelWorkload mirrors AnnotationWorkload as a pod label so the
	// operator-managed headless Service (one per annotated workload) can
	// select the workload's pods — Service selectors match labels only.
	LabelWorkload = AnnotationWorkload

	// AnnotationSAN overrides the DNS SAN get-cert requests. For workloads
	// adopted into C8s whose clients already dial an existing Service name;
	// without it the SAN is derived from the cw id (see workloadSAN).
	AnnotationSAN = "confidential.ai/c8s-san"

	AnnotationCertVolume             = "confidential.ai/c8s-cert-volume"
	AnnotationCertDir                = "confidential.ai/c8s-cert-dir"
	AnnotationCertFile               = "confidential.ai/c8s-cert-file"
	AnnotationKeyFile                = "confidential.ai/c8s-key-file"
	AnnotationCAFile                 = "confidential.ai/c8s-ca-file"
	AnnotationRenewInterval          = "confidential.ai/c8s-renew-interval"
	AnnotationReloadNginx            = "confidential.ai/c8s-reload-nginx"
	AnnotationReloadWatchPaths       = "confidential.ai/c8s-reload-watch-paths"
	AnnotationReloadWatchVolume      = "confidential.ai/c8s-reload-watch-volume"
	AnnotationReloadWatchMountPath   = "confidential.ai/c8s-reload-watch-mount-path"
	AnnotationDiscoveryVolume        = "confidential.ai/c8s-discovery-volume"
	AnnotationDiscoveryMountPath     = "confidential.ai/c8s-discovery-mount-path"
	AnnotationDiscoveryOut           = "confidential.ai/c8s-discovery-out"
	AnnotationDiscoveryCDSCertURL    = "confidential.ai/c8s-discovery-cds-cert-url"
	AnnotationDiscoveryMeshCAURL     = "confidential.ai/c8s-discovery-mesh-ca-url"
	AnnotationDiscoveryPublicTLSMode = "confidential.ai/c8s-discovery-public-tls-mode"
	AnnotationGetCertRunAsUser       = "confidential.ai/c8s-get-cert-run-as-user"
	AnnotationGetCertRunAsGroup      = "confidential.ai/c8s-get-cert-run-as-group"
	AnnotationGetCertRunAsNonRoot    = "confidential.ai/c8s-get-cert-run-as-non-root"
	AnnotationGetCertVerbose         = "confidential.ai/c8s-get-cert-verbose"

	// AnnotationSecrets requests secrets for the pod, as a comma-separated
	// list of NAME=/store/path. NAME is the file each value is written to
	// under AnnotationSecretDir. Setting it injects the fetcher sidecar.
	AnnotationSecrets = "confidential.ai/c8s-secrets"
	// AnnotationSecretDir overrides where the files land.
	AnnotationSecretDir = "confidential.ai/c8s-secret-dir"

	// AnnotationVolumes requests encrypted volumes for the pod, as a
	// comma-separated list of NAME=/store/path. NAME selects the node's device
	// by serial and names the directory the plaintext appears in under
	// AnnotationVolumeDir. Setting it injects the volume fetcher sidecar.
	AnnotationVolumes = "confidential.ai/c8s-volumes"
	// AnnotationVolumeDir overrides where the volumes are mounted.
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
const defaultGetCertRunAsUser int64 = 65532
const defaultGetCertRunAsGroup int64 = 65532
const defaultGetCertRunAsNonRoot = true
const discoveryPublicTLSModeCDS = "cds"
const discoveryPublicTLSModeWebPKI = "webpki"

// reservedSecretContainerName is the injected secret fetcher. Reserved like
// the cert containers: a pod that declared the name itself would have the
// webhook's container silently replace or collide with it.
const reservedSecretContainerName = workloadclaims.SecretContainerName

// defaultCertVolumeName is the injected cert volume when a pod does not name
// its own with AnnotationCertVolume.
const defaultCertVolumeName = "c8s-certs"

// secretsVolumeName is the memory-backed volume the fetcher writes to and the
// workload reads from.
const secretsVolumeName = "c8s-secrets"

// defaultSecretDir is where the fetcher writes, matching its own default.
const defaultSecretDir = "/run/c8s/secrets"

// reservedVolumeContainerName is the injected volume fetcher. Reserved like the
// cert containers.
const reservedVolumeContainerName = workloadclaims.VolumeContainerName

// defaultVolumeDir is where opened volumes are mounted, one directory each.
const defaultVolumeDir = "/run/c8s/volumes"

// reservedCertContainerName is the injected mesh-cert sidecar's name. It is
// operator-reserved: a pod may not declare its own container under it. The
// webhook rebuilds the sidecar every call (injectInitContainers) and rejects
// the name in the regular/ephemeral lists (rejectReservedCertContainer); the
// cw-label-integrity VAP enforces its presence in the API server.
const reservedCertContainerName = workloadclaims.CertContainerName

// reservedCertWaitContainerName is the injected gate init container that blocks
// the workload until c8s-cert has written the initial cert (see
// certWaitContainer). Operator-reserved like c8s-cert: a pod may not declare
// its own container under it.
const reservedCertWaitContainerName = workloadclaims.CertWaitContainerName

// Config tunes the injector.
type Config struct {
	// GetCertImage is the c8s multi-mode binary image used for the
	// injected get-cert containers.
	GetCertImage string

	// CDSURL points at the CDS Service in-cluster.
	CDSURL string

	// AttestationApiURL points at the node-local attestation-api.
	AttestationApiURL string

	// CDSMeasurements are the launch measurements the secret fetcher requires
	// CDS to present. Empty pins none, which leaves an impostor CDS able to
	// answer with a value of its choosing.
	CDSMeasurements []string

	// CDSRTMRs are the TDX RTMR pins (<index>=<sha384-hex>) the injected
	// sidecars additionally hold CDS to. On TDX the launch measurement covers
	// TDVF firmware alone, so without these CDSMeasurements says nothing
	// about CDS's kernel or rootfs. Ignored for SNP evidence; empty pins no
	// registers.
	CDSRTMRs []string

	// CDSMeasurementsConfigJSON retains the complete identity policy for injected clients.
	CDSMeasurementsConfigJSON string

	// CertDir is the mount path for the shared cert volume.
	CertDir string

	// CertFSGroup is applied to the pod when it does not already specify
	// fsGroup. A negative value disables fsGroup mutation.
	CertFSGroup *int64

	// CertRenewInterval is passed to the renewal sidecar. Non-positive
	// values use the default interval.
	CertRenewInterval time.Duration

	// GetCertRunAsUser/Group/NonRoot configure injected get-cert identity.
	GetCertRunAsUser    *int64
	GetCertRunAsGroup   *int64
	GetCertRunAsNonRoot *bool

	// WorkloadClaimsHostDir, when set (node-CVM), is the host directory holding
	// the nri-image-policy inventory socket. That plugin bind-mounts the
	// directory at workloadclaims.SidecarSocketDir into the injected sidecars
	// (an NRI mount, never a pod-spec hostPath — PodSecurity baseline and
	// restricted forbid hostPath); the webhook injects --workload-claims so
	// get-cert redeems a sandbox token over that socket (docs/armtls.md).
	WorkloadClaimsHostDir string
}

// Register wires the pod mutator onto the manager's webhook server.
func Register(mgr ctrl.Manager, cfg Config) error {
	cfg = cfg.withDefaults()
	mgr.GetWebhookServer().Register("/mutate-pods", &admission.Webhook{
		Handler: &podMutator{
			decoder: admission.NewDecoder(mgr.GetScheme()),
			cfg:     cfg,
		},
	})
	return nil
}

type podMutator struct {
	decoder admission.Decoder
	cfg     Config
}

// injection captures everything the mutator decides from pod annotations.
type injection struct {
	WorkloadID string
	// SAN is the DNS SAN get-cert requests from CDS. The c8s-san annotation
	// sets it directly; otherwise Handle derives it from the workload id and
	// pod namespace (see workloadSAN), falling back to the id verbatim.
	SAN       string
	Cert      certSpec
	Reload    reloadSpec
	Discovery discoverySpec
	Security  getCertSecuritySpec
	Secrets   secretsSpec
	Volumes   volumesSpec
	Verbose   bool
}

// secretsSpec is the pod's secret request: which secrets, and where the files
// land. Empty Specs means no fetcher is injected.
type secretsSpec struct {
	Specs []string
	Dir   string
}

// volumesSpec is the pod's encrypted-volume request: which volumes, and where
// they are mounted. Empty Specs means no fetcher is injected.
type volumesSpec struct {
	Specs []string
	Dir   string
}

type certSpec struct {
	Volume        string
	Dir           string
	CertFile      string
	KeyFile       string
	CAFile        string
	RenewInterval time.Duration
}

type reloadSpec struct {
	Nginx          bool
	WatchPaths     []string
	WatchVolume    string
	WatchMountPath string
}

type discoverySpec struct {
	Volume        string
	MountPath     string
	Out           string
	CDSCertURL    string
	MeshCAURL     string
	PublicTLSMode string
}

type getCertSecuritySpec struct {
	RunAsUser    *int64
	RunAsGroup   *int64
	RunAsNonRoot *bool
}

// parseAnnotations returns nil if the pod isn't opted in.
func parseAnnotations(pod *corev1.Pod) (*injection, error) {
	annotations := pod.Annotations
	id := annotations[AnnotationWorkload]
	if id == "" {
		if hasInjectionDetailAnnotations(annotations) {
			return nil, fmt.Errorf("%w: %s is required when c8s injection detail annotations are set", errInvalidInjectionAnnotation, AnnotationWorkload)
		}
		return nil, nil
	}

	inj := &injection{
		WorkloadID: id,
		SAN:        strings.TrimSpace(annotations[AnnotationSAN]),
		Cert: certSpec{
			Volume:   annotations[AnnotationCertVolume],
			Dir:      annotations[AnnotationCertDir],
			CertFile: annotations[AnnotationCertFile],
			KeyFile:  annotations[AnnotationKeyFile],
			CAFile:   annotations[AnnotationCAFile],
		},
		Reload: reloadSpec{
			WatchVolume:    annotations[AnnotationReloadWatchVolume],
			WatchMountPath: annotations[AnnotationReloadWatchMountPath],
		},
		Secrets: secretsSpec{
			Specs: listAnnotation(annotations, AnnotationSecrets),
			Dir:   strings.TrimSpace(annotations[AnnotationSecretDir]),
		},
		Volumes: volumesSpec{
			Specs: listAnnotation(annotations, AnnotationVolumes),
			Dir:   strings.TrimSpace(annotations[AnnotationVolumeDir]),
		},
		Discovery: discoverySpec{
			Volume:        annotations[AnnotationDiscoveryVolume],
			MountPath:     annotations[AnnotationDiscoveryMountPath],
			Out:           annotations[AnnotationDiscoveryOut],
			CDSCertURL:    annotations[AnnotationDiscoveryCDSCertURL],
			MeshCAURL:     annotations[AnnotationDiscoveryMeshCAURL],
			PublicTLSMode: annotations[AnnotationDiscoveryPublicTLSMode],
		},
	}
	var err error
	if inj.Cert.RenewInterval, err = durationAnnotation(annotations, AnnotationRenewInterval); err != nil {
		return nil, err
	}
	if inj.Reload.Nginx, err = boolAnnotation(annotations, AnnotationReloadNginx); err != nil {
		return nil, err
	}
	if inj.Reload.WatchPaths = listAnnotation(annotations, AnnotationReloadWatchPaths); len(inj.Reload.WatchPaths) > 0 {
		inj.Reload.Nginx = true
	}
	if inj.Security.RunAsUser, err = int64Annotation(annotations, AnnotationGetCertRunAsUser); err != nil {
		return nil, err
	}
	if inj.Security.RunAsGroup, err = int64Annotation(annotations, AnnotationGetCertRunAsGroup); err != nil {
		return nil, err
	}
	if inj.Security.RunAsNonRoot, err = boolPtrAnnotation(annotations, AnnotationGetCertRunAsNonRoot); err != nil {
		return nil, err
	}
	if inj.Verbose, err = boolAnnotation(annotations, AnnotationGetCertVerbose); err != nil {
		return nil, err
	}
	if err := inj.validate(); err != nil {
		return nil, err
	}
	return inj, nil
}

func durationAnnotation(annotations map[string]string, name string) (time.Duration, error) {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return 0, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%w %s: %v", errInvalidInjectionAnnotation, name, err)
	}
	return parsed, nil
}

func int64Annotation(annotations map[string]string, name string) (*int64, error) {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errInvalidInjectionAnnotation, name, err)
	}
	return &parsed, nil
}

func boolPtrAnnotation(annotations map[string]string, name string) (*bool, error) {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errInvalidInjectionAnnotation, name, err)
	}
	return &parsed, nil
}

func boolAnnotation(annotations map[string]string, name string) (bool, error) {
	parsed, err := boolPtrAnnotation(annotations, name)
	if err != nil || parsed == nil {
		return false, err
	}
	return *parsed, nil
}

func listAnnotation(annotations map[string]string, name string) []string {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func hasInjectionDetailAnnotations(annotations map[string]string) bool {
	for _, name := range []string{
		AnnotationSAN,
		AnnotationCertVolume,
		AnnotationCertDir,
		AnnotationCertFile,
		AnnotationKeyFile,
		AnnotationCAFile,
		AnnotationRenewInterval,
		AnnotationReloadNginx,
		AnnotationReloadWatchPaths,
		AnnotationReloadWatchVolume,
		AnnotationReloadWatchMountPath,
		AnnotationDiscoveryVolume,
		AnnotationDiscoveryMountPath,
		AnnotationDiscoveryOut,
		AnnotationDiscoveryCDSCertURL,
		AnnotationDiscoveryMeshCAURL,
		AnnotationDiscoveryPublicTLSMode,
		AnnotationGetCertRunAsUser,
		AnnotationGetCertRunAsGroup,
		AnnotationGetCertRunAsNonRoot,
		AnnotationGetCertVerbose,
		AnnotationSecrets,
		AnnotationSecretDir,
		AnnotationVolumes,
		AnnotationVolumeDir,
	} {
		if annotations[name] != "" {
			return true
		}
	}
	return false
}

func (inj *injection) validate() error {
	if errs := validation.IsValidLabelValue(inj.WorkloadID); len(errs) > 0 {
		return fmt.Errorf("%w: %s must be a valid label value (mirrored as the %s pod label): %s",
			errInvalidInjectionAnnotation, AnnotationWorkload, LabelWorkload, strings.Join(errs, "; "))
	}
	if inj.SAN != "" {
		if errs := validation.IsDNS1123Subdomain(inj.SAN); len(errs) > 0 {
			return fmt.Errorf("%w: %s must be a valid DNS name: %s",
				errInvalidInjectionAnnotation, AnnotationSAN, strings.Join(errs, "; "))
		}
	}
	if inj.Cert.RenewInterval < 0 {
		return fmt.Errorf("%w: %s must not be negative", errInvalidInjectionAnnotation, AnnotationRenewInterval)
	}
	if err := inj.Reload.validate(); err != nil {
		return err
	}
	if err := inj.Discovery.validate(); err != nil {
		return err
	}
	if err := inj.Secrets.validate(); err != nil {
		return err
	}
	if err := inj.Volumes.validate(); err != nil {
		return err
	}
	return nil
}

// validate checks each NAME=/store/path pair against the rules get-secret
// enforces, so a spec the fetcher could never satisfy is a rejected manifest
// rather than a Running pod whose fetcher crash-loops. The name becomes a
// filename in the secret dir.
func (s secretsSpec) validate() error {
	seen := map[string]bool{}
	for _, spec := range s.Specs {
		name, path, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("%w: %s entry %q must be NAME=/store/path",
				errInvalidInjectionAnnotation, AnnotationSecrets, spec)
		}
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
			return fmt.Errorf("%w: %s name %q must be non-empty and not a path",
				errInvalidInjectionAnnotation, AnnotationSecrets, name)
		}
		if seen[name] {
			return fmt.Errorf("%w: %s names %q twice; each names a distinct file",
				errInvalidInjectionAnnotation, AnnotationSecrets, name)
		}
		seen[name] = true
		if _, err := pkgallowlist.CanonicalSecretPath(strings.TrimSpace(path)); err != nil {
			return fmt.Errorf("%w: %s %q: %s", errInvalidInjectionAnnotation, AnnotationSecrets, name, err)
		}
	}
	if s.Dir != "" && !strings.HasPrefix(s.Dir, "/") {
		return fmt.Errorf("%w: %s must be an absolute path",
			errInvalidInjectionAnnotation, AnnotationSecretDir)
	}
	return nil
}

// validate checks each NAME=/store/path pair. The name is rejected here rather
// than at the node so a spec the device lookup could never resolve does not
// reach a Running pod, and because it becomes a Kubernetes volume name.
func (v volumesSpec) validate() error {
	seen := map[string]bool{}
	for _, spec := range v.Specs {
		name, path, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("%w: %s entry %q must be NAME=/store/path",
				errInvalidInjectionAnnotation, AnnotationVolumes, spec)
		}
		name = strings.TrimSpace(name)
		if err := volume.ValidVolumeName(name); err != nil {
			return fmt.Errorf("%w: %s: %s", errInvalidInjectionAnnotation, AnnotationVolumes, err)
		}
		if seen[name] {
			return fmt.Errorf("%w: %s names %q twice; each is a distinct device and mount",
				errInvalidInjectionAnnotation, AnnotationVolumes, name)
		}
		seen[name] = true
		if _, err := pkgallowlist.CanonicalSecretPath(strings.TrimSpace(path)); err != nil {
			return fmt.Errorf("%w: %s %q: %s", errInvalidInjectionAnnotation, AnnotationVolumes, name, err)
		}
	}
	if v.Dir != "" && !strings.HasPrefix(v.Dir, "/") {
		return fmt.Errorf("%w: %s must be an absolute path", errInvalidInjectionAnnotation, AnnotationVolumeDir)
	}
	return nil
}

func (r reloadSpec) validate() error {
	if len(r.WatchPaths) == 0 {
		if r.WatchVolume != "" || r.WatchMountPath != "" {
			return fmt.Errorf("%w: %s requires %s", errInvalidInjectionAnnotation, AnnotationReloadWatchVolume, AnnotationReloadWatchPaths)
		}
		return nil
	}
	if r.WatchVolume == "" {
		return fmt.Errorf("%w: %s requires %s", errInvalidInjectionAnnotation, AnnotationReloadWatchPaths, AnnotationReloadWatchVolume)
	}
	if r.WatchMountPath == "" {
		return fmt.Errorf("%w: %s requires %s", errInvalidInjectionAnnotation, AnnotationReloadWatchPaths, AnnotationReloadWatchMountPath)
	}
	return nil
}

func (d discoverySpec) validate() error {
	if !d.configured() {
		return nil
	}

	var missing []string
	if d.Volume == "" {
		missing = append(missing, AnnotationDiscoveryVolume)
	}
	if d.MountPath == "" {
		missing = append(missing, AnnotationDiscoveryMountPath)
	}
	if d.Out == "" {
		missing = append(missing, AnnotationDiscoveryOut)
	}
	if d.CDSCertURL == "" {
		missing = append(missing, AnnotationDiscoveryCDSCertURL)
	}
	if d.PublicTLSMode == "" {
		missing = append(missing, AnnotationDiscoveryPublicTLSMode)
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: incomplete discovery annotations, missing %s", errInvalidInjectionAnnotation, strings.Join(missing, ", "))
	}

	switch d.PublicTLSMode {
	case discoveryPublicTLSModeCDS, discoveryPublicTLSModeWebPKI:
		return nil
	default:
		return fmt.Errorf("%w: %s must be %q or %q, got %q", errInvalidInjectionAnnotation, AnnotationDiscoveryPublicTLSMode, discoveryPublicTLSModeCDS, discoveryPublicTLSModeWebPKI, d.PublicTLSMode)
	}
}

func (d discoverySpec) configured() bool {
	return d.Volume != "" ||
		d.MountPath != "" ||
		d.Out != "" ||
		d.CDSCertURL != "" ||
		d.MeshCAURL != "" ||
		d.PublicTLSMode != ""
}

func (m *podMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	l := log.FromContext(ctx).WithValues("pod", req.Name, "ns", req.Namespace)

	pod := &corev1.Pod{}
	if err := m.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// An ephemeral container is attached to a running pod, so nothing here is
	// injected — the only decision is whether it may reach what the injected
	// containers already put on that pod.
	if req.SubResource == "ephemeralcontainers" {
		if err := rejectEphemeralReservedMounts(pod); err != nil {
			l.Info("denying ephemeral container", "reason", err.Error())
			return admission.Errored(http.StatusBadRequest, err)
		}
		return admission.Allowed("ephemeral container mounts no reserved c8s volume")
	}

	if err := validateWorkloadLabel(pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	inj, err := parseAnnotations(pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	// A hostNetwork pod shares the node IP, so it cannot be a mesh endpoint
	// and the cw inbound guard (which keys on distinct pod IPs) cannot cover
	// it: the confidential workload would serve plaintext on the node IP with
	// no interception and no drop. Reject the contradictory combination at
	// admission rather than let it onboard silently unprotected.
	if inj != nil && pod.Spec.HostNetwork {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf(
			"%w: %s pods must not set hostNetwork — a hostNetwork pod shares the node IP and cannot be mesh-intercepted or protected by the cw inbound guard",
			errInvalidInjectionAnnotation, AnnotationWorkload))
	}
	// The fetcher redeems a sandbox token from the mounted nri-image-policy
	// socket. An operator without it has nothing to point the fetcher at, so
	// injecting would produce a Running pod whose fetcher CrashLoops while the
	// workload blocks forever on a file that never lands. Refuse at admission.
	hasWorkloadClaimsEndpoint := m.cfg.WorkloadClaimsHostDir != ""
	if inj != nil && len(inj.Secrets.Specs) > 0 && !hasWorkloadClaimsEndpoint {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf(
			"%w: %s needs an admission inventory, which this operator is not configured with (node inventory not configured); see docs/secrets.md",
			errInvalidInjectionAnnotation, AnnotationSecrets))
	}
	// Same for volumes: the fetcher hands the key to volumed over the mounted
	// socket directory. An operator without it has no daemon to hand it to,
	// so the workload would wait on a mount that can never land (docs/volumes.md).
	if inj != nil && len(inj.Volumes.Specs) > 0 && !hasWorkloadClaimsEndpoint {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf(
			"%w: %s needs a volume daemon, which this operator is not configured with (node inventory not configured); see docs/volumes.md",
			errInvalidInjectionAnnotation, AnnotationVolumes))
	}
	if inj != nil && inj.SAN == "" {
		// req.Namespace, not pod.Namespace: template-created pods reach
		// admission with an empty metadata.namespace.
		inj.SAN = workloadSAN(inj.WorkloadID, req.Namespace)
	}

	// Injection is idempotent by reconstruction (mutatePod rebuilds the sidecar
	// every call), so it no longer keys off the confidential.ai/c8s-injected
	// marker: an author cannot skip injection by pre-setting it.
	if inj == nil {
		return admission.Allowed("no c8s annotation — passthrough")
	}
	getCertNeeded := m.cfg.GetCertImage != ""

	// Only the webhook may place a container under the reserved c8s-cert name.
	// The init sidecar is rebuilt below (injectInitContainers), but a
	// regular/ephemeral collision cannot be, so reject it: get-cert injection
	// integrity is name-based.
	if err := rejectReservedCertContainer(pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if getCertNeeded {
		// ensureVolume keeps a pre-declared same-named volume rather than
		// overwriting it, so a pod that declares the reserved cert volume as a
		// hostPath/PVC/disk-backed emptyDir would have its private keys written
		// to persistent, host-visible storage outside the TEE memory boundary.
		// Reject anything but the expected memory-backed emptyDir.
		if err := rejectReservedCertVolume(pod, inj.withDefaults(m.cfg).Cert.Volume); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		// Same reasoning for the released secrets: a hostPath here would write
		// them to host-visible storage.
		if err := rejectReservedSecretsVolume(pod); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		if err := rejectReservedVolumeVolume(pod); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		l.Info("injecting c8s get-cert containers", "workload", inj.WorkloadID)
		mutatePod(pod, inj, m.cfg)
	}

	raw, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
}

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

// validateWorkloadLabel rejects pods that set the confidential.ai/cw label
// out of band. The webhook stamps this label during injection and the
// operator-managed headless Services select on it, so a pod carrying it must
// also carry the matching opt-in annotation — otherwise an un-injected,
// un-attested pod could join a confidential workload's Service endpoints.
//
// CREATE-time check only. Post-create label mutation is denied by the
// cw-label-integrity ValidatingAdmissionPolicy (chart template
// cw-label-integrity-policy.yaml), which encodes this invariant in CEL plus
// UPDATE immutability. One deliberate difference: the CEL treats an empty
// label value as absent (it can never match a managed Service selector),
// while this check compares it against the annotation like any other value.
func validateWorkloadLabel(pod *corev1.Pod) error {
	label, ok := pod.Labels[LabelWorkload]
	if !ok {
		return nil
	}
	if pod.Annotations[AnnotationWorkload] != label {
		return fmt.Errorf("%w: pod label %s=%q must match the %s annotation (the webhook stamps this label during injection)",
			errInvalidInjectionAnnotation, LabelWorkload, label, AnnotationWorkload)
	}
	return nil
}

// mutatePod is pure — easy to unit test.
func mutatePod(pod *corev1.Pod, inj *injection, cfg Config) {
	cfg = cfg.withDefaults()
	effective := inj.withDefaults(cfg)
	if *cfg.CertFSGroup >= 0 {
		ensureFSGroup(pod, *cfg.CertFSGroup)
	}
	ensureVolume(pod, certsVolume(effective.Cert.Volume))
	if cfg.WorkloadClaimsHostDir != "" {
		// The inventory socket is group-owned by InventorySocketGID and the non-root
		// get-cert sidecar connects to it; without this supplemental group the
		// connect fails closed and the pod hangs on its initial cert.
		ensureSupplementalGroup(pod, workloadclaims.InventorySocketGID)
	}

	mountAll(pod, corev1.VolumeMount{
		Name:      effective.Cert.Volume,
		MountPath: effective.Cert.Dir,
		ReadOnly:  true,
	})

	if effective.Reload.Nginx {
		pod.Spec.ShareProcessNamespace = new(true)
	}

	injected := []corev1.Container{certContainer(&effective, cfg), certWaitContainer(&effective, cfg)}
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
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[LabelWorkload] = inj.WorkloadID
}

// certContainer is the workload's mesh-cert sidecar. It bootstraps the leaf
// cert from CDS on startup and keeps it fresh on a --renew-interval, SIGHUP-ing
// nginx after each renewal when --reload-nginx is on.
//
// Native sidecar (restartPolicy: Always) so it stays resident.
//
// --key-out is idempotent (load if a key already exists at the path, else
// generate-and-write); a fresh key on every restart would invalidate every
// cert CDS has previously issued for it.
func certContainer(inj *injection, cfg Config) corev1.Container {
	args := []string{
		"get-cert",
		"--cds-url=" + cfg.CDSURL,
		"--attestation-api-url=" + cfg.sidecarAttestationApiURL(),
		"--san=" + inj.SAN,
		"--out=" + certPath(inj.Cert.Dir, inj.Cert.CertFile),
		"--key-out=" + certPath(inj.Cert.Dir, inj.Cert.KeyFile),
		// The mesh CA alone (0644), next to the leaf+CA bundle in tls.crt: an
		// app that pins the CA as its own file (mysqld --ssl-ca, any client
		// doing VERIFY_CA against the mesh) reads it directly instead of
		// splitting the bundle in an entrypoint.
		"--ca-out=" + certPath(inj.Cert.Dir, inj.Cert.CAFile),
		"--renew-interval=" + inj.Cert.RenewInterval.String(),
		"--reload-nginx=" + strconv.FormatBool(inj.Reload.Nginx),
		"--continue-on-initial-error",
	}
	for _, path := range inj.Reload.WatchPaths {
		args = append(args, "--reload-watch="+path)
	}
	args = append(args, discoveryArgs(inj.Discovery)...)
	args = append(args, cdsPinArgs(cfg, true)...)
	// get-cert redeems a sandbox token from the node's inventory over the
	// mounted socket.
	if cfg.WorkloadClaimsHostDir != "" {
		args = append(args, "--workload-claims")
	}
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
		VolumeMounts:    getCertVolumeMounts(inj, true),
		SecurityContext: getCertSecurityContext(inj),
		// The workload is gated on the initial cert by the c8s-cert-wait
		// init container (certWaitContainer), not a startupProbe here: a
		// native sidecar is "started" the moment its process launches.
	}
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
			certPath(inj.Cert.Dir, inj.Cert.CertFile),
		},
		VolumeMounts:    getCertVolumeMounts(inj, false),
		SecurityContext: getCertSecurityContext(inj),
	}
}

func certPath(dir, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
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

func getCertVolumeMounts(inj *injection, includeReloadWatch bool) []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{Name: inj.Cert.Volume, MountPath: inj.Cert.Dir},
	}
	if inj.Discovery.Volume != "" && inj.Discovery.MountPath != "" {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      inj.Discovery.Volume,
			MountPath: inj.Discovery.MountPath,
		})
	}
	if includeReloadWatch && inj.Reload.WatchVolume != "" && inj.Reload.WatchMountPath != "" {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      inj.Reload.WatchVolume,
			MountPath: inj.Reload.WatchMountPath,
			ReadOnly:  true,
		})
	}
	return mounts
}

func getCertEnv(inj *injection) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "C8S_WORKLOAD_ID", Value: inj.WorkloadID},
		{Name: "C8S_POD_NAME", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
		}},
		{Name: "C8S_POD_UID", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"},
		}},
		// cvmMode=bare-metal: the chart passes the operator a verbatim
		// --attestation-api-url=http://$(HOST_IP):8400, which reaches this arg
		// (certContainer) through sidecarAttestationApiURL — its pass-through of
		// non-unix URLs is what keeps $(HOST_IP) unexpanded. The kubelet expands
		// $(HOST_IP) against THIS tenant pod's node, so the sidecar reaches the
		// node-baked host attestation-api on whichever node it lands. Unused
		// (harmless) in modes whose URL has no $(HOST_IP).
		{Name: "HOST_IP", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.hostIP"},
		}},
	}
}

func (inj *injection) withDefaults(cfg Config) injection {
	effective := *inj
	if effective.SAN == "" {
		effective.SAN = effective.WorkloadID
	}
	if effective.Cert.Volume == "" {
		effective.Cert.Volume = defaultCertVolumeName
	}
	if effective.Cert.Dir == "" {
		effective.Cert.Dir = cfg.CertDir
	}
	if effective.Cert.CertFile == "" {
		effective.Cert.CertFile = "tls.crt"
	}
	if effective.Cert.KeyFile == "" {
		effective.Cert.KeyFile = "tls.key"
	}
	if effective.Cert.CAFile == "" {
		effective.Cert.CAFile = "ca.crt"
	}
	if effective.Cert.RenewInterval <= 0 {
		effective.Cert.RenewInterval = cfg.CertRenewInterval
	}
	if effective.Secrets.Dir == "" {
		effective.Secrets.Dir = defaultSecretDir
	}
	if effective.Volumes.Dir == "" {
		effective.Volumes.Dir = defaultVolumeDir
	}
	if effective.Security.RunAsUser == nil {
		effective.Security.RunAsUser = cfg.GetCertRunAsUser
	}
	if effective.Security.RunAsGroup == nil {
		effective.Security.RunAsGroup = cfg.GetCertRunAsGroup
	}
	if effective.Security.RunAsNonRoot == nil {
		effective.Security.RunAsNonRoot = cfg.GetCertRunAsNonRoot
	}
	return effective
}

func (cfg Config) withDefaults() Config {
	if cfg.CertDir == "" {
		cfg.CertDir = "/etc/c8s/certs"
	}
	if cfg.CertFSGroup == nil {
		cfg.CertFSGroup = new(defaultCertFSGroup)
	}
	if cfg.CertRenewInterval <= 0 {
		cfg.CertRenewInterval = defaultCertRenewInterval
	}
	if cfg.GetCertRunAsUser == nil {
		cfg.GetCertRunAsUser = new(defaultGetCertRunAsUser)
	}
	if cfg.GetCertRunAsGroup == nil {
		cfg.GetCertRunAsGroup = new(defaultGetCertRunAsGroup)
	}
	if cfg.GetCertRunAsNonRoot == nil {
		cfg.GetCertRunAsNonRoot = new(defaultGetCertRunAsNonRoot)
	}
	return cfg
}

func getCertSecurityContext(inj *injection) *corev1.SecurityContext {
	falseValue := false
	trueValue := true
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &falseValue,
		ReadOnlyRootFilesystem:   &trueValue,
		RunAsNonRoot:             inj.Security.RunAsNonRoot,
		RunAsUser:                inj.Security.RunAsUser,
		RunAsGroup:               inj.Security.RunAsGroup,
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

// rejectEphemeralReservedMounts denies an ephemeral container that mounts a
// volume holding C8s material — the released secrets, or the pod's private key.
//
// The release check cannot help here: it gates the fetch, and by the time an
// ephemeral container is attached the file already exists. Without this,
// `kubectl debug` with any allowlisted image and a volumeMount reads a secret
// straight out of a live pod.
//
// Reserved container names are checked too. The pod-CREATE path already does
// that, but Kubernetes strips spec.ephemeralContainers at CREATE, so that check
// only ever runs against an empty list.
//
// On an injected pod no container may be targeted: every one mounts C8s
// material, and a target shares its process namespace, so a same-UID process
// reads its files through /proc/<pid>/root.
func rejectEphemeralReservedMounts(pod *corev1.Pod) error {
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
// what the injected sidecars mount, plus the cert volume the annotation names.
//
// The sidecars' own mounts are what makes this sound. AnnotationCertVolume
// stays mutable on a running pod — the mutating webhook intercepts CREATE and
// pods/ephemeralcontainers but not a plain pod UPDATE, and the
// cw-label-integrity VAP freezes only confidential.ai/cw — so a caller holding
// `patch pods` can rewrite it to name a decoy and then attach an ephemeral
// container mounting the volume that actually holds the leaf key. Reading the
// mounts off spec.initContainers, immutable after CREATE, closes that: the
// sidecar names the real volume whatever the annotation was rewritten to say.
//
// The annotation (or the default when unset) is still folded in, so a pod whose
// sidecars were never injected is judged exactly as before.
func reservedVolumeNames(pod *corev1.Pod) map[string]bool {
	certVolume := strings.TrimSpace(pod.Annotations[AnnotationCertVolume])
	if certVolume == "" {
		certVolume = defaultCertVolumeName
	}
	reserved := map[string]bool{secretsVolumeName: true, certVolume: true}
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

// rejectReservedSecretsVolume denies a pod that pre-declares the secrets volume
// as anything but the expected memory-backed emptyDir. ensureVolume keeps an
// existing same-named volume rather than overwriting it, so without this a pod
// spec could point it at a hostPath and have a CDS-released secret written to
// persistent, host-visible storage outside the TEE boundary. Omitting it is
// fine — the webhook injects it.
func rejectReservedSecretsVolume(pod *corev1.Pod) error {
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.Name != secretsVolumeName {
			continue
		}
		if v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory {
			return fmt.Errorf("%w: volume %q is reserved for released secrets; it must be a memory-backed emptyDir (medium: Memory) or omitted",
				errInvalidInjectionAnnotation, secretsVolumeName)
		}
	}
	return nil
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

// rejectReservedVolumeVolume denies a pod that pre-declares any volume under
// the reserved prefix as anything but the expected memory-backed emptyDir.
// Reserved by prefix rather than by re-deriving names from the annotation: the
// annotation is host-written, so a guard that reads it can be steered away from
// the name it is meant to protect.
func rejectReservedVolumeVolume(pod *corev1.Pod) error {
	want := corev1.StorageMediumDefault
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if !strings.HasPrefix(v.Name, volume.KubeVolumePrefix) {
			continue
		}
		if v.EmptyDir == nil || v.EmptyDir.Medium != want {
			return fmt.Errorf("%w: volume %q is reserved for an encrypted volume; it must be a %s-medium emptyDir or omitted (see openedVolume)",
				errInvalidInjectionAnnotation, v.Name, mediumName(want))
		}
	}
	return nil
}

func mediumName(m corev1.StorageMedium) string {
	if m == corev1.StorageMediumMemory {
		return "Memory"
	}
	return "default"
}

// volumeContainer is the workload's volume fetcher.
//
// A native sidecar ordered after c8s-cert-wait, like the secret fetcher and for
// the same reason: it authenticates with the leaf that sidecar writes, and CDS
// releases only once every main container is running.
func volumeContainer(inj *injection, cfg Config) corev1.Container {
	args := []string{
		"get-volume",
		"--cds-url=" + cfg.CDSURL,
		"--attestation-api-url=" + cfg.sidecarAttestationApiURL(),
		"--cert=" + certPath(inj.Cert.Dir, inj.Cert.CertFile),
		"--key=" + certPath(inj.Cert.Dir, inj.Cert.KeyFile),
	}
	for _, spec := range inj.Volumes.Specs {
		args = append(args, "--volume="+spec)
	}
	args = append(args, cdsPinArgs(cfg, false)...)

	always := corev1.ContainerRestartPolicyAlways
	return corev1.Container{
		Name:            reservedVolumeContainerName,
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		RestartPolicy:   &always,
		Args:            args,
		Env:             getCertEnv(inj),
		// It reads the leaf and talks to the node agent's socket; the volumes
		// themselves are mounted into the workload, not into this.
		VolumeMounts:    getCertVolumeMounts(inj, false),
		SecurityContext: getCertSecurityContext(inj),
	}
}

// secretContainer is the workload's secret fetcher.
//
// A native sidecar (restartPolicy: Always), and ordered after c8s-cert-wait so
// the leaf it authenticates with is already on disk. It cannot be a plain init
// container: CDS releases only once every main container is running, so an init
// container would be asking before its siblings exist and would deadlock the
// pod it is gating (docs/secrets.md).
func secretContainer(inj *injection, cfg Config) corev1.Container {
	args := []string{
		"get-secret",
		"--cds-url=" + cfg.CDSURL,
		"--attestation-api-url=" + cfg.sidecarAttestationApiURL(),
		"--cert=" + certPath(inj.Cert.Dir, inj.Cert.CertFile),
		"--key=" + certPath(inj.Cert.Dir, inj.Cert.KeyFile),
		"--out-dir=" + inj.Secrets.Dir,
	}
	for _, spec := range inj.Secrets.Specs {
		args = append(args, "--secret="+spec)
	}
	args = append(args, cdsPinArgs(cfg, false)...)

	always := corev1.ContainerRestartPolicyAlways
	return corev1.Container{
		Name:            reservedSecretContainerName,
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		RestartPolicy:   &always,
		Args:            args,
		Env:             getCertEnv(inj),
		// The only container with write access: the shared directory is
		// readable pod-wide by design, but a workload able to write it could
		// replace a value another container has yet to read.
		VolumeMounts: append(getCertVolumeMounts(inj, false), corev1.VolumeMount{
			Name:      secretsVolumeName,
			MountPath: inj.Secrets.Dir,
		}),
		SecurityContext: getCertSecurityContext(inj),
	}
}

func certsVolume(name string) corev1.Volume {
	return corev1.Volume{
		Name:     name,
		EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
	}
}

// sidecarAttestationApiURL rebases a unix:// attestation-api endpoint under
// the inventory's host directory onto the sidecar's NRI-injected mount of that
// directory (workloadclaims.SidecarSocketDir); every other shape passes
// through verbatim.
func (cfg Config) sidecarAttestationApiURL() string {
	hostPrefix := "unix://" + cfg.WorkloadClaimsHostDir + "/"
	if cfg.WorkloadClaimsHostDir == "" || !strings.HasPrefix(cfg.AttestationApiURL, hostPrefix) {
		return cfg.AttestationApiURL
	}
	return "unix://" + workloadclaims.SidecarSocketDir + "/" + strings.TrimPrefix(cfg.AttestationApiURL, hostPrefix)
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
// order, and drops any existing init container that collides with an injected
// name. Injection is therefore idempotent (a reinvocation rebuilds the same
// list) and a pre-declared c8s-cert/c8s-cert-wait cannot shed or shadow the
// real ones — the operator-built containers always win. Order matters:
// c8s-cert leads, then c8s-cert-wait gates the workload on the initial cert
// (see certWaitContainer), then the pod's own init containers.
func injectInitContainers(existing []corev1.Container, injected ...corev1.Container) []corev1.Container {
	reserved := make(map[string]struct{}, len(injected))
	for _, c := range injected {
		reserved[c.Name] = struct{}{}
	}
	out := make([]corev1.Container, 0, len(existing)+len(injected))
	out = append(out, injected...)
	for _, ec := range existing {
		if _, ok := reserved[ec.Name]; !ok {
			out = append(out, ec)
		}
	}
	return out
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

// rejectReservedCertVolume denies a pod that pre-declares the reserved cert
// volume as anything other than the expected memory-backed emptyDir (see
// certsVolume). ensureVolume keeps an existing same-named volume instead of
// overwriting it, so without this guard an author could point the cert volume
// at a hostPath, PVC, or disk-backed emptyDir and have the injected sidecar
// write private keys to persistent, host-visible storage outside the TEE
// memory boundary. Omitting the volume is fine — the webhook injects it.
func rejectReservedCertVolume(pod *corev1.Pod, volName string) error {
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.Name != volName {
			continue
		}
		if v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory {
			return fmt.Errorf("%w: volume %q is reserved for the injected in-memory cert store; it must be a memory-backed emptyDir (medium: Memory) or omitted",
				errInvalidInjectionAnnotation, volName)
		}
	}
	return nil
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

// cdsPinArgs propagates the complete CDS identity without weakening operator
// pins into a digest-only policy. Independent digest/register inputs use
// their corresponding flags.
func cdsPinArgs(cfg Config, certificate bool) []string {
	if cfg.CDSMeasurementsConfigJSON != "" {
		return []string{"--image-policy-json=" + cfg.CDSMeasurementsConfigJSON}
	}
	var args []string
	if certificate {
		if joined := strings.Join(cfg.CDSMeasurements, ","); joined != "" {
			args = append(args, "--cds-measurements="+joined)
		}
		if joined := strings.Join(cfg.CDSRTMRs, ","); joined != "" {
			args = append(args, "--cds-rtmrs="+joined)
		}
		return args
	}
	for _, m := range cfg.CDSMeasurements {
		args = append(args, "--measurements="+m)
	}
	for _, r := range cfg.CDSRTMRs {
		args = append(args, "--rtmrs="+r)
	}
	return args
}
