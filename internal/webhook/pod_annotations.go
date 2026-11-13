package webhook

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// injection captures everything the mutator decides from pod annotations.
type injection struct {
	WorkloadID string
	// SAN is the DNS SAN get-cert requests from CDS. The c8s-san annotation
	// sets it directly; otherwise Handle derives it from the workload id and
	// pod namespace (see workloadSAN), falling back to the id verbatim.
	SAN       string
	Cert      certSpec
	Discovery discoverySpec
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
	RenewInterval time.Duration
}

type discoverySpec struct {
	Volume        string
	MountPath     string
	Out           string
	CDSCertURL    string
	MeshCAURL     string
	PublicTLSMode string
}

// pinnedDestinations are the annotations that used to move a sidecar mount.
// Each is refused unless it names the fixed destination.
var pinnedDestinations = []struct{ annotation, path string }{
	{AnnotationCertDir, CertDir},
	{AnnotationSecretDir, defaultSecretDir},
	{AnnotationDiscoveryMountPath, discoveryMountPath},
}

// parseAnnotations reads the pod's injection request. Both webhooks derive the
// injected shape from it, so the same pod yields the same shape in each.
func parseAnnotations(pod *corev1.Pod, namespace string) (*injection, error) {
	annotations := pod.Annotations
	id := annotations[AnnotationWorkload]
	if id == "" && hasInjectionDetailAnnotations(annotations) {
		return nil, fmt.Errorf("%w: %s is required when c8s injection detail annotations are set", errInvalidInjectionAnnotation, AnnotationWorkload)
	}

	for _, pinned := range pinnedDestinations {
		if value := strings.TrimSpace(annotations[pinned.annotation]); value != "" && value != pinned.path {
			return nil, fmt.Errorf("%w: %s is no longer supported: the C8s sidecars mount at %s, which the allowlist pins; remove the annotation and read the files there",
				errInvalidInjectionAnnotation, pinned.annotation, pinned.path)
		}
	}

	inj := &injection{
		WorkloadID: id,
		SAN:        selectSAN(annotations, id, namespace),
		Secrets: secretsSpec{
			Specs: workloadclaims.SplitList(annotations[AnnotationSecrets]),
		},
		Volumes: volumesSpec{
			Specs: workloadclaims.SplitList(annotations[AnnotationVolumes]),
			Dir:   strings.TrimSpace(annotations[AnnotationVolumeDir]),
		},
		Discovery: discoverySpec{
			Volume:        annotations[AnnotationDiscoveryVolume],
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
	if inj.Verbose, err = boolAnnotation(annotations, AnnotationGetCertVerbose); err != nil {
		return nil, err
	}
	if err := inj.validate(); err != nil {
		return nil, err
	}
	return inj, nil
}

// selectSAN is the one SAN get-cert requests for this pod. A pod without the cw
// annotation requests none even when c8s-san names one: c8s-san
// refines an identity the pod opted in to, and cannot grant one.
func selectSAN(annotations map[string]string, workloadID, namespace string) string {
	if workloadID == "" {
		return sanNone
	}
	if san := strings.TrimSpace(annotations[AnnotationSAN]); san != "" {
		return san
	}
	// namespace comes from the admission request: a template-created pod
	// reaches admission with an empty metadata.namespace.
	return workloadSAN(workloadID, namespace)
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

func boolAnnotation(annotations map[string]string, name string) (bool, error) {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%w %s: %v", errInvalidInjectionAnnotation, name, err)
	}
	return parsed, nil
}

func hasInjectionDetailAnnotations(annotations map[string]string) bool {
	for _, name := range []string{
		AnnotationRenewInterval,
		AnnotationDiscoveryVolume,
		AnnotationDiscoveryMountPath,
		AnnotationDiscoveryOut,
		AnnotationDiscoveryCDSCertURL,
		AnnotationDiscoveryMeshCAURL,
		AnnotationDiscoveryPublicTLSMode,
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
	if err := inj.Discovery.validate(); err != nil {
		return err
	}
	if err := inj.validateDiscoveryVolume(); err != nil {
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
	if v.Dir == "" {
		return nil
	}
	// A secrets grant needs every mount pinned by an exact rule, and a data
	// rule can only name a destination below the data prefix.
	dir, root := filepath.Clean(v.Dir), strings.TrimSuffix(pkgallowlist.DataMountPrefix, "/")
	if dir != root && !below(dir, root) {
		return fmt.Errorf("%w: %s must be an absolute path at or below %s, where an allowlist data rule can pin the mount",
			errInvalidInjectionAnnotation, AnnotationVolumeDir, pkgallowlist.DataMountPrefix)
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

	// Directly in the mount, so the directory get-cert opens to write is the
	// mount point: a subdirectory the workload controls could be a symlink
	// into the cert or secrets volume.
	if !below(d.Out, discoveryMountPath) || filepath.Dir(filepath.Clean(d.Out)) != discoveryMountPath {
		return fmt.Errorf("%w: %s %q must name a file directly in %s, where get-cert mounts the discovery volume",
			errInvalidInjectionAnnotation, AnnotationDiscoveryOut, d.Out, discoveryMountPath)
	}

	switch types.FrontDoorMode(d.PublicTLSMode) {
	case types.FrontDoorModeCDS, types.FrontDoorModeWebPKI:
		return nil
	default:
		return fmt.Errorf("%w: %s must be %q or %q, got %q", errInvalidInjectionAnnotation, AnnotationDiscoveryPublicTLSMode, types.FrontDoorModeCDS, types.FrontDoorModeWebPKI, d.PublicTLSMode)
	}
}

// validateDiscoveryVolume refuses a discovery volume that is also the cert,
// secrets or an encrypted volume: get-cert writes the discovery document into
// it, which would overwrite the key or a released value at the same name.
func (inj *injection) validateDiscoveryVolume() error {
	name := inj.Discovery.Volume
	if name == "" {
		return nil
	}
	if name == CertVolumeName || name == secretsVolumeName || strings.HasPrefix(name, volume.KubeVolumePrefix) {
		return fmt.Errorf("%w: %s %q is reserved for c8s; name a volume of its own",
			errInvalidInjectionAnnotation, AnnotationDiscoveryVolume, name)
	}
	return nil
}

func (d discoverySpec) configured() bool {
	return d.Volume != "" ||
		d.Out != "" ||
		d.CDSCertURL != "" ||
		d.MeshCAURL != "" ||
		d.PublicTLSMode != ""
}

// below reports whether path names a file strictly inside dir.
func below(path, dir string) bool {
	return filepath.IsAbs(path) && strings.HasPrefix(filepath.Clean(path), dir+"/")
}
