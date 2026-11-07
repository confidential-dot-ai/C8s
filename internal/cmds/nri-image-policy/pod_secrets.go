package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Pod secret delivery (POC; workload attestation Q1). The signed pod manifest
// names the secrets its pod reads in podSecretsAnnotation. Once the pod's
// snapshot matches a CDS secrets grant, the guest broker writes each value
// into the pod's memory emptyDir podSecretVolume. Only workload containers
// whose image the releasing grant names may mount that volume, read-only.
// One fetch per pod: no rotation, no refresh.
const (
	podSecretsAnnotation = "confidential.ai/pod-secrets"
	podSecretVolume      = "c8s-pod-secrets"
	podSecretFileMode    = 0o444
	podSecretRetry       = 30 * time.Second
	maxPodSecrets        = 8
)

// podSecretState is guest-owned; plugin.podMu guards it.
type podSecretState struct {
	changes chan struct{}
	// readers are the image digests of containers admitted with the volume.
	readers map[string]bool
	// granted is nil until publication, then the digests every released
	// grant names: the only images a later container may read it from.
	granted map[string]bool
}

type podSecretRequest struct {
	name string
	path string
}

var (
	openPodSecretRoot = openVerifiedPodSecretRoot
	podSecretFetch    = workloadclaims.ObtainPodSecretContext
)

// podSecretRequests parses the manifest's NAME=/store/path[,NAME=/store/path]
// list. The kubelet runs the static pod the signed assignment carries, so the
// annotation is the assignment's.
func podSecretRequests(pod *api.PodSandbox) ([]podSecretRequest, error) {
	raw := strings.TrimSpace(pod.GetAnnotations()[podSecretsAnnotation])
	if raw == "" {
		return nil, nil
	}
	var out []podSecretRequest
	seen := map[string]bool{}
	for spec := range strings.SplitSeq(raw, ",") {
		name, p, ok := strings.Cut(strings.TrimSpace(spec), "=")
		if !ok || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || seen[name] {
			return nil, fmt.Errorf("%s: %q must be NAME=/store/path with a distinct file name", podSecretsAnnotation, spec)
		}
		canonical, err := allowlist.CanonicalSecretPath(p)
		if err != nil || canonical != p {
			return nil, fmt.Errorf("%s: secret %q needs a canonical store path", podSecretsAnnotation, name)
		}
		seen[name] = true
		out = append(out, podSecretRequest{name: name, path: canonical})
	}
	if len(out) > maxPodSecrets {
		return nil, fmt.Errorf("%s names more than %d secrets", podSecretsAnnotation, maxPodSecrets)
	}
	return out, nil
}

func podSecretSource(pod *api.PodSandbox) string {
	return kubeletRoot + "/pods/" + pod.GetUid() + "/volumes/" + emptyDirPlugin + "/" + podSecretVolume
}

// podSecretReader checks a container's final mounts against the secret
// volume, as podCredentialSource does for the mesh credentials: a platform
// container never mounts it, a workload container only read-only, only the
// exact volume and never through a parent bind, and after publication only
// from an image the releasing grant names. record notes the image as a
// reader; the caller holds podMu.
func (p *plugin) podSecretReader(pod *api.PodSandbox, ctr *api.Container, role, digest string, mounts []allowlist.ObservedMount, record bool) error {
	if !p.cfg.podRole() || strings.ContainsAny(pod.GetUid(), "/\\") || pod.GetUid() == "" {
		return nil
	}
	base := podSecretSource(pod)
	reads := false
	for _, mount := range ctr.GetMounts() {
		src := path.Clean(mount.GetSource())
		parent := path.IsAbs(src) && (src == "/" || strings.HasPrefix(base, src+"/"))
		if src != base && !strings.HasPrefix(src, base+"/") && !parent {
			continue
		}
		if role != "" || mount.GetSource() != base || !fileBind(mount) || !endsReadOnly(mount) {
			return errors.New("only a workload container may mount the exact Pod secret volume, read-only")
		}
		reads = true
	}
	verified := false
	for _, mount := range mounts {
		if mount.Volume != podSecretVolume {
			continue
		}
		if role != "" || mount.Class != allowlist.MountEmptyDir || mount.Storage != allowlist.MountMemory || !mount.ReadOnly {
			return errors.New("the Pod secret mount must be a read-only memory emptyDir of a workload container")
		}
		verified = true
	}
	if reads && !verified {
		return errors.New("the Pod secret volume has no verified memory-backed mount evidence")
	}
	if !reads {
		return nil
	}
	if requests, err := podSecretRequests(pod); err != nil || len(requests) == 0 {
		return errors.New("the Pod secret volume is mounted but the manifest requests no secret")
	}
	b := p.podBroker
	if b == nil || b.secrets == nil {
		return errors.New("pod secret broker was not initialized")
	}
	if b.secrets.granted != nil && !b.secrets.granted[digest] {
		return errors.New("the released Pod secret grant does not name this container's image")
	}
	if record {
		b.secrets.readers[digest] = true
	}
	return nil
}

// runPodSecretWorker fetches the manifest's secrets once, retrying on each
// snapshot change: a grant matches only the complete workload image set, so
// release succeeds once the last granted container is admitted. Consumers
// wait for their file, as node get-secret consumers do.
func (p *plugin) runPodSecretWorker() {
	b := p.podBroker
	if b.secrets == nil {
		return
	}
	requests, err := podSecretRequests(b.pod)
	if err != nil {
		p.logger.Error("Pod secrets not requested", "error", err)
		return
	}
	if len(requests) == 0 {
		return
	}
	client := attestclient.NewClientWithHTTP(p.cfg.pullURL(), b.client)
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			done, err := p.fetchPodSecrets(b.ctx, client, requests)
			if done {
				if err != nil {
					p.logger.Error("Pod secrets will not be delivered", "error", err)
				}
				return
			}
			if err != nil && b.ctx.Err() == nil {
				p.logger.Info("Pod secrets not yet released", "error", err)
			}
			select {
			case <-b.ctx.Done():
				return
			case <-b.secrets.changes:
			case <-time.After(podSecretRetry):
			}
		}
	}()
}

// fetchPodSecrets reports done once the secrets are published or can never
// be.
func (p *plugin) fetchPodSecrets(ctx context.Context, client attestclient.Client, requests []podSecretRequest) (bool, error) {
	claims, err := p.podSnapshot(ctx)
	if err != nil {
		return false, err
	}
	released := make([]workloadclaims.PodSecret, 0, len(requests))
	for _, r := range requests {
		s, err := podSecretFetch(ctx, client, p.cfg.Allowlist.Pull.AttestationApiURL, r.path, claims)
		if err != nil {
			return false, fmt.Errorf("secret %s: %w", r.name, err)
		}
		released = append(released, s)
	}
	p.podMu.Lock()
	defer p.podMu.Unlock()
	current, err := p.podSnapshotLocked()
	if err != nil {
		return false, err
	}
	if current.Revision != claims.Revision || current.InstanceID() != claims.InstanceID() {
		return false, errors.New("pod admission changed during secret release")
	}
	b := p.podBroker
	root, err := openPodSecretRoot(podSecretSource(b.pod))
	if err != nil {
		return false, err
	}
	defer root.Close()
	if err := b.secrets.publish(root, requests, released); err != nil {
		return errors.Is(err, errPodSecretReader), err
	}
	p.logger.Info("Pod secrets delivered", "count", len(requests), "workload", released[0].Workload)
	return true, nil
}

var errPodSecretReader = errors.New("a container mounting the secret volume is not named by every released grant")

// publish writes the released values once every container admitted with the
// volume runs an image all releasing grants name, and then holds later
// admissions to those images.
func (s *podSecretState) publish(root *os.Root, requests []podSecretRequest, released []workloadclaims.PodSecret) error {
	granted := map[string]bool{}
	for _, d := range released[0].Readers {
		granted[d] = true
	}
	for _, r := range released[1:] {
		for d := range granted {
			if !slices.Contains(r.Readers, d) {
				delete(granted, d)
			}
		}
	}
	for d := range s.readers {
		if !granted[d] {
			return fmt.Errorf("%w: image %s", errPodSecretReader, d)
		}
	}
	for i, r := range requests {
		if err := fileutil.WriteAtomicRoot(root, r.name, released[i].Value, podSecretFileMode); err != nil {
			return fmt.Errorf("write Pod secret %s: %w", r.name, err)
		}
	}
	s.granted = granted
	return nil
}
