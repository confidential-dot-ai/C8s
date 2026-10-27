package nriimagepolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const podBrokerMarker = "pod-credential-instance"

// podCredentialBroker is guest-owned. Only the issued TLS generation crosses
// into the endpoint's volume; the inventory, quote access and boot identity do
// not become services a Pod container can call. plugin.podMu guards its state.
type podCredentialBroker struct {
	ctx      context.Context
	cancel   context.CancelFunc
	client   *http.Client
	runtime  *os.Root
	bootID   string
	pod      *api.PodSandbox
	root     *os.Root
	changes  chan struct{}
	terminal error
	wg       sync.WaitGroup
}

var runGuestCredentials = getcert.RunGuest

func (p *plugin) lockPodAdmission() func() {
	if p.cfg.Pod == nil {
		return func() {}
	}
	p.podMu.Lock()
	return p.podMu.Unlock
}

func (p *plugin) afterPodStart(pod *api.PodSandbox, source string) error {
	if p.cfg.Pod == nil {
		return nil
	}
	if source != "" {
		claiming := p.podBroker != nil && p.podBroker.pod == nil
		if err := p.startPodCredentials(pod, source); err != nil {
			return p.denyContainer(pod.GetId(), err)
		}
		if claiming {
			// The worker's first issuance reads the snapshot this start is
			// already in.
			return nil
		}
	}
	p.podChanged()
	return nil
}

func (p *plugin) preparePodBroker(ctx context.Context, client *http.Client) error {
	if p.cfg.Pod == nil {
		return nil
	}
	if client == nil {
		return errors.New("pod broker has no authenticated CDS client")
	}
	pins, err := p.cfg.Allowlist.Pull.policySet(p.cfg.NormalizedPlatform())
	if err != nil {
		return fmt.Errorf("pod broker CDS pins: %w", err)
	}
	if pins.Empty() {
		return errors.New("pod broker requires pinned CDS server trust")
	}
	runtime, err := os.OpenRoot(p.cfg.WorkloadClaims.SocketDir)
	if err != nil {
		return fmt.Errorf("open Pod broker state: %w", err)
	}
	if err := fileutil.RequireRAMBackedRoot(runtime); err != nil {
		runtime.Close()
		return err
	}
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		runtime.Close()
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	p.podBroker = &podCredentialBroker{ctx: ctx, cancel: cancel, client: client, runtime: runtime, bootID: hex.EncodeToString(id[:]), changes: make(chan struct{}, 1)}
	return nil
}

func (p *plugin) closePodBroker() {
	if b := p.podBroker; b != nil {
		b.cancel()
		b.wg.Wait()
		if b.root != nil {
			_ = b.root.Close()
		}
		_ = b.runtime.Close()
	}
}

// podChanged is called under podMu after an admission or lifecycle change.
// podChanged wakes the broker to issue from a new snapshot. Its callers are
// the events that change the claims or end the identity: an admitted start,
// a denial and the sandbox's removal. A stop or a removal of a container
// changes no claim (the history keeps the admission), so neither wakes it.
func (p *plugin) podChanged() {
	if b := p.podBroker; b != nil {
		select {
		case b.changes <- struct{}{}:
		default:
		}
	}
}

func (p *plugin) endPodIdentity(reason error) {
	clear(p.podStarts)
	if b := p.podBroker; b != nil {
		if b.terminal == nil {
			b.terminal = reason
		}
		b.cancel()
	}
}

// startPodCredentials follows measurement and inventory recording. The
// exclusive boot marker prevents a restart from issuing from incomplete
// reconstructed history, including a restart while no sandbox is live.
func (p *plugin) startPodCredentials(pod *api.PodSandbox, source string) error {
	b := p.podBroker
	if b == nil {
		return errors.New("pod credential broker was not initialized")
	}
	if b.terminal != nil {
		return b.terminal
	}
	if b.pod != nil {
		if b.pod.GetId() != pod.GetId() || b.pod.GetUid() != pod.GetUid() {
			return errors.New("pod sandbox changed after the boot identity was claimed")
		}
		return samePodCredentialRoot(b.root, source)
	}
	if p.bootRestart.Load() {
		return errors.New("pod credentials cannot use reconstructed admission history; a new guest boot is required")
	}
	root, err := openPodCredentialRoot(source)
	if err != nil {
		return err
	}
	marker, err := b.runtime.OpenFile(podBrokerMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		root.Close()
		return fmt.Errorf("claim fresh Pod boot identity: %w", err)
	}
	_, writeErr := marker.WriteString(b.bootID + "\n")
	if err := errors.Join(writeErr, marker.Close()); err != nil {
		root.Close()
		return fmt.Errorf("record Pod boot identity: %w", err)
	}
	b.root = root
	b.pod = proto.Clone(pod).(*api.PodSandbox)
	identity := workloadclaims.PodClaims{BootID: b.bootID, RuntimePodUID: pod.GetUid(), SandboxID: pod.GetId()}.InstanceID()
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		err := runGuestCredentials(b.ctx, getcert.GuestConfig{
			CDSURL: p.cfg.Allowlist.Pull.URL, AttestationAPIURL: p.cfg.Allowlist.Pull.AttestationApiURL,
			HTTPClient: b.client, VolumeRoot: root, InstanceID: identity,
			Snapshot: p.podSnapshot, Commit: p.commitPodCredentials, Changes: b.changes,
		})
		if err != nil && b.ctx.Err() == nil {
			p.logger.Error("Pod credential worker stopped", "error", err)
			p.podMu.Lock()
			p.endPodIdentity(err)
			p.podMu.Unlock()
		}
	}()
	return nil
}

func (p *plugin) podSnapshot(ctx context.Context) (workloadclaims.PodClaims, error) {
	p.podMu.Lock()
	defer p.podMu.Unlock()
	if err := ctx.Err(); err != nil {
		return workloadclaims.PodClaims{}, err
	}
	return p.podSnapshotLocked()
}

func (p *plugin) podSnapshotLocked() (workloadclaims.PodClaims, error) {
	b := p.podBroker
	if b == nil || b.pod == nil {
		return workloadclaims.PodClaims{}, errors.New("no measured Pod endpoint")
	}
	if b.terminal != nil {
		return workloadclaims.PodClaims{}, b.terminal
	}
	if err := b.ctx.Err(); err != nil {
		return workloadclaims.PodClaims{}, err
	}
	if err := p.inventory.denial(b.pod.GetId()); err != nil {
		return workloadclaims.PodClaims{}, err
	}
	if err := p.mesh.verifyMember(b.pod.GetId()); err != nil {
		return p.podSnapshotLost(err)
	}
	containers, revision, err := p.inventory.podSnapshot(b.pod.GetId())
	if err != nil {
		return p.podSnapshotLost(err)
	}
	if p.measurer == nil {
		return p.podSnapshotLost(errors.New("pod broker has no runtime journal"))
	}
	claims := workloadclaims.PodClaims{Version: 1, BootID: b.bootID, AssignedPodUID: p.cfg.Pod.UID,
		RuntimePodUID: b.pod.GetUid(), SandboxID: b.pod.GetId(), Revision: revision,
		RuntimeExtensions: p.measurer.Digests(), Containers: containers}
	if _, err := claims.Canonical(); err != nil {
		return p.podSnapshotLost(err)
	}
	return claims, nil
}

func (p *plugin) podSnapshotLost(err error) (workloadclaims.PodClaims, error) {
	p.endPodIdentity(err)
	return workloadclaims.PodClaims{}, err
}

// commitPodCredentials serializes the final local publication with admission.
// No network call runs under this lock; a response to an old snapshot cannot
// replace the generation after another container has been admitted.
func (p *plugin) commitPodCredentials(claims workloadclaims.PodClaims, publish func() error) error {
	p.podMu.Lock()
	defer p.podMu.Unlock()
	current, err := p.podSnapshotLocked()
	if err != nil {
		return err
	}
	if current.Revision != claims.Revision || current.InstanceID() != claims.InstanceID() {
		return errors.New("pod admission changed during credential issuance")
	}
	return publish()
}

// podCredentialSource checks the final mount table independently of a tenant's
// allowlist. A broad mounts policy must never hand it the platform's key.
func (p *plugin) podCredentialSource(pod *api.PodSandbox, ctr *api.Container, role string, mounts []allowlist.ObservedMount) (string, error) {
	if p.cfg.Pod == nil {
		return "", nil
	}
	if pod.GetNamespace() != p.cfg.Pod.Namespace || pod.GetName() != p.cfg.Pod.Name || pod.GetUid() == "" || pod.GetId() == "" {
		return "", errors.New("runtime Pod does not match the staged Pod identity")
	}
	if b := p.podBroker; b != nil && b.terminal != nil {
		return "", b.terminal
	}
	base := kubeletRoot + "/pods/" + pod.GetUid() + "/volumes/" + emptyDirPlugin + "/" + podmesh.CertVolumeName
	if !cleanAbsolute(base) || strings.ContainsAny(pod.GetUid(), "/\\") {
		return "", errors.New("invalid runtime Pod UID")
	}
	var source string
	for _, mount := range ctr.GetMounts() {
		src := path.Clean(mount.GetSource())
		// A bind of a parent directory exposes the key just as a direct bind
		// does, even if a broad tenant mount policy admits that parent.
		containsCredentials := path.IsAbs(src) && (src == "/" || strings.HasPrefix(base, src+"/"))
		reserved := src == base || strings.HasPrefix(src, base+"/") || containsCredentials || mount.GetDestination() == podmesh.CertDir
		if !reserved {
			continue
		}
		if role != meshRole || source != "" || mount.GetSource() != base || mount.GetDestination() != podmesh.CertDir || !fileBind(mount) || !endsReadOnly(mount) {
			return "", errors.New("only the measured mesh endpoint may read the exact private credential volume")
		}
		source = base
	}
	verified := false
	for _, mount := range mounts {
		if mount.Volume != podmesh.CertVolumeName {
			continue
		}
		if role != meshRole || mount.Destination != podmesh.CertDir || mount.Class != allowlist.MountEmptyDir || mount.Storage != allowlist.MountMemory || !mount.ReadOnly {
			return "", errors.New("the mesh credential mount must be a read-only memory emptyDir")
		}
		verified = true
	}
	if role == meshRole && source == "" {
		return "", errors.New("the measured mesh endpoint has no private credential volume")
	}
	if source != "" && !verified {
		return "", errors.New("the credential volume has no verified memory-backed mount evidence")
	}
	return source, nil
}
