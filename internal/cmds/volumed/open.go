package volumed

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

// cleanupTimeout bounds an unwind that no longer has a caller waiting on it.
const cleanupTimeout = 30 * time.Second

// cleanupContext detaches the unwind from the caller's cancellation.
//
// INVARIANT: every device-mapper target this daemon creates is either owned by
// a live mount or removed. A fetcher whose request deadline expires mid-open
// cancels ctx, and closing a mapping needs a live context to run cryptsetup —
// so unwinding on the caller's ctx cannot remove what the open already created,
// and the leaked mapper name fails every retry with "already exists".
func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

// DeviceOps are the privileged steps. Behind an interface so the orchestration
// and every unwind path are exercised without device-mapper.
//
// Each Open has a matching Close, and the orchestration calls Close for every
// step it completed when a later one fails.
type DeviceOps interface {
	CryptOpen(ctx context.Context, device, mapper string, key []byte, readOnly bool) error
	CryptClose(ctx context.Context, mapper string) error
	VerityOpen(ctx context.Context, dataDev, mapper string, v volume.Verity) error
	VerityClose(ctx context.Context, mapper string) error
	// MountRO and MountRW take the resolved target as an open handle rather
	// than a path: the implementation mounts through /proc/self/fd so nothing
	// can be swapped between resolving the target and using it. Unmount takes
	// a path, because by teardown that handle is long closed.
	MountRO(ctx context.Context, source string, target *os.File, fsType string) error
	MountRW(ctx context.Context, source string, target *os.File, fsType string) error
	Unmount(ctx context.Context, target string) error
	// ListMappings names the device-mapper targets published on this node.
	ListMappings(ctx context.Context) ([]string, error)
}

// ErrNotAuthorized is returned when a caller presents the wrong key for a
// volume already open under its pod.
var ErrNotAuthorized = errors.New("volumed: not authorized for this volume")

// ErrTooManyMounts reports the per-node cap. Each mount costs two device-mapper
// devices and a mount, and every cw pod can reach the socket.
var ErrTooManyMounts = errors.New("volumed: too many open volumes on this node")

// ErrVolumeInUse reports an open that conflicts with a live mount of the same
// device. Two read-write mounts of one device corrupt the filesystem, and a
// read-write mount under read-only readers corrupts what they read, so a
// device shared with any mount refuses a mutable open, and one shared with a
// mutable mount refuses every open.
var ErrVolumeInUse = errors.New("volumed: volume device is already in use")

// Request is one open, after the caller has been resolved.
type Request struct {
	// Pod is the calling pod, as the kernel placed it. Its cgroup path is held
	// so teardown can ask whether the pod still exists.
	Pod    PodCgroup
	Name   string
	Device string
	Blob   volume.Blob
}

// mount is a live volume. The commitment is what a second caller must reproduce
// to be handed the same mapping. The device and mode are kept so an open that
// would mount the same device unsafely is refused (see ErrVolumeInUse).
type mount struct {
	pod        PodCgroup
	name       string
	commitment [sha256.Size]byte
	device     string
	mutable    bool
	cryptDev   string
	target     string
}

// Opener opens volumes and remembers what it has open.
type Opener struct {
	Ops DeviceOps
	// Targets resolves the volume mount within kubelet's pod directory.
	Targets Targets
	// MaxMounts caps live volumes; zero means DefaultMaxMounts.
	MaxMounts int

	mu     sync.Mutex
	mounts map[string]*mount
	// opening tracks in-flight opens by device, so a concurrent open is judged
	// against one that has not landed in mounts yet.
	opening map[string]bool
}

// DefaultMaxMounts bounds live volumes when MaxMounts is unset.
const DefaultMaxMounts = 64

// Open makes the volume available at the calling pod's mount target, and is
// idempotent for a caller repeating an identical request — which a restarted
// sidecar does, since kubelet restarts it for the pod's life.
//
// A request naming a volume already open must present the same key, mode, and
// root hash. Without that check the volume *name* would be the credential, and
// a name is a label in a host-written annotation: any pod reaching the socket
// would be handed the plaintext once one entitled pod had opened it.
func (o *Opener) Open(ctx context.Context, req Request) error {
	key, err := req.Blob.DecodeKey()
	if err != nil {
		return err
	}
	defer zero(key)
	if err := req.Blob.Validate(); err != nil {
		return err
	}
	if !volumeNameRE.MatchString(req.Name) {
		return fmt.Errorf("volumed: volume name %q is not a dns-1123 label", req.Name)
	}

	commitment := commitmentFor(key, req.Blob)

	o.mu.Lock()
	if o.mounts == nil {
		o.mounts = map[string]*mount{}
		o.opening = map[string]bool{}
	}
	if existing, ok := o.mounts[mountKey(req.Pod.UID, req.Name)]; ok {
		o.mu.Unlock()
		if subtle.ConstantTimeCompare(existing.commitment[:], commitment[:]) != 1 {
			return ErrNotAuthorized
		}
		return nil
	}
	if len(o.mounts) >= o.maxMounts() {
		o.mu.Unlock()
		return ErrTooManyMounts
	}
	if o.deviceConflict(req.Device, req.Blob.Mutable) {
		o.mu.Unlock()
		return ErrVolumeInUse
	}
	// Reserve the device for the open's duration, so a conflicting open racing
	// this one is judged against it rather than against a mounts map it has
	// not landed in yet.
	o.opening[req.Device] = req.Blob.Mutable
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		delete(o.opening, req.Device)
		o.mu.Unlock()
	}()

	m, err := o.open(ctx, req, key, commitment)
	if err != nil {
		return err
	}

	// A cancelled caller is one that has already posted its close (the sidecar
	// cancels the open before it does), so a mapping landing now would outlive
	// its pod with only the reaper behind it.
	if err := ctx.Err(); err != nil {
		o.teardown(ctx, m)
		return err
	}
	// A concurrent identical request may have won the race; keep one mapping
	// and tear the loser down outside the lock.
	o.mu.Lock()
	existing, lost := o.mounts[mountKey(req.Pod.UID, req.Name)]
	if !lost {
		o.mounts[mountKey(req.Pod.UID, req.Name)] = m
	}
	o.mu.Unlock()
	if !lost {
		return nil
	}
	o.teardown(ctx, m)
	if subtle.ConstantTimeCompare(existing.commitment[:], commitment[:]) != 1 {
		return ErrNotAuthorized
	}
	return nil
}

// deviceConflict reports whether opening device in mode mutable conflicts with
// a live mount or an in-flight open. Caller holds mu.
func (o *Opener) deviceConflict(device string, mutable bool) bool {
	if openingMutable, inFlight := o.opening[device]; inFlight && (openingMutable || mutable) {
		return true
	}
	for _, m := range o.mounts {
		if m.device == device && (m.mutable || mutable) {
			return true
		}
	}
	return false
}

// open runs the privileged steps, undoing everything it completed if a later
// step fails. A half-open volume leaves a device-mapper target holding the key
// in kernel memory with nothing owning it.
func (o *Opener) open(ctx context.Context, req Request, key []byte, commitment [sha256.Size]byte) (*mount, error) {
	target, err := o.Targets.Dir(req.Pod.UID, KubeVolumeName(req.Name))
	if err != nil {
		return nil, err
	}
	defer target.Close()

	var undo []func(context.Context)
	fail := func(err error) (*mount, error) {
		cleanup, cancel := cleanupContext(ctx)
		defer cancel()
		for _, u := range slices.Backward(undo) {
			u(cleanup)
		}
		return nil, err
	}

	cryptMapper := mapperName(cryptKind, req.Pod.UID, req.Name)
	if err := o.Ops.CryptOpen(ctx, req.Device, cryptMapper, key, !req.Blob.Mutable); err != nil {
		return fail(fmt.Errorf("volumed: open dm-crypt: %w", err))
	}
	undo = append(undo, func(ctx context.Context) { _ = o.Ops.CryptClose(ctx, cryptMapper) })

	mode := modeFor(req.Blob.Mutable)
	if err := mode.open(ctx, o.Ops, req.Pod.UID, req.Name, cryptMapper, req.Blob, target); err != nil {
		return fail(err)
	}
	undo = append(undo, func(ctx context.Context) { mode.close(ctx, o.Ops, req.Pod.UID, req.Name, target.Name()) })

	return &mount{
		pod:        req.Pod,
		name:       req.Name,
		commitment: commitment,
		device:     req.Device,
		mutable:    req.Blob.Mutable,
		cryptDev:   cryptMapper,
		target:     target.Name(),
	}, nil
}

// Close tears down one volume. Idempotent: a volume already gone is not an
// error, because teardown races kubelet removing the pod directory.
func (o *Opener) Close(ctx context.Context, podUID, name string) {
	o.mu.Lock()
	m, ok := o.mounts[mountKey(podUID, name)]
	if ok {
		delete(o.mounts, mountKey(podUID, name))
	}
	o.mu.Unlock()
	if ok {
		o.closeMount(ctx, mountKey(podUID, name), m)
	}
}

// ClosePod tears down every volume a pod holds — the sidecar's termination
// close, and the reaper's collection of a dead pod — and reports how many it
// closed.
func (o *Opener) ClosePod(ctx context.Context, podUID string) int {
	if podUID == "" {
		return 0
	}
	o.mu.Lock()
	doomed := map[string]*mount{}
	for k, m := range o.mounts {
		if m.pod.UID == podUID {
			doomed[k] = m
			delete(o.mounts, k)
		}
	}
	o.mu.Unlock()
	closed := 0
	for k, m := range doomed {
		if o.closeMount(ctx, k, m) {
			closed++
		}
	}
	return closed
}

// closeMount tears m down and reports success. A mapping that refuses to close
// keeps its record: it still holds the key and the device, so it must stay
// visible to deviceConflict and to the reaper, which retries it each sweep.
func (o *Opener) closeMount(ctx context.Context, key string, m *mount) bool {
	if o.teardown(ctx, m) {
		return true
	}
	o.mu.Lock()
	if _, taken := o.mounts[key]; !taken {
		o.mounts[key] = m
	}
	o.mu.Unlock()
	return false
}

// teardown unwinds in reverse and does not stop at the first failure: the
// device-mapper targets hold the key, so a failed unmount must not leave them
// behind. It reports whether the crypt mapping — the layer holding the key and
// the device — actually closed.
func (o *Opener) teardown(ctx context.Context, m *mount) bool {
	cleanup, cancel := cleanupContext(ctx)
	defer cancel()
	modeFor(m.mutable).close(cleanup, o.Ops, m.pod.UID, m.name, m.target)
	return o.Ops.CryptClose(cleanup, m.cryptDev) == nil
}

// SweepStale closes the C8s mappings left on this node by an earlier volumed,
// and reports how many it closed and which it could not.
//
// Nothing else on a node can reap these: they outlive the release that made
// them, and until they are closed they hold the backing disk open, so the next
// install cannot reopen it. This runs once, before the daemon serves, which is
// what makes the residue self-healing rather than permanent.
//
// INVARIANT: the kernel is the liveness check. A mapping something still has
// mounted refuses to close, so a workload's volume cannot be pulled out from
// under it — including one whose pod outlived the volumed that opened it. That
// is stronger than inferring liveness here, which would be a decision this
// process has no state to make.
func (o *Opener) SweepStale(ctx context.Context) (closed int, stuck []string) {
	mappings, err := o.Ops.ListMappings(ctx)
	if err != nil {
		return 0, []string{fmt.Sprintf("unreadable %s: %v", mapperDir, err)}
	}
	// verity is stacked on crypt and holds it open, so it goes first.
	for _, kind := range []string{verityKind, cryptKind} {
		prefix := "c8s-" + kind + "-"
		for _, name := range mappings {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			close := o.Ops.VerityClose
			if kind == cryptKind {
				close = o.Ops.CryptClose
			}
			if err := close(ctx, name); err != nil {
				stuck = append(stuck, name)
				continue
			}
			closed++
		}
	}
	return closed, stuck
}

// Pods returns the distinct pods holding a volume, so teardown can ask which of
// them still exist.
func (o *Opener) Pods() []PodCgroup {
	o.mu.Lock()
	defer o.mu.Unlock()
	seen := map[string]struct{}{}
	var out []PodCgroup
	for _, m := range o.mounts {
		if _, dup := seen[m.pod.UID]; dup {
			continue
		}
		seen[m.pod.UID] = struct{}{}
		out = append(out, m.pod)
	}
	return out
}

// Len reports live volumes, for metrics and tests.
func (o *Opener) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.mounts)
}

func (o *Opener) maxMounts() int {
	if o.MaxMounts > 0 {
		return o.MaxMounts
	}
	return DefaultMaxMounts
}

// commitmentFor binds a mapping to the exact key and mode that opened it — and,
// for an immutable volume, the root hash. Without the mode a caller holding the
// key could be handed a writable mapping by presenting an immutable request, or
// the reverse.
func commitmentFor(key []byte, b volume.Blob) [sha256.Size]byte {
	h := sha256.New()
	h.Write(key)
	if b.Mutable {
		h.Write([]byte("mutable"))
	} else {
		h.Write([]byte(b.Verity.RootHash))
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func mountKey(podUID, name string) string { return podUID + "/" + name }

// mapperName is scoped by pod so two pods opening the same volume get their own
// mappings, and one pod's teardown cannot remove another's.
// The two halves of a volume's device stack, and the mapper-name prefixes
// SweepStale matches on.
const (
	cryptKind  = "crypt"
	verityKind = "verity"
)

func mapperName(kind, podUID, name string) string {
	return fmt.Sprintf("c8s-%s-%s-%s", kind, podUID, name)
}

// mapperDir is where device-mapper publishes its nodes. A mapper name is a bare
// name beneath it, never a path.
const mapperDir = "/dev/mapper"

func devPath(mapper string) string { return mapperDir + "/" + mapper }

// zero best-effort clears a key buffer. The blob arrived as JSON, so copies
// exist that cannot be reached; this clears the one that was used.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
