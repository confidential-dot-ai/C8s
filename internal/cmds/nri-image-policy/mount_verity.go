package nriimagepolicy

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

var (
	errVerityFilesystem  = errors.New("filesystem does not enforce fs-verity")
	errVerityUnavailable = errors.New("file has no SHA-256 fs-verity digest")
	errVerityWritable    = errors.New("file is on a writable mount")
	errVerityNotBind     = errors.New("file is not a mount of its own")
	errNotContainerInit  = errors.New("process is not the container's")
	errVerityOverrun     = errors.New("measurement overran its budget")
	errVerityBusy        = errors.New("every measurement worker is busy")
)

// verityBudget bounds the fs-verity measurements of one check, inside
// containerd's per-request NRI timeout. A syscall on a hung filesystem cannot
// be cancelled, so a measurement that overruns finishes in the background and
// gives no evidence; verityWorkers bounds those stragglers.
var (
	verityBudget  = time.Second
	verityWorkers = make(chan struct{}, 16)
)

// measureContainerFile is replaced in tests, which cannot start a container
// on a filesystem with fs-verity.
var measureContainerFile = containerFileDigest

// verityCheck measures, for one check, the fs-verity digest of each file a
// candidate bind hands a container. It remembers each result for that check
// alone, so the admission and the records it leads to read one measurement.
type verityCheck struct {
	logger *slog.Logger
	// declared reports whether an fsVerityFile rule names a bind.
	declared func(source, destination string) bool
	deadline time.Time

	mu      sync.Mutex
	digests map[verityTarget]string
}

type verityTarget struct {
	container   string
	pid         uint32
	destination string
}

type verityCheckKey struct{}

// withVerityCheck starts the fs-verity measurements of one check: one
// container start, or the whole recovery and startup check of a Synchronize.
// Mounts observed under a context without one carry no fs-verity evidence.
func (p *plugin) withVerityCheck(ctx context.Context) context.Context {
	return context.WithValue(ctx, verityCheckKey{}, &verityCheck{
		logger:   p.logger,
		declared: p.policy.declaresFSVerityFile,
		deadline: time.Now().Add(verityBudget),
		digests:  map[verityTarget]string{},
	})
}

func verityCheckOf(ctx context.Context) *verityCheck {
	check, _ := ctx.Value(verityCheckKey{}).(*verityCheck)
	return check
}

// attach adds fs-verity provenance to mount, the host evidence of m, when
// the file ctr sees at m's destination has a measured digest. A node-root
// file keeps its own provenance.
func (c *verityCheck) attach(ctr *api.Container, m *api.Mount, mount allowlist.ObservedMount) allowlist.ObservedMount {
	if c == nil || ctr.GetPid() == 0 || mount.Provenance != "" || !mount.ReadOnly || mount.HostSourceDigest == "" || !fileBind(m) || !c.declared(m.GetSource(), m.GetDestination()) {
		return mount
	}
	if digest := c.digest(verityTarget{container: ctr.GetId(), pid: ctr.GetPid(), destination: m.GetDestination()}); digest != "" {
		mount.Provenance, mount.VerityDigest = allowlist.ProvenanceFSVerity, digest
	}
	return mount
}

func (c *verityCheck) digest(target verityTarget) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if digest, ok := c.digests[target]; ok {
		return digest
	}
	digest, err := c.measure(target)
	if err != nil {
		c.logger.Warn("fs-verity digest not measured", "container", target.container, "destination", target.destination, "reason", err)
	}
	c.digests[target] = digest
	return digest
}

func (c *verityCheck) measure(target verityTarget) (string, error) {
	remaining := time.Until(c.deadline)
	if remaining <= 0 {
		return "", errVerityOverrun
	}
	select {
	case verityWorkers <- struct{}{}:
	default:
		return "", errVerityBusy
	}
	type measured struct {
		digest string
		err    error
	}
	result := make(chan measured, 1)
	go func() {
		defer func() { <-verityWorkers }()
		digest, err := measureContainerFile(target.pid, target.container, target.destination)
		result <- measured{digest, err}
	}()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case r := <-result:
		return r.digest, r.err
	case <-timer.C:
		return "", errVerityOverrun
	}
}
