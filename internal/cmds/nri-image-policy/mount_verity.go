package nriimagepolicy

import (
	"context"
	"errors"
	"log/slog"
	"slices"
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

// verityBudget bounds the time the fs-verity measurements of one check take,
// inside containerd's per-request NRI timeout. A syscall on a hung filesystem
// cannot be cancelled, so a measurement that overruns finishes in the
// background and gives no evidence; verityWorkers bounds those stragglers.
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
	// deferUnmeasured has a check of running containers judge, as the
	// validation check does, the fsVerityFile rule of a file it could not
	// measure (deferred): a file is only denied for what a measurement found.
	// The start check refuses such a container.
	deferUnmeasured bool

	mu      sync.Mutex
	budget  time.Duration
	digests map[verityTarget]string
	// unmeasured holds, per container, the destinations of the files whose
	// measurement did not run to its end.
	unmeasured map[string][]string
}

type verityTarget struct {
	container   string
	pid         uint32
	destination string
}

type verityCheckKey struct{}

// withVerityCheck starts the fs-verity measurements of one container start.
// Mounts observed under a context without one carry no fs-verity evidence.
func (p *plugin) withVerityCheck(ctx context.Context) context.Context {
	return context.WithValue(ctx, verityCheckKey{}, p.newVerityCheck(false))
}

// withExistingVerityCheck starts the fs-verity measurements of one check of
// containers already running: the whole recovery and startup check of a
// Synchronize, or one container's revocation recheck.
func (p *plugin) withExistingVerityCheck(ctx context.Context) context.Context {
	return context.WithValue(ctx, verityCheckKey{}, p.newVerityCheck(true))
}

func (p *plugin) newVerityCheck(deferUnmeasured bool) *verityCheck {
	return &verityCheck{
		logger:          p.logger,
		declared:        p.policy.declaresFSVerityFile,
		deferUnmeasured: deferUnmeasured,
		budget:          verityBudget,
		digests:         map[verityTarget]string{},
		unmeasured:      map[string][]string{},
	}
}

func verityCheckOf(ctx context.Context) *verityCheck {
	check, _ := ctx.Value(verityCheckKey{}).(*verityCheck)
	return check
}

// attach adds fs-verity provenance to mount, the host evidence of m, when
// the file ctr sees at m's destination has a measured digest. A node-root
// file keeps its own provenance.
func (c *verityCheck) attach(ctr *api.Container, m *api.Mount, mount allowlist.ObservedMount) allowlist.ObservedMount {
	if c == nil || mount.Provenance != "" || !mount.ReadOnly || mount.HostSourceDigest == "" || !fileBind(m) || !c.declared(m.GetSource(), m.GetDestination()) {
		return mount
	}
	if ctr.GetPid() == 0 {
		c.noteUnmeasured(ctr.GetId(), m.GetDestination())
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
	// A process that is gone, or a measurement that never ran to its end,
	// says nothing about the file.
	if errors.Is(err, errNotContainerInit) || errors.Is(err, errVerityOverrun) || errors.Is(err, errVerityBusy) {
		c.unmeasuredLocked(target.container, target.destination)
	}
	c.digests[target] = digest
	return digest
}

func (c *verityCheck) noteUnmeasured(container, destination string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unmeasuredLocked(container, destination)
}

func (c *verityCheck) unmeasuredLocked(container, destination string) {
	if !slices.Contains(c.unmeasured[container], destination) {
		c.unmeasured[container] = append(c.unmeasured[container], destination)
	}
}

// deferred returns the destinations of container's files the check judges
// without a digest (deferUnmeasured): only those whose measurement did not
// run, so a file a measurement found wanting is still denied.
func (c *verityCheck) deferred(container string) []string {
	if c == nil || !c.deferUnmeasured {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.unmeasured[container])
}

// measure charges the budget only with the time it measures, so the other
// work of a check does not use it up.
func (c *verityCheck) measure(target verityTarget) (string, error) {
	if c.budget <= 0 {
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
	start := time.Now()
	defer func() { c.budget -= time.Since(start) }()
	timer := time.NewTimer(c.budget)
	defer timer.Stop()
	select {
	case r := <-result:
		return r.digest, r.err
	case <-timer.C:
		return "", errVerityOverrun
	}
}
