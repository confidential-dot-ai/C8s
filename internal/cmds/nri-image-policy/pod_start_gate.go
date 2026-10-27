package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/podstart"
)

const podStartLifetime = 30 * time.Second

// Grants exist only in this NRI session and are protected by podMu.
type podStartGrant struct {
	request podstart.Request
	name    string
	expires time.Time
}

var listenPodStarts = func() (net.Listener, error) {
	return podstart.Listen(podstart.SocketPath)
}

func (p *plugin) listenPodStarts() (net.Listener, error) {
	if !p.cfg.podRole() {
		return nil, nil
	}
	return listenPodStarts()
}

// NRI disconnect must revoke authority without waiting for an active callback.
func (p *plugin) disconnectPodStarts() { p.podStartDisconnected.Store(true) }

func (p *plugin) runWithPodStarts(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return p.Run(ctx)
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = listener.Close() }()
	finished := make(chan error, 2)
	go func() { finished <- p.Run(ctx) }()
	go func() { finished <- podstart.Serve(ctx, listener, p.consumePodStart) }()
	err := <-finished
	p.disconnectPodStarts()
	cancel()
	_ = listener.Close()
	other := <-finished
	if parent.Err() != nil {
		err = podStartShutdownError(err)
	}
	other = podStartShutdownError(other)
	return errors.Join(err, other)
}

func podStartShutdownError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// finishPodStart follows final checks and history recording on both ready paths.
func (p *plugin) finishPodStart(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, source string) error {
	if err := p.afterPodStart(pod, source); err != nil {
		return err
	}
	if !p.cfg.podRole() {
		return nil
	}
	request := podstart.Request{ContainerID: ctr.GetId(), SandboxID: pod.GetId(), PID: ctr.GetPid()}
	if err := p.requirePodStart(ctx, request); err != nil {
		return p.denyContainer(pod.GetId(), err)
	}
	if p.podStarts == nil {
		p.podStarts = make(map[string]podStartGrant)
	}
	now := time.Now()
	for id, grant := range p.podStarts {
		if grant.name == ctr.GetName() || !now.Before(grant.expires) {
			delete(p.podStarts, id)
		}
	}
	p.podStarts[ctr.GetId()] = podStartGrant{request: request, name: ctr.GetName(), expires: now.Add(podStartLifetime)}
	return nil
}

func (p *plugin) consumePodStart(ctx context.Context, request podstart.Request) error {
	defer p.lockPodAdmission()()
	grant, exists := p.podStarts[request.ContainerID]
	if !exists || grant.request != request || !time.Now().Before(grant.expires) {
		return errors.New("pod start has no matching current admission")
	}
	// Every use, including a failed revalidation, retires this permission.
	delete(p.podStarts, request.ContainerID)
	return p.requirePodStart(ctx, request)
}

// requirePodStart reads only guest-owned state; the request grants no identity.
func (p *plugin) requirePodStart(ctx context.Context, request podstart.Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if !p.cfg.podRole() || p.measurer == nil || p.inventory == nil {
		return errors.New("pod start lacks admission, measurement or process identity")
	}
	b := p.podBroker
	if b == nil || b.ctx == nil || b.ctx.Err() != nil || b.terminal != nil || b.pod.GetId() != request.SandboxID {
		return errors.New("pod start has no live credential identity")
	}
	if _, _, err := p.inventory.podSnapshot(request.SandboxID); err != nil {
		return fmt.Errorf("pod start admission history: %w", err)
	}
	p.inventory.mu.RLock()
	record, exists := p.inventory.containers[request.ContainerID]
	p.inventory.mu.RUnlock()
	if !exists || record.sandboxID != request.SandboxID || record.digest == "" {
		return errors.New("pod start is absent from the live admission inventory")
	}
	if p.podStartDisconnected.Load() {
		return errors.New("pod start admission lost its runtime connection")
	}
	return ctx.Err()
}
