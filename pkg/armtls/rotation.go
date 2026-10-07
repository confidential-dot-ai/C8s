package armtls

import (
	"context"
	"time"
)

const rotationPollInterval = time.Minute

// RunRotation checks renewal deadlines once per minute until ctx ends.
// Run one worker per manager, including when initial WarmUp fails.
func (m *CertManager) RunRotation(ctx context.Context) {
	s := m.state
	s.mu.Lock()
	if s.rotationEnded == nil {
		s.rotationEnded = make(chan struct{}, 1)
	}
	finished := s.rotationEnded
	s.mu.Unlock()
	defer s.stopRotation(finished)
	ticker := time.NewTicker(rotationPollInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		s.rotateIfDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *certState) rotateIfDue(ctx context.Context) {
	s.mu.Lock()
	deadline := s.rotateAt
	if s.cert != nil && s.cert.Leaf != nil && s.cert.Leaf.NotAfter.Before(deadline) {
		deadline = s.cert.Leaf.NotAfter
	}
	now := time.Now()
	if now.Before(deadline) || now.Before(s.retryAt) {
		s.mu.Unlock()
		return
	}
	provider, revision := s.provider, s.revision
	rotationCtx, started := s.beginRotationLocked(ctx, revision)
	s.mu.Unlock()
	if started {
		s.backgroundProvision(rotationCtx, provider, revision)
	}
}

func (s *certState) notifyRotationEndedLocked() {
	select {
	case s.rotationEnded <- struct{}{}:
	default:
	}
}

func (s *certState) certificateInstalledLocked() {
	s.revision++
	s.retryAt = time.Time{}
	if s.retryBackoff != nil {
		s.retryBackoff.Reset()
	}
}

func (s *certState) beginRotationLocked(ctx context.Context, revision uint64) (context.Context, bool) {
	if ctx.Err() != nil || s.revision != revision || time.Now().Before(s.retryAt) || !s.rotating.CompareAndSwap(false, true) {
		return nil, false
	}
	rotationCtx, cancel := context.WithCancel(ctx)
	s.rotationCancel = cancel
	return rotationCtx, true
}

func (s *certState) stopRotation(finished <-chan struct{}) {
	s.mu.Lock()
	if s.rotationCancel != nil {
		s.rotationCancel()
	}
	s.mu.Unlock()
	for s.rotating.Load() {
		<-finished
	}
}

func (s *certState) requestRotation(provider CertProvider, revision uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationEnded != nil {
		return
	}
	if ctx, started := s.beginRotationLocked(context.Background(), revision); started {
		go s.backgroundProvision(ctx, provider, revision)
	}
}
