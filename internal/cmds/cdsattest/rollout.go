package cdsattest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/rolloutstate"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// statePollInterval is how often the router reads CDS's rollout state. It
// must stay well under the activation lease CDS advertises.
const statePollInterval = time.Second

// zeroLeaseMaxStateAge bounds how long a state read stays fresh when CDS
// advertises no activation lease. CDS then enforces writes at once, so the
// fence gives pinned clients no guarantee; this only keeps the router from
// serving on a state it can no longer refresh.
const zeroLeaseMaxStateAge = 5 * statePollInterval

// rollout tracks CDS's allowlist rollout state for the session fence: a
// session is served only while the last state read is younger than the lease
// and its envelope covers the current bound. CDS enforces a newly published
// policy only once the lease has run, so a session this router still serves
// never reaches a workload outside its envelope.
type rollout struct {
	url    string // allowlist-proxy base URL; it verifies CDS over RA-TLS
	caFile string // mesh CA bundle; every state must verify against it
	client *http.Client

	mu sync.Mutex
	// authority, position and head are the journal coordinates of the last
	// stored state. Under one authority the journal only moves forward; a
	// new authority (a CDS restart, which regenerates the mesh CA) may start
	// over, and is logged.
	authority string
	position  uint64
	head      string
	bound     []string
	lease     time.Duration
	seenAt    time.Time // when the request behind bound was sent
	// widenedAt is when this router last saw the bound gain a digest; it
	// starts at process start, since a restart forgets earlier widenings.
	widenedAt time.Time
	// gen is cancelled, and replaced, every time the bound changes. Every
	// forwarded request runs under it (requestContext), so no request admitted
	// under one bound keeps streaming under the next.
	gen       context.Context
	cancelGen context.CancelCauseFunc
	// onChange runs, under mu, before gen is replaced. The upstream backend
	// registers its connection reset here, so a request admitted under the new
	// bound never reuses a connection whose peer was checked under the old one.
	onChange []func()
}

// errBoundChanged cancels a forwarded request when the bound changes.
var errBoundChanged = errors.New("the allowlist bound changed")

func newRollout(url, caFile string) *rollout {
	r := &rollout{url: url, caFile: caFile, client: &http.Client{Timeout: 5 * time.Second}, widenedAt: time.Now()}
	r.gen, r.cancelGen = context.WithCancelCause(context.Background())
	return r
}

// onBoundChange registers f to run every time the bound changes.
func (r *rollout) onBoundChange(f func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onChange = append(r.onChange, f)
}

// requestContext derives a context from parent that is also cancelled, with
// cause errBoundChanged, when the bound next changes. Callers take it before
// they check the fence, so a change between the check and the forward still
// cancels the request.
func (r *rollout) requestContext(parent context.Context) (context.Context, context.CancelFunc) {
	r.mu.Lock()
	gen := r.gen
	r.mu.Unlock()
	ctx, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(gen, func() { cancel(errBoundChanged) })
	return ctx, func() {
		stop()
		cancel(context.Canceled)
	}
}

// boundChanged runs the change hooks, then cancels every request admitted
// under the previous bound. Callers hold r.mu.
func (r *rollout) boundChanged() {
	for _, f := range r.onChange {
		f()
	}
	r.cancelGen(errBoundChanged)
	r.gen, r.cancelGen = context.WithCancelCause(context.Background())
}

// challenge fetches the state bound to nonce.
func (r *rollout) challenge(ctx context.Context, nonce []byte) (*types.SignedRolloutState, []string, error) {
	body, err := json.Marshal(map[string]string{"nonce": hex.EncodeToString(nonce)})
	if err != nil {
		return nil, nil, err
	}
	signed, st, err := r.fetch(ctx, http.MethodPost, "/.well-known/c8s/state/challenge", body, rolloutstate.ContextChallenge)
	if err != nil {
		return nil, nil, err
	}
	if st.Nonce != hex.EncodeToString(nonce) {
		return nil, nil, fmt.Errorf("CDS state answers another nonce")
	}
	return signed, st.Bound, nil
}

// poll refreshes the state and returns the newest bound seen, which a
// concurrent challenge may have stored ahead of this response.
func (r *rollout) poll(ctx context.Context) ([]string, error) {
	if _, _, err := r.fetch(ctx, http.MethodGet, "/.well-known/c8s/state", nil, rolloutstate.ContextState); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bound, nil
}

func (r *rollout) fetch(ctx context.Context, method, path string, body []byte, sigContext string) (*types.SignedRolloutState, *types.RolloutState, error) {
	sent := time.Now()
	req, err := http.NewRequestWithContext(ctx, method, r.url+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("read CDS state: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("read CDS state: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("read CDS state: status %d", resp.StatusCode)
	}
	var signed types.SignedRolloutState
	var st types.RolloutState
	if err := json.Unmarshal(raw, &signed); err != nil {
		return nil, nil, fmt.Errorf("decode CDS state: %w", err)
	}
	if err := r.verify(&signed, sigContext); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(signed.State, &st); err != nil {
		return nil, nil, fmt.Errorf("decode CDS state: %w", err)
	}
	if err := rolloutstate.CheckTime(&st, time.Now()); err != nil {
		return nil, nil, err
	}

	if st.Protocol != stateProtocol {
		return nil, nil, fmt.Errorf("CDS state protocol %d, want %d", st.Protocol, stateProtocol)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if sent.After(r.seenAt) {
		if err := r.checkProgress(&st); err != nil {
			return nil, nil, err
		}
		r.authority, r.position, r.head = st.Authority, st.Position, st.Head
		if !covers(r.bound, st.Bound) {
			r.widenedAt = time.Now()
		}
		changed := !slices.Equal(r.bound, st.Bound)
		r.seenAt, r.bound, r.lease = sent, st.Bound, time.Duration(st.Lease)*time.Second
		if changed {
			r.boundChanged()
		}
	}
	return &signed, &st, nil
}

// stateProtocol is the RolloutState protocol this router understands.
const stateProtocol = 1

// checkProgress refuses a state whose journal went backwards under the
// authority of the last stored state: a lower position, or another head at
// the same position. A state under a new authority is accepted, since a CDS
// restart regenerates the mesh CA and may start a new journal, and logged.
// Callers hold r.mu.
func (r *rollout) checkProgress(st *types.RolloutState) error {
	if r.seenAt.IsZero() {
		return nil
	}
	if st.Authority != r.authority {
		slog.Warn("CDS rollout authority changed: accepting a new journal",
			"old_authority", r.authority, "old_position", r.position,
			"new_authority", st.Authority, "new_position", st.Position)
		return nil
	}
	switch {
	case st.Position < r.position:
		return fmt.Errorf("CDS journal went backwards under authority %s: position %d after %d", st.Authority, st.Position, r.position)
	case st.Position == r.position && st.Head != r.head:
		return fmt.Errorf("CDS journal forked under authority %s: head %s at position %d, was %s", st.Authority, st.Head, st.Position, r.head)
	}
	return nil
}

// verify requires the state to be signed by a key in the mesh CA bundle, the
// CA clients check it against: the proxy's CDS pins are deployment config.
func (r *rollout) verify(signed *types.SignedRolloutState, sigContext string) error {
	pemBytes, err := os.ReadFile(r.caFile)
	if err != nil {
		return fmt.Errorf("read mesh CA: %w", err)
	}
	cas, err := certutil.ParsePEMCertificates(pemBytes)
	if err != nil {
		return fmt.Errorf("parse mesh CA: %w", err)
	}
	for _, ca := range cas {
		if key, ok := ca.PublicKey.(*ecdsa.PublicKey); ok && rolloutstate.Verify(key, sigContext, signed.State, signed.Signature) {
			return nil
		}
	}
	return fmt.Errorf("CDS state is not signed by the mesh CA")
}

// admits reports whether a session with envelope may be served at now, and
// whether it must be dropped because the bound outgrew it.
func (r *rollout) admits(envelope []string, now time.Time) (ok, drop bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !covers(envelope, r.bound) {
		return false, true
	}
	return r.fresh(now), false
}

// covers reports whether every digest in bound is in envelope.
func covers(envelope, bound []string) bool {
	for _, d := range bound {
		if !slices.Contains(envelope, d) {
			return false
		}
	}
	return true
}

// verifyPeer admits an upstream leaf only when its matched-workload stamp
// names a policy in the current bound.
func (r *rollout) verifyPeer(leaf *x509.Certificate) error {
	stamp, err := ratls.MatchedWorkloadFromCert(leaf)
	if err != nil {
		return fmt.Errorf("upstream matched-workload stamp: %w", err)
	}
	if stamp == nil {
		return fmt.Errorf("upstream leaf carries no matched-workload stamp")
	}
	digest := "sha256:" + hex.EncodeToString(stamp.AllowlistDigest)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.bound, digest) {
		return fmt.Errorf("upstream %q was admitted under policy %s, outside the bound", stamp.Name, digest)
	}
	return nil
}

// admitsConnection reports whether a request on a front-door connection
// opened at start may be forwarded at now: the state must be fresh and the
// bound must not have widened since the client could have checked it.
func (r *rollout) admitsConnection(start, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fresh(now) && start.After(r.widenedAt)
}

// fresh reports whether a state has been read and whether the last read is
// younger than the lease. A state advertising no lease is held to
// zeroLeaseMaxStateAge instead: it is never fresh forever, so the router
// still stops serving when it loses CDS. Callers hold r.mu.
func (r *rollout) fresh(now time.Time) bool {
	maxAge := r.lease
	if maxAge <= 0 {
		maxAge = zeroLeaseMaxStateAge
	}
	return !r.seenAt.IsZero() && now.Sub(r.seenAt) < maxAge
}
