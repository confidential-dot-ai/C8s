package cdsattest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// statePollInterval is how often the router reads CDS's rollout state. It
// must stay well under the activation lease CDS advertises.
const statePollInterval = time.Second

// rollout tracks CDS's allowlist rollout state for the session fence: a
// session is served only while the last state read is younger than the lease
// and its envelope covers the current bound. CDS enforces a newly published
// policy only once the lease has run, so a session this router still serves
// never reaches a workload outside its envelope.
type rollout struct {
	url    string // allowlist-proxy base URL; it verifies CDS over RA-TLS
	caFile string // mesh CA bundle; every state must verify against it
	client *http.Client

	mu     sync.Mutex
	bound  []string
	lease  time.Duration
	seenAt time.Time // when the request behind bound was sent
}

func newRollout(url, caFile string) *rollout {
	return &rollout{url: url, caFile: caFile, client: &http.Client{Timeout: 5 * time.Second}}
}

// challenge fetches the state bound to nonce.
func (r *rollout) challenge(ctx context.Context, nonce []byte) (*types.SignedRolloutState, []string, error) {
	body, err := json.Marshal(map[string]string{"nonce": hex.EncodeToString(nonce)})
	if err != nil {
		return nil, nil, err
	}
	signed, st, err := r.fetch(ctx, http.MethodPost, "/.well-known/c8s/state/challenge", body)
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
	if _, _, err := r.fetch(ctx, http.MethodGet, "/.well-known/c8s/state", nil); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bound, nil
}

func (r *rollout) fetch(ctx context.Context, method, path string, body []byte) (*types.SignedRolloutState, *types.RolloutState, error) {
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
	if err := r.verify(&signed); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(signed.State, &st); err != nil {
		return nil, nil, fmt.Errorf("decode CDS state: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if sent.After(r.seenAt) {
		r.seenAt, r.bound, r.lease = sent, st.Bound, time.Duration(st.Lease)*time.Second
	}
	return &signed, &st, nil
}

// verify requires the state to be signed by a key in the mesh CA bundle, the
// CA clients check it against: the proxy's CDS pins are deployment config.
func (r *rollout) verify(signed *types.SignedRolloutState) error {
	pemBytes, err := os.ReadFile(r.caFile)
	if err != nil {
		return fmt.Errorf("read mesh CA: %w", err)
	}
	cas, err := certutil.ParsePEMCertificates(pemBytes)
	if err != nil {
		return fmt.Errorf("parse mesh CA: %w", err)
	}
	sum := sha512.Sum384(signed.State)
	for _, ca := range cas {
		if key, ok := ca.PublicKey.(*ecdsa.PublicKey); ok && ecdsa.VerifyASN1(key, sum[:], signed.Signature) {
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
	return r.lease == 0 || now.Sub(r.seenAt) < r.lease, false
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
