// Package secretprobe implements the hidden secret-probe subcommand: one
// workload secret request against CDS with every input under the caller's
// control. The conformance steps exec it inside a pod's certificate sidecar to
// present what a well-behaved sidecar never would — a missing or replayed
// challenge, another pod's token, a non-canonical path — and report what CDS
// answered. It is a test instrument, not a client for applications.
package secretprobe

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
)

// probe is a CDS client bound to one leaf: the mTLS client presenting it, the
// key a sandbox token must be bound to, and where challenges and tokens come
// from.
type probe struct {
	client   *http.Client
	pub      crypto.PublicKey
	cdsURL   string
	endpoint string // inventory endpoint, unix://<socket>
	timeout  time.Duration
}

func newProbe(o options) (*probe, error) {
	leaf, err := tls.LoadX509KeyPair(o.certPath, o.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load leaf: %w", err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf %s: %w", o.certPath, err)
	}
	return &probe{
		client: &http.Client{
			Timeout: o.timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{leaf},
				// The scenarios test the CDS's authorization of this client,
				// not this client's verification of the CDS; a probe that
				// could not reach a reconfigured CDS would fail for the wrong
				// reason. The sidecars verify through armtls; this never
				// handles a secret a scenario cares about.
				InsecureSkipVerify: true,
			}},
		},
		pub:      parsed.PublicKey,
		cdsURL:   o.cdsURL,
		endpoint: "unix://" + o.socket,
		timeout:  o.timeout,
	}, nil
}

// challenge fetches a fresh single-use challenge from CDS.
func (p *probe) challenge(ctx context.Context) ([]byte, error) {
	return sidecar.FetchChallenge(ctx, p.client, p.cdsURL, p.timeout)
}

// token redeems a sandbox token for this process's sandbox, bound to the leaf
// key and nonce, as the JSON the Authorization header carries.
func (p *probe) token(ctx context.Context, nonce []byte) ([]byte, error) {
	return sidecar.RedeemToken(ctx, p.endpoint, p.timeout, p.pub, nonce)
}

// errUnsendable marks a request that never left: a path the URL parser
// refuses is a usage error, not an answer from CDS.
type errUnsendable struct{ err error }

func (e errUnsendable) Error() string { return "build request: " + e.err.Error() }
func (e errUnsendable) Unwrap() error { return e.err }

// request sends one store request and returns the status and body as
// received. A nil challenge or tokenJSON omits its header. A transport failure
// is status 0 with the error, not a failure to answer: the scenario asked what
// happens, and "nothing answered" is an answer.
func (p *probe) request(ctx context.Context, method, path string, challenge, tokenJSON []byte) (int, []byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := sidecar.NewStoreRequest(reqCtx, p.cdsURL, method, path, challenge, tokenJSON)
	if err != nil {
		return 0, nil, errUnsendable{err}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, body, fmt.Errorf("read response body: %w", err)
	}
	return resp.StatusCode, body, nil
}

// randomNonce is what a token binds to when the scenario sends no challenge:
// the inventory refuses an empty nonce, and a fetched challenge the request
// then omits would be consumed for nothing.
func randomNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}
