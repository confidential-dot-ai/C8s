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
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
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

// clientFunc builds the mTLS client to CDS and returns the leaf's key;
// sidecar.NewClient in the command, a client trusting a test server in tests.
type clientFunc func(sidecar.Config, armtls.Pins) (*http.Client, crypto.PublicKey, error)

// newProbe verifies CDS as the pod's sidecars do, through armTLS against the
// pins it was given. The pins are loaded without the sidecars' unpinned
// warning: the steps read the probe's output and stderr as one stream.
func newProbe(o options) (*probe, error) {
	cfg := sidecar.Config{
		SecretsURL:             o.cdsURL,
		AttestationApiURL:      o.attestationURL,
		Measurements:           o.measurements,
		RTMRs:                  o.rtmrs,
		MeasurementsConfig:     o.policyFile,
		MeasurementsConfigJSON: o.policyJSON,
		CertPath:               o.certPath,
		KeyPath:                o.keyPath,
		RequestTimeout:         o.timeout,
	}
	policy, err := (cmdsutil.ImagePolicySource{File: cfg.MeasurementsConfig, JSON: cfg.MeasurementsConfigJSON}).Load(
		cmdsutil.MeasurementPins{Measurements: cfg.Measurements, Registers: cfg.RTMRs})
	if err != nil {
		return nil, err
	}
	client, pub, err := o.newClient(cfg, armtls.Pins(policy))
	if err != nil {
		return nil, err
	}
	return &probe{
		client:   client,
		pub:      pub,
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
