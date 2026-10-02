package sidecar

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// leafProvider presents the pod's CDS-issued leaf as the client certificate.
// It reloads from disk on each provision, so a renewal written by the cert
// sidecar is picked up without restarting this one.
type leafProvider struct{ certPath, keyPath string }

func (p leafProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	cert, err := tls.LoadX509KeyPair(p.certPath, p.keyPath)
	if err != nil {
		return nil, 0, fmt.Errorf("load leaf %s: %w", p.certPath, err)
	}
	return &cert, time.Hour, nil
}

// NewClient builds the mTLS client to CDS and returns the leaf's public key,
// which the sandbox token is bound to.
func NewClient(cfg Config, pins ratls.Pins) (*http.Client, crypto.PublicKey, error) {
	provider := leafProvider{certPath: cfg.CertPath, keyPath: cfg.KeyPath}
	leaf, _, err := provider.Provision(context.Background())
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf: %w", err)
	}
	tlsCfg, _, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:       pins.VerifyPolicy(cfg.AttestationApiURL),
		CertProvider: provider,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build CDS client: %w", err)
	}
	return &http.Client{
		Timeout:   cfg.RequestTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, parsed.PublicKey, nil
}

// Do performs one store request: a fresh challenge, a sandbox token redeemed
// at endpoint and bound to the challenge and this pod's leaf key, then the
// request itself. Both are single-use, so every call takes its own.
func Do(ctx context.Context, cfg Config, client *http.Client, pub crypto.PublicKey, endpoint, method, path string) ([]byte, int, error) {
	challenge, err := fetchChallenge(ctx, cfg, client)
	if err != nil {
		return nil, 0, err
	}
	token, err := workloadclaims.FetchSandboxToken(ctx, endpoint, cfg.InventoryTimeout, pub, challenge)
	if err != nil {
		return nil, 0, fmt.Errorf("redeem sandbox token: %w", err)
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, 0, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, cfg.CDSURL+"/secrets"+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set(secrets.ChallengeHeader, base64.StdEncoding.EncodeToString(challenge))
	req.Header.Set("Authorization", secrets.AuthScheme+base64.StdEncoding.EncodeToString(tokenJSON))

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("decode secret response: %w", err)
		}
		value, err := base64.StdEncoding.DecodeString(body.Value)
		if err != nil {
			return nil, resp.StatusCode, fmt.Errorf("secret value is not base64: %w", err)
		}
		return value, resp.StatusCode, nil
	default:
		// The body is deliberately opaque; the reason is in the CDS log.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, resp.StatusCode, &StatusError{
			Code: envelopeCode(detail),
			Err:  fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(detail))),
		}
	}
}

// StatusError is a non-2xx answer from CDS. Code is the C8s error-envelope code
// its body named, and is empty for a body that is not an envelope.
type StatusError struct {
	Code string
	Err  error
}

func (e *StatusError) Error() string { return e.Err.Error() }
func (e *StatusError) Unwrap() error { return e.Err }

func envelopeCode(body []byte) string {
	var env types.ErrorResponse
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	return env.Error
}

func fetchChallenge(ctx context.Context, cfg Config, client *http.Client) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.CDSURL+secrets.ChallengeRoute, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch challenge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch challenge: %s", resp.Status)
	}
	var out types.ChallengeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	challenge, err := base64.StdEncoding.DecodeString(out.Challenge)
	if err != nil {
		return nil, fmt.Errorf("challenge is not base64: %w", err)
	}
	return challenge, nil
}
