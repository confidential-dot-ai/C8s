package cds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// PodSecretHandler serves POST secretbroker.PodRoute: CDS as a broker of pod
// secret release (docs/pod-secrets.md). The caller is the pod its
// mesh-CA-verified leaf names, and its client document must hash to the
// digest that leaf carries. CDS signs a statement saying so with its broker
// key and forwards it to the KMS, which decides. The value passes through
// this handler on its way to the pod and is kept nowhere.
type PodSecretHandler struct {
	Broker *secretBroker
	KMS    kmsReleaser
}

// kmsReleaser sends one release request to the KMS. A refusal by the KMS is a
// *kmsRefusal; any other error is the KMS being unreachable or broken.
type kmsReleaser interface {
	Release(ctx context.Context, req secretbroker.ReleaseRequest) ([]byte, error)
}

type kmsRefusal struct {
	status int
	reason string
}

func (r *kmsRefusal) Error() string { return fmt.Sprintf("KMS refused (%d): %s", r.status, r.reason) }

func (h PodSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	refuse := func(reason string, args ...any) {
		slog.Warn("pod secret refused", append([]any{"reason", reason, "remote_addr", r.RemoteAddr}, args...)...)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeSecretRefused, "not authorized for this secret")
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		refuse("no client certificate verified against the mesh CA")
		return
	}
	leaf := r.TLS.PeerCertificates[0]
	pod, err := armtls.SandboxIDFromCert(leaf)
	if err != nil || pod == "" {
		refuse("the leaf names no pod")
		return
	}
	digest, ok := armtls.ClientDocumentDigest(leaf)
	if !ok {
		refuse("the leaf carries no client document digest", "pod", pod)
		return
	}
	matched, err := armtls.MatchedWorkloadFromCert(leaf)
	if err != nil {
		refuse("matched workload extension", "pod", pod, "error", err)
		return
	}
	req, err := decodePodRequest(r.Body)
	if err != nil {
		httputil.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, "invalid pod secret request")
		return
	}
	if got := sha256.Sum256(req.ClientDocument); !bytes.Equal(got[:], digest) {
		refuse("the client document does not hash to the leaf's digest", "pod", pod, "secret", req.Secret)
		return
	}
	var workload *secretbroker.Workload
	if matched != nil {
		workload = &secretbroker.Workload{Name: matched.Name, AllowlistVersion: matched.AllowlistVersion, AllowlistDigest: hex.EncodeToString(matched.AllowlistDigest)}
	}
	statement, err := secretbroker.NewStatement(pod, workload, digest, req.Secret, time.Now())
	if err != nil {
		httputil.WriteError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, "invalid pod secret request")
		return
	}
	signature, chain, err := h.Broker.sign(statement)
	if err != nil {
		slog.Error("pod secret: broker signature", "error", err)
		httputil.WriteError(w, http.StatusServiceUnavailable, types.ErrorCodeInternal, "secret release unavailable")
		return
	}
	logged := []any{"pod", pod, "secret", req.Secret, "client_document_digest", hex.EncodeToString(digest), "remote_addr", r.RemoteAddr}
	value, err := h.KMS.Release(r.Context(), secretbroker.ReleaseRequest{
		Version: secretbroker.ReleaseVersion, Statement: statement, Signature: signature,
		BrokerChain: chain, ClientDocument: req.ClientDocument,
	})
	var refusal *kmsRefusal
	switch {
	case errors.As(err, &refusal):
		slog.Warn("pod secret refused by the KMS", append(logged, "status", refusal.status, "reason", refusal.reason)...)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeSecretRefused, "the KMS refused: "+refusal.reason)
		return
	case err != nil:
		slog.Error("pod secret: KMS unavailable", append(logged, "error", err)...)
		httputil.WriteError(w, http.StatusBadGateway, types.ErrorCodeKMSUnavailable, "the KMS is unavailable")
		return
	}
	defer clear(value)
	slog.Info("pod secret released", logged...)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(secretbroker.PodResponse{Value: value})
}

func decodePodRequest(body io.Reader) (secretbroker.PodRequest, error) {
	var req secretbroker.PodRequest
	raw, err := io.ReadAll(body)
	if err != nil {
		return req, err
	}
	if err := strictjson.Unmarshal(raw, &req); err != nil {
		return req, err
	}
	return req, secretbroker.ValidSecretName(req.Secret)
}

// kmsClient posts release requests to the KMS the measured configuration
// names, authenticating it by its pinned TLS key.
type kmsClient struct {
	url    string
	client *http.Client
}

// kmsTimeout bounds one release round trip to the KMS.
const kmsTimeout = 15 * time.Second

func newKMSClient(kms *cdsconfig.KMS) *kmsClient {
	return &kmsClient{url: kms.URL, client: &http.Client{
		Timeout:   kmsTimeout,
		Transport: &http.Transport{TLSClientConfig: pinVerifiedTLSConfig(kms.TLSKey), ForceAttemptHTTP2: true},
	}}
}

// pinVerifiedTLSConfig accepts the peer that holds the key pin hashes. The
// pin replaces CA verification: the KMS is who holds the key the measured
// configuration names, whatever signed its certificate.
func pinVerifiedTLSConfig(pin [sha256.Size]byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection checks the pinned key
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo) != pin {
				return errors.New("KMS TLS key does not match the pinned key")
			}
			return checkValidity(cs.PeerCertificates[0], time.Now())
		},
	}
}

func checkValidity(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("KMS TLS certificate is outside its validity period")
	}
	return nil
}

// maxKMSResponse bounds a KMS answer: a value and its JSON framing.
const maxKMSResponse = 2*secretbroker.MaxValue + 4096

func (k *kmsClient) Release(ctx context.Context, release secretbroker.ReleaseRequest) ([]byte, error) {
	body, err := json.Marshal(release)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxKMSResponse+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxKMSResponse {
		return nil, errors.New("KMS response is too large")
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		// A release names its value: an answer without one is no release.
		var answer secretbroker.ReleaseResponse
		if err := json.Unmarshal(raw, &answer); err != nil || answer.Version != secretbroker.ReleaseVersion || answer.Value == nil || len(answer.Value) > secretbroker.MaxValue {
			clear(raw)
			return nil, errors.New("malformed KMS release response")
		}
		clear(raw)
		return answer.Value, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		var refusal secretbroker.Refusal
		_ = json.Unmarshal(raw, &refusal)
		return nil, &kmsRefusal{status: resp.StatusCode, reason: shortReason(refusal.Error)}
	default:
		return nil, fmt.Errorf("KMS answered %d", resp.StatusCode)
	}
}

// shortReason bounds a KMS's refusal text before it is logged and relayed.
func shortReason(s string) string {
	const max = 256
	if s == "" {
		return "no reason given"
	}
	if len(s) > max {
		return s[:max]
	}
	return s
}
