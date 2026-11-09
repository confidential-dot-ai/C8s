package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
)

// maxRequest bounds a release request: a 16 KiB client document, a statement
// and a two-certificate chain, base64 encoded.
const maxRequest = 64 << 10

// policy maps a client key to the secret names pods holding its documents
// may read.
type policy struct {
	Clients []struct {
		ClientKey string   `json:"client_key"`
		Secrets   []string `json:"secrets"`
	} `json:"clients"`
}

func (p policy) allows(clientKey, secret string) bool {
	for _, c := range p.Clients {
		if c.ClientKey == clientKey && slices.Contains(c.Secrets, secret) {
			return true
		}
	}
	return false
}

// clientDoc is the reference client document format. C8s never reads a
// client document; this format is this KMS's example of one. signature is
// Ed25519 under client_key over
// "c8s-reference-client-document/v1" || 0x00 || client_key || agent_id.
type clientDoc struct {
	ClientKey string `json:"client_key"`
	AgentID   string `json:"agent_id"`
	Signature string `json:"signature"`
}

const clientDocDomain = "c8s-reference-client-document/v1\x00"

func clientDocMessage(pub []byte, agentID string) []byte {
	return slices.Concat([]byte(clientDocDomain), pub, []byte(agentID))
}

// newClientDocument signs a document with a fresh random 128-bit agent ID.
func newClientDocument(key ed25519.PrivateKey) ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)
	agentID := hex.EncodeToString(id)
	return json.Marshal(clientDoc{
		ClientKey: base64.StdEncoding.EncodeToString(pub),
		AgentID:   agentID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, clientDocMessage(pub, agentID))),
	})
}

// verifyClientDocument returns the client key a document is signed by.
func verifyClientDocument(raw []byte) (string, error) {
	var d clientDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return "", errors.New("client document is not a reference client document")
	}
	pub, err := base64.StdEncoding.DecodeString(d.ClientKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("client document key is not an Ed25519 public key")
	}
	if id, err := hex.DecodeString(d.AgentID); err != nil || len(id) < 16 {
		return "", errors.New("client document agent ID must be at least 128 bits of hex")
	}
	sig, err := base64.StdEncoding.DecodeString(d.Signature)
	if err != nil || !ed25519.Verify(pub, clientDocMessage(pub, d.AgentID), sig) {
		return "", errors.New("client document signature does not verify")
	}
	return d.ClientKey, nil
}

func newVerifier(meshCAKeySHA256 string) (secretbroker.Verifier, error) {
	var v secretbroker.Verifier
	pin, err := hex.DecodeString(meshCAKeySHA256)
	if err != nil || len(pin) != sha256.Size {
		return v, errors.New("mesh_ca_key_sha256 must be 64 hex characters")
	}
	copy(v.MeshCAKey[:], pin)
	return v, nil
}

// secretSource is where values live; Azure Key Vault in this KMS.
type secretSource interface {
	Get(ctx context.Context, name string) ([]byte, error)
}

type handler struct {
	verifier secretbroker.Verifier
	policy   policy
	secrets  secretSource
	nonces   *nonceCache
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "POST a release request")
		return
	}
	var req secretbroker.ReleaseRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		refuse(w, http.StatusBadRequest, "malformed release request")
		return
	}
	value, status, err := h.release(r.Context(), req)
	if err != nil {
		slog.Warn("release refused", "status", status, "reason", err)
		refuse(w, status, err.Error())
		return
	}
	defer clear(value)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(secretbroker.ReleaseResponse{Version: secretbroker.ReleaseVersion, Value: value})
}

// release makes the decision. The order is: CDS vouches for the pod and the
// document (the broker statement), the document's owner is the client key it
// names (its signature), and the policy lets that key read the secret.
func (h *handler) release(ctx context.Context, req secretbroker.ReleaseRequest) ([]byte, int, error) {
	s, err := h.verifier.Verify(req)
	if err != nil {
		return nil, http.StatusForbidden, err
	}
	if !h.nonces.first(s.Nonce, s.IssuedAt) {
		return nil, http.StatusForbidden, errors.New("statement replayed")
	}
	clientKey, err := verifyClientDocument(req.ClientDocument)
	if err != nil {
		return nil, http.StatusForbidden, err
	}
	if !h.policy.allows(clientKey, s.Secret) {
		return nil, http.StatusForbidden, fmt.Errorf("client key may not read %s", s.Secret)
	}
	value, err := h.secrets.Get(ctx, s.Secret)
	if err != nil {
		slog.Error("secret store", "secret", s.Secret, "error", err)
		return nil, http.StatusBadGateway, errors.New("secret unavailable")
	}
	slog.Info("released", "secret", s.Secret, "pod", s.Pod, "client_document_digest", s.ClientDocumentDigest)
	return value, http.StatusOK, nil
}

func refuse(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(secretbroker.Refusal{Error: reason})
}

// nonceCache remembers statement nonces for as long as Verify would accept
// their statement.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newNonceCache() *nonceCache { return &nonceCache{seen: map[string]time.Time{}} }

func (c *nonceCache) first(nonce []byte, issuedAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for n, at := range c.seen {
		if now.Sub(at) > 2*secretbroker.MaxStatementAge {
			delete(c.seen, n)
		}
	}
	if _, ok := c.seen[string(nonce)]; ok {
		return false
	}
	c.seen[string(nonce)] = issuedAt
	return true
}
