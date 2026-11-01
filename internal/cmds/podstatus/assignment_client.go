package podstatus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"

	strictjson "sigs.k8s.io/json"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

var ErrAlreadyAssigned = errors.New("guest already holds a Pod")

// AssignmentTarget holds the freshly verified, key-pinned channel of an empty
// guest. Prepare and Send are separate so the provider can persist its exact
// assignment intent before an ambiguous network operation.
type AssignmentTarget struct {
	client *http.Client
	base   string
	peer   crypto.PublicKey
	spki   []byte
}

// VerifyAssignmentTarget requires fresh launch evidence with an empty measured
// list. A certificate alone never establishes an unassigned guest.
func VerifyAssignmentTarget(ctx context.Context, cfg AttestConfig) (*AssignmentTarget, error) {
	cfg.ExpectDigests = []string{}
	_, client, err := Attest(ctx, cfg)
	if err != nil {
		return nil, err
	}
	base := "https://" + hostPort(cfg.Node)
	digests, peer, err := fetchDigests(ctx, client, base)
	if err != nil || len(digests) != 0 {
		client.CloseIdleConnections()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("assignment target has measured containers")
	}
	spki, err := x509.MarshalPKIXPublicKey(peer)
	if err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	return &AssignmentTarget{client: client, base: base, peer: peer, spki: spki}, nil
}

// ServingKey returns the verified SPKI DER to freeze alongside the intent.
func (t *AssignmentTarget) ServingKey() []byte { return bytes.Clone(t.spki) }

// Close releases this target's idle connections.
func (t *AssignmentTarget) Close() { t.client.CloseIdleConnections() }

// Prepare obtains an unused nonce and signs without sending an assignment.
func (t *AssignmentTarget) Prepare(ctx context.Context, key *ecdsa.PrivateKey, manifest, entries, meshPeers []byte) ([]byte, error) {
	data, _, _, err := doPeer(ctx, t.client, http.MethodGet, t.base+AssignNoncePath, nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Nonce []byte `json:"nonce"`
	}
	strictErrors, err := strictjson.UnmarshalStrict(data, &response)
	if err != nil || len(strictErrors) != 0 || len(response.Nonce) != podassign.NonceSize {
		return nil, errors.New("guest returned an invalid assignment nonce")
	}
	req, err := podassign.Sign(key, t.peer, podassign.Request{Nonce: response.Nonce, Manifest: manifest, Entries: entries, MeshPeers: meshPeers})
	if err != nil {
		return nil, err
	}
	return podassign.Encode(req)
}

// Send transmits the already persisted bytes unchanged. A caller recovering an
// intent must compare ServingKey with its frozen value before calling this.
func (t *AssignmentTarget) Send(ctx context.Context, data []byte) (string, error) {
	assignment, err := podassign.Decode(data)
	if err != nil {
		return "", err
	}
	pod, err := launchconfig.ParsePodManifest(assignment.Manifest)
	if err != nil || pod.UID == "" {
		return "", errors.New("assignment manifest has no valid Pod identity")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+AssignPath, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := t.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send assignment: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return "", err
	}
	if response.StatusCode == http.StatusConflict {
		return "", ErrAlreadyAssigned
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("assignment refused with HTTP %d", response.StatusCode)
	}
	if len(body) > 4096 {
		return "", errors.New("assignment response exceeds size limit")
	}
	var accepted struct {
		UID string `json:"uid"`
	}
	strictErrors, err := strictjson.UnmarshalStrict(body, &accepted)
	if err != nil || len(strictErrors) != 0 || accepted.UID != string(pod.UID) {
		return "", errors.New("assignment response does not match the persisted Pod")
	}
	return accepted.UID, nil
}
