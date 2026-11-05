// Package podassign frames the authenticated, one-time Pod assignment protocol.
// It authenticates bytes; launchconfig validates their workload authority.
package podassign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"

	strictjson "sigs.k8s.io/json"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	NonceSize        = 32
	MaxBody          = 4 << 20
	assignmentDomain = "c8s-pod-assign/v1\x00"
)

var (
	ErrMalformed = errors.New("malformed Pod assignment")
	ErrSignature = errors.New("invalid Pod assignment signature")
)

// Request preserves the exact signed payload bytes. JSON members are base64
// strings, including entries and meshPeers, whose decoded values are JSON.
type Request struct {
	Nonce     []byte `json:"nonce"`
	Manifest  []byte `json:"manifest"`
	Entries   []byte `json:"entries"`
	MeshPeers []byte `json:"meshPeers"`
	Signature []byte `json:"signature"`
}

type wireRequest struct {
	Nonce     *string `json:"nonce"`
	Manifest  *string `json:"manifest"`
	Entries   *string `json:"entries"`
	MeshPeers *string `json:"meshPeers"`
	Signature *string `json:"signature"`
}

// Decode accepts exactly the five required, case-sensitive members. Missing,
// null, duplicate, unknown and noncanonical base64 members are refused.
func Decode(data []byte) (Request, error) {
	var wire wireRequest
	if len(data) > MaxBody {
		return Request{}, ErrMalformed
	}
	strictErrors, err := strictjson.UnmarshalStrict(data, &wire)
	if err != nil || len(strictErrors) != 0 {
		return Request{}, ErrMalformed
	}
	var req Request
	for _, field := range []struct {
		src *string
		dst *[]byte
	}{
		{wire.Nonce, &req.Nonce}, {wire.Manifest, &req.Manifest},
		{wire.Entries, &req.Entries}, {wire.MeshPeers, &req.MeshPeers},
		{wire.Signature, &req.Signature},
	} {
		if field.src == nil {
			return Request{}, ErrMalformed
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(*field.src)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != *field.src {
			return Request{}, ErrMalformed
		}
		*field.dst = decoded
	}
	if len(req.Nonce) != NonceSize {
		return Request{}, ErrMalformed
	}
	return req, nil
}

// Encode emits strings even for empty payloads; payload validity is a separate
// assignment decision. The nonce and complete encoded body are bounded here.
func Encode(req Request) ([]byte, error) {
	if len(req.Nonce) != NonceSize || len(req.Manifest) > MaxBody || len(req.Entries) > MaxBody || len(req.MeshPeers) > MaxBody || len(req.Signature) > MaxBody {
		return nil, ErrMalformed
	}
	nonce := base64.StdEncoding.EncodeToString(req.Nonce)
	manifest := base64.StdEncoding.EncodeToString(req.Manifest)
	entries := base64.StdEncoding.EncodeToString(req.Entries)
	peers := base64.StdEncoding.EncodeToString(req.MeshPeers)
	signature := base64.StdEncoding.EncodeToString(req.Signature)
	data, err := json.Marshal(wireRequest{&nonce, &manifest, &entries, &peers, &signature})
	if err != nil || len(data) > MaxBody {
		return nil, ErrMalformed
	}
	return data, nil
}

// Sign binds the payload to this verified serving key and fresh nonce. The
// detached-signature helper hashes the framed message exactly once.
func Sign(key *ecdsa.PrivateKey, servingKey crypto.PublicKey, req Request) (Request, error) {
	if key == nil || !p256(&key.PublicKey) {
		return Request{}, ErrSignature
	}
	if _, err := Encode(req); err != nil {
		return Request{}, err
	}
	message, err := signingMessage(servingKey, req)
	if err != nil {
		return Request{}, err
	}
	signature, err := operatorauth.SignDetached(key, message)
	if err != nil {
		return Request{}, ErrSignature
	}
	req.Signature, err = base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return Request{}, ErrSignature
	}
	return req, nil
}

// Verify authenticates the exact payload bytes under the measured launch key.
func Verify(key *ecdsa.PublicKey, servingKey crypto.PublicKey, req Request) error {
	if !p256(key) {
		return ErrSignature
	}
	if _, err := Encode(req); err != nil {
		return err
	}
	message, err := signingMessage(servingKey, req)
	if err != nil {
		return err
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{key}, message, base64.StdEncoding.EncodeToString(req.Signature)); err != nil {
		return ErrSignature
	}
	return nil
}

func p256(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256()
}

func signingMessage(servingKey crypto.PublicKey, req Request) ([]byte, error) {
	value := reflect.ValueOf(servingKey)
	if !value.IsValid() || (value.Kind() == reflect.Pointer && value.IsNil()) {
		return nil, ErrSignature
	}
	spki, err := x509.MarshalPKIXPublicKey(servingKey)
	if err != nil {
		return nil, ErrSignature
	}
	message := append([]byte(assignmentDomain), spki...)
	message = append(message, req.Nonce...)
	for _, payload := range [][]byte{req.Manifest, req.Entries, req.MeshPeers} {
		digest := sha256.Sum256(payload)
		message = append(message, digest[:]...)
	}
	return message, nil
}
