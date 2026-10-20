package operatorauth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// PublishedKeysPath is the CDS endpoint that serves its pinned operator keys.
const PublishedKeysPath = "/operator-keys"

// MaxPublishedKeysBytes caps a PublishedKeysPath body. A key bundle is a
// handful of PEM blocks of about 200 bytes each.
const MaxPublishedKeysBytes = 256 << 10

// ErrNoPublishedKeys reports a 404 from PublishedKeysPath: the CDS pins no
// operator keys, so allowlist writes are disabled.
var ErrNoPublishedKeys = errors.New("CDS pins no operator keys")

// ReadPublishedKeys reads the keys from a GET PublishedKeysPath response. It
// returns ErrNoPublishedKeys on 404. It does not close resp.Body.
func ReadPublishedKeys(resp *http.Response) ([]*ecdsa.PublicKey, error) {
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNoPublishedKeys
	default:
		return nil, fmt.Errorf("%s returned %d", PublishedKeysPath, resp.StatusCode)
	}
	pemBytes, err := readutil.ReadAll(resp.Body, MaxPublishedKeysBytes)
	if errors.Is(err, readutil.ErrTooLarge) {
		return nil, fmt.Errorf("%s response exceeds %d bytes", PublishedKeysPath, MaxPublishedKeysBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", PublishedKeysPath, err)
	}
	keys, err := ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", PublishedKeysPath, err)
	}
	return keys, nil
}
