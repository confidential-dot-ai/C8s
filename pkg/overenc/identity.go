package overenc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	identityTranscriptDomain = types.ProtocolVersion
	// lbTranscriptDomain separates the attest-lb transcript from the attest-pq
	// one: the two endpoints sign different statements, so a response can
	// never be replayed across them.
	lbTranscriptDomain = types.BindingAttestLB
	identityNonceBytes = 32
)

// IdentityTranscriptHash commits the front-door mode and the complete key
// exchange — the client's X-Wing encapsulation key, the server's ciphertext,
// the session id, and the client nonce — together with the exact mesh leaf
// and issuing mesh CA to one SHA-384 value suitable for TEE report_data. The
// evidence therefore covers both sides of the exchange, not only the server's
// contribution. stateDigest is StateDigest of the bundle's CDS rollout state,
// empty when it carries none. Every variable-length field is length-prefixed
// to make the transcript unambiguous across the Go and browser implementations.
func IdentityTranscriptHash(mode types.FrontDoorMode, xwingEK, xwingCT, sessionID, nonce, leafDER, caDER, stateDigest []byte) ([]byte, error) {
	if mode == "" {
		return nil, fmt.Errorf("overenc: identity transcript requires a front-door mode")
	}
	if len(xwingEK) != XWingEKBytes {
		return nil, fmt.Errorf("overenc: identity transcript X-Wing key must be %d bytes, got %d", XWingEKBytes, len(xwingEK))
	}
	if len(xwingCT) != XWingCTBytes {
		return nil, fmt.Errorf("overenc: identity transcript X-Wing ciphertext must be %d bytes, got %d", XWingCTBytes, len(xwingCT))
	}
	if len(sessionID) != SessionIDBytes {
		return nil, fmt.Errorf("overenc: identity transcript session id must be %d bytes, got %d", SessionIDBytes, len(sessionID))
	}
	if len(nonce) != identityNonceBytes {
		return nil, fmt.Errorf("overenc: identity transcript nonce must be %d bytes, got %d", identityNonceBytes, len(nonce))
	}
	if len(leafDER) == 0 || len(caDER) == 0 {
		return nil, fmt.Errorf("overenc: identity transcript requires leaf and CA certificates")
	}
	if err := checkStateDigest(stateDigest); err != nil {
		return nil, err
	}

	leafHash := sha256.Sum256(leafDER)
	caHash := sha256.Sum256(caDER)
	var encoded []byte
	// Most-stable fields first so a signer can reuse the hash state across sessions.
	for _, field := range [][]byte{
		[]byte(identityTranscriptDomain),
		[]byte(mode),
		caHash[:],
		leafHash[:],
		xwingEK,
		xwingCT,
		sessionID,
		nonce,
		stateDigest,
	} {
		var err error
		if encoded, err = appendLengthPrefixed(encoded, field); err != nil {
			return nil, err
		}
	}
	sum := sha512.Sum384(encoded)
	return sum[:], nil
}

// LBTranscriptHash commits the front-door mode, client nonce, exact outer
// serving leaf, exact mesh leaf, and issuing mesh CA to one SHA-384 value
// suitable for TEE report_data — the attest-lb binding for clients that ride
// ordinary nginx TLS:
//
//	SHA-384( LP("c8s/attest-lb/v1") || LP(mode) || LP(nonce) ||
//	         LP(SHA-256(serving_leaf_DER)) || LP(SHA-256(mesh_leaf_DER)) ||
//	         LP(SHA-256(mesh_CA_DER)) || LP(state_digest) )
//
// A client recomputes it from the exact leaf it observed on the connection
// being authorized, so a response relayed through a different serving leaf
// fails even when both leaves share an issuer.
func LBTranscriptHash(mode types.FrontDoorMode, nonce, servingLeafDER, meshLeafDER, caDER, stateDigest []byte) ([]byte, error) {
	if mode == "" {
		return nil, fmt.Errorf("overenc: lb transcript requires a front-door mode")
	}
	if len(nonce) != identityNonceBytes {
		return nil, fmt.Errorf("overenc: lb transcript nonce must be %d bytes, got %d", identityNonceBytes, len(nonce))
	}
	if len(servingLeafDER) == 0 || len(meshLeafDER) == 0 || len(caDER) == 0 {
		return nil, fmt.Errorf("overenc: lb transcript requires serving leaf, mesh leaf, and CA certificates")
	}
	if err := checkStateDigest(stateDigest); err != nil {
		return nil, err
	}

	servingHash := sha256.Sum256(servingLeafDER)
	meshHash := sha256.Sum256(meshLeafDER)
	caHash := sha256.Sum256(caDER)
	var encoded []byte
	for _, field := range [][]byte{
		[]byte(lbTranscriptDomain),
		[]byte(mode),
		nonce,
		servingHash[:],
		meshHash[:],
		caHash[:],
		stateDigest,
	} {
		var err error
		if encoded, err = appendLengthPrefixed(encoded, field); err != nil {
			return nil, err
		}
	}
	sum := sha512.Sum384(encoded)
	return sum[:], nil
}

// StateDigest is the SHA-384 of the exact CDS rollout state bytes a bundle
// carries, or nil when it carries none.
func StateDigest(state []byte) []byte {
	if len(state) == 0 {
		return nil
	}
	sum := sha512.Sum384(state)
	return sum[:]
}

func checkStateDigest(d []byte) error {
	if len(d) != 0 && len(d) != sha512.Size384 {
		return fmt.Errorf("overenc: transcript state digest must be empty or %d bytes, got %d", sha512.Size384, len(d))
	}
	return nil
}

// appendLengthPrefixed is the single owner of the transcript's LP(field) wire
// encoding (uint32_be length || field).
func appendLengthPrefixed(dst, field []byte) ([]byte, error) {
	if uint64(len(field)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("overenc: identity transcript field is too large")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	dst = append(dst, size[:]...)
	return append(dst, field...), nil
}
