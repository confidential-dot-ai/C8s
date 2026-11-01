package podassign_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

func key(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func request() podassign.Request {
	return podassign.Request{Nonce: bytes.Repeat([]byte{7}, 32), Manifest: []byte("manifest\n"), Entries: []byte("{}"), MeshPeers: []byte("[]")}
}

func TestAssignmentBindsEveryFieldAndServingKey(t *testing.T) {
	launch, serving := key(t, elliptic.P256()), key(t, elliptic.P256())
	for _, field := range []string{"none", "nonce", "manifest", "entries", "peers", "signature", "launch-key", "serving-key"} {
		t.Run(field, func(t *testing.T) {
			req, err := podassign.Sign(launch, &serving.PublicKey, request())
			if err != nil {
				t.Fatal(err)
			}
			pub, target := &launch.PublicKey, &serving.PublicKey
			switch field {
			case "nonce":
				req.Nonce[0]++
			case "manifest":
				req.Manifest = append(req.Manifest, ' ')
			case "entries":
				req.Entries = []byte("{ }")
			case "peers":
				req.MeshPeers = []byte("[ ]")
			case "signature":
				req.Signature[0] ^= 1
			case "launch-key":
				pub = &key(t, elliptic.P256()).PublicKey
			case "serving-key":
				target = &key(t, elliptic.P256()).PublicKey
			}
			data, err := podassign.Encode(req)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := podassign.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			err = podassign.Verify(pub, target, decoded)
			if field == "none" && err != nil || field != "none" && !errors.Is(err, podassign.ErrSignature) {
				t.Fatalf("binding %s: %v", field, err)
			}
		})
	}
}

// Construct the spec message independently of the implementation. This catches
// a mutually compatible signer/verifier that hashes twice or omits the domain.
func TestAssignmentUsesTheSpecifiedSingleHashMessage(t *testing.T) {
	launch, serving := key(t, elliptic.P256()), key(t, elliptic.P256())
	req, err := podassign.Sign(launch, &serving.PublicKey, request())
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&serving.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	message := bytes.NewBufferString("c8s-pod-assign/v1")
	message.WriteByte(0)
	message.Write(spki)
	message.Write(req.Nonce)
	m, e, p := sha256.Sum256(req.Manifest), sha256.Sum256(req.Entries), sha256.Sum256(req.MeshPeers)
	message.Write(m[:])
	message.Write(e[:])
	message.Write(p[:])
	digest := sha256.Sum256(message.Bytes())
	if !ecdsa.VerifyASN1(&launch.PublicKey, digest[:], req.Signature) {
		t.Fatal("signature is not over the specified message")
	}
	double := sha256.Sum256(digest[:])
	if ecdsa.VerifyASN1(&launch.PublicKey, double[:], req.Signature) {
		t.Fatal("double-hashed message accepted")
	}
	other := sha256.Sum256(append([]byte("c8s-pod-assign/v2\x00"), message.Bytes()[len("c8s-pod-assign/v1\x00"):]...))
	if ecdsa.VerifyASN1(&launch.PublicKey, other[:], req.Signature) {
		t.Fatal("another domain accepted")
	}
}

func TestDecodeRequiresExactBase64Object(t *testing.T) {
	valid, err := podassign.Encode(request())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(valid, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nonce", "manifest", "entries", "meshPeers", "signature"} {
		for _, value := range []string{"missing", "null", "[]", "23", "true", "\"?\"", "\"AB==\"", "\"YQ==\\n\""} {
			t.Run(name+"/"+value, func(t *testing.T) {
				copyFields := make(map[string]json.RawMessage, len(fields))
				for k, v := range fields {
					copyFields[k] = v
				}
				if value == "missing" {
					delete(copyFields, name)
				} else {
					copyFields[name] = json.RawMessage(value)
				}
				data, err := json.Marshal(copyFields)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := podassign.Decode(data); !errors.Is(err, podassign.ErrMalformed) {
					t.Fatalf("invalid %s accepted: %v", name, err)
				}
			})
		}
	}
	for _, data := range []string{
		"null", "[]", string(valid) + "{}", string(valid[:len(valid)-1]) + ",\"extra\":\"\"}",
		string(valid[:len(valid)-1]) + ",\"nonce\":" + string(fields["nonce"]) + "}",
		strings.Replace(string(valid), "\"nonce\"", "\"Nonce\"", 1),
		strings.Repeat(" ", podassign.MaxBody+1),
	} {
		if _, err := podassign.Decode([]byte(data)); !errors.Is(err, podassign.ErrMalformed) {
			t.Fatalf("invalid object accepted: %v", err)
		}
	}
	for _, size := range []int{0, 31, 33} {
		req := request()
		req.Nonce = make([]byte, size)
		if _, err := podassign.Encode(req); !errors.Is(err, podassign.ErrMalformed) {
			t.Fatal("invalid nonce encoded")
		}
		fields["nonce"], _ = json.Marshal(base64.StdEncoding.EncodeToString(req.Nonce))
		data, _ := json.Marshal(fields)
		if _, err := podassign.Decode(data); !errors.Is(err, podassign.ErrMalformed) {
			t.Fatal("invalid nonce decoded")
		}
	}
}

func TestProtocolSeparatesPayloadValidityAndKeyValidity(t *testing.T) {
	launch, serving := key(t, elliptic.P256()), key(t, elliptic.P256())
	req := request()
	req.Manifest, req.Entries, req.MeshPeers = nil, nil, nil
	signed, err := podassign.Sign(launch, &serving.PublicKey, req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := podassign.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("null")) {
		t.Fatal("empty bytes encoded as null")
	}
	decoded, err := podassign.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := podassign.Verify(&launch.PublicKey, &serving.PublicKey, decoded); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []*ecdsa.PrivateKey{nil, key(t, elliptic.P384()), {}} {
		if _, err := podassign.Sign(invalid, &serving.PublicKey, request()); !errors.Is(err, podassign.ErrSignature) {
			t.Fatal("invalid signing key accepted")
		}
	}
	if err := podassign.Verify(nil, &serving.PublicKey, signed); !errors.Is(err, podassign.ErrSignature) {
		t.Fatal("nil key accepted")
	}
	if _, err := podassign.Sign(launch, nil, request()); !errors.Is(err, podassign.ErrSignature) {
		t.Fatal("nil serving key accepted")
	}
	if _, err := podassign.Sign(launch, (*ecdsa.PublicKey)(nil), request()); !errors.Is(err, podassign.ErrSignature) {
		t.Fatal("typed-nil serving key accepted")
	}
	req = request()
	req.Manifest = make([]byte, podassign.MaxBody)
	if _, err := podassign.Encode(req); !errors.Is(err, podassign.ErrMalformed) {
		t.Fatal("oversized encoded body accepted")
	}
}
