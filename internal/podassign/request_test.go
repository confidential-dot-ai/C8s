package podassign_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	return podassign.Request{Nonce: bytes.Repeat([]byte{7}, 32), Manifest: []byte("manifest\n"), Entries: []byte("{}"), MeshPeers: []byte("[]"), ClientDocument: []byte("client document")}
}

// A round trip verifies; any altered signed field, another
// serving key or another launch key is refused.
func TestAssignmentBindsEveryFieldAndServingKey(t *testing.T) {
	launch, serving := key(t, elliptic.P256()), key(t, elliptic.P256())
	for _, field := range []string{"none", "nonce", "manifest", "entries", "peers", "client-document", "signature", "launch-key", "p384-launch-key", "serving-key"} {
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
			case "client-document":
				req.ClientDocument[0] ^= 1
			case "signature":
				req.Signature[0] ^= 1
			case "launch-key":
				pub = &key(t, elliptic.P256()).PublicKey
			case "p384-launch-key":
				pub = &key(t, elliptic.P384()).PublicKey
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

// Construct the spec message independently of the implementation. This
// catches a mutually compatible signer/verifier that hashes twice or omits the
// domain.
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
	message := bytes.NewBufferString("c8s-pod-assign/v2")
	message.WriteByte(0)
	message.Write(spki)
	message.Write(req.Nonce)
	m, e, p, c := sha256.Sum256(req.Manifest), sha256.Sum256(req.Entries), sha256.Sum256(req.MeshPeers), sha256.Sum256(req.ClientDocument)
	message.Write(m[:])
	message.Write(e[:])
	message.Write(p[:])
	message.Write(c[:])
	digest := sha256.Sum256(message.Bytes())
	if !ecdsa.VerifyASN1(&launch.PublicKey, digest[:], req.Signature) {
		t.Fatal("signature is not over the specified message")
	}
	double := sha256.Sum256(digest[:])
	if ecdsa.VerifyASN1(&launch.PublicKey, double[:], req.Signature) {
		t.Fatal("double-hashed message accepted")
	}
	other := sha256.Sum256(append([]byte("c8s-pod-assign/v1\x00"), message.Bytes()[len("c8s-pod-assign/v2\x00"):]...))
	if ecdsa.VerifyASN1(&launch.PublicKey, other[:], req.Signature) {
		t.Fatal("another domain accepted")
	}
}

// Exactly the six members, each base64. One case per Decode refusal.
func TestDecodeRequiresExactBase64Object(t *testing.T) {
	valid, err := podassign.Encode(request())
	if err != nil {
		t.Fatal(err)
	}
	body := string(valid[:len(valid)-1])
	for name, data := range map[string]string{
		"missing member":       strings.Replace(string(valid), "\"nonce\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\",", "", 1),
		"extra member":         body + ",\"extra\":\"\"}",
		"non-base64 signature": strings.Replace(string(valid), "\"signature\":\"\"", "\"signature\":\"?\"", 1),
		"noncanonical":         strings.Replace(string(valid), "\"entries\":\"e30=\"", "\"entries\":\"e30=\\n\"", 1),
		"short nonce":          strings.Replace(string(valid), "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=", "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw==", 1),
		"oversized body":       strings.Repeat(" ", podassign.MaxBody+1),
		"oversized document":   strings.Replace(string(valid), "\"clientDocument\":\"Y2xpZW50IGRvY3VtZW50\"", "\"clientDocument\":\""+base64.StdEncoding.EncodeToString(make([]byte, podassign.MaxClientDocument+1))+"\"", 1),
	} {
		if data == string(valid) {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := podassign.Decode([]byte(data)); !errors.Is(err, podassign.ErrMalformed) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	req := request()
	req.Nonce = req.Nonce[1:]
	if _, err := podassign.Encode(req); !errors.Is(err, podassign.ErrMalformed) {
		t.Fatal("short nonce encoded")
	}
	req = request()
	req.ClientDocument = make([]byte, podassign.MaxClientDocument+1)
	if _, err := podassign.Encode(req); !errors.Is(err, podassign.ErrMalformed) {
		t.Fatal("oversized client document encoded")
	}
}

// An assignment without a client document carries an empty member, which the
// signature covers like any other.
func TestAssignmentWithoutClientDocument(t *testing.T) {
	launch, serving := key(t, elliptic.P256()), key(t, elliptic.P256())
	req := request()
	req.ClientDocument = nil
	signed, err := podassign.Sign(launch, &serving.PublicKey, req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := podassign.Encode(signed)
	if err != nil || !strings.Contains(string(data), `"clientDocument":""`) {
		t.Fatalf("encoded %s: %v", data, err)
	}
	decoded, err := podassign.Decode(data)
	if err != nil || len(decoded.ClientDocument) != 0 {
		t.Fatalf("decoded %+v: %v", decoded, err)
	}
	if err := podassign.Verify(&launch.PublicKey, &serving.PublicKey, decoded); err != nil {
		t.Fatal(err)
	}
	decoded.ClientDocument = []byte("added")
	if err := podassign.Verify(&launch.PublicKey, &serving.PublicKey, decoded); !errors.Is(err, podassign.ErrSignature) {
		t.Fatalf("a document added after signing verified: %v", err)
	}
}
