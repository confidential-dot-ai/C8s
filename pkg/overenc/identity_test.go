package overenc

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Cross-language contract: c8s-verify-js/test/identity.test.ts must reproduce
// the v1 transcript vector pinned here.
func TestIdentityTranscriptHashBindsEveryField(t *testing.T) {
	ek := bytes.Repeat([]byte{0x11}, XWingEKBytes)
	ct := bytes.Repeat([]byte{0x22}, XWingCTBytes)
	sessionID := bytes.Repeat([]byte{0x44}, SessionIDBytes)
	nonce := bytes.Repeat([]byte{0x33}, identityNonceBytes)
	leaf := []byte("leaf-der")
	ca := []byte("ca-der")
	const mode = "cds"

	base, err := IdentityTranscriptHash(mode, ek, ct, sessionID, nonce, leaf, ca, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha512.Size384 {
		t.Fatalf("transcript hash length = %d, want %d", len(base), sha512.Size384)
	}
	const vector = "8f534c54dce6062fbf66e7f9b4317ab98b736786c72f101de5df3b4f1951e090325fccc6f700083b03a132a07d40c9df"
	if hex.EncodeToString(base) != vector {
		t.Fatalf("cross-language transcript vector = %x, want %s", base, vector)
	}
	withState, err := IdentityTranscriptHash(mode, ek, ct, sessionID, nonce, leaf, ca, StateDigest([]byte(`{"bound":[]}`)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(withState, base) {
		t.Fatal("state digest does not change the transcript")
	}
	if _, err := IdentityTranscriptHash(mode, ek, ct, sessionID, nonce, leaf, ca, []byte{1}); err == nil {
		t.Fatal("accepted a state digest that is neither empty nor SHA-384")
	}

	tests := []struct {
		name                     string
		mode                     types.FrontDoorMode
		ek, ct, sessionID, nonce []byte
		leaf, ca                 []byte
	}{
		{name: "mode", mode: "acme", ek: ek, ct: ct, sessionID: sessionID, nonce: nonce, leaf: leaf, ca: ca},
		{name: "ek", mode: mode, ek: bytes.Repeat([]byte{0x55}, XWingEKBytes), ct: ct, sessionID: sessionID, nonce: nonce, leaf: leaf, ca: ca},
		{name: "ct", mode: mode, ek: ek, ct: bytes.Repeat([]byte{0x66}, XWingCTBytes), sessionID: sessionID, nonce: nonce, leaf: leaf, ca: ca},
		{name: "session id", mode: mode, ek: ek, ct: ct, sessionID: bytes.Repeat([]byte{0x77}, SessionIDBytes), nonce: nonce, leaf: leaf, ca: ca},
		{name: "nonce", mode: mode, ek: ek, ct: ct, sessionID: sessionID, nonce: bytes.Repeat([]byte{0x88}, identityNonceBytes), leaf: leaf, ca: ca},
		{name: "leaf", mode: mode, ek: ek, ct: ct, sessionID: sessionID, nonce: nonce, leaf: []byte("other-leaf"), ca: ca},
		{name: "ca", mode: mode, ek: ek, ct: ct, sessionID: sessionID, nonce: nonce, leaf: leaf, ca: []byte("other-ca")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IdentityTranscriptHash(tt.mode, tt.ek, tt.ct, tt.sessionID, tt.nonce, tt.leaf, tt.ca, nil)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatal("changed field did not change transcript hash")
			}
		})
	}
}

func TestLBTranscriptHashBindsEveryField(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x33}, identityNonceBytes)
	serving := []byte("serving-der")
	leaf := []byte("leaf-der")
	ca := []byte("ca-der")
	const mode = "cds"

	base, err := LBTranscriptHash(mode, nonce, serving, leaf, ca, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha512.Size384 {
		t.Fatalf("transcript hash length = %d, want %d", len(base), sha512.Size384)
	}

	tests := []struct {
		name                     string
		mode                     types.FrontDoorMode
		nonce, serving, leaf, ca []byte
	}{
		{name: "mode", mode: "acme", nonce: nonce, serving: serving, leaf: leaf, ca: ca},
		{name: "nonce", mode: mode, nonce: bytes.Repeat([]byte{0x66}, identityNonceBytes), serving: serving, leaf: leaf, ca: ca},
		{name: "serving leaf", mode: mode, nonce: nonce, serving: []byte("other-serving"), leaf: leaf, ca: ca},
		{name: "mesh leaf", mode: mode, nonce: nonce, serving: serving, leaf: []byte("other-leaf"), ca: ca},
		{name: "ca", mode: mode, nonce: nonce, serving: serving, leaf: leaf, ca: []byte("other-ca")},
		// Swapping the serving and mesh leaves must change the hash: the
		// per-field positions are load-bearing, not just the field set.
		{name: "serving/mesh swap", mode: mode, nonce: nonce, serving: leaf, leaf: serving, ca: ca},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LBTranscriptHash(tt.mode, tt.nonce, tt.serving, tt.leaf, tt.ca, nil)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatal("changed field did not change transcript hash")
			}
		})
	}
}

func TestLBTranscriptHashValidatesShape(t *testing.T) {
	nonce := make([]byte, identityNonceBytes)
	for _, tc := range []struct {
		name                     string
		mode                     types.FrontDoorMode
		nonce, serving, leaf, ca []byte
		wantErr                  string
	}{
		{name: "mode empty", nonce: nonce, serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}, wantErr: "lb transcript requires a front-door mode"},
		{name: "nonce short", mode: "cds", nonce: make([]byte, 16), serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}, wantErr: "lb transcript nonce must be 32 bytes, got 16"},
		{name: "nonce long", mode: "cds", nonce: make([]byte, 33), serving: []byte{1}, leaf: []byte{2}, ca: []byte{3}, wantErr: "lb transcript nonce must be 32 bytes, got 33"},
		{name: "serving leaf empty", mode: "cds", nonce: nonce, leaf: []byte{2}, ca: []byte{3}, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
		{name: "mesh leaf empty", mode: "cds", nonce: nonce, serving: []byte{1}, ca: []byte{3}, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
		{name: "ca empty", mode: "cds", nonce: nonce, serving: []byte{1}, leaf: []byte{2}, wantErr: "lb transcript requires serving leaf, mesh leaf, and CA certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LBTranscriptHash(tc.mode, tc.nonce, tc.serving, tc.leaf, tc.ca, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestLBTranscriptGoldenVectors pins the attest-lb transcript encoding.
// Cross-repo contract: TEErminator reimplements this transcript; its
// internal/verifier/endpoint_test.go must reproduce these vectors.
func TestLBTranscriptGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "attest_lb_transcript_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Description    string              `json:"description"`
		FrontDoorMode  types.FrontDoorMode `json:"front_door_mode"`
		NonceB64       string              `json:"nonce_b64"`
		ServingLeafB64 string              `json:"serving_leaf_der_b64"`
		MeshLeafB64    string              `json:"mesh_leaf_der_b64"`
		MeshCAB64      string              `json:"mesh_ca_der_b64"`
		StateB64       string              `json:"state_b64"`
		ReportDataB64  string              `json:"report_data_b64"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no golden vectors")
	}
	decode := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("bad vector base64 %q: %v", s, err)
		}
		return b
	}
	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			got, err := LBTranscriptHash(v.FrontDoorMode, decode(v.NonceB64), decode(v.ServingLeafB64), decode(v.MeshLeafB64), decode(v.MeshCAB64), StateDigest(decode(v.StateB64)))
			if err != nil {
				t.Fatal(err)
			}
			if want := decode(v.ReportDataB64); !bytes.Equal(got, want) {
				t.Fatalf("report_data = %x, want %x", got, want)
			}
		})
	}
}

func TestIdentityTranscriptHashValidatesShape(t *testing.T) {
	ek := make([]byte, XWingEKBytes)
	ct := make([]byte, XWingCTBytes)
	id := make([]byte, SessionIDBytes)
	nonce := make([]byte, identityNonceBytes)
	for _, tc := range []struct {
		name                     string
		mode                     types.FrontDoorMode
		ek, ct, sessionID, nonce []byte
		leaf, ca                 []byte
		wantErr                  string
	}{
		{name: "mode empty", ek: ek, ct: ct, sessionID: id, nonce: nonce, leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript requires a front-door mode"},
		{name: "ek", mode: "cds", ek: make([]byte, 1), ct: ct, sessionID: id, nonce: nonce, leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript X-Wing key must be 1216 bytes, got 1"},
		{name: "ct", mode: "cds", ek: ek, ct: make([]byte, 1), sessionID: id, nonce: nonce, leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript X-Wing ciphertext must be 1120 bytes, got 1"},
		{name: "session id", mode: "cds", ek: ek, ct: ct, sessionID: make([]byte, 1), nonce: nonce, leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript session id must be 16 bytes, got 1"},
		{name: "nonce", mode: "cds", ek: ek, ct: ct, sessionID: id, nonce: make([]byte, 16), leaf: []byte{1}, ca: []byte{2}, wantErr: "identity transcript nonce must be 32 bytes, got 16"},
		{name: "leaf", mode: "cds", ek: ek, ct: ct, sessionID: id, nonce: nonce, ca: []byte{2}, wantErr: "identity transcript requires leaf and CA certificates"},
		{name: "ca", mode: "cds", ek: ek, ct: ct, sessionID: id, nonce: nonce, leaf: []byte{1}, wantErr: "identity transcript requires leaf and CA certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := IdentityTranscriptHash(tc.mode, tc.ek, tc.ct, tc.sessionID, tc.nonce, tc.leaf, tc.ca, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
