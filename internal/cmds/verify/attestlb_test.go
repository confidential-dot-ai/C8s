package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// attestLBServer answers attest-lb with a transcript over bindLeaf, or over
// its own serving leaf when bindLeaf is nil.
func attestLBServer(t *testing.T, id *endpointIdentity, bindLeaf []byte) *httptest.Server {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		leaf := bindLeaf
		if leaf == nil {
			leaf = ts.Certificate().Raw
		}
		transcript, err := overenc.LBTranscriptHash(types.FrontDoorModeCDS, nonce, leaf, id.leaf.Raw, id.ca.Raw)
		if err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"version":         types.BindingAttestLB,
			"platform":        "snp",
			"nonce":           base64.RawURLEncoding.EncodeToString(nonce),
			"evidence":        map[string]any{"attestation_report": "AAAA"},
			"front_door_mode": "cds",
			"cds_cert_pem":    id.chainPEM,
			"identity_proof":  id.proofJSON(t, transcript),
		})
	}))
	return ts
}

func TestGatherFromAttestLB(t *testing.T) {
	id := mintEndpointIdentity(t)

	ts := attestLBServer(t, id, nil)
	defer ts.Close()
	ev, err := gatherFromAttestLB(context.Background(), ts.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if !ev.fresh || ev.leaf == nil || !bytes.Equal(ev.leaf.Raw, id.leaf.Raw) {
		t.Errorf("evidence = fresh %v, leaf %v; want a fresh verdict on the committed mesh leaf", ev.fresh, ev.leaf != nil)
	}

	relayed := attestLBServer(t, id, []byte("another serving leaf"))
	defer relayed.Close()
	if _, err := gatherFromAttestLB(context.Background(), relayed.URL, "", 5*time.Second); err == nil || !isSecurityError(err) {
		t.Fatalf("gather over a different serving leaf = %v, want a security error", err)
	}
}

func TestEvidenceFromAttestLBJSONRejects(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	leaf := []byte("serving leaf")
	for _, tc := range []struct {
		name     string
		version  string
		echoed   []byte
		security bool
	}{
		{"attest-pq binding", types.BindingAttestPQ, nonce, false},
		{"other nonce", types.BindingAttestLB, bytes.Repeat([]byte{0x08}, nonceSize), true},
	} {
		data, err := json.Marshal(map[string]any{
			"version":  tc.version,
			"nonce":    base64.RawURLEncoding.EncodeToString(tc.echoed),
			"evidence": map[string]any{"attestation_report": "AAAA"},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = evidenceFromAttestLBJSON(data, nonce, leaf, "test")
		if err == nil || isSecurityError(err) != tc.security {
			t.Errorf("%s: err = %v, want an error (security %v)", tc.name, err, tc.security)
		}
	}
}
