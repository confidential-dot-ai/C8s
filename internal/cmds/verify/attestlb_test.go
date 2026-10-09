package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		_, err = evidenceFromAttestLBJSON(data, nonce, leaf, true, "test")
		if err == nil || isSecurityError(err) != tc.security {
			t.Errorf("%s: err = %v, want an error (security %v)", tc.name, err, tc.security)
		}
	}
}

func TestGatherAttestLBFromFile(t *testing.T) {
	id := mintEndpointIdentity(t)
	ts := attestLBServer(t, id, nil)
	defer ts.Close()

	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x07}, nonceSize))
	resp, err := ts.Client().Get(ts.URL + "/.well-known/c8s/attest-lb?nonce=" + nonce)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeCert := func(name string, der []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	serving := writeCert("serving.pem", ts.Certificate().Raw)

	ev, err := gatherAttestLBFromFile(receipt, serving, nonce, "test")
	if err != nil {
		t.Fatalf("gatherAttestLBFromFile: %v", err)
	}
	if ev.fresh || !bytes.Equal(ev.leaf.Raw, id.leaf.Raw) {
		t.Errorf("evidence = fresh %v; want a non-fresh verdict on the committed mesh leaf", ev.fresh)
	}
	if want := servingLeafDigest(ts.Certificate().Raw); ev.servingLeafSHA256 != want {
		t.Errorf("servingLeafSHA256 = %q, want %q (the observed leaf)", ev.servingLeafSHA256, want)
	}
	if !strings.Contains(ev.bindingNote, "--observed-serving-cert") {
		t.Errorf("bindingNote = %q, want it to name the caller-supplied serving leaf", ev.bindingNote)
	}

	var object map[string]any
	if err := json.Unmarshal(receipt, &object); err != nil {
		t.Fatal(err)
	}
	object["serving_leaf_sha256"] = servingLeafDigest(id.leaf.Raw)
	mislabeled, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gatherAttestLBFromFile(mislabeled, serving, nonce, "test"); !isSecurityError(err) {
		t.Errorf("receipt whose serving_leaf_sha256 names another leaf = %v, want a security error", err)
	}

	other := writeCert("other.pem", id.leaf.Raw)
	if _, err := gatherAttestLBFromFile(receipt, other, nonce, "test"); !isSecurityError(err) {
		t.Errorf("receipt with another serving leaf = %v, want a security error", err)
	}
	otherNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x08}, nonceSize))
	if _, err := gatherAttestLBFromFile(receipt, serving, otherNonce, "test"); !isSecurityError(err) {
		t.Errorf("receipt with another nonce = %v, want a security error", err)
	}
	if _, err := gatherAttestLBFromFile(receipt, serving, "short", "test"); err == nil || isSecurityError(err) {
		t.Errorf("malformed nonce = %v, want a usage error", err)
	}
}

func TestRunAttestLBFromFileFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config
	}{
		{"missing nonce", config{mode: "attest-lb", fromFile: "r.json", observedServingCert: "c.pem"}},
		{"missing serving cert", config{mode: "attest-lb", fromFile: "r.json", attestationNonce: "n"}},
		{"live attest-lb", config{mode: "attest-lb", url: "x", observedServingCert: "c.pem", attestationNonce: "n"}},
		{"other mode", config{fromFile: "r.json", observedServingCert: "c.pem", attestationNonce: "n"}},
	} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), tc.cfg, &out, &errOut); code != exitUsage {
			t.Errorf("%s: run = %d, want %d; stderr: %s", tc.name, code, exitUsage, errOut.String())
		}
	}
}
