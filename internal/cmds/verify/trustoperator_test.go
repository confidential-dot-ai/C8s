package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestTrustOperator(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keysPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	keySet, err := operatorauth.KeySetHash([]*ecdsa.PublicKey{&key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}

	objects := map[string]string{"/.well-known/c8s/operator-keys": string(keysPEM)}
	policy := func(body string, signed bool) string {
		sum := sha256.Sum256([]byte(body))
		path := "/.well-known/c8s/objects/sha256/" + hex.EncodeToString(sum[:])
		objects[path] = body
		if signed {
			auth, err := signer.Authorization(http.MethodPut, "/allowlist", []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			objects[path+"/signature"] = strings.TrimPrefix(auth, "Bearer ")
		}
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	signed := policy(`{"schema":"a"}`, true)
	unsigned := policy(`{"schema":"b"}`, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := objects[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	state := func(keys string, bound ...string) *types.RolloutState {
		return &types.RolloutState{Bound: bound, Lease: 30, OperatorKeys: keys}
	}
	for _, tc := range []struct {
		name string
		ev   evidence
		want string
	}{
		{"every policy signed", evidence{fresh: true, rollout: state(keySet, signed)}, ""},
		{"unsigned policy", evidence{fresh: true, rollout: state(keySet, signed, unsigned)}, "policy_not_signed"},
		{"state names another key set", evidence{fresh: true, rollout: state("sha256:other", signed)}, "operator_keys_mismatch"},
		{"immutable allowlist", evidence{fresh: true, rollout: state(types.OperatorKeysNone, signed)}, "operator_keys_mismatch"},
		{"stale state", evidence{rollout: state(keySet, signed)}, "pinned_state_stale"},
	} {
		oc := Outcome{Verified: true}
		trustOperator(context.Background(), config{url: srv.URL, trustOperator: true, timeout: 5 * time.Second}, &tc.ev, &oc)
		if (tc.want == "") != oc.Verified || !strings.Contains(oc.Error, tc.want) {
			t.Errorf("%s: verified=%v error=%q, want error containing %q", tc.name, oc.Verified, oc.Error, tc.want)
		}
	}

	// A pinned key set wins over the one the router serves.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pinned := filepath.Join(dir, "keys.pem")
	wrong := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(pinned, keysPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrong, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	objects["/.well-known/c8s/operator-keys"] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}))
	for _, tc := range []struct {
		keys string
		want string
	}{{pinned, ""}, {wrong, "operator_keys_mismatch"}} {
		oc := Outcome{Verified: true}
		ev := evidence{fresh: true, rollout: state(keySet, signed)}
		trustOperator(context.Background(), config{url: srv.URL, trustOperator: true, trustOperatorKeys: tc.keys, timeout: 5 * time.Second}, &ev, &oc)
		if (tc.want == "") != oc.Verified || !strings.Contains(oc.Error, tc.want) {
			t.Errorf("pinned %s: verified=%v error=%q, want error containing %q", filepath.Base(tc.keys), oc.Verified, oc.Error, tc.want)
		}
	}
	if _, err := buildPolicy(config{trustOperatorKeys: pinned}); err == nil || !strings.Contains(err.Error(), "requires --trust-operator") {
		t.Fatalf("buildPolicy(--trust-operator-keys alone) = %v, want the --trust-operator error", err)
	}
}
