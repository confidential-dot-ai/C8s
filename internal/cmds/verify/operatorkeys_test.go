package verify

import (
	"bytes"
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
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// startKeysTLSServer serves /operator-keys over TLS and returns the base URL
// plus the hex SHA-256 of its serving certificate (what the attested-cert pin
// expects).
func startKeysTLSServer(t *testing.T, handler http.HandlerFunc) (base, certSHA256 string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return srv.URL, hex.EncodeToString(sum[:])
}

func operatorPubPEM(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), hex.EncodeToString(sum[:])
}

func TestFetchOperatorKeyFingerprints(t *testing.T) {
	pubPEM, wantFP := operatorPubPEM(t)
	base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/operator-keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(pubPEM)
	})

	fps, digest, note, err := fetchOperatorKeyFingerprints(context.Background(), base, "", certSHA, 5*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if note != "" {
		t.Fatalf("unexpected note: %q", note)
	}
	if len(fps) != 1 || fps[0] != wantFP {
		t.Fatalf("fingerprints = %v, want [%s]", fps, wantFP)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want, err := operatorauth.KeySetDigest(keys)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !bytes.Equal(digest, want) {
		t.Fatalf("served-set digest = %x, want %x", digest, want)
	}
}

// TestFetchOperatorKeysRejectsCertMismatch proves the attested-cert binding: a
// server presenting a different cert than the one whose attestation was
// verified must be rejected, so a MITM on the key fetch cannot inject keys.
func TestFetchOperatorKeysRejectsCertMismatch(t *testing.T) {
	pubPEM, _ := operatorPubPEM(t)
	base, _ := startKeysTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(pubPEM)
	})

	wrong := strings.Repeat("ab", 32) // a sha256 that is not the serving cert's
	_, _, _, err := fetchOperatorKeyFingerprints(context.Background(), base, "", wrong, 5*time.Second)
	if err == nil {
		t.Fatal("expected a cert mismatch to fail the fetch")
	}
}

// A response of exactly operatorauth.MaxPublishedKeysBytes is within the cap and must parse.
func TestFetchOperatorKeysExactCapAccepted(t *testing.T) {
	pubPEM, wantFP := operatorPubPEM(t)
	if len(pubPEM) > operatorauth.MaxPublishedKeysBytes {
		t.Fatalf("fixture PEM larger than the cap (%d bytes)", len(pubPEM))
	}
	body := append(append([]byte{}, pubPEM...), bytes.Repeat([]byte{'\n'}, operatorauth.MaxPublishedKeysBytes-len(pubPEM))...)
	base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})

	fps, _, _, err := fetchOperatorKeyFingerprints(context.Background(), base, "", certSHA, 5*time.Second)
	if err != nil {
		t.Fatalf("an exactly-cap-sized response must be accepted: %v", err)
	}
	if len(fps) != 1 || fps[0] != wantFP {
		t.Fatalf("fingerprints = %v, want [%s]", fps, wantFP)
	}
}

func TestFetchOperatorKeys404MeansDisabled(t *testing.T) {
	base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no operator keys configured", http.StatusNotFound)
	})

	fps, digest, note, err := fetchOperatorKeyFingerprints(context.Background(), base, "", certSHA, 5*time.Second)
	if err != nil {
		t.Fatalf("404 should not be an error, got %v", err)
	}
	emptyDigest, err := operatorauth.KeySetDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fps) != 0 || !bytes.Equal(digest, emptyDigest) || note == "" {
		t.Fatalf("expected no fingerprints, the empty-set digest, and an explanatory note, got fps=%v digest=%x note=%q", fps, digest, note)
	}
}

func TestGatherOperatorKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("skipped for non-cds kinds and file targets", func(t *testing.T) {
		got := gatherOperatorKeys(ctx, config{kind: "lb", url: "x"}, &evidence{})
		if !strings.Contains(got.note, "skipped") || got.fingerprints != nil || got.fetchErr != nil {
			t.Errorf("non-cds kind must skip the cross-check without fetching, got %+v", got)
		}
		if got := gatherOperatorKeys(ctx, config{kind: "cds"}, &evidence{}); got.note != "" {
			t.Errorf("no url should be a no-op, got %+v", got)
		}
	})

	t.Run("no serving cert to bind to", func(t *testing.T) {
		got := gatherOperatorKeys(ctx, config{kind: "cds", url: "cds.example.com"}, &evidence{})
		if got.note == "" || got.fingerprints != nil {
			t.Errorf("no attested cert must skip the fetch with a note, got %+v", got)
		}
	})

	t.Run("bad target", func(t *testing.T) {
		got := gatherOperatorKeys(ctx, config{kind: "cds", url: "https://\x7f"}, &evidence{certSHA256: "aa"})
		if !strings.HasPrefix(got.note, "not fetched:") || got.fetchErr != nil {
			t.Errorf("unparseable target should degrade to a note, got %+v", got)
		}
	})

	t.Run("fetches and binds to the attested cert", func(t *testing.T) {
		pubPEM, wantFP := operatorPubPEM(t)
		base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/operator-keys" {
				http.NotFound(w, r)
				return
			}
			w.Write(pubPEM)
		})
		got := gatherOperatorKeys(ctx, config{kind: "cds", url: base, timeout: 5 * time.Second}, &evidence{certSHA256: certSHA})
		if got.fetchErr != nil || got.note != "" {
			t.Fatalf("fetch failed: %+v", got)
		}
		if len(got.fingerprints) != 1 || got.fingerprints[0] != wantFP {
			t.Errorf("fingerprints = %v, want [%s]", got.fingerprints, wantFP)
		}
	})

	t.Run("fetch failure records fetchErr", func(t *testing.T) {
		base, _ := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		got := gatherOperatorKeys(ctx, config{kind: "cds", url: base, timeout: 5 * time.Second}, &evidence{certSHA256: strings.Repeat("ab", 32)})
		if got.fetchErr == nil || !strings.HasPrefix(got.note, "not fetched:") {
			t.Errorf("expected a recorded fetch error, got %+v", got)
		}
	})
}

func TestFetchOperatorKeyFingerprints_Errors(t *testing.T) {
	ctx := context.Background()

	t.Run("no attested cert pin", func(t *testing.T) {
		if _, _, _, err := fetchOperatorKeyFingerprints(ctx, "https://x", "", "", time.Second); err == nil {
			t.Error("empty wantCertSHA256 must be rejected")
		}
	})

	t.Run("non-200 non-404", func(t *testing.T) {
		base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		})
		if _, _, _, err := fetchOperatorKeyFingerprints(ctx, base, "", certSHA, 5*time.Second); err == nil || !strings.Contains(err.Error(), "500") {
			t.Errorf("expected a 500 error, got %v", err)
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write(bytes.Repeat([]byte("A"), operatorauth.MaxPublishedKeysBytes+2))
		})
		if _, _, _, err := fetchOperatorKeyFingerprints(ctx, base, "", certSHA, 5*time.Second); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("expected an oversize rejection, got %v", err)
		}
	})

	t.Run("unparseable body", func(t *testing.T) {
		base, certSHA := startKeysTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not pem at all"))
		})
		if _, _, _, err := fetchOperatorKeyFingerprints(ctx, base, "", certSHA, 5*time.Second); err == nil || !strings.Contains(err.Error(), "parse /operator-keys") {
			t.Errorf("expected a parse error, got %v", err)
		}
	})
}
