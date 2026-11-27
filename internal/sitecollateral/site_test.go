package sitecollateral

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSiteSelection(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	const name = "https://vendor.example/signed"
	obj := []byte("vendor response")
	digest := func(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
	sign := func(gen uint64) ([]byte, []byte, Selection) {
		m := Manifest{
			Generation: gen,
			Target:     "platform1",
			ExpiresAt:  now.Add(time.Hour),
			Objects:    map[string]Object{name: {SHA256: digest(obj), Header: http.Header{"Issuer-Chain": {"vendor chain"}}}},
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw, ed25519.Sign(key, raw), Selection{Generation: gen, SHA256: digest(raw)}
	}
	rawA, sigA, activeA := sign(1)
	rawB, sigB, activeB := sign(2)
	for _, tc := range []struct {
		name                  string
		selected              Selection
		raw, sig, body        []byte
		date                  time.Time
		echo, available       bool
		wantPass, unavailable bool
	}{
		{"first generation", activeA, rawA, sigA, obj, now, true, true, true, false},
		{"new generation", activeB, rawB, sigB, obj, now, true, true, true, false},
		{"restored older store", activeB, rawA, sigA, obj, now, true, true, false, false},
		{"changed object", activeB, rawB, sigB, []byte("another"), now, true, true, false, false},
		{"changed signature", activeB, rawB, sigA, obj, now, true, true, false, false},
		{"wrong generation", Selection{Generation: 1, SHA256: activeB.SHA256}, rawB, sigB, obj, now, true, true, false, false},
		{"expired", activeB, rawB, sigB, obj, now.Add(time.Hour), true, true, false, false},
		{"missing site time", activeB, rawB, sigB, obj, time.Time{}, true, true, false, true},
		{"replayed selection", activeB, rawB, sigB, obj, now, false, true, false, true},
		{"changed during read", activeB, rawB, sigB, obj, now, true, true, false, false},
		{"expired during read", activeB, rawB, sigB, obj, now, true, true, false, false},
		{"site unavailable", activeB, rawB, sigB, obj, now, true, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/active":
					if !tc.available {
						http.Error(w, "unavailable", http.StatusServiceUnavailable)
						return
					}
					reads++
					at := tc.date
					selection := tc.selected
					if reads == 2 && tc.name == "changed during read" {
						selection = activeA
					}
					if reads == 2 && tc.name == "expired during read" {
						at = now.Add(time.Hour)
					}
					if at.IsZero() {
						w.Header()["X-C8s-Time"] = nil
					} else {
						w.Header().Set("X-C8s-Time", at.Format(time.RFC3339Nano))
					}
					challenge, err := hex.DecodeString(r.Header.Get("X-C8s-Challenge"))
					if err != nil || len(challenge) != 32 {
						t.Error("missing 256-bit challenge")
					}
					if tc.echo {
						w.Header().Set("X-C8s-Challenge", r.Header.Get("X-C8s-Challenge"))
					}
					_ = json.NewEncoder(w).Encode(selection)
				case "/snapshots/" + tc.selected.SHA256 + ".json":
					_, _ = w.Write(tc.raw)
				case "/snapshots/" + tc.selected.SHA256 + ".sig":
					_, _ = w.Write(tc.sig)
				case "/objects/" + digest(obj):
					_, _ = w.Write(tc.body)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			p := Profile{
				Origin:         server.URL,
				Target:         "platform1",
				TLSCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
				MediaPublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "profile.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			snap, err := Open(context.Background(), path)
			if err == nil {
				site, err := p.authority()
				if err != nil {
					t.Fatal(err)
				}
				if site.client.Timeout <= 0 || site.client.Timeout > 10*time.Second {
					t.Fatalf("site HTTP timeout = %s, want a positive bound of at most ten seconds", site.client.Timeout)
				}
				if _, _, err := snap.Get("https://unselected.example"); err == nil {
					t.Error("accepted an unlisted object")
				}
				var headers http.Header
				var data []byte
				headers, data, err = snap.Get(name)
				if err == nil && (!snap.Time.Equal(tc.date) || string(data) != string(obj) || headers.Get("Issuer-Chain") != "vendor chain") {
					t.Fatal("authenticated time, body or issuer chain differs")
				}
			}
			if (err == nil) != tc.wantPass || errors.Is(err, ErrUnavailable) != tc.unavailable {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}
