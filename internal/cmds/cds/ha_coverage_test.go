package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/shamir"
)

// decrees reads the applied record from a replica and refuses what it cannot
// trust or decode.
func TestHADecreesCLI(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := strings.Repeat("a", 96)
	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "g1", Kind: cdsha.Genesis, BootstrapNode: "n0",
		Images: []cdsha.DecreeImage{{MRTD: h, RTMR1: h, RTMR2: h}}}, k)
	if err != nil {
		t.Fatal(err)
	}
	records := []cdsha.DecreeRecord{{Decree: sd, AtMS: 1, Epoch: 1}}
	serve := func(code int, body string) string {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ha/decrees" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(code)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(s.Close)
		return s.URL
	}
	raw, _ := json.Marshal(records)
	good := serve(http.StatusOK, string(raw))
	out, err := runHA(t, "decrees", "--url", good+"/", "--insecure")
	if err != nil || !strings.Contains(out, "Genesis") || !strings.Contains(out, "images=1") || !strings.Contains(out, "node=n0") {
		t.Fatalf("decrees: %v %q", err, out)
	}
	if _, err := runHA(t, "decrees", "--url", good); err == nil {
		t.Fatal("plaintext http without --insecure accepted")
	}
	for name, url := range map[string]string{
		"server error":  serve(http.StatusInternalServerError, "boom"),
		"not JSON":      serve(http.StatusOK, "{"),
		"nobody serves": "http://127.0.0.1:1",
	} {
		if _, err := runHA(t, "decrees", "--url", url, "--insecure"); err == nil {
			t.Errorf("%s: decrees succeeded", name)
		}
	}
}

func TestPrintDecreesRefusesAKeyThatIsNotAPublicKey(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := printDecrees(io.Discard, nil, writePEM(t, "EC PRIVATE KEY", der), false); err == nil || !strings.Contains(err.Error(), "PUBLIC KEY") {
		t.Fatalf("a private key taken as the decree key: %v", err)
	}
	notPEM := filepath.Join(t.TempDir(), "plain")
	_ = os.WriteFile(notPEM, []byte("plain"), 0o600)
	if err := printDecrees(io.Discard, nil, notPEM, false); err == nil {
		t.Fatal("a file without PEM taken as the decree key")
	}
}

func TestLoadECPrivateKeyRefusesOtherKeyTypes(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(edKey)
	if _, err := loadECPrivateKey(writePEM(t, "PRIVATE KEY", der)); err == nil || !strings.Contains(err.Error(), "not ECDSA") {
		t.Fatalf("an Ed25519 operator key: %v", err)
	}
}

// The decree command refuses a bad --image before it reads the key.
func TestHADecreeCLIRefusesBadImage(t *testing.T) {
	if _, err := runHA(t, "decree", "--cluster-id", "c1", "--operator-key", filepath.Join(t.TempDir(), "none"),
		"--kind", "UpdateMeasurements", "--base-epoch", "1", "--image", "aa:bb"); err == nil || !strings.Contains(err.Error(), "--image") {
		t.Fatalf("bad --image: %v", err)
	}
}

func TestRecoveryKeyErrors(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := SplitRecoveryKey(key, 2, 3); err == nil {
		t.Fatal("a threshold above the share count")
	}
	dir := t.TempDir()
	if _, err := loadRecoveryShares([]string{filepath.Join(dir, "none")}); err == nil {
		t.Fatal("a missing share file")
	}
	garbage := filepath.Join(dir, "garbage.json")
	_ = os.WriteFile(garbage, []byte("{"), 0o600)
	if _, err := loadRecoveryKey("", []string{garbage}); err == nil || !strings.Contains(err.Error(), garbage) {
		t.Fatalf("a share that is not JSON: %v", err)
	}
	fp, _ := publicKeySHA256(&key.PublicKey)
	shares := func(der []byte, fp string) []RecoveryKeyShare {
		parts, err := shamir.Split(der, 3, 2)
		if err != nil {
			t.Fatal(err)
		}
		var out []RecoveryKeyShare
		for _, p := range parts {
			out = append(out, RecoveryKeyShare{Kind: recoveryShareKind, Version: 1, X: p.X, Y: p.Y, Threshold: 2, Shares: 3, PublicKeySHA256: fp})
		}
		return out
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKCS8PrivateKey(edKey)
	if _, err := CombineRecoveryKey(shares(edDER, fp)); err == nil || !strings.Contains(err.Error(), "EC key") {
		t.Fatalf("shares of an Ed25519 key: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	if _, err := CombineRecoveryKey(shares(otherDER, fp)); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("shares naming another key: %v", err)
	}
	s := shares(otherDER, fp)
	s[0].X = s[1].X
	if _, err := CombineRecoveryKey(s); err == nil {
		t.Fatal("two shares at the same x combined")
	}
}

func TestRecoveryKeySplitCLIErrors(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	keyFile := writePEM(t, "EC PRIVATE KEY", der)
	blocker := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	for name, args := range map[string][]string{
		"no key":        {"--recovery-key", filepath.Join(t.TempDir(), "none"), "--out", t.TempDir()},
		"bad threshold": {"--recovery-key", keyFile, "--out", t.TempDir(), "--shares", "2", "--threshold", "3"},
		"out is a file": {"--recovery-key", keyFile, "--out", filepath.Join(blocker, "sub")},
	} {
		cmd := newHARecoveryKeyCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append([]string{"split"}, args...))
		if err := cmd.Execute(); err == nil {
			t.Errorf("%s: split succeeded", name)
		}
	}
}
