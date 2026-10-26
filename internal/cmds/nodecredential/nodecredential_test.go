package nodecredential

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/nodetoken"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const testHost = "cl-1.k8s.example.test"

func testCA(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kubernetes"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(sum[:])
}

func execInfo(t *testing.T, cluster map[string]any) string {
	t.Helper()
	info := map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1",
		"kind":       "ExecCredential",
		"spec":       map[string]any{"interactive": false},
	}
	if cluster != nil {
		info["spec"].(map[string]any)["cluster"] = cluster
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCredential_MintsForPinnedCluster(t *testing.T) {
	caPEM, fp := testCA(t)
	keyPath := filepath.Join(t.TempDir(), "node", "key.pem")
	expires := time.Now().Add(5 * time.Minute).Truncate(time.Second)

	var gotAudience string
	var gotKey *ecdsa.PublicKey
	obtain := func(_ context.Context, _ string, nodeKey *ecdsa.PublicKey, audience string) (types.NodeTokenResponse, error) {
		gotAudience, gotKey = audience, nodeKey
		return types.NodeTokenResponse{Token: "tok", ExpiresAt: expires}, nil
	}
	var out bytes.Buffer
	err := credential(context.Background(), execInfo(t, map[string]any{
		"server": "https://" + testHost, "certificate-authority-data": caPEM,
	}), Pins{APIServer: testHost, CASHA256: strings.ToUpper(fp)}, keyPath, "http://127.0.0.1:8400", obtain, &out)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if gotAudience != testHost {
		t.Fatalf("audience %q", gotAudience)
	}

	var cred struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out.Bytes(), &cred); err != nil {
		t.Fatal(err)
	}
	if cred.APIVersion != "client.authentication.k8s.io/v1" || cred.Kind != "ExecCredential" ||
		cred.Status.Token != "tok" || !cred.Status.ExpirationTimestamp.Equal(expires) {
		t.Fatalf("credential %s", out.String())
	}

	// The key persists, so the node keeps its name across runs.
	name, err := NodeName(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := nodetoken.Subject(gotKey); name != want {
		t.Fatalf("node name %q, want %q from the attested key", name, want)
	}
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("node key mode %o", info.Mode().Perm())
	}
}

func TestCredential_RefusesUnpinnedCluster(t *testing.T) {
	caPEM, fp := testCA(t)
	otherPEM, _ := testCA(t)
	pins := Pins{APIServer: testHost, CASHA256: fp}
	good := func() map[string]any {
		return map[string]any{"server": "https://" + testHost, "certificate-authority-data": caPEM}
	}
	with := func(k string, v any) map[string]any { c := good(); c[k] = v; return c }

	cases := map[string]string{
		"no cluster info": execInfo(t, nil),
		"other host":      execInfo(t, with("server", "https://evil.example.test")),
		"plain http":      execInfo(t, with("server", "http://"+testHost)),
		"other port":      execInfo(t, with("server", "https://"+testHost+":6443")),
		"path":            execInfo(t, with("server", "https://"+testHost+"/proxy")),
		"tls server name": execInfo(t, with("tls-server-name", "evil.example.test")),
		"insecure":        execInfo(t, with("insecure-skip-tls-verify", true)),
		"other CA":        execInfo(t, with("certificate-authority-data", otherPEM)),
		"CA bundle":       execInfo(t, with("certificate-authority-data", append(append([]byte{}, caPEM...), otherPEM...))),
		"no CA":           execInfo(t, with("certificate-authority-data", nil)),
		"old api version": strings.Replace(execInfo(t, good()), "/v1\"", "/v1beta1\"", 1),
		"empty":           "",
	}
	for name, info := range cases {
		t.Run(name, func(t *testing.T) {
			called := false
			obtain := func(context.Context, string, *ecdsa.PublicKey, string) (types.NodeTokenResponse, error) {
				called = true
				return types.NodeTokenResponse{Token: "tok", ExpiresAt: time.Now()}, nil
			}
			var out bytes.Buffer
			err := credential(context.Background(), info, pins, filepath.Join(t.TempDir(), "k.pem"), "http://127.0.0.1:8400", obtain, &out)
			if err == nil {
				t.Fatal("accepted")
			}
			if called || out.Len() != 0 {
				t.Fatal("attested or printed a credential for an unpinned cluster")
			}
		})
	}
}

func TestCredential_PropagatesCDSRefusal(t *testing.T) {
	caPEM, fp := testCA(t)
	obtain := func(context.Context, string, *ecdsa.PublicKey, string) (types.NodeTokenResponse, error) {
		return types.NodeTokenResponse{}, errors.New("refused")
	}
	var out bytes.Buffer
	err := credential(context.Background(), execInfo(t, map[string]any{
		"server": "https://" + testHost, "certificate-authority-data": caPEM,
	}), Pins{APIServer: testHost, CASHA256: fp}, filepath.Join(t.TempDir(), "k.pem"), "http://127.0.0.1:8400", obtain, &out)
	if err == nil || out.Len() != 0 {
		t.Fatalf("err %v, out %q", err, out.String())
	}
}

func TestNodeKey_RefusesLooseMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.pem")
	if _, err := NodeName(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NodeName(path); err == nil {
		t.Fatal("used a node key others can read")
	}
}

func TestNewObtain_RefusesUnpinnedConfig(t *testing.T) {
	_, fp := testCA(t)
	base := config{
		cdsURL: "https://cds.example.test", attestationApiURL: "http://127.0.0.1:8400",
		apiServer: testHost, apiCASHA256: fp, cdsMeasurements: strings.Repeat("ab", 48),
	}
	cases := map[string]func(*config){
		"no api server": func(c *config) { c.apiServer = "" },
		"no CA pin":     func(c *config) { c.apiCASHA256 = "" },
		"bad CA pin":    func(c *config) { c.apiCASHA256 = "abc" },
		"http CDS":      func(c *config) { c.cdsURL = "http://cds.example.test" },
		"unpinned CDS":  func(c *config) { c.cdsMeasurements = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := newObtain(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := newObtain(base); err != nil {
		t.Fatalf("pinned config refused: %v", err)
	}
}
