package cds

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// The CDS server's settings that no launch chooses. The store bounds are read
// from the stores they bound.
func TestServerSettingsShipped(t *testing.T) {
	cfg := builtInConfig()
	cfg.allowlistDB = filepath.Join(t.TempDir(), "allowlist.db")
	st, err := openStores(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	maxPaths, maxPathsPerWorkload, maxValueBytes := st.secrets.Policy()
	bindingTTL, maxBindings := st.bindings.Policy()

	for _, tc := range []struct {
		setting string
		got     any
		want    any
	}{
		{"ca-common-name", cfg.caCommonName, "c8s Mesh CA"},
		{"ca-cert-validity", cfg.caCertValidity, 8760 * time.Hour},
		{"min-ca-validity", cfg.minCAValidity, time.Hour},
		{"cert-ttl", cfg.certTTL, 24 * time.Hour},
		{"cert-ttl as a sandbox binding's lifetime", bindingTTL, 24 * time.Hour},
		{"named-cert-ttl", cfg.namedCertTTL, 6 * time.Hour},
		{"armtls-cert-ttl", cfg.armtlsCertTTL, 24 * time.Hour},
		{"challenge-ttl", cfg.challengeTTL, time.Minute},
		{"request-timeout", cfg.requestTimeout, 5 * time.Second},
		{"allowed-cn-pattern", cfg.allowedCNPattern, ""},
		{"read-timeout", cfg.readTimeout, 10 * time.Second},
		{"read-header-timeout", cfg.readHeaderTimeout, 5 * time.Second},
		{"write-timeout", cfg.writeTimeout, 10 * time.Second},
		{"idle-timeout", cfg.idleTimeout, 20 * time.Second},
		{"max-header-bytes", cfg.maxHeaderBytes, 1 << 20},
		{"readiness-interval", cfg.readinessInterval, 10 * time.Second},
		{"rate-limit", cfg.rateLimit, 10.0},
		{"rate-burst", cfg.rateBurst, 20},
		{"rate-limiter-max-entries", cfg.rateLimiterMax, 10000},
		{"rate-limiter-evict-interval", cfg.rateLimiterEvictInterval, time.Minute},
		{"rate-limiter-idle-timeout", cfg.rateLimiterIdleTimeout, 5 * time.Minute},
		{"secrets-max-paths", maxPaths, 1024},
		{"secrets-max-paths-per-workload", maxPathsPerWorkload, 64},
		{"secrets-max-value-bytes", maxValueBytes, 4096},
		{"sandbox-ledger-max-entries", maxBindings, 10000},
	} {
		t.Run(tc.setting, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("%s = %v (%T), want %v (%T)", tc.setting, tc.got, tc.got, tc.want, tc.want)
			}
		})
	}
}

// The built-in settings stay inside the bounds other code holds them to.
func TestBuiltInSettingsFitTheirBounds(t *testing.T) {
	cfg := builtInConfig()
	if cfg.certTTL > issuer.MaxLeafTTL {
		t.Errorf("leaf TTL %v exceeds the %v every leaf is clamped to", cfg.certTTL, issuer.MaxLeafTTL)
	}
	if cfg.namedCertTTL > issuer.MaxNamedLeafTTL {
		t.Errorf("named leaf TTL %v exceeds the %v every named leaf is clamped to", cfg.namedCertTTL, issuer.MaxNamedLeafTTL)
	}
	if cfg.secretsMaxValueBytes < secrets.GeneratedValueBytes {
		t.Errorf("secret value bound %d is below the %d bytes CDS generates", cfg.secretsMaxValueBytes, secrets.GeneratedValueBytes)
	}
	if renewalStart := cfg.caCertValidity / 2; renewalStart <= cfg.minCAValidity+caRenewalCheckInterval {
		t.Errorf("mesh CA renewal starts with %v left, not more than the %v readiness needs plus one %v check", renewalStart, cfg.minCAValidity, caRenewalCheckInterval)
	}
}

// `c8s cds` launched with only the flags its unit passes mints its mesh CA
// under the shipped name and lifetime, and serves under a day-long armTLS
// certificate.
func TestCommandServesTheShippedMeshCA(t *testing.T) {
	path := writeMeasuredDocument(t)
	stub := launchBoundAttestationAPI(t, path)
	port := freePort(t)
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--config=" + path,
		"--attestation-api-url=" + stub.URL(),
		"--allowlist-db=" + filepath.Join(t.TempDir(), "allowlist.db"),
		"--host=127.0.0.1",
		"--port=" + strconv.Itoa(port),
		"--log-level=error",
	})
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	exited := make(chan error, 1)
	go func() { exited <- cmd.ExecuteContext(ctx) }()

	resp := awaitServing(t, armTLSClient(nil), fmt.Sprintf("https://127.0.0.1:%d/ca", port), exited)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatalf("GET /ca body is not PEM: %q", body)
	}
	meshCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serving := resp.TLS.PeerCertificates[0]

	if meshCA.Subject.CommonName != "c8s Mesh CA" {
		t.Errorf("mesh CA common name = %q, want %q", meshCA.Subject.CommonName, "c8s Mesh CA")
	}
	if got := lifetime(meshCA); got != 8760*time.Hour {
		t.Errorf("mesh CA lifetime = %v, want 8760h", got)
	}
	if got := lifetime(serving); got != 24*time.Hour {
		t.Errorf("armTLS serving certificate lifetime = %v, want 24h", got)
	}

	stop()
	if err := <-exited; err != nil {
		t.Fatalf("`c8s cds` returned %v on shutdown", err)
	}
}

// launchBoundAttestationAPI is a stub attestation-api whose self-report binds
// the configuration file at path, as a CDS VM's launch does.
func launchBoundAttestationAPI(t *testing.T, path string) *mockapi.Stub {
	t.Helper()
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformSNP)
	launchMeasurement := strings.Repeat("ab", 48)
	verdict := mockapi.PassingVerdict(launchMeasurement)
	bound := runtimemeasure.HostData(document)
	verdict.Claims.InitData = bound[:]
	stub.SetVerdict(verdict)
	return stub
}

// awaitServing polls url until it answers 200, failing the test if the server
// exits first or never answers.
func awaitServing(t *testing.T, client *http.Client, url string, exited <-chan error) *http.Response {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			t.Fatalf("`c8s cds` exited before serving: %v", err)
		default:
		}
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp
		}
		if err == nil {
			_ = resp.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never answered", url)
	return nil
}

// lifetime is a certificate's validity period rounded to the minute, since a
// certificate keeps whole seconds.
func lifetime(cert *x509.Certificate) time.Duration {
	return cert.NotAfter.Sub(cert.NotBefore).Round(time.Minute)
}
