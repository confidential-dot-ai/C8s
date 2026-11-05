package podstatus

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// A register that replays no prefix of the list is final, whether the
// channel fails at the handshake or in the fresh evidence afterwards, and the
// handshake error must survive net/http's wrapping for every client entry
// point. A list the register has not caught up with is a retryable failure.
func TestAttestReportsAHistoryTheRegisterDoesNotReplayAsFinal(t *testing.T) {
	entries := map[string]func(context.Context, AttestConfig) error{
		"attest": func(ctx context.Context, cfg AttestConfig) error { _, _, err := Attest(ctx, cfg); return err },
		"get":    func(ctx context.Context, cfg AttestConfig) error { _, err := Get(ctx, cfg); return err },
		"assignment target": func(ctx context.Context, cfg AttestConfig) error {
			_, err := VerifyAssignmentTarget(ctx, cfg)
			return err
		},
	}
	for name, tc := range map[string]struct {
		registered, journal []string
		handshake, final    bool
	}{
		"at the handshake":                        {[]string{dA}, []string{dA}, true, true},
		"in the fresh evidence":                   {[]string{dA}, []string{dB}, false, true},
		"list ahead of the register is retryable": {[]string{dA}, []string{dA, dB}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := attestFixture(t, tc.registered, tc.journal, nil)
			calls := map[string]func(context.Context, AttestConfig) error{"attest": entries["attest"]}
			if tc.handshake {
				calls = entries
				newClient = func(guestverify.Policy, time.Duration) *http.Client {
					return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, //nolint:gosec // the fixture stands in for the armTLS check
						VerifyConnection: func(tls.ConnectionState) error {
							return fmt.Errorf("armtls: %w: %w", errors.New("guest is not bound to the expected anchor"), guestverify.ErrPoliciesDoNotReplay)
						},
					}}}
				}
			}
			for entry, call := range calls {
				err := call(context.Background(), cfg)
				if err == nil || errors.Is(err, ErrMeasuredHistoryDoesNotReplay) != tc.final {
					t.Errorf("%s: %v, want final=%v", entry, err, tc.final)
				}
			}
		})
	}
}

// The service exits on every startup failure to confirm the launch
// key but one, a register that replays no prefix of the journal. A guest that
// exited then would look to a verifying client like one still booting; one
// that serves fails that client's verification, which is the observation.
func TestServeRunsWhenTheRegisterDoesNotReplay(t *testing.T) {
	staged := filepath.Join(t.TempDir(), "config.json")
	doc, err := json.Marshal(stagedPodDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	old := loadMeasuredLaunchKey
	t.Cleanup(func() { loadMeasuredLaunchKey = old })

	t.Run("another failure still exits", func(t *testing.T) {
		loadMeasuredLaunchKey = func(context.Context, string, string) ([]byte, error) {
			return nil, errors.New("attestation-api not ready")
		}
		err := Serve(context.Background(), ServeConfig{Platform: "tdx", StagedPath: staged, ListenAddr: "127.0.0.1:0"})
		if err == nil || !strings.Contains(err.Error(), "load measured launch key") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no replaying prefix serves", func(t *testing.T) {
		loadMeasuredLaunchKey = func(context.Context, string, string) ([]byte, error) {
			return nil, fmt.Errorf("%w: RTMR[3] carries another value", credrelease.ErrRegisterDoesNotReplay)
		}
		// The serving certificate is provisioned before the listener opens, so
		// an attestation-api must answer: the stub does, with a fake quote.
		api := mockapi.New(t)
		api.SetPlatform(teetypes.PlatformTDX)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Serve(ctx, ServeConfig{Platform: "tdx", StagedPath: staged, ListenAddr: addr, AttestationAPIURL: api.URL()})
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				conn.Close()
				break
			}
			select {
			case err := <-done:
				t.Fatalf("Serve returned before listening: %v", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("service did not listen on %s: %v", addr, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Serve did not return after cancel")
		}
	})
}

// stagedPodDocument is a pre-assigned pod document, so Serve needs no
// assignment store.
func stagedPodDocument(t *testing.T) *launchconfig.Document {
	t.Helper()
	public := func() string {
		der, err := x509.MarshalPKIXPublicKey(&ecdsaCert(t).PrivateKey.(*ecdsa.PrivateKey).PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	uid := "0b2a6c6e-1111-4e2c-9d2f-000000000001"
	manifest := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"tenant","uid":"` + uid +
		`"},"spec":{"containers":[{"name":"app","image":"busybox@sha256:` + strings.Repeat("a", 64) + `"}]}}`
	return &launchconfig.Document{
		SchemaVersion: launchconfig.SchemaVersion, ClusterID: "cluster", Role: launchconfig.Pod,
		Node:                 launchconfig.Node{Name: "guest"},
		Server:               launchconfig.ServerConfig{Address: "192.0.2.1", OperatorPublicKey: public()},
		PodOperatorPublicKey: public(),
		CDS:                  launchconfig.CDS{Address: "cds.example.org:8443", Measurements: testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)},
		Image:                launchconfig.Image{Platform: "tdx", Measurement: strings.Repeat("11", 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}},
		Pod:                  &launchconfig.PodSpec{UID: uid, Namespace: "tenant", Name: "app", Manifest: manifest},
	}
}
