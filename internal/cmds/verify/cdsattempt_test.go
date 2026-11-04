package verify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// alternatingCDS selects a distinct armTLS leaf on each TLS connection.
func alternatingCDS(t *testing.T, handler http.HandlerFunc, closed ...chan struct{}) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	first := attestedTLSServer(t, http.NotFoundHandler()).TLS.Certificates[0]
	second := attestedTLSServer(t, http.NotFoundHandler()).TLS.Certificates[0]
	var connections atomic.Int32
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed && len(closed) > 0 {
			closed[0] <- struct{}{}
		}
	}
	srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cert := first
		if connections.Add(1)%2 == 0 {
			cert = second
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &connections
}

func TestCDSAttemptClosesOwnedSocket(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelParent), func(t *testing.T) {
			closed := make(chan struct{}, 1)
			srv, _ := alternatingCDS(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }, closed)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, err := openCDSAttempt(ctx, config{url: srv.URL, timeout: time.Second}, leafTrust{})
			if err != nil {
				t.Fatal(err)
			}
			defer a.close()
			if cancelParent {
				cancel()
			} else {
				a.close()
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("retained the owned socket")
			}
		})
	}
}

func TestCDSAttemptBoundsHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = openCDSAttempt(ctx, config{url: "https://" + ln.Addr().String(), timeout: 100 * time.Millisecond}, leafTrust{})
	if err == nil || !isConnectError(err) {
		t.Fatalf("handshake error=%v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("handshake exceeded its timeout")
	}
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("no accepted handshake")
	}
}

func TestCDSAttemptCrosscheckVerdict(t *testing.T) {
	pub, _ := operatorPubPEM(t)
	otherPub, _ := operatorPubPEM(t)
	served := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	body, err := refvalues.Format(served)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(keyPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                         string
		keys, policy, disabled, want bool
	}{
		{"policy", false, true, false, true},
		{"keys", true, false, false, true},
		{"both", true, true, false, true},
		{"disabled keys", false, true, true, true},
		{"delayed disabled keys", false, true, true, true},
		{"delayed key error", false, true, false, true},
		{"wrong keys", true, true, false, false},
		{"wrong policy", true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var connections atomic.Pointer[atomic.Int32]
			srv, count := alternatingCDS(t, func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.Version != tls.VersionTLS13 || r.ProtoMajor != 1 || r.TLS.ServerName != "cds.example" {
					t.Errorf("unexpected transport: %s %+v", r.Proto, r.TLS)
				}
				if r.URL.Path == "/operator-keys" {
					if tc.disabled || tc.name == "delayed key error" {
						status := http.StatusNotFound
						if !tc.disabled {
							status = http.StatusInternalServerError
						}
						w.Header().Set("Content-Length", "6")
						w.WriteHeader(status)
						w.(http.Flusher).Flush()
						if strings.HasPrefix(tc.name, "delayed") {
							time.Sleep(100 * time.Millisecond)
						}
						w.Write([]byte("absent"))
					} else if connections.Load().Load() != 1 || tc.name == "wrong keys" {
						w.Write(otherPub)
					} else {
						w.Write(pub)
					}
				} else if connections.Load().Load() != 1 || tc.name == "wrong policy" {
					w.Write([]byte(`{"schema_version":"1","tee":"sev-snp","measurements":[]}`))
				} else {
					w.Write(body)
				}
			})
			connections.Store(count)
			cfg := config{kind: "cds", url: srv.URL, server: "cds.example", timeout: time.Second, measurementsConfig: testutil.CDSPinFile(t)}
			if tc.keys {
				cfg.operatorKeys = keyPath
			}
			if tc.policy {
				cfg.servedPolicyFile = writeImagePolicy(t, "served.json", served)
			}
			plan := mustPlan(t, cfg)
			a, err := openCDSAttempt(context.Background(), cfg, leafTrust{})
			if err != nil {
				t.Fatal(err)
			}
			defer a.close()
			op := gatherOperatorKeys(context.Background(), cfg, a.evidence, a.fetch)
			measurements := gatherMeasurements(context.Background(), cfg, plan, a.evidence, a.fetch)
			binding := runtimemeasure.HostData([]byte(testutil.CDSLaunchFile))
			result := &teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformSNP,
				Claims: teetypes.Claims{LaunchDigest: testutil.TestMeasurement, InitData: binding[:]}}
			oc := newOutcome(cfg, a.evidence, result, nil, plan)
			applyVerdictPolicies(&oc, cfg, a.evidence, nil, op, plan, measurements)
			if oc.Verified != tc.want || count.Load() != 1 {
				t.Fatalf("verified=%t error=%s op=%+v measurements=%+v connections=%d", oc.Verified, oc.Error, op, measurements, count.Load())
			}
		})
	}
}

func TestCDSAttemptBoundsAndRejectsResponses(t *testing.T) {
	var redirects atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirects.Add(1) }))
	defer target.Close()
	for _, tc := range []string{"redirect", "malformed", "oversized", "truncated", "headers", "body", "cancel"} {
		t.Run(tc, func(t *testing.T) {
			srv, connections := alternatingCDS(t, func(w http.ResponseWriter, r *http.Request) {
				switch tc {
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusFound)
				case "malformed":
					w.Write([]byte("not JSON"))
				case "oversized":
					w.Write([]byte(strings.Repeat("x", maxServedMeasurements+1)))
				case "truncated":
					w.Header().Set("Content-Length", "100")
					w.Write([]byte("short"))
				case "headers":
					<-r.Context().Done()
				default:
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, err := openCDSAttempt(ctx, config{url: srv.URL, timeout: time.Second}, leafTrust{})
			if err != nil {
				t.Fatal(err)
			}
			defer a.close()
			fetch := a.fetch
			if tc == "cancel" {
				fetch = func(ctx context.Context, endpoint, server, pin string, timeout time.Duration) (*http.Response, error) {
					resp, err := a.fetch(ctx, endpoint, server, pin, timeout)
					cancel()
					return resp, err
				}
			}
			_, err = fetchServedMeasurements(ctx, srv.URL, "", a.evidence.certSHA256, 100*time.Millisecond, fetch)
			if err == nil {
				t.Fatal("accepted an invalid/incomplete response")
			}
			if tc == "cancel" && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("cancellation error=%v", err)
			}
			if connections.Load() != 1 {
				t.Fatalf("opened %d connections", connections.Load())
			}
		})
	}
	if redirects.Load() != 0 {
		t.Fatal("followed an unauthenticated redirect")
	}
}

func TestCDSAttemptRefusesReplacementConnection(t *testing.T) {
	for _, closeAfterEvidence := range []bool{true, false} {
		t.Run(fmt.Sprint(closeAfterEvidence), func(t *testing.T) {
			srv, connections := alternatingCDS(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Connection", "close")
				w.Write([]byte("first document"))
			})
			a, err := openCDSAttempt(context.Background(), config{url: srv.URL, timeout: time.Second}, leafTrust{})
			if err != nil {
				t.Fatal(err)
			}
			defer a.close()
			if closeAfterEvidence {
				srv.CloseClientConnections()
			} else {
				resp, err := a.fetch(context.Background(), srv.URL+"/operator-keys", "", a.evidence.certSHA256, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != "first document" {
					t.Fatalf("body=%q error=%v", body, err)
				}
			}
			if _, err := a.fetch(context.Background(), srv.URL+"/measurements", "", a.evidence.certSHA256, time.Second); err == nil {
				t.Fatal("accepted a document after the attested socket closed")
			}
			if connections.Load() != 1 {
				t.Fatalf("redialed %d connections", connections.Load())
			}
		})
	}
}

func TestCDSRunKeepsEvidenceConnection(t *testing.T) {
	pub, _ := operatorPubPEM(t)
	served := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	body, err := refvalues.Format(served)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(keyPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, check := range []string{"policy", "keys", "both"} {
		t.Run(check, func(t *testing.T) {
			var requests atomic.Int32
			srv, connections := alternatingCDS(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch r.URL.Path {
				case "/operator-keys":
					w.Write(pub)
				case "/measurements":
					w.Write(body)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			})
			cfg := config{kind: "cds", url: srv.URL, timeout: time.Second, measurementsConfig: testutil.CDSPinFile(t)}
			if check != "keys" {
				cfg.servedPolicyFile = writeImagePolicy(t, "served.json", served)
			}
			if check != "policy" {
				cfg.operatorKeys = keyPath
			}
			var out, errOut bytes.Buffer
			if code := run(context.Background(), cfg, &out, &errOut); code != exitFailed {
				t.Fatalf("fixture's unsigned hardware report: exit=%d, output=%s %s", code, &out, &errOut)
			}
			wantRequests := int32(2)
			if check == "keys" {
				wantRequests = 1
			}
			if connections.Load() != 1 || requests.Load() != wantRequests {
				t.Fatalf("handshakes=%d requests=%d, want 1/%d on the evidence socket", connections.Load(), requests.Load(), wantRequests)
			}
		})
	}
}
