package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/cdsgenesis"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// A node whose CDS cannot answer yet starts on its launch pins (the base
// allowlist then serves) instead of exiting, and follows the chain once the
// CDS answers.
func TestChainFollowNeverStopsTheStart(t *testing.T) {
	enforcerRuntimeDir = t.TempDir()
	cfg := validConfig()
	cfg.Allowlist.Pull.URL = "https://127.0.0.1:1"
	cfg.Allowlist.Pull.Timeout = time.Second
	cfg.Allowlist.Pull.CDSChain = "0:" + strings.Repeat("ab", 32)
	launch := cfg.Allowlist.Pull.CDSMeasurementsConfig
	chain, err := followChainAtStart(&cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || chain == nil {
		t.Fatalf("a CDS that does not answer stopped the start: %v", err)
	}
	if cfg.Allowlist.Pull.CDSMeasurementsConfig != launch {
		t.Fatal("the launch pins were replaced before the chain was followed")
	}
}

// The chain counts as followed only once its pins are written, the node's
// and the pods' copy, and the pull follows them: a failed step, or a CDS
// that refuses, is retried on the next pull.
func TestChainPinsRetryUntilWritten(t *testing.T) {
	dir := t.TempDir()
	state := testState(t)
	answers := []error{errors.New("503 store unreachable"), nil, nil, nil, nil, nil}
	c := &chainPins{path: filepath.Join(dir, "missing", "cds.json"), follow: func(context.Context, *cdschain.State) (*cdschain.State, error) {
		err := answers[0]
		answers = answers[1:]
		return state, err
	}}
	if _, err := c.refresh(context.Background()); err == nil || c.known != nil {
		t.Fatal("a refused follow counted")
	}
	if err := os.WriteFile(filepath.Join(dir, "missing"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.refresh(context.Background()); err == nil || c.known != nil {
		t.Fatal("a failed pins write counted as followed")
	}
	c.path = filepath.Join(dir, "cds.json")
	if changed, err := c.refresh(context.Background()); err != nil || !changed || c.known == nil {
		t.Fatalf("changed=%v %v", changed, err)
	}
	if _, err := os.Stat(c.path); err != nil {
		t.Fatal(err)
	}
	c.known, c.podPins = nil, filepath.Join(dir, "missing", "pods.json")
	if _, err := c.refresh(context.Background()); err == nil || c.known != nil {
		t.Fatal("a failed write of the pods' copy counted as followed")
	}
	c.podPins = filepath.Join(dir, "pods.json")
	c.pullTransport = func() (*http.Transport, error) { return nil, errors.New("pins do not parse") }
	if _, err := c.refresh(context.Background()); err == nil || c.known != nil {
		t.Fatal("a pull that cannot follow counted as followed")
	}
	pull := &http.Transport{}
	c.pullTransport = func() (*http.Transport, error) { return pull, nil }
	if changed, err := c.refresh(context.Background()); err != nil || !changed || c.known == nil || c.pull.Load() != pull {
		t.Fatalf("changed=%v %v, or the pull does not follow", changed, err)
	}
	node, _ := os.ReadFile(c.path)
	pods, err := os.ReadFile(c.podPins)
	if err != nil || !bytes.Equal(pods, node) {
		t.Fatalf("the pods' copy is not the node's pins: %v", err)
	}
}

// slowChain serves pages of a chain of pages*32 entries, each page after
// delay, and counts the pages served; a negative delay never answers page 0.
func slowChain(t *testing.T, pages int, delay time.Duration) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	served := &atomic.Int32{}
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cdsha.ChainPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set(cdsgenesis.Header, r.Header.Get(cdsgenesis.Header))
		if delay < 0 {
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		time.Sleep(delay)
		page := cdsha.Chain{}
		if int(served.Add(1)) <= pages {
			page.Entries = make([]cdschain.Entry, 32)
			for i := range page.Entries {
				page.Entries[i] = cdschain.Entry{Body: bytes.Repeat([]byte("x"), 64), Sig: "sig"}
			}
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv, served
}

func slowChainPins(t *testing.T, url string, timeout time.Duration) *chainPins {
	t.Helper()
	enforcerRuntimeDir = t.TempDir()
	cfg := validConfig().Allowlist.Pull
	cfg.Timeout = timeout
	cfg.AttestationApiURL = "http://127.0.0.1:1"
	cfg.CDSChain = "0:" + strings.Repeat("ab", 32)
	c, err := newChainPins(cfg, url, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A node with no chain yet (after any restart) reads it from genesis, which
// on a long chain takes longer than one pull's timeout: the pull loop's
// follow reads every page, each within the timeout, instead of giving up
// at the first timeout and starting from genesis again on the next pull.
func TestALongChainIsReadWholeByThePullLoop(t *testing.T) {
	srv, served := slowChain(t, 10, 40*time.Millisecond)
	slowChainPins(t, srv.URL, 200*time.Millisecond).refresher()(context.Background())
	if got := served.Load(); got != 11 {
		t.Fatalf("the follow read %d of 11 pages", got)
	}
}

// Each chain request is bounded on its own: a CDS that never answers fails
// the follow within the timeout, so the pull goes on.
func TestAChainRequestTimesOut(t *testing.T) {
	srv, _ := slowChain(t, 1, -1)
	done := make(chan struct{})
	go func() {
		slowChainPins(t, srv.URL, 200*time.Millisecond).refresher()(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a chain request that never answers holds the pull loop")
	}
}

func testState(t *testing.T) *cdschain.State {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := cdschain.PublicKeyPEM(&k.PublicKey)
	payload, _ := json.Marshal(cdschain.Genesis{
		Endpoints: []string{"a:1"}, Members: []string{pub}, OperatorKeys: pub, CAKey: pub,
		Accepted: []cdschain.Build{{Measurements: testutil.CDSPinDocument(testutil.TestMeasurement, "launch"), Version: "v1.0.0"}},
	})
	e, err := cdschain.Sign(k, cdschain.Body{Cluster: "lane", Type: cdschain.TypeGenesis, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	s, err := cdschain.VerifyGenesis(e)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// After an upgrade the sandbox-digests listener admits a CDS replica of a
// build the followed chain accepts, not only the builds it started with,
// and still refuses one outside the set.
func TestDigestsListenerFollowsTheChainsBuilds(t *testing.T) {
	as := mockapi.New(t)
	measA, measB, measC := strings.Repeat("a1", 48), strings.Repeat("b2", 48), strings.Repeat("c3", 48)
	pins := func(meas string) armtls.Pins {
		values, err := refvalues.Parse([]byte(testutil.CDSPinDocument(meas, "launch")))
		if err != nil {
			t.Fatal(err)
		}
		return armtls.Pins(values.Policy())
	}
	attest := attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), as.URL())
	serverTLS, digests, err := workloadclaims.DigestsServerTLSConfig("sev-snp", attest, as.URL(), pins(measA), time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				_, _ = conn.Write([]byte("ok"))
				_ = conn.Close()
			}()
		}
	}()
	// handshake connects as a CDS replica whose attestation reports meas.
	handshake := func(meas string) error {
		verdict := mockapi.PassingVerdict(meas)
		binding := runtimemeasure.HostData([]byte("launch"))
		verdict.Claims.InitData = binding[:]
		as.SetVerdict(verdict)
		clientTLS, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{Policy: pins(meas).VerifyPolicy(as.URL()), Platform: "sev-snp", AttestFunc: attest, CertTTL: time.Hour})
		if err != nil {
			return err
		}
		conn, err := tls.Dial("tcp", l.Addr().String(), clientTLS)
		if err != nil {
			return err
		}
		defer conn.Close()
		// TLS 1.3: a refused client certificate surfaces on the first read.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(make([]byte, 2))
		return err
	}
	if err := handshake(measB); err == nil {
		t.Fatal("negative control: a build the listener started without was admitted")
	}
	state := testState(t)
	state.Accepted = []cdschain.Build{{Measurements: testutil.CDSPinDocument(measA, "launch"), Version: "v1.0.0"}, {Measurements: testutil.CDSPinDocument(measB, "launch"), Version: "v1.1.0"}}
	chain := &chainPins{path: filepath.Join(t.TempDir(), "cds.json"), attestationAPI: as.URL(),
		follow: func(context.Context, *cdschain.State) (*cdschain.State, error) { return state, nil }}
	chain.attachDigests(digests)
	if changed, err := chain.refresh(context.Background()); err != nil || !changed {
		t.Fatalf("follow: %v %v", changed, err)
	}
	if err := handshake(measB); err != nil {
		t.Fatalf("a replica of a build the chain accepts was refused: %v", err)
	}
	if err := handshake(measC); err == nil {
		t.Fatal("a replica of a build outside the chain's set was admitted")
	}
}
