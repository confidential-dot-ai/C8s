package secretprobe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// stubResolver is an inventory that vouches for one sandbox; the unix socket
// supplies the peer credentials, so nothing here needs to disambiguate.
type stubResolver struct{}

func (stubResolver) SandboxForPeer(workloadclaims.Peer) (string, error) {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil
}

func (stubResolver) DigestsForSandbox(string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return nil, nil, false, nil
}

// startInventory serves the real token route on a unix socket and returns the
// socket path.
func startInventory(t *testing.T) string {
	t.Helper()
	signer, err := workloadclaims.NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go workloadclaims.ServeTokens(ctx, l, stubResolver{}, signer)
	t.Cleanup(func() { cancel(); l.Close() })
	return sock
}

// writeLeaf stages a self-signed leaf where the cert sidecar would leave it.
func writeLeaf(t *testing.T) (certPath, keyPath string, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for path, block := range map[string]*pem.Block{
		certPath: {Type: "CERTIFICATE", Bytes: der},
		keyPath:  {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath, &key.PublicKey
}

// seen is one store request as the fake CDS received it.
type seen struct {
	method, uri      string
	challenge, token string
	hasChallenge     bool
	hasToken         bool
	peerKey          *ecdsa.PublicKey // the client certificate's key, over TLS
}

// fakeCDS issues one fixed challenge and records every store request.
type fakeCDS struct {
	mu         sync.Mutex
	challenge  []byte
	challenges int
	requests   []seen
	status     int
	body       string
}

func newFakeCDS(status int, body string) *fakeCDS {
	return &fakeCDS{challenge: bytes.Repeat([]byte{7}, 32), status: status, body: body}
}

func (f *fakeCDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == http.MethodPost && r.RequestURI == secrets.ChallengeRoute {
		f.challenges++
		json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(f.challenge)})
		return
	}
	s := seen{method: r.Method, uri: r.RequestURI}
	_, s.hasChallenge = r.Header[secrets.ChallengeHeader]
	_, s.hasToken = r.Header["Authorization"]
	s.challenge = r.Header.Get(secrets.ChallengeHeader)
	s.token = r.Header.Get("Authorization")
	if r.TLS != nil && len(r.TLS.PeerCertificates) == 1 {
		s.peerKey, _ = r.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
	}
	f.requests = append(f.requests, s)
	w.WriteHeader(f.status)
	w.Write([]byte(f.body))
}

func (f *fakeCDS) only(t *testing.T) seen {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 1 {
		t.Fatalf("CDS saw %d store requests, want 1", len(f.requests))
	}
	return f.requests[0]
}

// harness is one probe invocation's environment: a leaf, an inventory and a
// CDS, plus the common flags that point the probe at them.
type harness struct {
	cds     *fakeCDS
	cdsURL  string
	socket  string
	leafPub *ecdsa.PublicKey
	common  []string
}

func newHarness(t *testing.T, cds *fakeCDS) *harness {
	t.Helper()
	srv := httptest.NewServer(cds)
	t.Cleanup(srv.Close)
	return newHarnessAt(t, cds, srv.URL)
}

func newHarnessAt(t *testing.T, cds *fakeCDS, cdsURL string) *harness {
	t.Helper()
	certPath, keyPath, pub := writeLeaf(t)
	h := &harness{cds: cds, cdsURL: cdsURL, socket: startInventory(t), leafPub: pub}
	h.common = []string{"--cds-url", cdsURL, "--cert", certPath, "--key", keyPath, "--socket", h.socket, "--timeout", "5s"}
	return h
}

// run executes the command as c8s would, with the shared flags ahead of the
// action, and returns exit code, stdout and stderr.
func (h *harness) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return execute(t, append(append([]string{}, h.common...), args...)...)
}

func execute(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	code := -1
	var out, errOut bytes.Buffer
	cmd := newCmd(func(c int) { code = c })
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("an error escaped to cobra's caller, which would exit 1: %v", err)
	}
	return code, out.String(), errOut.String()
}

// decodeToken is the SignedSandboxToken an Authorization header carries.
func decodeToken(t *testing.T, header string) workloadclaims.SignedSandboxToken {
	t.Helper()
	raw, ok := strings.CutPrefix(header, secrets.AuthScheme)
	if !ok {
		t.Fatalf("Authorization = %q, want the %q scheme", header, secrets.AuthScheme)
	}
	js, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("Authorization is not base64: %v", err)
	}
	var tok workloadclaims.SignedSandboxToken
	if err := json.Unmarshal(js, &tok); err != nil {
		t.Fatalf("Authorization is not the token JSON: %v", err)
	}
	if len(tok.Token) == 0 || len(tok.Signature) == 0 {
		t.Fatalf("token is incomplete: %s", js)
	}
	return tok
}

// For the same challenge and token, the probe's headers are byte-for-byte what
// sidecar.Do sends: the scenarios then test the CDS, not a probe dialect.
func TestRequestHeadersMatchDo(t *testing.T) {
	cds := newFakeCDS(http.StatusOK, `{"value":"`+base64.StdEncoding.EncodeToString([]byte("v"))+`"}`)
	h := newHarness(t, cds)

	cfg := sidecar.Config{CDSURL: h.cdsURL, RequestTimeout: 5 * time.Second, InventoryTimeout: 5 * time.Second}
	if _, _, err := sidecar.Do(context.Background(), cfg, http.DefaultClient, h.leafPub, "unix://"+h.socket, http.MethodGet, "/api/db"); err != nil {
		t.Fatal(err)
	}
	byDo := cds.only(t)
	tokenJSON, _ := json.Marshal(decodeToken(t, byDo.token))

	cds.mu.Lock()
	cds.requests = nil
	cds.mu.Unlock()
	code, out, errOut := h.run(t, "request", "GET", "/api/db",
		"--challenge", base64.StdEncoding.EncodeToString(cds.challenge), "--token", string(tokenJSON))
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	byProbe := cds.only(t)
	if byProbe.challenge != byDo.challenge || byProbe.token != byDo.token || byProbe.uri != byDo.uri || byProbe.method != byDo.method {
		t.Fatalf("probe sent %+v, Do sent %+v", byProbe, byDo)
	}
	if !strings.HasPrefix(out, "200\n") {
		t.Fatalf("stdout = %q, want the status first", out)
	}
}

// With nothing given, the probe does what a sidecar does: one fresh challenge,
// one token bound to it and to the leaf, both on the request.
func TestRequestDefaultsToFreshChallengeAndToken(t *testing.T) {
	cds := newFakeCDS(http.StatusForbidden, "")
	h := newHarness(t, cds)
	code, out, errOut := h.run(t, "request", "POST", "/api/db")
	if code != 0 || out != "403\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	got := cds.only(t)
	if cds.fetched() != 1 {
		t.Fatalf("fetched %d challenges, want 1", cds.fetched())
	}
	if got.challenge != base64.StdEncoding.EncodeToString(cds.challenge) {
		t.Fatalf("challenge header = %q, want the one CDS issued", got.challenge)
	}
	if got.method != http.MethodPost {
		t.Fatalf("method = %q", got.method)
	}
	decodeToken(t, got.token)
}

// Each omission flag drops exactly its header; a request with no challenge
// still carries a token, bound to a nonce the probe draws, and never fetches a
// challenge it would not send.
func TestRequestOmissions(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		flags                  []string
		wantChallenge, wantTok bool
		wantFetches            int
	}{
		{"no challenge", []string{"--no-challenge"}, false, true, 0},
		{"no token", []string{"--no-token"}, true, false, 1},
		{"neither", []string{"--no-challenge", "--no-token"}, false, false, 0},
		{"given challenge", []string{"--challenge", base64.StdEncoding.EncodeToString([]byte("replayed-challenge-of-32-bytes!!"))}, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cds := newFakeCDS(http.StatusUnauthorized, "")
			h := newHarness(t, cds)
			code, _, errOut := h.run(t, append([]string{"request", "GET", "/api/db"}, tc.flags...)...)
			if code != 0 {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			got := cds.only(t)
			if got.hasChallenge != tc.wantChallenge || got.hasToken != tc.wantTok {
				t.Fatalf("challenge header present=%v token present=%v, want %v/%v", got.hasChallenge, got.hasToken, tc.wantChallenge, tc.wantTok)
			}
			if cds.fetched() != tc.wantFetches {
				t.Fatalf("fetched %d challenges, want %d", cds.fetched(), tc.wantFetches)
			}
			if got.hasToken {
				decodeToken(t, got.token)
			}
		})
	}
}

// The path is the scenario's to get wrong: it reaches the wire as given.
func TestRequestPathIsVerbatim(t *testing.T) {
	for _, path := range []string{"/a//b", "/a%2Fb", "/api/db/"} {
		t.Run(path, func(t *testing.T) {
			cds := newFakeCDS(http.StatusNotFound, "")
			h := newHarness(t, cds)
			if code, _, errOut := h.run(t, "request", "GET", path, "--no-challenge", "--no-token"); code != 0 {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if got := cds.only(t).uri; got != "/secrets"+path {
				t.Fatalf("request URI = %q, want %q", got, "/secrets"+path)
			}
		})
	}
}

// The first line is the status, the rest is the body as received: no added
// newline, no trimming.
func TestRequestPrintsStatusThenBody(t *testing.T) {
	const body = "{\"error\":\"denied\"}\n\nmore"
	h := newHarness(t, newFakeCDS(http.StatusForbidden, body))
	code, out, errOut := h.run(t, "request", "GET", "/api/db", "--no-challenge", "--no-token")
	if code != 0 || out != "403\n"+body {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// Nothing answering is an answer: status 000, the reason on stderr, exit 0.
func TestRequestReportsNoAnswerAs000(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedURL := "http://" + l.Addr().String()
	l.Close()
	h := newHarnessAt(t, newFakeCDS(0, ""), closedURL)
	code, out, errOut := h.run(t, "request", "GET", "/api/db", "--no-challenge", "--no-token")
	if code != 0 || out != "000\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !strings.Contains(errOut, "connect") {
		t.Fatalf("stderr %q does not say why nothing answered", errOut)
	}
}

// A token the caller gives goes out untouched; from a file, less the newline
// the token action printed.
func TestRequestSendsGivenToken(t *testing.T) {
	const given = `{"token":"AAEC","signature":"AwQF"}`
	file := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(file, []byte(given+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, flag := range map[string]string{"inline": given, "file": "@" + file} {
		t.Run(name, func(t *testing.T) {
			cds := newFakeCDS(http.StatusUnauthorized, "")
			h := newHarness(t, cds)
			if code, _, errOut := h.run(t, "request", "GET", "/api/db", "--no-challenge", "--token", flag); code != 0 {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			want := secrets.AuthScheme + base64.StdEncoding.EncodeToString([]byte(given))
			if got := cds.only(t).token; got != want {
				t.Fatalf("Authorization = %q, want %q", got, want)
			}
		})
	}
}

// The leaf is the client certificate, and a CDS whose certificate chains to
// nothing the probe knows is still reached.
func TestRequestPresentsLeafOverTLS(t *testing.T) {
	cds := newFakeCDS(http.StatusForbidden, "")
	srv := httptest.NewUnstartedServer(cds)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h := newHarnessAt(t, cds, srv.URL)
	if code, _, errOut := h.run(t, "request", "GET", "/api/db", "--no-challenge", "--no-token"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if got := cds.only(t).peerKey; got == nil || !got.Equal(h.leafPub) {
		t.Fatal("the request did not present the leaf as its client certificate")
	}
}

func TestChallengePrintsWhatCDSIssued(t *testing.T) {
	cds := newFakeCDS(0, "")
	h := newHarness(t, cds)
	code, out, errOut := h.run(t, "challenge")
	if code != 0 || out != base64.StdEncoding.EncodeToString(cds.challenge)+"\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// The token is bound to the given challenge, or to a nonce when none is given,
// and printed as the one-line JSON the request action accepts back.
func TestTokenPrintsAuthorizationJSON(t *testing.T) {
	h := newHarness(t, newFakeCDS(0, ""))
	for name, flags := range map[string][]string{
		"bound to a challenge": {"--challenge", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))},
		"bound to a nonce":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := h.run(t, append([]string{"token"}, flags...)...)
			if code != 0 {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
				t.Fatalf("stdout %q is not one line", out)
			}
			var tok workloadclaims.SignedSandboxToken
			if err := json.Unmarshal([]byte(out), &tok); err != nil || len(tok.Token) == 0 || len(tok.Signature) == 0 {
				t.Fatalf("stdout %q is not the token JSON (%v)", out, err)
			}
		})
	}
}

// Without the inventory there is no token, and the failure names the socket.
func TestTokenFailsWithoutInventory(t *testing.T) {
	h := newHarness(t, newFakeCDS(0, ""))
	absent := filepath.Join(t.TempDir(), "absent.sock")
	code, out, errOut := h.run(t, "token", "--socket", absent)
	if code != exitUsage || out != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !strings.Contains(errOut, "sandbox token") || !strings.Contains(errOut, absent) {
		t.Fatalf("stderr %q does not name the token fetch and the socket", errOut)
	}
}

// Anything that is not an answer exits 2 with the reason on stderr, including
// what cobra would otherwise hand to c8s's main as exit 1.
func TestUsageErrorsExit2(t *testing.T) {
	h := newHarness(t, newFakeCDS(0, ""))
	for name, args := range map[string][]string{
		"no action":               nil,
		"unknown action":          {"frobnicate"},
		"unknown flag":            {"request", "GET", "/a", "--bogus"},
		"too few arguments":       {"request", "GET"},
		"too many arguments":      {"challenge", "extra"},
		"method":                  {"request", "PUT", "/a"},
		"challenge both ways":     {"request", "GET", "/a", "--challenge", "AA==", "--no-challenge"},
		"token both ways":         {"request", "GET", "/a", "--token", "{}", "--no-token"},
		"challenge not base64":    {"request", "GET", "/a", "--challenge", "!!!"},
		"token file missing":      {"request", "GET", "/a", "--token", "@" + filepath.Join(t.TempDir(), "none")},
		"path the parser rejects": {"request", "GET", "/a%zz", "--no-challenge", "--no-token"},
		"missing leaf":            {"challenge", "--cert", filepath.Join(t.TempDir(), "none.crt")},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := h.run(t, args...)
			if code != exitUsage || out != "" || errOut == "" {
				t.Fatalf("exit %d, stdout %q, stderr %q; want 2, nothing, a reason", code, out, errOut)
			}
		})
	}
	for name, args := range map[string][]string{
		"no cds-url": {"--cert", "c", "--key", "k", "challenge"},
		"no cert":    {"--cds-url", "https://cds.example", "challenge"},
		"bad url":    {"--cds-url", "cds.example", "--cert", "c", "--key", "k", "challenge"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, errOut := execute(t, args...); code != exitUsage || errOut == "" {
				t.Fatalf("exit %d, stderr %q; want 2 and a reason", code, errOut)
			}
		})
	}
}

// A CDS that cannot be reached for the challenge is a failure to ask, not an
// answer: the default request exits 2 rather than printing 000.
func TestRequestExits2WhenTheChallengeCannotBeFetched(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedURL := "http://" + l.Addr().String()
	l.Close()
	h := newHarnessAt(t, newFakeCDS(0, ""), closedURL)
	code, out, errOut := h.run(t, "request", "GET", "/api/db")
	if code != exitUsage || out != "" || !strings.Contains(errOut, "challenge") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestNewCmdIsHiddenWithDefaults(t *testing.T) {
	cmd := NewCmd()
	if !cmd.Hidden {
		t.Fatal("secret-probe must be hidden: it is a test instrument")
	}
	for flag, want := range map[string]string{
		"socket":  workloadclaims.SidecarSocketDir + "/" + workloadclaims.SocketName,
		"timeout": "20s",
	} {
		if got := cmd.PersistentFlags().Lookup(flag).DefValue; got != want {
			t.Fatalf("--%s default = %q, want %q", flag, got, want)
		}
	}
}

// fetched is how many challenges the CDS issued.
func (f *fakeCDS) fetched() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.challenges
}
