package routes

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
)

// fakeCDS mimics the CDS route API: token check (W1), Parse (D9), the
// revision rule and If-Match (C3).
type fakeCDS struct {
	mu      sync.Mutex
	env     *pkgroutes.Envelope
	rev     uint64
	keys    []*ecdsa.PublicKey
	puts    int
	ifMatch []string // If-Match of each PUT, "" when absent
	// beforePut, when set, runs at the start of each PUT, as another writer.
	beforePut func(*fakeCDS)
}

func (f *fakeCDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		if f.env == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.env)
	case http.MethodPut:
		f.puts++
		if f.beforePut != nil {
			f.beforePut(f)
		}
		body, _ := io.ReadAll(r.Body)
		if err := (operatorauth.Verifier{Keys: f.keys}).Authorize(r, body); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		m, err := pkgroutes.Parse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		if m.Revision <= f.rev {
			http.Error(w, "revision not greater", http.StatusConflict)
			return
		}
		ifMatch := r.Header.Get("If-Match")
		f.ifMatch = append(f.ifMatch, ifMatch)
		if ifMatch != "" && (f.env == nil || ifMatch != digestHex(f.env.Manifest)) {
			http.Error(w, "digest differs", http.StatusPreconditionFailed)
			return
		}
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.env, f.rev = &pkgroutes.Envelope{Manifest: body, Token: token}, m.Revision
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *fakeCDS) stored(t *testing.T) *pkgroutes.Manifest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.env == nil {
		t.Fatal("no manifest stored")
	}
	s, err := pkgroutes.VerifySigned(*f.env, f.keys, nil)
	if err != nil {
		t.Fatalf("VerifySigned(stored) = %v", err)
	}
	return s.Manifest()
}

type harness struct {
	cds     *fakeCDS
	url     string
	keyFile string
	pubFile string
	stderr  bytes.Buffer
}

func writeKey(t *testing.T, dir, name string) (keyFile, pubFile string, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(dir, name+".key")
	pubFile = filepath.Join(dir, name+".pub")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, pubFile, &key.PublicKey
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	keyFile, pubFile, pub := writeKey(t, t.TempDir(), "operator")
	cds := &fakeCDS{keys: []*ecdsa.PublicKey{pub}}
	srv := httptest.NewServer(cds)
	t.Cleanup(srv.Close)
	return &harness{cds: cds, url: srv.URL, keyFile: keyFile, pubFile: pubFile}
}

// run runs c8s routes against the fake CDS, trusting the harness operator
// key unless args name --operator-keys.
func (h *harness) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if !slices.Contains(args, "--operator-keys") {
		args = append(args, "--operator-keys", h.pubFile)
	}
	return h.runUnverified(t, args...)
}

func (h *harness) runUnverified(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newCmd(nil)
	var out bytes.Buffer
	cmd.SetOut(&out)
	h.stderr.Reset()
	cmd.SetErr(&h.stderr)
	cmd.SetArgs(append(args, "--url", h.url, "--insecure", "--operator-key", h.keyFile))
	err := cmd.Execute()
	return out.String(), err
}

func (h *harness) mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := h.run(t, args...)
	if err != nil {
		t.Fatalf("c8s routes %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// C6: a new manifest starts at the Unix time.
func TestAddStartsAtUnixTime(t *testing.T) {
	h := newHarness(t)
	start := time.Now()
	before := start.UTC().Truncate(time.Second)
	h.mustRun(t, "add", "--host", "app.example", "--path", "/", "--address", "vllm.ai.svc:8443", "--workload", "vllm", "--max-age", "1h")
	end := time.Now()

	m := h.cds.stored(t)
	if m.Revision < uint64(start.Unix()) || m.Revision > uint64(end.Unix()) || m.MaxAge != time.Hour || m.NotBefore.Before(before) {
		t.Fatalf("stored revision %d, maxAge %s, notBefore %s; want the Unix time %d, 1h, >= %s", m.Revision, m.MaxAge, m.NotBefore, start.Unix(), before)
	}
	rs := m.Hosts["app.example"].Routes
	if len(rs) != 1 || rs[0].Path != "/" || rs[0].Match != pkgroutes.MatchPrefix || rs[0].Backend.Workload != "vllm" {
		t.Fatalf("stored routes = %+v", rs)
	}
}

// add and rm bump the revision, keep maxAgeSeconds and the other routes, and
// set notBefore to now.
func TestAddRmEditOneRoute(t *testing.T) {
	h := newHarness(t)
	h.mustRun(t, "add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a", "--max-age", "2h")
	h.mustRun(t, "add", "--host", "app.example", "--path", "/admin", "--match", "exact", "--address", "b:1", "--workload", "b", "--max-age", "5m")
	prev := h.cds.stored(t).Revision
	out := h.mustRun(t, "add", "--host", "app.example", "--path", "/", "--address", "c:1", "--workload", "c")
	m := h.cds.stored(t)
	if !strings.Contains(out, "replaced prefix route app.example /") || !strings.Contains(out, fmt.Sprintf("revision %d", m.Revision)) {
		t.Fatalf("add output = %q", out)
	}
	if m.Revision <= prev || m.MaxAge != 2*time.Hour {
		t.Fatalf("after add: revision %d, maxAge %s; want above %d, 2h", m.Revision, m.MaxAge, prev)
	}
	prev = m.Revision
	rs := m.Hosts["app.example"].Routes
	if len(rs) != 2 || rs[0].Backend.Workload != "c" || rs[1].Path != "/admin" {
		t.Fatalf("after add: routes = %+v", rs)
	}

	h.mustRun(t, "rm", "--host", "app.example", "--path", "/admin")
	m = h.cds.stored(t)
	if m.Revision <= prev || len(m.Hosts["app.example"].Routes) != 1 {
		t.Fatalf("after rm: revision %d, routes %+v; want above %d, one route", m.Revision, m.Hosts["app.example"].Routes, prev)
	}
	prev = m.Revision
	// D5: the host's last route takes the host with it.
	h.mustRun(t, "rm", "--host", "app.example", "--path", "/")
	if m := h.cds.stored(t); m.Revision <= prev || len(m.Hosts) != 0 {
		t.Fatalf("after last rm: revision %d, hosts %+v; want above %d, none", m.Revision, m.Hosts, prev)
	}
}

func TestRmRefusals(t *testing.T) {
	h := newHarness(t)
	if _, err := h.run(t, "rm", "--host", "app.example", "--path", "/"); err == nil {
		t.Fatal("rm with no stored manifest: want an error")
	}
	h.mustRun(t, "add", "--host", "app.example", "--path", "/x", "--address", "a:1", "--workload", "a")
	h.mustRun(t, "add", "--host", "app.example", "--path", "/x", "--match", "exact", "--address", "a:1", "--workload", "a")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--host", "other.example", "--path", "/x"}, "no host"},
		{[]string{"--host", "app.example", "--path", "/y"}, "no route"},
		{[]string{"--host", "app.example", "--path", "/x"}, "pass --match"},
	} {
		if _, err := h.run(t, append([]string{"rm"}, tc.args...)...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("rm %v: error = %v, want %q", tc.args, err, tc.want)
		}
	}
	h.mustRun(t, "rm", "--host", "app.example", "--path", "/x", "--match", "exact")
}

func TestAddBackendFlags(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{
		{},
		{"--workload", "a", "--server-name", "a.example"},
		{"--server-name", "a.example"},
	} {
		base := []string{"add", "--host", "app.example", "--path", "/", "--address", "a:1"}
		if _, err := h.run(t, append(base, args...)...); err == nil {
			t.Errorf("add %v: want a backend-flag error", args)
		}
	}
	if h.cds.puts != 0 {
		t.Fatalf("CDS saw %d writes, want none", h.cds.puts)
	}
}

// A 409 tells the operator how to recover.
func TestPutStaleRevisionGuidance(t *testing.T) {
	h := newHarness(t)
	h.mustRun(t, "add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a")
	file := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(file, []byte(`{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := h.run(t, "put", file)
	if err == nil || !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "raise the file's revision") {
		t.Fatalf("put stale revision: error = %v", err)
	}
}

// put stores the file's bytes verbatim, and show and digest report the same
// route digest.
func TestPutShowDigest(t *testing.T) {
	h := newHarness(t)
	manifest := []byte("{\"schema\":\"c8s.routes/v1\", \"revision\":7,\"notBefore\":\"2026-09-01T00:00:00Z\",\"maxAgeSeconds\":60,\n\"hosts\":{\"app.example\":{\"routes\":[{\"path\":\"/\",\"match\":\"exact\",\"backend\":{\"address\":\"a:1\",\"workload\":\"a\"}}]}}}\n")
	file := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(file, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := pkgroutes.Digest(manifest)
	want := hex.EncodeToString(sum[:])

	h.mustRun(t, "put", file)
	if !bytes.Equal(h.cds.env.Manifest, manifest) {
		t.Fatalf("stored bytes = %q, want the file verbatim", h.cds.env.Manifest)
	}
	if out := h.mustRun(t, "digest", file); strings.TrimSpace(out) != want {
		t.Fatalf("digest = %q, want %s", out, want)
	}
	out := h.mustRun(t, "show", "--operator-keys", h.pubFile)
	for _, s := range []string{"revision:      7", want, "verified against --operator-keys", "workload a"} {
		if !strings.Contains(out, s) {
			t.Errorf("show output lacks %q:\n%s", s, out)
		}
	}
	if out := h.mustRun(t, "show", "--raw"); out != string(manifest) {
		t.Fatalf("show --raw = %q, want the stored bytes", out)
	}
}

// W2: show refuses a manifest no trusted key signed.
func TestShowRejectsUntrustedSignature(t *testing.T) {
	h := newHarness(t)
	h.mustRun(t, "add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a")
	_, otherPub, _ := writeKey(t, t.TempDir(), "other")
	if _, err := h.run(t, "show", "--operator-keys", otherPub); err == nil || !strings.Contains(err.Error(), "fails verification") {
		t.Fatalf("show with an untrusted key: error = %v", err)
	}
}

func TestRefusesURLWithPath(t *testing.T) {
	h := newHarness(t)
	h.url += "/cds"
	if _, err := h.run(t, "show"); err == nil || !strings.Contains(err.Error(), "no path") {
		t.Fatalf("show with a URL path: error = %v", err)
	}
}

func TestPutRejectsInvalidFileLocally(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(file, []byte(`{"schema":"c8s.routes/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run(t, "put", file); err == nil {
		t.Fatal("put of an invalid manifest: want an error")
	}
	if h.cds.puts != 0 {
		t.Fatalf("CDS saw %d writes, want none", h.cds.puts)
	}
}

// add and rm re-sign what they fetch, so they refuse to run unverified, and
// refuse a stored manifest no trusted key signed.
func TestEditRequiresVerifiedManifest(t *testing.T) {
	h := newHarness(t)
	add := []string{"add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a"}
	if _, err := h.runUnverified(t, add...); err == nil || !strings.Contains(err.Error(), "pass --operator-keys") {
		t.Fatalf("add without --operator-keys: error = %v", err)
	}
	if _, err := h.runUnverified(t, "rm", "--host", "app.example", "--path", "/"); err == nil || !strings.Contains(err.Error(), "pass --operator-keys") {
		t.Fatalf("rm without --operator-keys: error = %v", err)
	}

	rogueKey, _, _ := writeKey(t, t.TempDir(), "rogue")
	keyPEM, err := os.ReadFile(rogueKey)
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	planted := []byte(`{"schema":"c8s.routes/v1","revision":3,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{"app.example":{"routes":[{"path":"/","match":"prefix","backend":{"address":"evil:1","workload":"evil"}}]}}}`)
	authz, err := rogue.Authorization(http.MethodPut, pkgroutes.Path, planted)
	if err != nil {
		t.Fatal(err)
	}
	h.cds.env = &pkgroutes.Envelope{Manifest: planted, Token: strings.TrimPrefix(authz, "Bearer ")}
	h.cds.rev = 3
	if _, err := h.run(t, add...); err == nil || !strings.Contains(err.Error(), "fails verification") {
		t.Fatalf("add over a rogue-signed manifest: error = %v", err)
	}
	if h.cds.puts != 0 {
		t.Fatalf("CDS saw %d writes, want none", h.cds.puts)
	}
}

// D3: an edit keeps a staged notBefore, to the nanosecond, rather than
// pulling it to now.
func TestEditKeepsFutureNotBefore(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(file, []byte(`{"schema":"c8s.routes/v1","revision":1,"notBefore":"2099-01-01T00:00:00.5Z","maxAgeSeconds":60,"hosts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustRun(t, "put", file)
	want := time.Date(2099, 1, 1, 0, 0, 0, 5e8, time.UTC)
	for _, args := range [][]string{
		{"add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a"},
		{"rm", "--host", "app.example", "--path", "/"},
	} {
		prev := h.cds.stored(t).Revision
		h.mustRun(t, args...)
		if m := h.cds.stored(t); m.Revision <= prev || !m.NotBefore.Equal(want) {
			t.Fatalf("after %s: revision %d, notBefore %s; want above %d, %s", args[0], m.Revision, m.NotBefore, prev, want)
		}
	}
}

// show describes the stored manifest, not what the router applies.
func TestShowEmptyManifest(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(file, []byte(`{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.mustRun(t, "put", file)
	if out := h.mustRun(t, "show"); !strings.Contains(out, "no hosts in the stored manifest") || strings.Contains(out, "router") {
		t.Fatalf("show = %q, want it to state only what is stored", out)
	}
}

// C6: a stored revision above the clock gets stored+1, and --revision must
// be above the stored one. Before signing, the edit lists every route.
func TestEditRevisionAboveClock(t *testing.T) {
	h := newHarness(t)
	ahead := uint64(time.Now().Unix()) + 3600
	file := filepath.Join(t.TempDir(), "routes.json")
	writeFile(t, file, `{"schema":"c8s.routes/v1","revision":`+strconv.FormatUint(ahead, 10)+`,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{"app.example":{"routes":[{"path":"/old","match":"exact","backend":{"address":"b:1","workload":"b"}}]}}}`)
	h.mustRun(t, "put", file)

	h.mustRun(t, "add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a")
	if m := h.cds.stored(t); m.Revision != ahead+1 {
		t.Fatalf("add over stored revision %d: revision %d, want %d", ahead, m.Revision, ahead+1)
	}
	for _, want := range []string{fmt.Sprintf("stored revision %d", ahead), "app.example /old exact -> b:1, workload b", "app.example / prefix -> a:1, workload a"} {
		if !strings.Contains(h.stderr.String(), want) {
			t.Errorf("add stderr = %q, want %q", h.stderr.String(), want)
		}
	}

	puts := h.cds.puts
	_, err := h.run(t, "rm", "--host", "app.example", "--path", "/old", "--revision", strconv.FormatUint(ahead, 10))
	if want := fmt.Sprintf("not above the stored revision %d", ahead+1); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("rm --revision below stored: error = %v, want %q", err, want)
	}
	if h.cds.puts != puts {
		t.Fatalf("CDS saw %d writes, want none", h.cds.puts-puts)
	}
	h.mustRun(t, "rm", "--host", "app.example", "--path", "/old", "--revision", strconv.FormatUint(ahead+10, 10))
	if m := h.cds.stored(t); m.Revision != ahead+10 {
		t.Fatalf("rm --revision %d: revision %d", ahead+10, m.Revision)
	}
}

func TestRmRejectsUnknownMatch(t *testing.T) {
	h := newHarness(t)
	h.mustRun(t, "add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a")
	if _, err := h.run(t, "rm", "--host", "app.example", "--path", "/", "--match", "Prefix"); err == nil || !strings.Contains(err.Error(), `--match "Prefix"`) {
		t.Fatalf("rm --match Prefix: error = %v", err)
	}
}

// add, rm and put load the operator key before dialing CDS, so a missing key
// fails before the attestation probe.
func TestWritesLoadKeyBeforeConnecting(t *testing.T) {
	t.Setenv("C8S_OPERATOR_KEY", "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	dials := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			dials++
			mu.Unlock()
			_ = conn.Close()
		}
	}()

	file := filepath.Join(t.TempDir(), "routes.json")
	writeFile(t, file, `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{}}`)
	_, pubFile, _ := writeKey(t, t.TempDir(), "operator")
	common := []string{"--url", "https://" + ln.Addr().String(), "--measurements", strings.Repeat("ab", 48), "--timeout", "2s"}
	for _, args := range [][]string{
		{"put", file},
		{"add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a", "--operator-keys", pubFile},
		{"rm", "--host", "app.example", "--path", "/", "--operator-keys", pubFile},
	} {
		cmd := newCmd(nil)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append(args, common...))
		if err := cmd.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "operator key required") {
			t.Errorf("%s without --operator-key: error = %v", args[0], err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if dials != 0 {
		t.Fatalf("CDS saw %d connections, want none", dials)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// C3: add and rm send the digest of the manifest they fetched as If-Match, so
// a write that landed in between fails with 412; put sends none.
func TestEditSendsIfMatch(t *testing.T) {
	h := newHarness(t)
	add := []string{"add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a"}
	h.mustRun(t, add...)
	first := digestHex(h.cds.env.Manifest)
	h.mustRun(t, "rm", "--host", "app.example", "--path", "/")
	file := filepath.Join(t.TempDir(), "routes.json")
	writeFile(t, file, `{"schema":"c8s.routes/v1","revision":`+strconv.FormatUint(h.cds.rev+1, 10)+`,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{}}`)
	h.mustRun(t, "put", file)
	if want := []string{"", first, ""}; !slices.Equal(h.cds.ifMatch, want) {
		t.Fatalf("If-Match per PUT = %q, want %q", h.cds.ifMatch, want)
	}

	h.cds.beforePut = func(f *fakeCDS) {
		f.env = &pkgroutes.Envelope{Manifest: append(bytes.Clone(f.env.Manifest), ' '), Token: f.env.Token}
	}
	_, err := h.run(t, add...)
	if err == nil || !strings.Contains(err.Error(), "412") || !strings.Contains(err.Error(), "another write landed first") {
		t.Fatalf("add after a concurrent write: error = %v", err)
	}
}

func TestAddMaxAge(t *testing.T) {
	h := newHarness(t)
	add := []string{"add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a"}
	if _, err := h.run(t, append(add, "--max-age", "500ms")...); err == nil || !strings.Contains(err.Error(), "--max-age") {
		t.Fatalf("add --max-age 500ms: error = %v, want one naming --max-age", err)
	}
	h.mustRun(t, append(add, "--max-age", "1h")...)
	h.mustRun(t, append(add, "--max-age", "2h")...)
	if m := h.cds.stored(t); m.MaxAge != time.Hour || !strings.Contains(h.stderr.String(), "--max-age ignored") {
		t.Fatalf("add --max-age 2h over a stored manifest: maxAge %s, stderr %q; want 1h and a warning", m.MaxAge, h.stderr.String())
	}
}

// A dry run refuses an unpinned endpoint, as a write does.
func TestDryRunRequiresPinnedEndpoint(t *testing.T) {
	_, pubFile, _ := writeKey(t, t.TempDir(), "operator")
	for _, args := range [][]string{
		{"add", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a"},
		{"rm", "--host", "app.example", "--path", "/"},
	} {
		cmd := newCmd(nil)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append(args, "--dry-run", "--operator-keys", pubFile, "--url", "https://127.0.0.1:1"))
		if err := cmd.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "unpinned CDS") {
			t.Errorf("%s --dry-run without --measurements: error = %v", args[0], err)
		}
	}
}
