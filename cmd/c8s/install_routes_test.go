//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/routesclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestRouteHosts(t *testing.T) {
	tests := []struct {
		name        string
		values      map[string]any
		release     string
		wantHosts   []string
		wantSkipped []string
	}{
		{"default san", map[string]any{}, "c8s", []string{"c8s-router.c8s-system.svc"}, nil},
		{"default san, long release", map[string]any{}, strings.Repeat("r", 60), []string{strings.Repeat("r", 60) + "-ro.c8s-system.svc"}, nil},
		{"san list", map[string]any{"router": map[string]any{"san": []any{"App.Example.", "*.example.com", "192.0.2.1", "app.example."}}}, "c8s",
			[]string{"app.example"}, []string{"*.example.com", "192.0.2.1"}},
		{"numeric final label", map[string]any{"router": map[string]any{"san": []any{"app.example", "host.123", "host.0x1f"}}}, "c8s",
			[]string{"app.example"}, []string{"host.123", "host.0x1f"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hosts, skipped := routeHosts(tc.values, tc.release, "c8s-system")
			if !reflect.DeepEqual(hosts, tc.wantHosts) || !reflect.DeepEqual(skipped, tc.wantSkipped) {
				t.Fatalf("routeHosts() = %v, %v, want %v, %v", hosts, skipped, tc.wantHosts, tc.wantSkipped)
			}
		})
	}
}

var testUpstream = upstreamRoutes{hosts: []string{"app.example", "c8s-router.c8s-system.svc"}, address: "c8s-web.ws.svc.cluster.local:8443", workload: "web"}

func TestUpstreamRoutesApply(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 500, time.UTC)
	m := &pkgroutes.Manifest{MaxAge: time.Hour}
	b, err := testUpstream.apply(m, now)
	if err != nil {
		t.Fatalf("apply() = %v", err)
	}
	got, err := pkgroutes.Parse(b)
	if err != nil {
		t.Fatalf("Parse(apply()) = %v", err)
	}
	wantNotBefore := now.Truncate(time.Second)
	if got.Revision != uint64(now.Unix()) || !got.NotBefore.Equal(wantNotBefore) || got.MaxAge != time.Hour {
		t.Fatalf("revision, notBefore, maxAge = %d, %v, %v, want %d, %v, 1h", got.Revision, got.NotBefore, got.MaxAge, now.Unix(), wantNotBefore)
	}
	want := pkgroutes.Route{Path: "/", Match: pkgroutes.MatchPrefix, Backend: pkgroutes.Backend{Address: testUpstream.address, Workload: "web"}}
	for _, h := range testUpstream.hosts {
		if routes := got.Hosts[h].Routes; !reflect.DeepEqual(routes, []pkgroutes.Route{want}) {
			t.Fatalf("host %s routes = %+v, want [%+v]", h, routes, want)
		}
	}

	// On a stored manifest it keeps the other routes, replaces "/" and moves
	// to the next revision; a staged notBefore stays.
	staged := now.Add(time.Hour).Truncate(time.Second)
	other := pkgroutes.Route{Path: "/admin", Match: pkgroutes.MatchPrefix, Backend: pkgroutes.Backend{Address: "admin:8443", Workload: "admin"}}
	old := pkgroutes.Route{Path: "/", Match: pkgroutes.MatchPrefix, Backend: pkgroutes.Backend{Address: "old:8443", Workload: "old"}}
	m = &pkgroutes.Manifest{Revision: 7, NotBefore: staged, MaxAge: time.Minute, Hosts: map[string]pkgroutes.Host{"app.example": {Routes: []pkgroutes.Route{old, other}}}}
	if b, err = testUpstream.apply(m, now); err != nil {
		t.Fatalf("apply(stored) = %v", err)
	}
	if got, err = pkgroutes.Parse(b); err != nil {
		t.Fatalf("Parse = %v", err)
	}
	if got.Revision != uint64(now.Unix()) || !got.NotBefore.Equal(staged) || got.MaxAge != time.Minute {
		t.Fatalf("revision, notBefore, maxAge = %d, %v, %v, want %d, %v, 1m", got.Revision, got.NotBefore, got.MaxAge, now.Unix(), staged)
	}
	if routes := got.Hosts["app.example"].Routes; !reflect.DeepEqual(routes, []pkgroutes.Route{want, other}) {
		t.Fatalf("app.example routes = %+v, want [%+v %+v]", routes, want, other)
	}

	// --routes-revision outranks a router that holds one above the clock.
	resetCLIState(t)
	installRoutesRevision = uint64(now.Unix()) + 3600
	if b, err = testUpstream.apply(&pkgroutes.Manifest{MaxAge: time.Hour}, now); err != nil {
		t.Fatalf("apply(--routes-revision) = %v", err)
	}
	if got, err = pkgroutes.Parse(b); err != nil || got.Revision != installRoutesRevision {
		t.Fatalf("apply(--routes-revision %d) = %+v, %v", installRoutesRevision, got, err)
	}
	if _, err = testUpstream.apply(&pkgroutes.Manifest{Revision: installRoutesRevision, MaxAge: time.Hour}, now); err == nil || !strings.Contains(err.Error(), "--routes-revision") {
		t.Fatalf("apply(--routes-revision at the stored revision) = %v, want a --routes-revision error", err)
	}
}

// signedEnvelope is what CDS serves after an operator stored manifest.
func signedEnvelope(t *testing.T, manifest []byte) (pkgroutes.Envelope, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	var env pkgroutes.Envelope
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		env = pkgroutes.Envelope{Manifest: body, Token: token}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer cds.Close()
	c, err := routesclient.New(cds.URL, cds.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Put(context.Background(), manifest, signer, ""); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return env, pub
}

func TestStoredManifest(t *testing.T) {
	stored, err := testUpstream.apply(&pkgroutes.Manifest{MaxAge: time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, pub := signedEnvelope(t, stored)
	_, otherPub := signedEnvelope(t, stored)
	parsed, err := pkgroutes.Parse(stored)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(env *pkgroutes.Envelope) routesclient.Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if env == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(env)
		}))
		t.Cleanup(srv.Close)
		c, err := routesclient.New(srv.URL, srv.Client())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	resetCLIState(t)
	installRoutesMaxAge = 2 * time.Hour

	tests := []struct {
		name         string
		env          *pkgroutes.Envelope
		operatorKeys string
		wantRevision uint64
		wantErr      string
	}{
		{"none stored", nil, "", 0, ""},
		{"stored, verified", &env, pub, parsed.Revision, ""},
		{"stored, no operator keys", &env, "", 0, "pass --operator-keys"},
		{"stored under another key", &env, otherPub, 0, "fails verification against --operator-keys"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installOperatorKeys = tc.operatorKeys
			m, _, err := storedManifest(context.Background(), serve(tc.env))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("storedManifest() = %v, want an error containing %q", err, tc.wantErr)
				}
				if !errors.As(err, new(storedManifestError)) {
					t.Fatalf("storedManifest() = %v, want a storedManifestError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("storedManifest() = %v", err)
			}
			if m.Revision != tc.wantRevision {
				t.Fatalf("storedManifest().Revision = %d, want %d", m.Revision, tc.wantRevision)
			}
			if tc.env == nil && m.MaxAge != 2*time.Hour {
				t.Fatalf("new manifest maxAge = %v, want --routes-max-age 2h", m.MaxAge)
			}
		})
	}
}

// TestStoredManifestKeysFromValues: a stored manifest verifies against the
// keys a -f file gives CDS when --operator-keys is absent.
func TestStoredManifestKeysFromValues(t *testing.T) {
	stored, err := testUpstream.apply(&pkgroutes.Manifest{MaxAge: time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, pub := signedEnvelope(t, stored)
	pubPEM, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	values := filepath.Join(t.TempDir(), "values.yaml")
	body, err := json.Marshal(map[string]any{"cds": map[string]any{"operatorKeys": string(pubPEM)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(values, body, 0o600); err != nil { // JSON is YAML
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	}))
	t.Cleanup(srv.Close)
	c, err := routesclient.New(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	resetCLIState(t)
	installValues = []string{values}
	want, err := pkgroutes.Parse(stored)
	if err != nil {
		t.Fatal(err)
	}
	var m *pkgroutes.Manifest
	stderr := captureStderr(t, func() { m, _, err = storedManifest(context.Background(), c) })
	if err != nil || m.Revision != want.Revision {
		t.Fatalf("storedManifest() = %+v, %v, want the stored revision %d", m, err, want.Revision)
	}
	if stderr != "" {
		t.Fatalf("storedManifest() warned without --routes-max-age: %s", stderr)
	}
	// A --routes-max-age the stored maxAgeSeconds overrides is reported.
	installRoutesMaxAge, installRoutesMaxAgeSet = 2*time.Hour, true
	stderr = captureStderr(t, func() { _, _, err = storedManifest(context.Background(), c) })
	if err != nil || !strings.Contains(stderr, "--routes-max-age 2h0m0s is ignored") {
		t.Fatalf("storedManifest() = %v, stderr %q, want the override warning", err, stderr)
	}
}

// TestWriteUpstreamRoutes: the fallback leads with `c8s routes add`, which
// keeps stored routes and the requested max-age and revision, and offers `put`
// of a new manifest only when install sent no write and CDS may store none.
func TestWriteUpstreamRoutes(t *testing.T) {
	const (
		add          = "c8s routes add --new --host app.example --path / --address c8s-web.ws.svc.cluster.local:8443 --workload web --max-age 2h0m0s --operator-keys"
		addOtherHost = "c8s routes add --new --host c8s-router.c8s-system.svc --path /"
		addRevision  = "--workload web --max-age 2h0m0s --revision 7 --operator-keys"
		addRevision2 = "--workload web --max-age 2h0m0s --revision 8 --operator-keys"
		replaces     = "it replaces a stored one and drops its other routes"
	)
	refused := errors.New("refused")
	stored, err := testUpstream.apply(&pkgroutes.Manifest{MaxAge: time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		manifest []byte
		cause    error
		revision uint64
		want     []string
		wantNot  []string
	}{
		{"CDS may store none", nil, refused, 0, []string{add, addOtherHost, replaces, "c8s routes put "}, []string{"--revision"}},
		{"CDS stores one", nil, storedManifestError{refused}, 0, []string{add, addOtherHost}, []string{"c8s routes put "}},
		{"write refused", stored, refused, 0, []string{add}, []string{"c8s routes put "}},
		{"--routes-revision", nil, nil, 7, []string{addRevision, addRevision2}, nil},
		{"--routes-revision refused", nil, storedManifestError{revisionError{refused}}, 7, []string{add}, []string{"--revision", "c8s routes put "}},
		{"--routes-revision, token spent", nil, storedManifestError{&operatorauth.StatusError{Status: http.StatusConflict, Body: allowlist.ErrTokenReused.Error()}}, 7, []string{addRevision}, []string{"c8s routes put "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetCLIState(t)
			installRoutesOut = filepath.Join(t.TempDir(), "routes.json")
			installMeasurements = []string{"abcd"}
			installRoutesMaxAge, installRoutesRevision = 2*time.Hour, tc.revision
			var out bytes.Buffer
			if err := writeUpstreamRoutes(&out, testUpstream, cdsTarget{namespace: "c8s-system", service: "c8s-cds", port: 8443}, map[string]adoptedEntry{"web": {}}, tc.manifest, tc.cause); err != nil {
				t.Fatalf("writeUpstreamRoutes() = %v", err)
			}
			b, err := os.ReadFile(installRoutesOut)
			if err != nil {
				t.Fatal(err)
			}
			m, err := pkgroutes.Parse(b)
			if err != nil || (tc.revision == 0 && m.Revision < 1e9) || (tc.revision != 0 && m.Revision != tc.revision) {
				t.Fatalf("written manifest = %+v, %v, want revision %d, or a Unix-time one for 0", m, err, tc.revision)
			}
			got := out.String()
			if i, j := strings.Index(got, add), strings.Index(got, "c8s routes put "); j >= 0 && j < i {
				t.Errorf("output leads with put:\n%s", got)
			}
			for _, want := range append(tc.want,
				"kubectl -n c8s-system port-forward svc/c8s-cds 8443:8443",
				"--url https://127.0.0.1:8443 --measurements abcd",
				"c8s allowlist list --url https://127.0.0.1:8443 --measurements abcd",
			) {
				if !strings.Contains(got, want) {
					t.Errorf("output lacks %q:\n%s", want, got)
				}
			}
			for _, not := range tc.wantNot {
				if strings.Contains(got, not) {
					t.Errorf("output holds %q:\n%s", not, got)
				}
			}
		})
	}
}

// TestWriteUpstreamRoutesKeyPaths: the printed commands name the key files
// install was given.
func TestWriteUpstreamRoutesKeyPaths(t *testing.T) {
	resetCLIState(t)
	installRoutesOut = filepath.Join(t.TempDir(), "routes.json")
	installOperatorKey, installOperatorKeys = "/keys/op.key", "/keys/op-pub.pem"
	var out bytes.Buffer
	if err := writeUpstreamRoutes(&out, testUpstream, cdsTarget{namespace: "c8s-system", service: "c8s-cds", port: 8443}, nil, nil, errors.New("refused")); err != nil {
		t.Fatalf("writeUpstreamRoutes() = %v", err)
	}
	got := out.String()
	for _, want := range []string{"--operator-keys /keys/op-pub.pem --url", "--operator-key /keys/op.key"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "<operator-") {
		t.Errorf("output holds a key placeholder:\n%s", got)
	}
}

// TestWriteUpstreamRoutesExistingFile: a default --routes-out that already
// exists is not overwritten, and the add commands still print.
func TestWriteUpstreamRoutesExistingFile(t *testing.T) {
	resetCLIState(t)
	installRoutesOut = filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(installRoutesOut, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := writeUpstreamRoutes(&out, testUpstream, cdsTarget{namespace: "c8s-system", service: "c8s-cds", port: 8443}, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--routes-out") {
		t.Fatalf("writeUpstreamRoutes() = %v, want the --routes-out refusal", err)
	}
	if !strings.Contains(out.String(), "c8s routes add --new --host app.example") {
		t.Errorf("output lacks the add command:\n%s", out.String())
	}
	if b, _ := os.ReadFile(installRoutesOut); string(b) != "keep" {
		t.Errorf("--routes-out = %q, want it untouched", b)
	}
}

func TestPreflightUpstreamRoutes(t *testing.T) {
	dir := t.TempDir()
	writeKeyPair := func(name string) (keyFile, pubFile string) {
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
		keyFile, pubFile = filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pubFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
			t.Fatal(err)
		}
		return keyFile, pubFile
	}
	key, pub := writeKeyPair("operator")
	_, otherPub := writeKeyPair("other")
	pubPEM, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	values := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(values, []byte("cds:\n  operatorKeys: |\n    "+strings.ReplaceAll(strings.TrimSpace(string(pubPEM)), "\n", "\n    ")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinned := []string{strings.Repeat("ab", 48)}
	emptied := filepath.Join(dir, "emptied.yaml")
	if err := os.WriteFile(emptied, []byte("cds:\n  operatorKeys: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name                        string
		upstream, key, keys, maxAge string
		outSet, maxAgeSet           bool
		revision                    uint64
		values                      []string
		measurements, rtmrs         []string
		wantErr                     string
	}{
		{name: "no upstream, no key"},
		{name: "key without upstream", key: key, wantErr: "pass --upstream"},
		{name: "--routes-out without upstream", outSet: true, wantErr: "--routes-out applies"},
		{name: "--routes-max-age without upstream", maxAgeSet: true, wantErr: "--routes-max-age applies"},
		{name: "--routes-revision without upstream", revision: 9, wantErr: "--routes-revision applies"},
		{name: "malformed --rtmrs", upstream: "web", key: key, keys: pub, measurements: pinned, rtmrs: []string{"1=zz"}, wantErr: "--rtmrs"},
		{name: "upstream without key", upstream: "web"},
		{name: "max age below a second", upstream: "web", maxAge: "500ms", wantErr: "--routes-max-age"},
		{name: "max age above D4", upstream: "web", maxAge: "600000h", wantErr: "--routes-max-age"},
		{name: "unpinned CDS", upstream: "web", key: key, keys: pub, wantErr: "unpinned CDS"},
		{name: "key in --operator-keys", upstream: "web", key: key, keys: pub, measurements: pinned},
		{name: "key in cds.operatorKeys", upstream: "web", key: key, values: []string{values}, measurements: pinned},
		{name: "no keys for CDS", upstream: "web", key: key, measurements: pinned, wantErr: "pass --operator-keys"},
		{name: "a later file empties cds.operatorKeys", upstream: "web", key: key, values: []string{values, emptied}, measurements: pinned, wantErr: "pass --operator-keys"},
		{name: "key CDS does not trust", upstream: "web", key: key, keys: otherPub, measurements: pinned, wantErr: "not among the operator keys"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetCLIState(t)
			installUpstream, installOperatorKey, installOperatorKeys = tc.upstream, tc.key, tc.keys
			installValues, installMeasurements = tc.values, tc.measurements
			installRoutesOutSet, installRoutesMaxAgeSet = tc.outSet, tc.maxAgeSet
			installRoutesRevision, installRegisters = tc.revision, tc.rtmrs
			if tc.maxAge != "" {
				d, err := time.ParseDuration(tc.maxAge)
				if err != nil {
					t.Fatal(err)
				}
				installRoutesMaxAge = d
			}
			err := preflightUpstreamRoutes()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("preflightUpstreamRoutes() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("preflightUpstreamRoutes() = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// webEntry is the entry install writes for a pod running digest with the
// injected cert mount alone, and that pod.
func webEntry(t *testing.T, digest string) (pkgallowlist.Workload, []pkgallowlist.RunningContainer) {
	t.Helper()
	e := adoptedEntryFor(t, templateRunning("example/web@"+digest))
	return e.workload, e.pod
}

// adoptedEntryFor is the entry and pod install models for a template whose
// images are pinned by digest.
func adoptedEntryFor(t *testing.T, tmpl corev1.PodTemplateSpec) adoptedEntry {
	t.Helper()
	_, entries, err := buildWorkloadImageArgs(nil, []adoptedWorkload{{workloadAdoption: workloadAdoption{cwID: "web"}, template: tmpl}}, "", io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	return entries["web"]
}

func TestCheckServedEntry(t *testing.T) {
	const (
		dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	ours, pod := webEntry(t, dA)
	stale, _ := webEntry(t, dB) // the web entry an earlier install wrote, before an image bump
	perDigest := pkgallowlist.DigestEntry(want2digest(t, dA), "example/web@"+dA)
	// A main running beside a native sidecar: an entry requiring both as mains
	// describes the running pod as well as the one install writes.
	always := corev1.ContainerRestartPolicyAlways
	sidecarTmpl := templateRunning("example/web@" + dA)
	sidecarTmpl.Spec.InitContainers = []corev1.Container{{Name: "proxy", Image: "example/proxy@" + dB, RestartPolicy: &always}}
	sidecar := adoptedEntryFor(t, sidecarTmpl)
	bothMains := sidecar.workload
	bothMains.Containers = append(slices.Clone(bothMains.Containers), bothMains.InitContainers...)
	bothMains.InitContainers = nil
	tests := []struct {
		name      string
		workloads map[string]pkgallowlist.Workload
		pod       []pkgallowlist.RunningContainer
		wantErr   string
	}{
		{"ours alone", map[string]pkgallowlist.Workload{"web": ours}, pod, ""},
		{"stale entry kept by a persistent CDS", map[string]pkgallowlist.Workload{"web": stale}, pod, "does not describe the pod"},
		{"no entry", map[string]pkgallowlist.Workload{}, pod, "serves no allowlist entry"},
		{"leftover per-digest entry", map[string]pkgallowlist.Workload{"web": ours, "web-aaaaaaaaaaaa": perDigest}, pod, "web, web-aaaaaaaaaaaa"},
		{"another entry names it", map[string]pkgallowlist.Workload{"web": stale, "old": ours}, pod, "entry old, not web"},
		{"argv-pinned entry that may match the pod", map[string]pkgallowlist.Workload{"web": ours, "pinned": argvPinned(ours)}, pod, "pinned, web"},
		{"own entry pins argv", map[string]pkgallowlist.Workload{"web": argvPinned(ours)}, pod, "install cannot check"},
		{"native sidecar", map[string]pkgallowlist.Workload{"web": sidecar.workload}, sidecar.pod, ""},
		{"entry requiring the native sidecar as a main", map[string]pkgallowlist.Workload{"web": sidecar.workload, "both": bothMains}, sidecar.pod, "both, web"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkServedEntry(&pkgallowlist.Allowlist{Workloads: tc.workloads}, "web", tc.pod)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkServedEntry() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkServedEntry() = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// argvPinned returns w admitting one exact command only.
func argvPinned(w pkgallowlist.Workload) pkgallowlist.Workload {
	w.Containers = slices.Clone(w.Containers)
	w.Containers[0].Command = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/serve"}}
	return w
}

func want2digest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestPutUpstreamRoutesReturnsARefusedManifest: when CDS refuses the write,
// putUpstreamRoutes hands back the manifest it built, for --routes-out.
func TestPutUpstreamRoutesReturnsARefusedManifest(t *testing.T) {
	resetCLIState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.Header.Get("If-Match"); got != "" {
			t.Errorf("PUT over an empty store sent If-Match %q, want none", got)
		}
		http.Error(w, "revision not greater", http.StatusConflict)
	}))
	t.Cleanup(srv.Close)
	c, err := routesclient.New(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	signer := authorizerFunc(func(string, string, []byte) (string, error) { return "Bearer x", nil })
	manifest, err := putUpstreamRoutes(context.Background(), io.Discard, c, signer, testUpstream)
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("putUpstreamRoutes() = %v, want the 409", err)
	}
	if _, err := pkgroutes.Parse(manifest); err != nil {
		t.Fatalf("putUpstreamRoutes() manifest = %q, %v, want the refused one", manifest, err)
	}
}

// TestPutUpstreamRoutesLostRace: install sends the digest of the manifest it
// verified as If-Match; when another write lands first, CDS answers 412 and
// the fallback still writes --routes-out with the add commands.
func TestPutUpstreamRoutesLostRace(t *testing.T) {
	stored, err := testUpstream.apply(&pkgroutes.Manifest{MaxAge: time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, pub := signedEnvelope(t, stored)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(env)
			return
		}
		if got, want := r.Header.Get("If-Match"), manifestDigest(stored); got != want {
			t.Errorf("PUT If-Match = %q, want the read manifest's digest %q", got, want)
		}
		http.Error(w, "route digest mismatch", http.StatusPreconditionFailed)
	}))
	t.Cleanup(srv.Close)
	c, err := routesclient.New(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	resetCLIState(t)
	installOperatorKeys = pub
	installRoutesOut = filepath.Join(t.TempDir(), "routes.json")
	signer := authorizerFunc(func(string, string, []byte) (string, error) { return "Bearer x", nil })
	manifest, err := putUpstreamRoutes(context.Background(), io.Discard, c, signer, testUpstream)
	if err == nil || !strings.Contains(err.Error(), "412") || !errors.As(err, new(storedManifestError)) {
		t.Fatalf("putUpstreamRoutes() = %v, want the 412 as a storedManifestError", err)
	}
	var out bytes.Buffer
	if err := writeUpstreamRoutes(&out, testUpstream, cdsTarget{namespace: "c8s-system", service: "c8s-cds", port: 8443}, nil, manifest, err); err != nil {
		t.Fatalf("writeUpstreamRoutes() = %v", err)
	}
	if b, err := os.ReadFile(installRoutesOut); err != nil || !bytes.Equal(b, manifest) {
		t.Fatalf("--routes-out = %q, %v, want the refused manifest", b, err)
	}
	if !strings.Contains(out.String(), "c8s routes add --new --host app.example") || strings.Contains(out.String(), "c8s routes put ") {
		t.Fatalf("output lacks the add command or offers put:\n%s", out.String())
	}
}

// TestPutUpstreamRoutesRevisionBelowStored: a --routes-revision not above the
// stored revision sends no write, and the fallback offers neither put nor
// --revision.
func TestPutUpstreamRoutesRevisionBelowStored(t *testing.T) {
	stored, err := testUpstream.apply(&pkgroutes.Manifest{MaxAge: time.Hour}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, pub := signedEnvelope(t, stored)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("%s /routes, want no write", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	}))
	t.Cleanup(srv.Close)
	c, err := routesclient.New(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	resetCLIState(t)
	installOperatorKeys = pub
	installRoutesOut = filepath.Join(t.TempDir(), "routes.json")
	installRoutesRevision = 7
	signer := authorizerFunc(func(string, string, []byte) (string, error) { return "Bearer x", nil })
	manifest, err := putUpstreamRoutes(context.Background(), io.Discard, c, signer, testUpstream)
	if err == nil || !errors.As(err, new(storedManifestError)) || !errors.As(err, new(revisionError)) {
		t.Fatalf("putUpstreamRoutes() = %v, want a stored-manifest revision error", err)
	}
	var out bytes.Buffer
	if err := writeUpstreamRoutes(&out, testUpstream, cdsTarget{namespace: "c8s-system", service: "c8s-cds", port: 8443}, nil, manifest, err); err != nil {
		t.Fatalf("writeUpstreamRoutes() = %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "c8s routes add --new --host app.example") || strings.Contains(got, "c8s routes put ") || strings.Contains(got, "--revision") {
		t.Fatalf("output lacks add, or offers put or --revision:\n%s", got)
	}
}

// TestDeliverUpstreamRoutesKeepsTheManifest: when install cannot reach CDS
// after the release changed the cluster, the manifest still lands in
// --routes-out with the command that stores it.
func TestDeliverUpstreamRoutesKeepsTheManifest(t *testing.T) {
	f := newFakeBin(t)
	f.tool(t, "kubectl", `echo "unable to forward" >&2; exit 1`)
	resetCLIState(t)
	installOperatorKey = "operator.key"
	installRoutesOut = filepath.Join(t.TempDir(), "routes.json")
	var out bytes.Buffer
	err := deliverUpstreamRoutes(context.Background(), &out, testUpstream, cdsTarget{namespace: "c8s-system", service: "c8s-cds", port: 8443}, nil)
	if err == nil || !strings.Contains(err.Error(), "unable to forward") || !strings.Contains(err.Error(), "add the route as printed above") {
		t.Fatalf("deliverUpstreamRoutes() = %v, want the port-forward failure and the fallback", err)
	}
	b, err := os.ReadFile(installRoutesOut)
	if err != nil {
		t.Fatalf("read --routes-out: %v", err)
	}
	if _, err := pkgroutes.Parse(b); err != nil {
		t.Fatalf("--routes-out = %v, want a manifest", err)
	}
	if !strings.Contains(out.String(), "c8s routes add ") || !strings.Contains(out.String(), "c8s routes put "+installRoutesOut) {
		t.Fatalf("output lacks the add and put commands:\n%s", out.String())
	}
}

type authorizerFunc func(method, path string, body []byte) (string, error)

func (f authorizerFunc) Authorization(method, path string, body []byte) (string, error) {
	return f(method, path, body)
}

func TestRoutesOutNeverClobbersByDefault(t *testing.T) {
	resetCLIState(t)
	installUpstream = "web"
	installRoutesOut = filepath.Join(t.TempDir(), "routes.json")
	if err := preflightRoutesOut(); err != nil {
		t.Fatalf("preflightRoutesOut() with no file = %v", err)
	}
	if err := os.WriteFile(installRoutesOut, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preflightRoutesOut(); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("preflightRoutesOut() over a file = %v, want the refusal", err)
	}
	if err := writeRoutesOut([]byte("new")); err == nil {
		t.Fatal("writeRoutesOut() replaced a file at the default path")
	}
	installRoutesOutSet = true
	if err := preflightRoutesOut(); err != nil {
		t.Fatalf("preflightRoutesOut() with --routes-out set = %v", err)
	}
	if err := writeRoutesOut([]byte("new")); err != nil {
		t.Fatalf("writeRoutesOut() with --routes-out set = %v", err)
	}
	if b, _ := os.ReadFile(installRoutesOut); string(b) != "new" {
		t.Fatalf("--routes-out = %q, want the new manifest", b)
	}
}
