package allowlistclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	testDigest = "sha256:" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	// testTag and otherTag stand for the ETags of two served documents.
	testTag  = `"sha256:` + "1111111111111111111111111111111111111111111111111111111111111111" + `"`
	otherTag = `"sha256:` + "2222222222222222222222222222222222222222222222222222222222222222" + `"`
)

// newClient is the tests' client against a local server; cases that need a
// transport deadline pass their own client to NewClientWithHTTP.
func newClient(baseURL string) Client {
	return NewClientWithHTTP(baseURL, &http.Client{})
}

type stubAuth struct{}

func (stubAuth) Authorization(method, path string, body []byte) (string, error) {
	return "Bearer test", nil
}

func TestList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", testTag)
		w.Header().Set(allowlist.VersionHeader, "7")
		io.WriteString(w, `{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[{"digest":"`+testDigest+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`)
	}))
	defer srv.Close()

	al, version, err := newClient(srv.URL).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != "7" {
		t.Fatalf("version = %q, want 7", version)
	}
	if cs := al.Workloads["cds"].Containers; len(cs) != 1 || cs[0].Digest.String() != testDigest {
		t.Fatalf("unexpected allowlist: %#v", al)
	}
}

// The served digest is the stamped policy digest of the canonical document.
func TestFetchServedDigestsServedBytes(t *testing.T) {
	al, err := allowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[{"digest":"` + testDigest + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", testTag)
		w.Write(body)
	}))
	defer srv.Close()

	served, notModified, err := newClient(srv.URL).FetchServed(context.Background(), "")
	if err != nil || notModified {
		t.Fatalf("FetchServed = nm=%v err=%v", notModified, err)
	}
	sum, err := al.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:" + hex.EncodeToString(sum); served.Digest != want {
		t.Errorf("FetchServed().Digest = %s, want %s", served.Digest, want)
	}
	if served.ETag != testTag || served.Allowlist == nil {
		t.Errorf("FetchServed() = %+v, want ETag %s and an allowlist", served, testTag)
	}
}

// The digest covers the bytes on the wire, not a re-encoding of them.
func TestFetchServedDigestsExactBytes(t *testing.T) {
	const body = `{"schema":"c8s.allowlist/v1",  "workloads":{"cds":{"containers":[{"digest":"` + testDigest + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	defer srv.Close()

	served, _, err := newClient(srv.URL).FetchServed(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	if want := "sha256:" + hex.EncodeToString(sum[:]); served.Digest != want {
		t.Errorf("FetchServed().Digest = %s, want %s", served.Digest, want)
	}
	if served.Allowlist == nil {
		t.Error("FetchServed() returned no allowlist")
	}
}

// A 304 still names the version CDS serves the held document at.
func TestFetchNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == testTag {
			w.Header().Set("ETag", testTag)
			w.Header().Set(allowlist.VersionHeader, "9")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		t.Fatalf("expected If-None-Match header")
	}))
	defer srv.Close()

	served, notModified, err := newClient(srv.URL).FetchServed(context.Background(), testTag)
	if err != nil || !notModified {
		t.Fatalf("expected notModified, got nm=%v err=%v", notModified, err)
	}
	if served.Version != "9" || served.Allowlist != nil {
		t.Fatalf("FetchServed() = %+v, want version 9 and no allowlist", served)
	}
}

func TestFetchServedStatus(t *testing.T) {
	const doc = `{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[{"digest":"` + testDigest + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`
	tests := []struct {
		name            string
		status          int
		etag            string
		wantETag        string
		wantNotModified bool
		wantErr         bool
	}{
		{name: "304", status: http.StatusNotModified, wantNotModified: true},
		{name: "200", status: http.StatusOK, etag: otherTag, wantETag: otherTag},
		{name: "5xx", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("If-None-Match"); got != testTag {
					t.Errorf("If-None-Match = %q, want %s", got, testTag)
				}
				if tt.etag != "" {
					w.Header().Set("ETag", tt.etag)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				if tt.status == http.StatusOK {
					io.WriteString(w, doc)
				}
			}))
			defer srv.Close()

			served, notModified, err := newClient(srv.URL).FetchServed(context.Background(), testTag)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FetchServed() error = %v, want error %v", err, tt.wantErr)
			}
			if served.ETag != tt.wantETag || notModified != tt.wantNotModified {
				t.Fatalf("FetchServed() = %q, %v; want %q, %v", served.ETag, notModified, tt.wantETag, tt.wantNotModified)
			}
		})
	}
}

// Object fetches a history document by digest and refuses bytes that hash
// to another one.
func TestObjectChecksTheDigest(t *testing.T) {
	al, err := allowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[{"digest":"` + testDigest + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/allowlist/objects/sha256/"+hex.EncodeToString(sum[:]) {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()
	c := newClient(srv.URL)

	got, err := c.Object(context.Background(), sum)
	if err != nil || len(got.Workloads["cds"].Containers) != 1 {
		t.Fatalf("Object() = %+v, %v, want the stored document", got, err)
	}
	other := sum
	other[0] ^= 1
	if _, err := c.Object(context.Background(), other); err == nil {
		t.Fatal("Object() of a digest the store lacks = nil error, want 404")
	}
	body = append(body, ' ')
	if _, err := c.Object(context.Background(), sum); err == nil || !strings.Contains(err.Error(), "another digest") {
		t.Fatalf("Object() of bytes hashing elsewhere = %v, want a digest error", err)
	}
}

// A CDS names the version in its version header; one released before the
// header names it only in its ETag W/"N".
func TestServedVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		etag    string
		want    string
	}{
		{name: "header", version: "7", etag: testTag, want: "7"},
		{name: "header over a weak ETag", version: "7", etag: `W/"6"`, want: "7"},
		{name: "weak ETag without header", etag: `W/"7"`, want: "7"},
		{name: "digest ETag without header", etag: testTag, want: ""},
		{name: "empty weak ETag", etag: `W/""`, want: ""},
		{name: "unclosed weak ETag", etag: `W/"7`, want: ""},
		{name: "neither", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.version != "" {
				h.Set(allowlist.VersionHeader, tt.version)
			}
			if tt.etag != "" {
				h.Set("ETag", tt.etag)
			}
			if got := servedVersion(h); got != tt.want {
				t.Errorf("servedVersion(%v) = %q, want %q", h, got, tt.want)
			}
		})
	}
}

func TestReplaceAllBindsBody(t *testing.T) {
	var gotPath, gotMethod, gotContentType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	al := &allowlist.Allowlist{
		Schema: allowlist.Schema,
		Workloads: map[string]allowlist.Workload{"my-app": {Containers: []allowlist.Container{{
			Digest:  mustDigest(t, testDigest),
			Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		}}}},
	}
	if err := newClient(srv.URL).ReplaceAll(context.Background(), al, "", stubAuth{}); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotPath != "/allowlist" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if !strings.Contains(string(gotBody), testDigest) {
		t.Fatalf("body missing digest: %s", gotBody)
	}
}

func TestMutateRejectsNilAuthorizer(t *testing.T) {
	err := newClient("http://x").ReplaceAll(context.Background(), &allowlist.Allowlist{Schema: allowlist.Schema}, "", nil)
	if err == nil || !strings.Contains(err.Error(), "nil Authorizer") {
		t.Fatalf("expected nil-authorizer error, got %v", err)
	}
}

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
