package allowlistclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const testDigest = "sha256:" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

type stubAuth struct{}

func (stubAuth) Authorization(method, path string, body []byte) (string, error) {
	return "Bearer test", nil
}

func TestList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"7"`)
		io.WriteString(w, `{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[{"digest":"`+testDigest+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`)
	}))
	defer srv.Close()

	al, version, err := NewClient(srv.URL).List(context.Background())
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

func TestFetchNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `W/"3"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		t.Fatalf("expected If-None-Match header")
	}))
	defer srv.Close()

	_, _, notModified, err := NewClient(srv.URL).Fetch(context.Background(), `W/"3"`)
	if err != nil || !notModified {
		t.Fatalf("expected notModified, got nm=%v err=%v", notModified, err)
	}
}

func TestFetchCanonical(t *testing.T) {
	const doc = `{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[{"digest":"` + testDigest + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`
	tests := []struct {
		name            string
		status          int
		etag            string
		wantBody        string
		wantVersion     string
		wantNotModified bool
		wantErr         bool
	}{
		{name: "304", status: http.StatusNotModified, wantNotModified: true},
		{name: "200", status: http.StatusOK, etag: `W/"8"`, wantBody: doc, wantVersion: "8"},
		{name: "200 without ETag", status: http.StatusOK, wantErr: true},
		{name: "200 with strong ETag", status: http.StatusOK, etag: `"8"`, wantErr: true},
		{name: "5xx", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("If-None-Match"); got != `W/"7"` {
					t.Errorf("If-None-Match = %q, want W/\"7\"", got)
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

			body, version, notModified, err := NewClient(srv.URL).FetchCanonical(context.Background(), `W/"7"`)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FetchCanonical() error = %v, want error %v", err, tt.wantErr)
			}
			if string(body) != tt.wantBody || version != tt.wantVersion || notModified != tt.wantNotModified {
				t.Fatalf("FetchCanonical() = %q, %q, %v; want %q, %q, %v", body, version, notModified, tt.wantBody, tt.wantVersion, tt.wantNotModified)
			}
		})
	}
}

func TestVersionFromETag(t *testing.T) {
	tests := []struct {
		name string
		etag string
		want string
	}{
		{name: "weak", etag: `W/"7"`, want: "7"},
		{name: "strong", etag: `"7"`, want: ""},
		{name: "empty weak", etag: `W/""`, want: ""},
		{name: "missing", etag: "", want: ""},
		{name: "unclosed", etag: `W/"7`, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VersionFromETag(tt.etag); got != tt.want {
				t.Errorf("VersionFromETag(%q) = %q, want %q", tt.etag, got, tt.want)
			}
		})
	}
}

func TestPutWorkloadBindsBody(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	wl := allowlist.Workload{Containers: []allowlist.Container{{
		Digest:  mustDigest(t, testDigest),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
	}}}
	if err := NewClient(srv.URL).PutWorkload(context.Background(), "my-app", wl, stubAuth{}); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotPath != "/allowlist/workloads/my-app" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(string(gotBody), testDigest) {
		t.Fatalf("body missing digest: %s", gotBody)
	}
}

func TestDeleteWorkloadOmitsContentType(t *testing.T) {
	var gotContentType string
	var seen bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = true
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := NewClient(srv.URL).DeleteWorkload(context.Background(), "my-app", stubAuth{}); err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Fatal("request never sent")
	}
	if gotContentType != "" {
		t.Fatalf("bodyless request should not set Content-Type, got %q", gotContentType)
	}
}

func TestMutateRejectsNilAuthorizer(t *testing.T) {
	err := NewClient("http://x").DeleteWorkload(context.Background(), "my-app", nil)
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
