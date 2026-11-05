package nodeservices

import (
	"strconv"
	"strings"
	"testing"
)

// A router block the baked router cannot serve is refused where it is read, so
// no staging publishes a file nginx would read as syntax.
func TestRouterValidateRefusesABlockTheRouterCannotServe(t *testing.T) {
	oneHostname := []string{"a.example.com"}
	for _, tc := range []struct {
		name   string
		router Router
		want   string
	}{
		{
			name:   "hostname is an address",
			router: Router{Hostnames: []string{"10.0.0.1"}},
			want:   "router.hostnames",
		},
		{
			name:   "hostname is a wildcard",
			router: Router{Hostnames: []string{"*.example.com"}},
			want:   "router.hostnames",
		},
		{
			name:   "hostname is not lowercase",
			router: Router{Hostnames: []string{"API.example.com"}},
			want:   "router.hostnames",
		},
		{
			name:   "hostname carries nginx syntax",
			router: Router{Hostnames: []string{`a.example.com; return 200 "x"`}},
			want:   "router.hostnames",
		},
		{
			name:   "hostname listed twice",
			router: Router{Hostnames: []string{"a.example.com", "a.example.com"}},
			want:   "twice",
		},
		{
			name:   "more hostnames than one certificate carries",
			router: Router{Hostnames: tooManyHostnames()},
			want:   "more than",
		},
		{
			name:   "acme without hostnames",
			router: Router{ACMEEmail: "ops@example.com"},
			want:   "require router.hostnames",
		},
		{
			name:   "acme directory without hostnames",
			router: Router{ACMEDirectoryURL: "https://acme.example/dir"},
			want:   "require router.hostnames",
		},
		{
			name:   "acme email with a display name",
			router: Router{Hostnames: oneHostname, ACMEEmail: "Ops <ops@example.com>"},
			want:   "router.acmeEmail",
		},
		{
			name:   "acme email in angle brackets",
			router: Router{Hostnames: oneHostname, ACMEEmail: "<ops@example.com>"},
			want:   "router.acmeEmail",
		},
		{
			name:   "acme directory over http",
			router: Router{Hostnames: oneHostname, ACMEDirectoryURL: "http://acme.example/dir"},
			want:   "must use https",
		},
		{
			name:   "acme directory without a host",
			router: Router{Hostnames: oneHostname, ACMEDirectoryURL: "https:///dir"},
			want:   "must name a host",
		},
		{
			name:   "acme directory with userinfo",
			router: Router{Hostnames: oneHostname, ACMEDirectoryURL: "https://u:p@acme.example/dir"},
			want:   "no userinfo",
		},
		{
			name:   "acme directory holding a space",
			router: Router{Hostnames: oneHostname, ACMEDirectoryURL: "https://acme.example/di r"},
			want:   "as it is dialled",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.router.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
			if _, err := RouterOutputs(tc.router); err == nil {
				t.Fatal("a refused block produced router inputs")
			}
		})
	}
}

// The blocks a document may carry: none at all, body limit only, and the full
// ACME front door.
func TestRouterValidateTakesTheBlocksADocumentCarries(t *testing.T) {
	for _, router := range []Router{
		{},
		{MaxRequestBodyBytes: 64 << 20},
		{
			Hostnames:        []string{"candidate.api.example.com", "api.example.com"},
			ACMEEmail:        "ops@example.com",
			ACMEDirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		},
	} {
		if _, err := router.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v", router, err)
		}
	}
}

// The body limit a document sets is what the router applies; a document that
// sets none gets nginx's own default.
func TestRouterRequestBodyLimit(t *testing.T) {
	if got := (Router{}).RequestBodyLimit(); got != DefaultMaxRequestBodyBytes {
		t.Errorf("limit without a document value = %d, want %d", got, DefaultMaxRequestBodyBytes)
	}
	if got := (Router{MaxRequestBodyBytes: 64 << 20}).RequestBodyLimit(); got != 64<<20 {
		t.Errorf("limit = %d, want the document's", got)
	}
}

// tooManyHostnames is one more name than a staged hostnames file carries.
func tooManyHostnames() []string {
	names := make([]string, maxStagedHostnames+1)
	for i := range names {
		names[i] = "h" + strconv.Itoa(i) + ".example.com"
	}
	return names
}
