package nodeservices

import (
	"fmt"
	"net/mail"
	"net/url"
	"strings"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Router selects the router's public hostnames and front-door limits. All
// fields are optional; non-empty Hostnames switches the front door to ACME.
// The route manifest, not this block, names every backend.
type Router struct {
	Hostnames        []string `yaml:"hostnames,omitempty" json:"hostnames,omitempty"`
	ACMEEmail        string   `yaml:"acmeEmail,omitempty" json:"acme_email,omitempty"`
	ACMEDirectoryURL string   `yaml:"acmeDirectoryURL,omitempty" json:"acme_directory_url,omitempty"`
	// MaxRequestBodyBytes caps an application request body on the public
	// listener; 0 keeps DefaultMaxRequestBodyBytes.
	MaxRequestBodyBytes uint64 `yaml:"maxRequestBodyBytes,omitempty" json:"max_request_body_bytes,omitempty"`
}

// DefaultMaxRequestBodyBytes is the router's application request body cap
// when the launch document sets none: nginx's own default, 1 MiB.
const DefaultMaxRequestBodyBytes = 1 << 20

// RequestBodyLimit is the application request body cap the router applies.
func (r Router) RequestBodyLimit() uint64 {
	if r.MaxRequestBodyBytes == 0 {
		return DefaultMaxRequestBodyBytes
	}
	return r.MaxRequestBodyBytes
}

// Empty reports whether the block sets no field.
func (r Router) Empty() bool {
	return len(r.Hostnames) == 0 && r.ACMEEmail == "" && r.ACMEDirectoryURL == "" && r.MaxRequestBodyBytes == 0
}

// maxStagedHostnames bounds the hostnames file staging writes, and with it
// the names one certificate is ordered for.
const maxStagedHostnames = 100

// ValidRouter is a router block staging can publish: every field has been
// checked by Validate, which is the only way to hold one.
type ValidRouter struct {
	router Router
}

// Validate accepts a router block the baked router can serve.
func (r Router) Validate() (ValidRouter, error) {
	if len(r.Hostnames) > maxStagedHostnames {
		return ValidRouter{}, fmt.Errorf("router.hostnames lists more than %d names", maxStagedHostnames)
	}
	for _, name := range r.Hostnames {
		if err := cmdsutil.ValidateHostname(name); err != nil {
			return ValidRouter{}, fmt.Errorf("router.hostnames: %w", err)
		}
	}
	seen := make(map[string]bool, len(r.Hostnames))
	for _, name := range r.Hostnames {
		if seen[name] {
			return ValidRouter{}, fmt.Errorf("router.hostnames lists %q twice", name)
		}
		seen[name] = true
	}
	if len(r.Hostnames) == 0 && (r.ACMEEmail != "" || r.ACMEDirectoryURL != "") {
		return ValidRouter{}, fmt.Errorf("router.acmeEmail and router.acmeDirectoryURL require router.hostnames")
	}
	if r.ACMEEmail != "" && !bareEmail(r.ACMEEmail) {
		return ValidRouter{}, fmt.Errorf("router.acmeEmail must be a bare email address")
	}
	if r.ACMEDirectoryURL != "" {
		if err := validateACMEDirectory(r.ACMEDirectoryURL); err != nil {
			return ValidRouter{}, fmt.Errorf("router.acmeDirectoryURL %w", err)
		}
	}
	return ValidRouter{router: r}, nil
}

// bareEmail reports whether s is one address and nothing else: no display
// name, no angle brackets, no second address.
func bareEmail(s string) bool {
	addr, err := mail.ParseAddress(s)
	return err == nil && addr.Address == s && addr.Name == ""
}

// validateACMEDirectory accepts the https URL of an ACME directory, written as
// the ACME client dials it.
func validateACMEDirectory(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("must be a URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("must use https")
	}
	if u.Host == "" {
		return fmt.Errorf("must name a host")
	}
	if u.User != nil {
		return fmt.Errorf("must carry no userinfo")
	}
	if u.String() != raw {
		return fmt.Errorf("must be written as it is dialled, which %q is not", u.String())
	}
	return nil
}

// BindRouterFlags binds the flags a document's router block is drafted from.
func BindRouterFlags(f *pflag.FlagSet, router *Router) {
	f.StringArrayVar(&router.Hostnames, "router-hostname", nil, "public DNS name the router serves with an ACME certificate; repeatable")
	f.StringVar(&router.ACMEEmail, "acme-email", "", "contact email for the router's ACME account (requires --router-hostname)")
	f.StringVar(&router.ACMEDirectoryURL, "acme-directory-url", "", "ACME directory URL, e.g. a staging directory for tests (requires --router-hostname; default Let's Encrypt)")
	f.Uint64Var(&router.MaxRequestBodyBytes, "router-max-request-body-bytes", 0, "largest application request body the router accepts, in bytes (default 1048576)")
}

// RouterTLSSnippetDir is where the node image installs tls-cds.conf and
// tls-acme.conf and the baked router mounts them. c8s-lib's
// c8s.routerWorkerConfigDir must equal it.
const RouterTLSSnippetDir = "/usr/lib/c8s/router-nginx"

// optionalLine renders an optional single-line value: empty stays empty.
func optionalLine(s string) []byte {
	if s == "" {
		return []byte{}
	}
	return []byte(s + "\n")
}

// The router's public inputs. Staging writes every one of them, empty where
// the document sets nothing, so the router pod never waits on a file.
const (
	routerTLSOutput           = "router/tls.conf"
	routerHostnamesOutput     = "router/hostnames"
	routerACMEEmailOutput     = "router/acme-email"
	routerACMEDirectoryOutput = "router/acme-directory-url"
	routerModeOutput          = "router/front-door-mode"
	routerRequestBodyOutput   = "router/request-body.conf"
)

// routerOutputNames are those files, the set both RouterOutputs writes and
// staging clears.
var routerOutputNames = []string{
	routerTLSOutput,
	routerHostnamesOutput,
	routerACMEEmailOutput,
	routerACMEDirectoryOutput,
	routerModeOutput,
	routerRequestBodyOutput,
}

// RouterOutputs are the router's public inputs from router, a document's
// router block; the zero block is a document that sets none. It checks the
// block, so no path can publish a file nginx reads as syntax.
func RouterOutputs(router Router) (map[string][]byte, error) {
	valid, err := router.Validate()
	if err != nil {
		return nil, fmt.Errorf("staged router: %w", err)
	}
	return valid.outputs(), nil
}

// outputs are the files the router reads, from a block that passed Validate.
func (v ValidRouter) outputs() map[string][]byte {
	router := v.router
	mode := types.FrontDoorModeCDS
	if len(router.Hostnames) > 0 {
		mode = types.FrontDoorModeACME
	}
	hostnames := []byte{}
	if len(router.Hostnames) > 0 {
		hostnames = []byte(strings.Join(router.Hostnames, "\n") + "\n")
	}
	return map[string][]byte{
		// nginx includes this in its server block to pick the certificate.
		routerTLSOutput:           []byte(fmt.Sprintf("include %s/tls-%s.conf;\n", RouterTLSSnippetDir, mode)),
		routerHostnamesOutput:     hostnames,
		routerACMEEmailOutput:     optionalLine(router.ACMEEmail),
		routerACMEDirectoryOutput: optionalLine(router.ACMEDirectoryURL),
		routerModeOutput:          []byte(string(mode) + "\n"),
		// nginx includes this in its application location.
		routerRequestBodyOutput: []byte(fmt.Sprintf("client_max_body_size %d;\n", router.RequestBodyLimit())),
	}
}
