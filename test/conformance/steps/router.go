package steps

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/cucumber/godog"
)

// Sentences about the router: what a client reaching its public HTTPS
// address gets from the built-in allowlist route, the discovery publication
// and the TLS handshake. What the router is configured to do is read from
// its rendered nginx configuration and its Deployment.
func registerRouter(sc *godog.ScenarioContext) {
	sc.Step(`^the built-in allowlist route is enabled$`, allowlistRouteEnabled)
	sc.Step(`^discovery publication is enabled$`, discoveryEnabled)
	sc.Step(`^the CDS-issued credential is the selected public TLS credential$`, cdsCredentialSelected)
	sc.Step(`^(?:a|the) client reads the allowlist through the built-in allowlist route$`, readsThroughRoute)
	sc.Step(`^a client requests a lookalike of the built-in allowlist route$`, requestsLookalike)
	sc.Step(`^the client (does not receive|receives) the served allowlist$`, clientReceivesServed)
	sc.Step(`^the client (does not receive|receives) the relay failure$`, clientReceivesRelayFailure)
	sc.Step(`^the operator sends that write through the built-in allowlist route with that write token$`, operatorSendsThroughRoute)
	sc.Step(`^that caller sends a write of a workload entry "([^"]*)" admitting image "([^"]*)" under any argv through the built-in allowlist route$`, callerWritesThroughRoute)
	sc.Step(`^the allowlist relay cannot reach the CDS$`, relayCannotReachCDS)
	sc.Step(`^the router serves the discovery document$`, servesDiscovery)
	sc.Step(`^a client connects to the router$`, connectsToRouter)
	sc.Step(`^the certificate the router presents is its CDS-issued certificate$`, presentsCDSCertificate)
}

// The router's built-in allowlist route (exact and prefix), a path that only
// looks like it, and the relay failure's body (router specification §9).
const (
	allowlistRoute     = "/allowlist"
	allowlistLookalike = "/allowlisted"
	relayFailureBody   = "CDS unavailable"
)

// routerState is what the scenario has learnt of the router: its rendered
// configuration, the last answer a client got and the certificate the
// router presented.
type routerState struct {
	conf    *nginxConf
	answer  *answer
	serving []byte // DER
}

// nginxConf is the router's rendered nginx configuration, as locations.
type nginxConf struct {
	exact  map[string]string // location = path -> its block
	prefix map[string]string // location path -> its block
}

var (
	locationRE = regexp.MustCompile(`(?m)^\s*location\s+(=\s+)?(\S+)\s*\{`)
	aliasRE    = regexp.MustCompile(`alias\s+(\S+);`)
)

// parseLocations reads each location's block, nested blocks included.
func parseLocations(conf string) *nginxConf {
	c := &nginxConf{exact: map[string]string{}, prefix: map[string]string{}}
	for _, m := range locationRE.FindAllStringSubmatchIndex(conf, -1) {
		start, depth, end := m[1], 1, len(conf)
		for i := start; i < len(conf) && depth > 0; i++ {
			switch conf[i] {
			case '{':
				depth++
			case '}':
				if depth--; depth == 0 {
					end = i
				}
			}
		}
		path, block := conf[m[4]:m[5]], conf[start:end]
		if m[2] >= 0 {
			c.exact[path] = block
		} else {
			c.prefix[path] = block
		}
	}
	return c
}

func (w *world) routerConf() (*nginxConf, error) {
	if w.router.conf != nil {
		return w.router.conf, nil
	}
	out, err := w.be.call("router_nginx_conf")
	if err != nil {
		return nil, err
	}
	w.router.conf = parseLocations(out)
	return w.router.conf, nil
}

// published is the exact location serving a mounted file as contentType,
// and, when file is given, a file of that name: the discovery document
// (application/json) or the CDS-issued certificate (cert.pem, beside the
// mesh CA's ca.pem, both application/x-pem-file).
func (c *nginxConf) published(contentType, file string) string {
	for path, block := range c.exact {
		alias := aliasRE.FindStringSubmatch(block)
		if alias == nil || !strings.Contains(block, "default_type "+contentType+";") {
			continue
		}
		if file == "" || strings.HasSuffix(alias[1], "/"+file) {
			return path
		}
	}
	return ""
}

// allowlistRouteEnabled reads the route off the router's configuration, or,
// where the backend cannot read it, from the router serving the allowlist
// there.
func allowlistRouteEnabled(ctx context.Context) error {
	w := getWorld(ctx)
	c, err := w.routerConf()
	if errors.Is(err, godog.ErrSkip) {
		a, err := w.httpRequest("router_request", http.MethodGet, allowlistRoute, nil, "", "", "")
		if err != nil {
			return err
		}
		if a.status != http.StatusOK {
			return skipf("the built-in allowlist route answers %d here", a.status)
		}
		return nil
	}
	if err != nil {
		return err
	}
	_, exact := c.exact[allowlistRoute]
	_, prefix := c.prefix[allowlistRoute+"/"]
	if !exact || !prefix {
		return skipf("the router does not render the built-in allowlist route here")
	}
	return nil
}

func discoveryEnabled(ctx context.Context) error {
	c, err := getWorld(ctx).routerConf()
	if err != nil {
		return err
	}
	if c.published("application/json", "") == "" {
		return skipf("the router does not publish discovery here")
	}
	return nil
}

func cdsCredentialSelected(ctx context.Context) error {
	mode, err := getWorld(ctx).be.call("router_tls_mode")
	if err != nil {
		return err
	}
	if mode != "cds" {
		return skipf("the router presents its %s credential here, not the CDS-issued one", mode)
	}
	return nil
}

// routerGet sends the router GET path with headers ("Name: value").
func (w *world) routerGet(path string, headers ...string) error {
	a, err := w.httpRequest("router_request", http.MethodGet, path, nil, "", "", "", headers...)
	if err != nil {
		return err
	}
	w.router.answer = a
	return nil
}

func readsThroughRoute(ctx context.Context) error {
	return getWorld(ctx).routerGet(allowlistRoute)
}

func requestsLookalike(ctx context.Context) error {
	return getWorld(ctx).routerGet(allowlistLookalike)
}

func (w *world) routerAnswer() (*answer, error) {
	if w.router.answer == nil {
		return nil, errors.New("no client has sent the router a request")
	}
	return w.router.answer, nil
}

// clientReceivesServed compares documents, not bytes: the CDS's own read
// may differ in whitespace from what the relay passed on.
func clientReceivesServed(ctx context.Context, quantifier string) error {
	w := getWorld(ctx)
	a, err := w.routerAnswer()
	if err != nil {
		return err
	}
	same := false
	if a.status == http.StatusOK {
		want, err := w.be.call("served_allowlist")
		if err != nil {
			return err
		}
		same = sameJSON(a.body, []byte(want))
	}
	switch {
	case quantifier == "receives" && !same:
		return fmt.Errorf("the router answered %d, not the served allowlist:\n%s", a.status, tail(string(a.body), 5))
	case quantifier == "does not receive" && same:
		return errors.New("the router answered with the served allowlist")
	}
	return nil
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func clientReceivesRelayFailure(ctx context.Context, quantifier string) error {
	a, err := getWorld(ctx).routerAnswer()
	if err != nil {
		return err
	}
	failure := a.status == http.StatusBadGateway && strings.TrimSpace(string(a.body)) == relayFailureBody
	switch {
	case quantifier == "receives" && !failure:
		return fmt.Errorf("the router answered %d %q, not the relay failure (502 %q)", a.status, tail(string(a.body), 3), relayFailureBody)
	case quantifier == "does not receive" && failure:
		return errors.New("the router answered with the relay failure")
	}
	return nil
}

func operatorSendsThroughRoute(ctx context.Context) error {
	w := getWorld(ctx)
	if w.api.pending == nil {
		return errors.New("the scenario has described no write to sign")
	}
	token, err := w.token("operator", *w.api.pending)
	if err != nil {
		return err
	}
	w.api.lastToken = token
	return w.sendVia("router_request", *w.api.pending, token)
}

func callerWritesThroughRoute(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	if w.api.caller != callerNone {
		return errors.New("the scenario has not said the caller holds no write token")
	}
	wr, err := w.putAnyArgv(name, image)
	if err != nil {
		return err
	}
	return w.sendVia("router_request", wr, "")
}

func relayCannotReachCDS(ctx context.Context) error {
	w := getWorld(ctx)
	w.onUndo(func() error {
		_, err := w.be.call("cds_relay_unblock")
		return err
	})
	_, err := w.be.call("cds_relay_block")
	return err
}

// servesDiscovery: P1's content type and Cache-Control, read off the
// response headers.
func servesDiscovery(ctx context.Context) error {
	w := getWorld(ctx)
	c, err := w.routerConf()
	if err != nil {
		return err
	}
	path := c.published("application/json", "")
	if path == "" {
		return errors.New("the router publishes no discovery document")
	}
	out, err := w.be.call("router_headers", path)
	if err != nil {
		return err
	}
	status, headers, _ := strings.Cut(out, "\n")
	if status != "200" {
		return fmt.Errorf("GET %s at the router answered %s", path, status)
	}
	h := http.Header{}
	for _, line := range strings.Split(headers, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return fmt.Errorf("the discovery document is served as %q, not application/json", ct)
	}
	if cc := h.Get("Cache-Control"); cc != "no-store" {
		return fmt.Errorf("the discovery document is served with Cache-Control %q, not no-store", cc)
	}
	return nil
}

func connectsToRouter(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("router_serving_cert")
	if err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(out))
	if block == nil {
		return fmt.Errorf("the router presented no certificate: %q", out)
	}
	w.router.serving = block.Bytes
	return nil
}

// presentsCDSCertificate compares the leaf on the wire with the first
// certificate the router publishes as its CDS-issued certificate (P1).
func presentsCDSCertificate(ctx context.Context) error {
	w := getWorld(ctx)
	if w.router.serving == nil {
		return errors.New("no client has connected to the router")
	}
	c, err := w.routerConf()
	if err != nil {
		return err
	}
	path := c.published("application/x-pem-file", "cert.pem")
	if path == "" {
		return errors.New("the router publishes no CDS-issued certificate")
	}
	a, err := w.httpRequest("router_request", http.MethodGet, path, nil, "", "", "")
	if err != nil {
		return err
	}
	if a.status != http.StatusOK {
		return fmt.Errorf("GET %s at the router answered %d", path, a.status)
	}
	block, _ := pem.Decode(a.body)
	if block == nil {
		return fmt.Errorf("%s holds no PEM certificate", path)
	}
	if !bytes.Equal(block.Bytes, w.router.serving) {
		return fmt.Errorf("the certificate on the wire is not the first certificate at %s", path)
	}
	return nil
}
