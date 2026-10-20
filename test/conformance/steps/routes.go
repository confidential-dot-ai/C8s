package steps

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cucumber/godog"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// The router polls the CDS every 30s by default; three polls and the
// first-apply backoff fit well inside this.
const routesApplyTimeout = 3 * time.Minute

// routesState is what the route manifest sentences keep: the anchor no
// backend's certificate chains to, whether the manifest stored before the
// scenario is saved for the undo, and the manifest the operator sent last.
type routesState struct {
	unrelatedCA string
	saved       bool
	sent        []byte
}

func registerRoutes(sc *godog.ScenarioContext) {
	sc.Step(`^the operator (writes|has written) a route manifest$`, operatorWritesManifest)
	sc.Step(`^that caller sends the CDS a route manifest$`, callerSendsManifest)
	sc.Step(`^the operator writes a route manifest with the revision of the stored one$`, operatorWritesSameRevision)
	sc.Step(`^the operator writes a route manifest naming (the route digest of the stored one|a route digest other than the stored one's) in If-Match$`, operatorWritesIfMatch)
	sc.Step(`^the operator writes a route manifest (carrying an unknown member|whose backend is neither a workload backend nor an address backend)$`, operatorWritesInvalidManifest)
	sc.Step(`^the CDS accepts the write$`, cdsAcceptsWrite)
	sc.Step(`^the CDS refuses the write as stale$`, cdsRefusesStale)
	sc.Step(`^the CDS refuses the write as conflicting$`, cdsRefusesConflicting)
	sc.Step(`^the CDS serves that route manifest with its write token$`, cdsServesManifest)
	sc.Step(`^the router has applied a route manifest routing path "([^"]*)" on host "([^"]*)"$`, routerApplied)
	sc.Step(`^the router has applied a route manifest routing path "([^"]*)" on host "([^"]*)" to the CDS under trust anchors that did not issue its certificate$`, routerAppliedUnrelatedCA)
	sc.Step(`^a client requests path "([^"]*)" on host "([^"]*)" through the router$`, clientRequestsOnHost)
	sc.Step(`^a client reads the allowlist through the built-in allowlist route on host "([^"]*)"$`, readsThroughRouteOnHost)
	sc.Step(`^the router answers that no route matches$`, func(ctx context.Context) error {
		return getWorld(ctx).routerAnswered(http.StatusNotFound, "no route")
	})
	sc.Step(`^the router answers that the backend is unavailable$`, func(ctx context.Context) error {
		return getWorld(ctx).routerAnswered(http.StatusBadGateway, "backend unavailable")
	})
}

// routeHost is the DNS name a logical host stands for, under the scenario's
// namespace so that no two scenarios route the same host.
func (w *world) routeHost(logical string) string {
	return logical + "." + w.namespace + ".c8s.test"
}

// storedManifest reads the CDS's signed manifest; found is false when it
// stores none.
func (w *world) storedManifest() (env routes.Envelope, found bool, err error) {
	a, err := w.cdsRequest(http.MethodGet, routes.Path, nil, "", "", "")
	if err != nil {
		return env, false, err
	}
	switch a.status {
	case http.StatusNotFound:
		return env, false, nil
	case http.StatusOK:
		if err := json.Unmarshal(a.body, &env); err != nil {
			return env, false, fmt.Errorf("GET %s: %w: %s", routes.Path, err, tail(string(a.body), 5))
		}
		return env, true, nil
	}
	return env, false, fmt.Errorf("GET %s answered %d: %s", routes.Path, a.status, tail(string(a.body), 5))
}

func manifestRevision(manifest []byte) (uint64, error) {
	var m struct {
		Revision uint64 `json:"revision"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return 0, fmt.Errorf("the stored route manifest: %w", err)
	}
	return m.Revision, nil
}

// revisions are the stored manifest's revision, 0 when none is stored, and
// the next one to write: past both it and the clock, so that a manifest
// written by an earlier run never outranks this one.
func (w *world) revisions() (stored, next uint64, err error) {
	env, found, err := w.storedManifest()
	if err != nil || !found {
		return 0, max(1, uint64(time.Now().Unix())), err
	}
	if stored, err = manifestRevision(env.Manifest); err != nil {
		return 0, 0, err
	}
	return stored, max(stored+1, uint64(time.Now().Unix())), nil
}

// manifest is a route manifest at revision routing hosts, valid since an
// hour ago so that a router clock behind the runner's still applies it.
func manifest(revision uint64, hosts map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{
		"schema":        routes.Schema,
		"revision":      revision,
		"notBefore":     time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"maxAgeSeconds": 86400,
		"hosts":         hosts,
	})
	return b
}

func prefixRoute(path string, backend map[string]any) map[string]any {
	return map[string]any{"routes": []any{map[string]any{"path": path, "match": "prefix", "backend": backend}}}
}

// unrelatedCA is a self-signed CA no backend's certificate chains to.
func (w *world) unrelatedCA() (string, error) {
	if w.routes.unrelatedCA != "" {
		return w.routes.unrelatedCA, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "c8s conformance unrelated CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	w.routes.unrelatedCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return w.routes.unrelatedCA, nil
}

// closedBackend is an address backend nothing listens at, so a request
// routed to it fails at once (B5).
func (w *world) closedBackend() (map[string]any, error) {
	ca, err := w.unrelatedCA()
	if err != nil {
		return nil, err
	}
	return map[string]any{"address": "127.0.0.1:1", "serverName": "closed.c8s.test", "ca": ca}, nil
}

// saveRoutes keeps the manifest stored before the scenario's first write and
// puts it back afterwards, under a revision past whatever the scenario
// stored; with none stored, an empty manifest takes its place, as the CDS
// has no removal.
func (w *world) saveRoutes() error {
	if w.routes.saved {
		return nil
	}
	before, found, err := w.storedManifest()
	if err != nil {
		return err
	}
	w.routes.saved = true
	w.undo = append(w.undo, func() error {
		_, next, err := w.revisions()
		if err != nil {
			return err
		}
		body := manifest(next, map[string]any{})
		if found {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(before.Manifest, &m); err != nil {
				return fmt.Errorf("the route manifest stored before the scenario: %w", err)
			}
			m["revision"] = json.RawMessage(strconv.FormatUint(next, 10))
			body, _ = json.Marshal(m)
		}
		a, err := w.putRoutes("operator", body, "")
		if err != nil {
			return err
		}
		if a.status != http.StatusNoContent {
			return fmt.Errorf("restoring the route manifest: the CDS answered %d: %s", a.status, tail(string(a.body), 5))
		}
		return nil
	})
	return nil
}

// putRoutes sends PUT /routes with a token from signer ("" for none) and
// ifMatch as If-Match when set, recording the answer as the last write's.
func (w *world) putRoutes(signer string, body []byte, ifMatch string) (*answer, error) {
	if err := w.saveRoutes(); err != nil {
		return nil, err
	}
	token := ""
	if signer != "" {
		var err error
		if token, err = w.token(signer, write{method: http.MethodPut, path: routes.Path, body: body}); err != nil {
			return nil, err
		}
	}
	var headers []string
	if ifMatch != "" {
		headers = append(headers, "If-Match: "+ifMatch)
	}
	a, err := w.httpRequest("cds_request", http.MethodPut, routes.Path, body, token, "", "", headers...)
	if err != nil {
		return nil, err
	}
	w.api.lastStatus, w.api.lastToken, w.routes.sent = a.status, token, body
	return a, nil
}

// writeRoutes is the operator's write of a manifest routing "/" on host
// "app" to a closed backend, at revision when non-zero, else the next one.
func (w *world) writeRoutes(revision uint64, ifMatch string) error {
	if revision == 0 {
		var err error
		if _, revision, err = w.revisions(); err != nil {
			return err
		}
	}
	backend, err := w.closedBackend()
	if err != nil {
		return err
	}
	_, err = w.putRoutes("operator", manifest(revision, map[string]any{w.routeHost("app"): prefixRoute("/", backend)}), ifMatch)
	return err
}

func operatorWritesManifest(ctx context.Context, tense string) error {
	w := getWorld(ctx)
	if err := w.writeRoutes(0, ""); err != nil {
		return err
	}
	if tense == "has written" {
		return cdsAcceptsWrite(ctx)
	}
	return nil
}

func callerSendsManifest(ctx context.Context) error {
	w := getWorld(ctx)
	signer := ""
	switch w.api.caller {
	case callerNone:
	case callerForeign:
		signer = "foreign"
	default:
		return errors.New("the scenario has not said what write token the caller holds")
	}
	_, next, err := w.revisions()
	if err != nil {
		return err
	}
	backend, err := w.closedBackend()
	if err != nil {
		return err
	}
	_, err = w.putRoutes(signer, manifest(next, map[string]any{w.routeHost("app"): prefixRoute("/", backend)}), "")
	return err
}

func operatorWritesSameRevision(ctx context.Context) error {
	w := getWorld(ctx)
	stored, _, err := w.revisions()
	if err != nil {
		return err
	}
	if stored == 0 {
		return errors.New("the CDS stores no route manifest")
	}
	return w.writeRoutes(stored, "")
}

func operatorWritesIfMatch(ctx context.Context, which string) error {
	w := getWorld(ctx)
	env, found, err := w.storedManifest()
	if err != nil {
		return err
	}
	if !found {
		return errors.New("the CDS stores no route manifest")
	}
	digest := routes.Digest(env.Manifest)
	if which != "the route digest of the stored one" {
		digest = sha256.Sum256(append(digest[:], 0))
	}
	return w.writeRoutes(0, hex.EncodeToString(digest[:]))
}

func operatorWritesInvalidManifest(ctx context.Context, fault string) error {
	w := getWorld(ctx)
	_, next, err := w.revisions()
	if err != nil {
		return err
	}
	var body []byte
	if fault == "carrying an unknown member" {
		backend, err := w.closedBackend()
		if err != nil {
			return err
		}
		var m map[string]any
		_ = json.Unmarshal(manifest(next, map[string]any{w.routeHost("app"): prefixRoute("/", backend)}), &m)
		m["comment"] = "not a manifest member"
		body, _ = json.Marshal(m)
	} else {
		body = manifest(next, map[string]any{w.routeHost("app"): prefixRoute("/", map[string]any{"address": "127.0.0.1:1"})})
	}
	_, err = w.putRoutes("operator", body, "")
	return err
}

func cdsAcceptsWrite(ctx context.Context) error {
	w := getWorld(ctx)
	if w.api.lastStatus == 0 {
		return errors.New("the scenario has sent the CDS no write")
	}
	if w.api.lastStatus != http.StatusNoContent {
		return fmt.Errorf("the CDS answered %d, not 204", w.api.lastStatus)
	}
	return nil
}

func cdsRefusesStale(ctx context.Context) error {
	return getWorld(ctx).refused(http.StatusConflict, "the revision is not greater than the stored one")
}

func cdsRefusesConflicting(ctx context.Context) error {
	return getWorld(ctx).refused(http.StatusPreconditionFailed, "If-Match differs from the stored route digest")
}

// cdsServesManifest compares bytes: the CDS stores both verbatim (C2).
func cdsServesManifest(ctx context.Context) error {
	w := getWorld(ctx)
	env, found, err := w.storedManifest()
	if err != nil {
		return err
	}
	switch {
	case !found:
		return errors.New("the CDS stores no route manifest")
	case !bytes.Equal(env.Manifest, w.routes.sent):
		return fmt.Errorf("the CDS serves a route manifest other than the one sent:\n%s", tail(string(env.Manifest), 5))
	case "Bearer "+env.Token != w.api.lastToken:
		return errors.New("the CDS serves a write token other than the one the manifest was sent with")
	}
	return nil
}

// applyRoutes writes a manifest routing hosts and waits for the router to
// route by it. Beside them it routes a probe host named for its revision to
// a closed backend: the probe's 502 is this revision applied, where an
// earlier manifest answers 404 and none 503.
func (w *world) applyRoutes(hosts map[string]any) error {
	_, next, err := w.revisions()
	if err != nil {
		return err
	}
	closed, err := w.closedBackend()
	if err != nil {
		return err
	}
	probe := w.routeHost("applied-" + strconv.FormatUint(next, 10))
	hosts[probe] = prefixRoute("/", closed)
	a, err := w.putRoutes("operator", manifest(next, hosts), "")
	if err != nil {
		return err
	}
	if a.status != http.StatusNoContent {
		return fmt.Errorf("the CDS answered the route manifest %d: %s", a.status, tail(string(a.body), 5))
	}
	last := 0
	applied, err := pollEvery(2*time.Second, routesApplyTimeout, func() (bool, error) {
		a, err := w.httpRequest("router_request", http.MethodGet, "/", nil, "", "", "", "Host: "+probe)
		if err != nil {
			return false, err
		}
		last = a.status
		return last == http.StatusBadGateway, nil
	})
	if err != nil || applied {
		return err
	}
	return fmt.Errorf("the router did not apply route manifest revision %d within %s: its probe host last answered %d", next, routesApplyTimeout, last)
}

func routerApplied(ctx context.Context, path, host string) error {
	w := getWorld(ctx)
	closed, err := w.closedBackend()
	if err != nil {
		return err
	}
	return w.applyRoutes(map[string]any{w.routeHost(host): prefixRoute(path, closed)})
}

// routerAppliedUnrelatedCA routes to the CDS's in-cluster address, which
// answers TLS under a certificate the unrelated CA did not issue (B3).
func routerAppliedUnrelatedCA(ctx context.Context, path, host string) error {
	w := getWorld(ctx)
	raw, err := w.be.call("cds_pod_url")
	if err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("the CDS URL %q: %w", raw, err)
	}
	if net.ParseIP(u.Hostname()) != nil {
		return skipf("the CDS URL %q names no DNS server name", raw)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	ca, err := w.unrelatedCA()
	if err != nil {
		return err
	}
	backend := map[string]any{"address": net.JoinHostPort(u.Hostname(), port), "serverName": u.Hostname(), "ca": ca}
	return w.applyRoutes(map[string]any{w.routeHost(host): prefixRoute(path, backend)})
}

func (w *world) routerGetOnHost(path, host string) error {
	a, err := w.httpRequest("router_request", http.MethodGet, path, nil, "", "", "", "Host: "+w.routeHost(host))
	if err != nil {
		return err
	}
	w.router.answer = a
	return nil
}

func clientRequestsOnHost(ctx context.Context, path, host string) error {
	return getWorld(ctx).routerGetOnHost(path, host)
}

func readsThroughRouteOnHost(ctx context.Context, host string) error {
	return getWorld(ctx).routerGetOnHost(allowlistRoute, host)
}

func (w *world) routerAnswered(status int, what string) error {
	a, err := w.routerAnswer()
	if err != nil {
		return err
	}
	if a.status != status {
		return fmt.Errorf("the router answered %d, not %d (%s):\n%s", a.status, status, what, tail(string(a.body), 5))
	}
	return nil
}
