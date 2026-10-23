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
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// The router polls the CDS every 30s by default; three polls and the
// first-apply backoff fit well inside this.
const routesApplyTimeout = 3 * time.Minute

// routesState is whether the manifest stored before the scenario is saved
// for the undo, the manifest the scenario sent last, and the hosts of the
// manifest it is describing, to apply.
type routesState struct {
	saved   bool
	sent    []byte
	pending map[string]any
}

// routesRead is the CDS's stored manifest as a step read it, and the
// revision to write next.
type routesRead struct {
	env    routes.Envelope
	found  bool
	stored uint64 // 0 when none is stored
	next   uint64
}

func registerRoutes(sc *godog.ScenarioContext) {
	sc.Step(`^the operator (writes|has written) a route manifest$`, operatorWritesManifest)
	sc.Step(`^that caller sends the CDS a route manifest$`, callerSendsManifest)
	sc.Step(`^the operator writes a route manifest with the revision of the stored one$`, operatorWritesSameRevision)
	sc.Step(`^the operator writes a route manifest naming (the route digest of the stored one|a route digest other than the stored one's) in If-Match$`, operatorWritesIfMatch)
	sc.Step(`^the operator writes a route manifest (carrying an unknown member|whose backend is neither a workload backend nor an address backend)$`, operatorWritesInvalidManifest)
	sc.Step(`^the CDS accepts the write$`, func(ctx context.Context) error {
		return getWorld(ctx).cdsAnswered(http.StatusNoContent, "stored")
	})
	sc.Step(`^the CDS refuses the write as stale$`, func(ctx context.Context) error {
		return getWorld(ctx).cdsAnswered(http.StatusConflict, "the revision is not greater than the stored one")
	})
	sc.Step(`^the CDS refuses the write as conflicting$`, func(ctx context.Context) error {
		return getWorld(ctx).cdsAnswered(http.StatusPreconditionFailed, "If-Match differs from the stored route digest")
	})
	sc.Step(`^the CDS serves that route manifest with its write token$`, cdsServesManifest)
	sc.Step(`^the router has applied a route manifest routing path "([^"]*)" on host "([^"]*)"$`, routerApplied)
	sc.Step(`^the router has applied a route manifest routing path "([^"]*)" on host "([^"]*)" to the CDS under trust anchors that did not issue its certificate$`, routerAppliedUnrelatedCA)
	sc.Step(`^a client requests path "([^"]*)" on host "([^"]*)" through the router$`, func(ctx context.Context, path, host string) error {
		w := getWorld(ctx)
		return w.routerGet(path, "Host: "+w.routeHost(host))
	})
	sc.Step(`^a client reads the allowlist through the built-in allowlist route on host "([^"]*)"$`, func(ctx context.Context, host string) error {
		w := getWorld(ctx)
		return w.routerGet(allowlistRoute, "Host: "+w.routeHost(host))
	})
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

// readRoutes reads the stored manifest. The next revision is past both it
// and the clock, so that a manifest an earlier run left never outranks it.
// The scenario's first read is the manifest its undo writes back: under a
// revision past whatever the scenario stored, or as an empty manifest when
// none was stored, since the CDS has no removal.
func (w *world) readRoutes() (r routesRead, err error) {
	a, err := w.cdsRequest(http.MethodGet, routes.Path, nil, "", "", "")
	if err != nil {
		return r, err
	}
	switch a.status {
	case http.StatusNotFound:
	case http.StatusOK:
		if err := json.Unmarshal(a.body, &r.env); err != nil {
			return r, fmt.Errorf("GET %s: %w: %s", routes.Path, err, tail(string(a.body), 5))
		}
		var m struct {
			Revision uint64 `json:"revision"`
		}
		if err := json.Unmarshal(r.env.Manifest, &m); err != nil {
			return r, fmt.Errorf("the stored route manifest: %w", err)
		}
		r.found, r.stored = true, m.Revision
	default:
		return r, fmt.Errorf("GET %s answered %d: %s", routes.Path, a.status, tail(string(a.body), 5))
	}
	r.next = max(r.stored+1, uint64(time.Now().Unix()))
	if !w.routes.saved {
		w.routes.saved = true
		before := r
		w.onUndo(func() error { return w.restoreRoutes(before) })
	}
	return r, nil
}

func (w *world) restoreRoutes(before routesRead) error {
	now, err := w.readRoutes()
	if err != nil {
		return err
	}
	body := mustJSON(manifest(now.next, map[string]any{}))
	if before.found {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(before.env.Manifest, &m); err != nil {
			return fmt.Errorf("the route manifest stored before the scenario: %w", err)
		}
		m["revision"] = json.RawMessage(strconv.FormatUint(now.next, 10))
		body = mustJSON(m)
	}
	if err := w.operatorWrite(w.routesWrite(body, "")); err != nil {
		return err
	}
	return w.cdsAnswered(http.StatusNoContent, "restoring the route manifest")
}

// manifest is a route manifest at revision routing hosts, valid since an
// hour ago so that a router clock behind the runner's still applies it.
func manifest(revision uint64, hosts map[string]any) map[string]any {
	return map[string]any{
		"schema":        routes.Schema,
		"revision":      revision,
		"notBefore":     time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"maxAgeSeconds": 86400,
		"hosts":         hosts,
	}
}

// appManifest routes "/" on host "app" to backend.
func (w *world) appManifest(revision uint64, backend map[string]any) map[string]any {
	return manifest(revision, map[string]any{w.routeHost("app"): prefixRoute("/", backend)})
}

func prefixRoute(path string, backend map[string]any) map[string]any {
	return map[string]any{"routes": []any{map[string]any{"path": path, "match": "prefix", "backend": backend}}}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// unrelatedCA is a self-signed CA no backend's certificate chains to.
var unrelatedCA = sync.OnceValue(func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
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
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
})

// closedBackend is an address backend nothing listens at, so a request
// routed to it fails at once (B5).
func closedBackend() map[string]any {
	return map[string]any{"address": "127.0.0.1:1", "serverName": "closed.c8s.test", "ca": unrelatedCA()}
}

// closedWorkload is the same address as a workload backend, for a route a
// scenario only has to see applied.
func closedWorkload() map[string]any {
	return map[string]any{"address": "127.0.0.1:1", "workload": "conformance-closed"}
}

// routesWrite is PUT /routes of body, with ifMatch as If-Match when set; it
// is the manifest the scenario sent last.
func (w *world) routesWrite(body []byte, ifMatch string) write {
	w.routes.sent = body
	wr := write{method: http.MethodPut, path: routes.Path, body: body}
	if ifMatch != "" {
		wr.headers = []string{"If-Match: " + ifMatch}
	}
	return wr
}

func operatorWritesManifest(ctx context.Context, tense string) error {
	w := getWorld(ctx)
	r, err := w.readRoutes()
	if err != nil {
		return err
	}
	if err := w.operatorWrite(w.routesWrite(mustJSON(w.appManifest(r.next, closedBackend())), "")); err != nil {
		return err
	}
	if tense == "has written" {
		return w.cdsAnswered(http.StatusNoContent, "stored")
	}
	return nil
}

func callerSendsManifest(ctx context.Context) error {
	w := getWorld(ctx)
	r, err := w.readRoutes()
	if err != nil {
		return err
	}
	return w.sendAsCaller(w.routesWrite(mustJSON(w.appManifest(r.next, closedBackend())), ""))
}

func operatorWritesSameRevision(ctx context.Context) error {
	w := getWorld(ctx)
	r, err := w.readRoutes()
	if err != nil {
		return err
	}
	if !r.found {
		return errors.New("the CDS stores no route manifest")
	}
	return w.operatorWrite(w.routesWrite(mustJSON(w.appManifest(r.stored, closedBackend())), ""))
}

func operatorWritesIfMatch(ctx context.Context, which string) error {
	w := getWorld(ctx)
	r, err := w.readRoutes()
	if err != nil {
		return err
	}
	if !r.found {
		return errors.New("the CDS stores no route manifest")
	}
	digest := routes.Digest(r.env.Manifest)
	if which != "the route digest of the stored one" {
		digest = sha256.Sum256(append(digest[:], 0))
	}
	return w.operatorWrite(w.routesWrite(mustJSON(w.appManifest(r.next, closedBackend())), hex.EncodeToString(digest[:])))
}

func operatorWritesInvalidManifest(ctx context.Context, fault string) error {
	w := getWorld(ctx)
	r, err := w.readRoutes()
	if err != nil {
		return err
	}
	m := w.appManifest(r.next, map[string]any{"address": "127.0.0.1:1"})
	if fault == "carrying an unknown member" {
		m = w.appManifest(r.next, closedBackend())
		m["comment"] = "not a manifest member"
	}
	return w.operatorWrite(w.routesWrite(mustJSON(m), ""))
}

// cdsServesManifest compares bytes: the CDS stores both verbatim (C2).
func cdsServesManifest(ctx context.Context) error {
	w := getWorld(ctx)
	r, err := w.readRoutes()
	if err != nil {
		return err
	}
	switch {
	case !r.found:
		return errors.New("the CDS stores no route manifest")
	case !bytes.Equal(r.env.Manifest, w.routes.sent):
		return fmt.Errorf("the CDS serves a route manifest other than the one sent:\n%s", tail(string(r.env.Manifest), 5))
	case "Bearer "+r.env.Token != w.api.lastToken:
		return errors.New("the CDS serves a write token other than the one the manifest was sent with")
	}
	return nil
}

// applyRoutes writes a manifest routing hosts and waits for the router to
// route by it. Beside them it routes a probe host named for its revision to
// a closed backend: the probe's failed dial (502, or 504 where the router's
// rules drop it) is this revision applied, where an earlier manifest answers
// 404 and none 503.
func (w *world) applyRoutes(hosts map[string]any) error {
	r, err := w.readRoutes()
	if err != nil {
		return err
	}
	probe := w.routeHost("applied-" + strconv.FormatUint(r.next, 10))
	hosts[probe] = prefixRoute("/", closedWorkload())
	if err := w.operatorWrite(w.routesWrite(mustJSON(manifest(r.next, hosts)), "")); err != nil {
		return err
	}
	if err := w.cdsAnswered(http.StatusNoContent, "the route manifest to apply"); err != nil {
		return err
	}
	// The router refetches every 30s by default; a faster poll only spends
	// backend calls.
	last := 0
	applied, err := pollEvery(5*time.Second, routesApplyTimeout, func() (bool, error) {
		a, err := w.httpRequest("router_request", http.MethodGet, "/", nil, "", "", "", "Host: "+probe)
		if err != nil {
			return false, err
		}
		last = a.status
		return last == http.StatusBadGateway || last == http.StatusGatewayTimeout, nil
	})
	if err != nil || applied {
		return err
	}
	return fmt.Errorf("the router did not apply route manifest revision %d within %s: its probe host last answered %d", r.next, routesApplyTimeout, last)
}

func routerApplied(ctx context.Context, path, host string) error {
	w := getWorld(ctx)
	return w.applyRoutes(map[string]any{w.routeHost(host): prefixRoute(path, closedWorkload())})
}

// routerAppliedUnrelatedCA routes to the CDS as an address backend whose ca
// is a CA that issued no certificate, so the dial's verification fails (B3).
func routerAppliedUnrelatedCA(ctx context.Context, path, host string) error {
	w := getWorld(ctx)
	url, err := w.be.call("cds_pod_url")
	if err != nil {
		return err
	}
	backend := map[string]any{
		"address":    strings.TrimPrefix(url, "https://"),
		"serverName": "cds.c8s.test",
		"ca":         unrelatedCA(),
	}
	return w.applyRoutes(map[string]any{w.routeHost(host): prefixRoute(path, backend)})
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
