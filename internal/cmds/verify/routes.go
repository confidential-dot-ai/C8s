package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// routeCheck is how a run checks the route digest an attested transcript
// binds (routes spec §13). Exactly one of pins and keys is set.
type routeCheck struct {
	// pins are the --route-digest values (V1); the transcript must bind one.
	pins [][]byte
	// keys are the --operator-keys the published manifest must verify under
	// (V2).
	keys []*ecdsa.PublicKey
	// floor is the --routes-floor value W4 checks the published manifest
	// against, nil when unset.
	floor *routeFloor
}

// routeFloor is the revision and route digest a client last accepted.
type routeFloor struct {
	revision uint64
	digest   [sha256.Size]byte
}

// boundRoute is the route digest a transcript is recomputed with, and the
// check that supplied it.
type boundRoute struct {
	digest []byte
	// revision is the published manifest's revision (V2 only).
	revision uint64
	note     string
	// alternatives are the other --route-digest values (V1).
	alternatives [][]byte
	// refetch binds a fresh publication fetch (V2), nil after the retry.
	refetch func() (*boundRoute, error)
}

// maxPublicationBytes bounds a /.well-known/c8s/routes response, like the
// CDS client's bound on GET /routes.
const maxPublicationBytes = 4 << 20

// attestedMode reports whether the run verifies an attested transcript, the
// only evidence that binds a route digest.
func attestedMode(cfg config) bool {
	mode := resolveMode(cfg)
	return mode == "attest-pq" || mode == "attest-lb"
}

// parseRouteCheck validates the route flags and reads --operator-keys once.
// It returns nil when the run checks no route digest. Outside the attested
// modes --operator-keys keeps its kind=cds meaning.
func parseRouteCheck(cfg config) (*routeCheck, error) {
	// The override replaces the transcript, and with it the route digest the
	// transcript binds.
	if cfg.expectedRDHex != "" && attestedMode(cfg) {
		return nil, errors.New("--expected-report-data does not apply to --mode " + resolveMode(cfg) + ": it replaces the transcript that binds the route digest")
	}
	if cfg.fromFile != "" && cfg.expectedRDHex != "" {
		if len(cfg.routeDigests) > 0 || cfg.routesFloor != "" {
			return nil, errors.New("route checks do not apply with --expected-report-data: the override replaces the transcript that binds the route digest")
		}
		return nil, nil
	}
	if !attestedMode(cfg) {
		switch {
		case cfg.routesFloor != "":
			return nil, errors.New("--routes-floor applies only to --mode attest-pq and attest-lb")
		case len(cfg.routeDigests) == 0:
			return nil, nil
		case cfg.fromFile == "":
			// A saved attest-pq bundle verifies through --from-file in any mode.
			return nil, errors.New("--route-digest applies only to --mode attest-pq, --mode attest-lb and saved attest-pq bundles")
		}
		return parseRoutePins(cfg.routeDigests)
	}
	switch {
	case len(cfg.routeDigests) > 0 && cfg.operatorKeys != "":
		return nil, errors.New("pass one of --route-digest and --operator-keys: each is a complete route digest check")
	case len(cfg.routeDigests) > 0:
		if cfg.routesFloor != "" {
			return nil, errors.New("--routes-floor applies only with --operator-keys: --route-digest already pins the manifests")
		}
		return parseRoutePins(cfg.routeDigests)
	case cfg.operatorKeys != "":
		if cfg.kind == "cds" {
			return nil, errors.New("--operator-keys in --mode " + resolveMode(cfg) + " checks the published route manifest, not the /operator-keys set --kind cds checks: drop --kind cds or the mode")
		}
		if cfg.fromFile != "" {
			return nil, errors.New("--operator-keys checks the manifest the live router publishes; to verify a saved receipt, pass --route-digest")
		}
		return parseRouteKeys(cfg)
	case cfg.fromFile != "":
		// --operator-keys needs a live router, so a saved file has one option.
		return nil, errors.New("--mode " + resolveMode(cfg) + " evidence binds the route digest: pass --route-digest HEX (from `c8s routes show`)")
	}
	return nil, errors.New("--mode " + resolveMode(cfg) + " evidence binds the route digest: pass --route-digest HEX (from `c8s routes show`) or --operator-keys FILE to verify the manifest the router publishes")
}

func parseRoutePins(values []string) (*routeCheck, error) {
	rc := &routeCheck{}
	for _, s := range values {
		pin, err := parseRouteDigest(s)
		if err != nil {
			return nil, fmt.Errorf("--route-digest %q: %w", s, err)
		}
		rc.pins = append(rc.pins, pin)
	}
	return rc, nil
}

func parseRouteKeys(cfg config) (*routeCheck, error) {
	pemBytes, err := os.ReadFile(cfg.operatorKeys)
	if err != nil {
		return nil, fmt.Errorf("read --operator-keys: %w", err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("--operator-keys: %w", err)
	}
	rc := &routeCheck{keys: keys}
	if cfg.routesFloor != "" {
		if rc.floor, err = parseRouteFloor(cfg.routesFloor); err != nil {
			return nil, fmt.Errorf("--routes-floor: %w", err)
		}
	}
	return rc, nil
}

// parseRouteFloor decodes <revision>:<hex digest>.
func parseRouteFloor(s string) (*routeFloor, error) {
	rev, digest, ok := strings.Cut(s, ":")
	if !ok {
		return nil, errors.New("want <revision>:<route digest hex>")
	}
	revision, err := strconv.ParseUint(rev, 10, 64)
	if err != nil || revision == 0 {
		return nil, fmt.Errorf("revision %q is not a positive integer", rev)
	}
	d, err := parseRouteDigest(digest)
	if err != nil {
		return nil, err
	}
	return &routeFloor{revision: revision, digest: [sha256.Size]byte(d)}, nil
}

// parseRouteDigest decodes a route digest in the form `c8s routes show` and
// `c8s routes digest` print: 64 hex characters.
func parseRouteDigest(s string) ([]byte, error) {
	d, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(d) != overenc.RouteDigestBytes {
		return nil, fmt.Errorf("%d bytes, want %d (SHA-256 of the manifest bytes)", len(d), overenc.RouteDigestBytes)
	}
	return d, nil
}

// bind returns the route digests a transcript may be recomputed with: the
// pins (V1), or the digest of the manifest published at base once it
// verifies under the operator keys and passes the floor (V2). A nil check
// binds nothing, and the transcript parsers refuse a nil route. base is ""
// for a saved file, which only a pin can check.
func (rc *routeCheck) bind(ctx context.Context, base, serverName string, timeout time.Duration) (*boundRoute, error) {
	switch {
	case rc == nil:
		return nil, nil
	case rc.pins != nil:
		return &boundRoute{digest: rc.pins[0], alternatives: rc.pins[1:], note: "pinned: matches --route-digest"}, nil
	case base == "":
		return nil, errors.New("--operator-keys needs a live target to fetch " + routes.PublicationPath)
	}
	route, err := rc.published(ctx, base, serverName, timeout)
	if err != nil {
		return nil, err
	}
	// Any revision passing the floor may answer: behind a load balancer the
	// re-fetch can reach a replica on an older manifest than the first did.
	route.refetch = func() (*boundRoute, error) { return rc.published(ctx, base, serverName, timeout) }
	return route, nil
}

// published fetches the manifest published at base and checks it under the
// operator keys and the floor.
func (rc *routeCheck) published(ctx context.Context, base, serverName string, timeout time.Duration) (*boundRoute, error) {
	env, err := fetchPublishedRoutes(ctx, base, serverName, timeout)
	if err != nil {
		return nil, err
	}
	signed, err := routes.VerifySigned(env, rc.keys, nil)
	if err != nil {
		return nil, &securityError{err: fmt.Errorf("the published route manifest does not verify under --operator-keys: %w", err)}
	}
	note := fmt.Sprintf("operator-signed: the manifest published at %s verifies under --operator-keys", routes.PublicationPath)
	if rc.floor != nil {
		if err := signed.Supersedes(rc.floor.revision, rc.floor.digest); err != nil {
			return nil, &securityError{err: fmt.Errorf("the published route manifest fails --routes-floor: %w", err)}
		}
		note += fmt.Sprintf(" and is not older than --routes-floor revision %d", rc.floor.revision)
	} else {
		note += "; any revision an operator signed is accepted (pass --routes-floor to refuse a rollback)"
	}
	digest := signed.Digest()
	return &boundRoute{digest: digest[:], revision: signed.Manifest().Revision, note: note}, nil
}

// fetchPublishedRoutes GETs the route publication. The fetch needs no
// transport trust: the operator signature authenticates the manifest, and
// the transcript binds its digest to the attested session.
func fetchPublishedRoutes(ctx context.Context, base, serverName string, timeout time.Duration) (routes.Envelope, error) {
	u, err := url.Parse(base)
	if err != nil {
		return routes.Envelope{}, fmt.Errorf("parse url %q: %w", base, err)
	}
	u.Path = routes.PublicationPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return routes.Envelope{}, err
	}
	resp, err := insecureClient(serverName, timeout).Do(req)
	if err != nil {
		return routes.Envelope{}, &connectError{err: fmt.Errorf("GET %s: %w", u, err)}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return routes.Envelope{}, &connectError{err: fmt.Errorf("GET %s returned 404: the router publishes no route manifest (publication off, or none applied yet); pass --route-digest instead", u)}
	default:
		return routes.Envelope{}, &connectError{err: fmt.Errorf("GET %s returned %d", u, resp.StatusCode)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPublicationBytes+1))
	if err != nil {
		return routes.Envelope{}, &connectError{err: fmt.Errorf("read %s: %w", u, err)}
	}
	if len(data) > maxPublicationBytes {
		return routes.Envelope{}, fmt.Errorf("%s response exceeds %d bytes", u, maxPublicationBytes)
	}
	var env routes.Envelope
	// A garbled envelope is unusable evidence, like a garbled bundle; only
	// the signature and floor checks are verdicts.
	if err := json.Unmarshal(data, &env); err != nil {
		return routes.Envelope{}, fmt.Errorf("parse %s: %w", u, err)
	}
	return env, nil
}

// errRouteRequired reports an attestation response verified with no route
// check: a usage error, since only a flag can supply the digest.
var errRouteRequired = errors.New("this attestation response binds a route digest: pass --route-digest HEX (from `c8s routes show`)")

// errRouteNotBound reports --route-digest on saved evidence that binds no
// route digest, a usage error like errRouteRequired.
var errRouteNotBound = errors.New("--route-digest does not apply to a certificate: only attest-pq and attest-lb evidence binds a route digest")

// resolveRoute picks the route the transcript is recomputed with, using the
// bundle's informational route_digest. It only ever rejects: a match proves
// nothing, since report_data is what binds the digest.
func resolveRoute(served string, route *boundRoute) (*boundRoute, error) {
	if route == nil {
		return nil, errRouteRequired
	}
	if served == "" {
		if len(route.alternatives) > 0 {
			return nil, errors.New("the responder reports no route_digest to choose among the --route-digest values: pass only the digest it binds")
		}
		return route, nil
	}
	if strings.EqualFold(served, hex.EncodeToString(route.digest)) {
		return route, nil
	}
	for _, d := range route.alternatives {
		if strings.EqualFold(served, hex.EncodeToString(d)) {
			return &boundRoute{digest: d, note: route.note}, nil
		}
	}
	if route.refetch == nil {
		if route.revision == 0 {
			return nil, &securityError{err: fmt.Errorf("route digest mismatch: the responder reports %s, which no --route-digest value names", served)}
		}
		return nil, &securityError{err: fmt.Errorf("route digest mismatch: the responder reports %s, the manifest published at %s has %x; the router may have applied another manifest after the publication fetch, and one re-fetch already ran", served, routes.PublicationPath, route.digest)}
	}
	// The router may have applied a newer manifest between the publication
	// fetch and the handshake (spec V2).
	fresh, err := route.refetch()
	if err != nil {
		return nil, err
	}
	return resolveRoute(served, fresh)
}
