//go:build !c8s_node

package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	cliroutes "github.com/confidential-dot-ai/c8s/internal/cmds/routes"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/routesclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var (
	installOperatorKey  string
	installRoutesOut    string
	installRoutesMaxAge time.Duration
	// installRoutesRevision is --routes-revision; zero lets NextRevision pick.
	installRoutesRevision uint64
	// installRoutesOutSet and installRoutesMaxAgeSet report whether the flag
	// was given. --routes-out may then replace an existing file.
	installRoutesOutSet, installRoutesMaxAgeSet bool
)

const flagOperatorKey = "operator-key"

// routeHosts are the manifest hosts --upstream routes: the router.san
// entries, lower-cased, that are valid manifest hosts (route policy D5).
// skipped lists the others, such as wildcards and IPs.
//
// The default repeats the chart's own: the router serves the namespace the
// enforcer compiles in, wherever the release is installed, and a manifest
// naming another host is one the router refuses.
func routeHosts(values map[string]any, release string) (hosts, skipped []string) {
	sans := stringsAtPath(values, "router.san")
	if len(sans) == 0 {
		sans = []string{fmt.Sprintf("%s.%s.svc", helmName(release+"-router"), workloadclaims.RouterNamespace)}
	}
	for _, san := range sans {
		host := strings.ToLower(strings.TrimSuffix(san, "."))
		if pkgroutes.CheckHost(host) != nil {
			skipped = append(skipped, san)
			continue
		}
		if !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
	}
	return hosts, skipped
}

// helmName mirrors the chart's `printf ... | trunc 63 | trimSuffix "-"`.
func helmName(name string) string {
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimSuffix(name, "-")
}

// upstreamRoutes is what --upstream writes: on every host, a prefix "/" route
// to the adopted workload's headless Service, verified as the allowlist entry
// named after its cw id (route policy B1).
type upstreamRoutes struct {
	hosts    []string
	address  string
	workload string
}

// apply adds the routes to m, replacing any prefix "/" route of those hosts,
// and makes m the next revision.
func (u upstreamRoutes) apply(m *pkgroutes.Manifest, now time.Time) ([]byte, error) {
	if m.Hosts == nil {
		m.Hosts = map[string]pkgroutes.Host{}
	}
	for _, host := range u.hosts {
		cliroutes.AddRoute(m, host, pkgroutes.Route{
			Path:    "/",
			Match:   pkgroutes.MatchPrefix,
			Backend: pkgroutes.Backend{Address: u.address, Workload: u.workload},
		})
	}
	revision, err := cliroutes.NextRevision(m.Revision, installRoutesRevision, now)
	if err != nil {
		return nil, revisionError{fmt.Errorf("--routes-revision: %w", err)}
	}
	m.Revision = revision
	// A staged notBefore stays staged (D3).
	if start := now.UTC().Truncate(time.Second); start.After(m.NotBefore) {
		m.NotBefore = start
	}
	manifest, err := cliroutes.Encode(m)
	if err != nil {
		return nil, err
	}
	if _, err := pkgroutes.Parse(manifest); err != nil {
		return nil, fmt.Errorf("route manifest for --%s: %w", flagUpstream, err)
	}
	return manifest, nil
}

// installCDSURL is the CDS this release names, as its clients dial it: the
// <host>:<port> it serves on outside the cluster, which the install reaches
// directly.
func installCDSURL(values map[string]any) (string, error) {
	raw, _ := valueAtPath(values, "cds.address")
	address, ok := raw.(string)
	if !ok || address == "" {
		return "", fmt.Errorf("cds.address names no CDS, so the route manifest has nowhere to go")
	}
	endpoint, err := cmdsutil.ParseCDSAddress(address)
	if err != nil {
		return "", fmt.Errorf("cds.address %w", err)
	}
	return endpoint.URL(), nil
}

// installOperatorKeyPath is --operator-key, else the environment variable
// `c8s routes` reads.
func installOperatorKeyPath() string {
	if installOperatorKey != "" {
		return installOperatorKey
	}
	return os.Getenv(cdsconn.EnvOperatorKey)
}

// installCDSConn is how install reaches CDS: under the pin document the chart
// holds it to.
func installCDSConn(url string) *cdsconn.Options {
	pin := ""
	if installCDS != nil {
		pin = installCDS.path
	}
	return &cdsconn.Options{
		URL:                url,
		MeasurementsConfig: pin,
		OperatorKey:        installOperatorKeyPath(),
		Timeout:            15 * time.Second,
	}
}

// maxManifestAge is the largest maxAgeSeconds a manifest may carry (D4).
const maxManifestAge = (1<<31 - 1) * time.Second

// preflightUpstreamRoutes fails before the cluster is touched when the
// --upstream manifest could not be built or stored: a route flag without
// --upstream, a --routes-max-age out of D4's range, or an --operator-key that
// is unreadable, faces an unpinned CDS endpoint, or is not among the operator
// keys this install gives CDS.
func preflightUpstreamRoutes() error {
	if installUpstream == "" {
		for _, f := range []struct {
			name string
			set  bool
		}{{flagOperatorKey, installOperatorKey != ""}, {"routes-out", installRoutesOutSet}, {"routes-max-age", installRoutesMaxAgeSet}, {"routes-revision", installRoutesRevision != 0}} {
			if f.set {
				return fmt.Errorf("--%s applies to the route manifest --%s writes; pass --%s <cw-id>", f.name, flagUpstream, flagUpstream)
			}
		}
		return nil // only the environment names a key; nothing to sign
	}
	if installRoutesMaxAge < time.Second || installRoutesMaxAge > maxManifestAge {
		return fmt.Errorf("--routes-max-age must be between 1s and %v, got %v", maxManifestAge, installRoutesMaxAge)
	}
	if installOperatorKeyPath() == "" {
		return nil
	}
	o := installCDSConn("https://cds")
	signer, err := o.Signer()
	if err != nil {
		return err
	}
	keys, source, err := installedOperatorKeys()
	if err != nil {
		return err
	}
	token, err := signer.Authorization(http.MethodPut, pkgroutes.Path, nil)
	if err != nil {
		return err
	}
	if err := operatorauth.VerifyStored(keys, strings.TrimPrefix(token, "Bearer "), http.MethodPut, pkgroutes.Path, nil); err != nil {
		return fmt.Errorf("--%s is not among the operator keys in %s, so CDS would refuse the route manifest it signs", flagOperatorKey, source)
	}
	return nil
}

// installedOperatorKeys are the operator public keys this install gives CDS:
// --operator-keys, else cds.operatorKeys from the last -f file that sets it,
// as Helm merges them. An empty value there leaves CDS without keys.
func installedOperatorKeys() (keys []*ecdsa.PublicKey, source string, err error) {
	var pemBytes []byte
	if installOperatorKeys != "" {
		if pemBytes, err = os.ReadFile(installOperatorKeys); err != nil {
			return nil, "", fmt.Errorf("read --operator-keys: %w", err)
		}
		source = "--operator-keys"
	} else {
		for _, f := range installValues {
			tree, err := decodeValuesFile(f)
			if err != nil {
				return nil, "", err
			}
			if v, ok := valueAtPath(tree, "cds.operatorKeys"); ok {
				pem, _ := v.(string)
				pemBytes, source = []byte(pem), "cds.operatorKeys in "+f
			}
		}
	}
	if len(bytes.TrimSpace(pemBytes)) == 0 {
		return nil, "", fmt.Errorf("--%s needs CDS to trust its public key: pass --operator-keys", flagOperatorKey)
	}
	keys, err = operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", source, err)
	}
	return keys, source, nil
}

// deliverUpstreamRoutes stores the --upstream routes on CDS when an operator
// key is available. Without one, or when storing fails, it writes them to
// --routes-out and prints how to store them. The router answers 503 until a
// manifest is stored.
func deliverUpstreamRoutes(ctx context.Context, w io.Writer, u upstreamRoutes, cdsURL string, entries map[string]adoptedEntry) error {
	if installOperatorKeyPath() == "" {
		return writeUpstreamRoutes(w, u, cdsURL, entries, nil, nil)
	}
	manifest, err := storeUpstreamRoutes(ctx, w, u, cdsURL, entries)
	if err == nil {
		return nil
	}
	if werr := writeUpstreamRoutes(w, u, cdsURL, entries, manifest, err); werr != nil {
		return fmt.Errorf("store the route manifest: %w; %w", err, werr)
	}
	return fmt.Errorf("store the route manifest: %w; after fixing the cause, add the route as printed above, or re-run install", err)
}

// storedManifestError is a failure to use the route manifest CDS stores, so
// writing a new one in its place would drop its routes.
type storedManifestError struct{ error }

func (e storedManifestError) Unwrap() error { return e.error }

// revisionError is a --routes-revision not above the stored revision.
type revisionError struct{ error }

func (e revisionError) Unwrap() error { return e.error }

// storeUpstreamRoutes dials the CDS, checks that it names the adopted pod
// after its entry, and stores the routes. It returns the manifest it built,
// if it got that far.
func storeUpstreamRoutes(ctx context.Context, w io.Writer, u upstreamRoutes, url string, entries map[string]adoptedEntry) ([]byte, error) {
	o := installCDSConn(url)
	hc, err := o.HTTPClient(ctx)
	if err != nil {
		return nil, err
	}
	if e, ok := entries[u.workload]; ok {
		al, _, err := allowlistclient.NewClientWithHTTP(url, hc).List(ctx)
		if err != nil {
			return nil, fmt.Errorf("read the served allowlist: %w", err)
		}
		if err := checkServedEntry(al, u.workload, e.pod); err != nil {
			return nil, err
		}
	}
	c, err := routesclient.New(url, hc)
	if err != nil {
		return nil, err
	}
	signer, err := o.Signer()
	if err != nil {
		return nil, err
	}
	return putUpstreamRoutes(ctx, w, c, signer, u)
}

// putUpstreamRoutes adds the routes to the manifest CDS stores and stores the
// next revision. It returns the manifest it built, stored or not.
func putUpstreamRoutes(ctx context.Context, w io.Writer, c routesclient.Client, signer operatorauth.Authorizer, u upstreamRoutes) ([]byte, error) {
	m, ifMatch, err := storedManifest(ctx, c)
	if err != nil {
		return nil, err
	}
	onStored := func(err error) error {
		if ifMatch == "" {
			return err
		}
		return storedManifestError{err}
	}
	now := time.Now()
	manifest, err := u.apply(m, now)
	if err != nil {
		return nil, onStored(err)
	}
	if err := c.Put(ctx, manifest, signer, ifMatch); err != nil {
		return manifest, onStored(err)
	}
	applies := ""
	if m.NotBefore.After(now) {
		applies = ", applies at " + m.NotBefore.Format(time.RFC3339)
	}
	fmt.Fprintf(w, "+ stored route manifest revision %d on CDS (digest %s): %s%s\n", m.Revision, manifestDigest(manifest), u.describe(), applies)
	return manifest, nil
}

// pinsProcess reports whether some container of w constrains its command,
// args or env.
func pinsProcess(w pkgallowlist.Workload) bool {
	return slices.ContainsFunc(append(slices.Clone(w.Containers), w.InitContainers...), func(c pkgallowlist.Container) bool {
		return c.Command.Policy != pkgallowlist.PolicyAny || c.Args.Policy != pkgallowlist.PolicyAny ||
			(c.Env.Policy != pkgallowlist.PolicyAny && c.Env.Policy != "")
	})
}

// anyProcess returns w admitting any command, args and env, its digests and
// mounts unchanged.
func anyProcess(w pkgallowlist.Workload) pkgallowlist.Workload {
	relax := func(cs []pkgallowlist.Container) []pkgallowlist.Container {
		out := slices.Clone(cs)
		for i := range out {
			out[i].Command = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
			out[i].Args = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
			out[i].Env = pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyAny}
		}
		return out
	}
	w.Containers, w.InitContainers = relax(w.Containers), relax(w.InitContainers)
	return w
}

// checkServedEntry fails unless the served allowlist names the adopted pod
// after its own entry: CDS stamps that name on the pod's certificate only
// when exactly that entry describes its containers, and the router refuses
// the backend otherwise. A persistent CDS keeps a stored entry by name over the
// seed, so an entry from an earlier install, or a leftover per-digest one, can
// shadow the one this install wrote.
func checkServedEntry(al *pkgallowlist.Allowlist, name string, pod []pkgallowlist.RunningContainer) error {
	// The pod's own entry must admit any argv and env, as install writes it:
	// describers treats every entry as if it did.
	own, ok := al.Workloads[name]
	if ok && pinsProcess(own) {
		return fmt.Errorf("CDS serves an allowlist entry %s that pins its containers' command, args or env, which install cannot check against the pod; make sure the pod satisfies them, or replace the entry with `c8s allowlist apply`, then re-run install", name)
	}
	names := describers(al.Workloads, pod)
	switch {
	case len(names) > 1:
		return fmt.Errorf("CDS serves allowlist entries %s that all describe the %s pod, so it stamps none on its certificate and the router refuses the backend; delete the stale ones with `c8s allowlist delete`, then re-run install", strings.Join(names, ", "), name)
	case len(names) == 0 && ok:
		return fmt.Errorf("CDS serves an allowlist entry %s that does not describe the pod install adopts (kept from an earlier install: a persistent CDS keeps stored entries over the seed); update it with `c8s allowlist apply`, then re-run install", name)
	case len(names) == 0:
		return fmt.Errorf("CDS serves no allowlist entry describing the %s pod, so the router would refuse the backend; add one named %s with `c8s allowlist apply`, then re-run install", name, name)
	case names[0] != name:
		return fmt.Errorf("CDS serves allowlist entry %s, not %s, as the one describing the %s pod, so the router would refuse the backend; delete or update %s, then re-run install", names[0], name, name, names[0])
	}
	return nil
}

// storedManifest returns the manifest to add the routes to: a new one when CDS
// stores none, else the stored one, verified first against the operator keys
// this install gives CDS, since install re-signs every route in it. The
// stored one keeps its maxAgeSeconds. ifMatch is the stored manifest's digest
// for the If-Match of the write, empty when CDS stores none.
func storedManifest(ctx context.Context, c routesclient.Client) (m *pkgroutes.Manifest, ifMatch string, err error) {
	env, err := c.Get(ctx)
	if errors.Is(err, routesclient.ErrNotFound) {
		return &pkgroutes.Manifest{MaxAge: installRoutesMaxAge}, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	keys, source, err := installedOperatorKeys()
	if err != nil {
		return nil, "", storedManifestError{fmt.Errorf("CDS already stores a route manifest, which install verifies before re-signing it: %w", err)}
	}
	// install holds no mesh CA set; the router refuses a mesh CA anchor itself.
	signed, err := pkgroutes.VerifySigned(env, keys, nil)
	if err != nil {
		return nil, "", storedManifestError{fmt.Errorf("stored route manifest fails verification against %s: %w", source, err)}
	}
	m = signed.Manifest()
	if installRoutesMaxAgeSet && m.MaxAge != installRoutesMaxAge {
		fmt.Fprintf(os.Stderr, "warning: --routes-max-age %v is ignored: the next revision keeps the stored manifest's maxAgeSeconds (%v); change it with `c8s routes put`\n", installRoutesMaxAge, m.MaxAge)
	}
	return m, manifestDigest(env.Manifest), nil
}

// preflightRoutesOut refuses, before the cluster is touched, to overwrite a
// file at the default --routes-out.
func preflightRoutesOut() error {
	// With --operator-key the file is written only when CDS refuses the
	// manifest, after the install; refusing now keeps that manifest.
	if installUpstream == "" || installRoutesOutSet {
		return nil
	}
	if _, err := os.Stat(installRoutesOut); err == nil {
		return fmt.Errorf("%s exists, and --%s would write its route manifest there: remove it, or name the file with --routes-out", installRoutesOut, flagUpstream)
	}
	return nil
}

// writeRoutesOut writes manifest to --routes-out, never over an existing
// file unless --routes-out was given.
func writeRoutesOut(manifest []byte) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !installRoutesOutSet {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(installRoutesOut, flags, 0o644)
	if err != nil {
		return fmt.Errorf("write --routes-out: %w", err)
	}
	if _, err := f.Write(manifest); err != nil {
		_ = f.Close()
		return fmt.Errorf("write --routes-out: %w", err)
	}
	return f.Close()
}

// writeUpstreamRoutes prints how to store the routes and writes manifest, or a
// new one holding just the routes when it is nil, to --routes-out. It prints
// `c8s routes add`, which re-reads and keeps any stored routes. cause is why
// storing failed, nil when install did not try. It offers `c8s routes put`
// only when install attempted no PUT (manifest is nil) and cause does not
// show that CDS stores a manifest, since putting drops the stored routes. A
// cause that refuses the revision drops --revision from the add commands.
func writeUpstreamRoutes(w io.Writer, u upstreamRoutes, cdsURL string, entries map[string]adoptedEntry, manifest []byte, cause error) error {
	var status *operatorauth.StatusError
	badRevision := errors.As(cause, new(revisionError)) || errors.As(cause, &status) && status.Status == http.StatusConflict && !cliroutes.SpentToken(cause)
	offerPut := manifest == nil && !errors.As(cause, new(storedManifestError))
	if manifest == nil {
		var err error
		if manifest, err = u.apply(&pkgroutes.Manifest{MaxAge: installRoutesMaxAge}, time.Now()); err != nil {
			return err
		}
	}
	m, err := pkgroutes.Parse(manifest)
	if err != nil {
		return err
	}
	operatorKey, operatorKeys := cmp.Or(installOperatorKeyPath(), "<operator-key.pem>"), cmp.Or(installOperatorKeys, "<operator-pub.pem>")
	conn := "--url " + cdsURL + " " + installPinFlags() + " --operator-key " + operatorKey
	// Printed before the write, so a refused --routes-out still shows them.
	fmt.Fprintf(w, "+ the router answers 503 until CDS stores a route manifest. Add the route with:\n")
	for i, host := range u.hosts {
		revision := ""
		if installRoutesRevision != 0 && !badRevision {
			revision = fmt.Sprintf(" --revision %d", installRoutesRevision+uint64(i))
		}
		fmt.Fprintf(w, "    c8s routes add --new --host %s --path / --address %s --workload %s --max-age %v%s --operator-keys %s %s\n", host, u.address, u.workload, installRoutesMaxAge, revision, operatorKeys, conn)
	}
	if err := writeRoutesOut(manifest); err != nil {
		return err
	}
	fmt.Fprintf(w, "+ wrote route manifest revision %d to %s (digest %s): %s\n", m.Revision, installRoutesOut, manifestDigest(manifest), u.describe())
	if offerPut {
		fmt.Fprintf(w, "  Or, only if CDS stores no route manifest, store %s; it replaces a stored one and drops its other routes:\n", installRoutesOut)
		fmt.Fprintf(w, "    c8s routes put %s %s\n", installRoutesOut, conn)
	}
	if _, ok := entries[u.workload]; ok {
		fmt.Fprintf(w, "  The router reaches the backend only if CDS names its pod %s. A persistent CDS keeps\n", u.workload)
		fmt.Fprintf(w, "  stored entries over this install's: check that %s is the only entry admitting the pod's images:\n", u.workload)
		fmt.Fprintf(w, "    c8s allowlist list --url %s %s\n", cdsURL, installPinFlags())
	}
	return nil
}

func installPinFlags() string {
	if installCDS == nil {
		return "--image-policy-file <the CDS pin document>"
	}
	return "--image-policy-file " + installCDS.path
}

func (u upstreamRoutes) describe() string {
	return fmt.Sprintf("%s / -> %s (workload %s)", strings.Join(u.hosts, ", "), u.address, u.workload)
}

func manifestDigest(manifest []byte) string {
	d := pkgroutes.Digest(manifest)
	return hex.EncodeToString(d[:])
}
