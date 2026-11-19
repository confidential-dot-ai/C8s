package routes

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/routesclient"
)

func newPutCmd(o *options) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "put <file>",
		Short: "Sign and store a manifest file verbatim",
		Long: `Validate a manifest file, sign its exact bytes with --operator-key and store
them on CDS. Its revision must be greater than the stored one.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifest, m, err := readManifest(args[0])
			if err != nil {
				return err
			}
			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "would store revision %d, digest %s\n", m.Revision, digestHex(manifest))
				return nil
			}
			signer, err := o.Signer()
			if err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			if err := put(ctx(cmd), &o.Options, c, manifest, signer, "", "raise the file's revision above the stored one ('c8s routes show')"); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored revision %d, digest %s\n", m.Revision, digestHex(manifest))
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate the file and print its revision and digest without calling CDS")
	return cmd
}

func newAddCmd(o *options) *cobra.Command {
	var (
		host, path, match, address string
		workload, serverName, ca   string
		maxAge                     time.Duration
		revision                   uint64
		dryRun, newManifest        bool
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add or replace one route and store the next revision",
		Long: `Fetch the stored manifest, verify it against --operator-keys (required once
CDS stores one), add a route for --host, and store the next revision. notBefore
becomes now, or keeps the stored value when it is later. A route with the same
--path and --match is replaced. When CDS stores no route manifest, add refuses
unless --new is passed, and then writes a new one with --max-age; otherwise it
keeps the stored maxAgeSeconds. After a CDS reset, 'c8s routes put' your last
manifest instead: once routers apply manifests, a new one outranks the routes
they hold and drops all but this one.
--dry-run also fetches the stored manifest from CDS.

Name the backend in one of two ways:
  --workload            an allowlist workload name; the router requires it in
                        the backend's named leaf.
  --server-name, --ca   a TLS server name and a PEM file of trust anchors; the
                        anchors must not include the CDS mesh CA.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (workload == "") == (serverName == "" && ca == "") {
				return fmt.Errorf("name the backend with --workload, or with --server-name and --ca")
			}
			if workload == "" && (serverName == "" || ca == "") {
				return fmt.Errorf("an address backend needs both --server-name and --ca")
			}
			if maxAge < time.Second {
				return fmt.Errorf("--max-age %s: pass at least 1s", maxAge)
			}
			r := pkgroutes.Route{
				Path:    path,
				Match:   pkgroutes.MatchKind(match),
				Backend: pkgroutes.Backend{Address: address, Workload: workload, ServerName: serverName},
			}
			if ca != "" {
				pemBytes, err := os.ReadFile(ca)
				if err != nil {
					return fmt.Errorf("read --ca: %w", err)
				}
				r.Backend.CA = string(pemBytes)
			}
			var newMaxAge time.Duration
			if newManifest {
				newMaxAge = maxAge
			}
			return o.edit(cmd, dryRun, newMaxAge, revision, func(m *pkgroutes.Manifest) (string, error) {
				return AddRoute(m, host, r), nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&host, "host", "", "request host, lower-case without port (required)")
	f.StringVar(&path, "path", "", "route path, beginning with / (required)")
	f.StringVar(&match, "match", string(pkgroutes.MatchPrefix), "exact or prefix")
	f.StringVar(&address, "address", "", "backend host:port (required)")
	f.StringVar(&workload, "workload", "", "allowlist workload name the backend's named leaf must carry")
	f.StringVar(&serverName, "server-name", "", "TLS server name of an address backend")
	f.StringVar(&ca, "ca", "", "PEM file of trust anchors for an address backend")
	f.DurationVar(&maxAge, "max-age", 24*time.Hour, "maxAgeSeconds of a manifest --new starts; otherwise add keeps the stored value")
	f.BoolVar(&newManifest, "new", false, "start a new manifest when CDS stores none (the first route of a cluster)")
	bindRevisionFlag(f, &revision)
	f.BoolVar(&dryRun, "dry-run", false, "fetch the stored manifest from CDS and print the new one without storing it")
	cmdsutil.RequireFlags(cmd, "host", "path", "address")
	return cmd
}

func newRmCmd(o *options) *cobra.Command {
	var (
		host, path, match string
		revision          uint64
		dryRun            bool
	)
	cmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove one route and store the next revision",
		Long: `Fetch the stored manifest, verify it against --operator-keys (required), remove
the route of --host at --path, and store the next revision. notBefore becomes
now, or keeps the stored value when it is later. A host left with no routes is
removed. Pass --match when the host has both an exact and a prefix route at
--path. --dry-run also fetches the stored manifest from CDS.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if match != "" && match != string(pkgroutes.MatchExact) && match != string(pkgroutes.MatchPrefix) {
				return fmt.Errorf("--match %q: want %q or %q", match, pkgroutes.MatchExact, pkgroutes.MatchPrefix)
			}
			return o.edit(cmd, dryRun, 0, revision, func(m *pkgroutes.Manifest) (string, error) {
				return removeRoute(m, host, path, pkgroutes.MatchKind(match))
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&host, "host", "", "request host (required)")
	f.StringVar(&path, "path", "", "route path (required)")
	f.StringVar(&match, "match", "", "exact or prefix; needed only when both exist at --path")
	bindRevisionFlag(f, &revision)
	f.BoolVar(&dryRun, "dry-run", false, "fetch the stored manifest from CDS and print the new one without storing it")
	cmdsutil.RequireFlags(cmd, "host", "path")
	return cmd
}

func newAddPatternCmd(o *options) *cobra.Command {
	var (
		p           pkgroutes.Pattern
		maxAge      time.Duration
		revision    uint64
		dryRun      bool
		newManifest bool
	)
	cmd := &cobra.Command{
		Use:   "add-pattern",
		Short: "Add or replace one pattern rule and store the next revision",
		Long: `Fetch the stored manifest, verify it against --operator-keys (required once
CDS stores one), add a pattern rule for --host-suffix, and store the next
revision, as 'add' does. A pattern with the same --host-suffix is replaced.

A pattern sends every request for <label>.<host-suffix> to the agent with that
label: the router finds a pod CVM that publishes a client document whose
agent label (base32 of the first 16 bytes of its SHA-256) is <label>, and
requires its leaf to carry --workload and that client document digest. Adding
an agent needs no manifest write. An exact host in the manifest shadows the
pattern.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if maxAge < time.Second {
				return fmt.Errorf("--max-age %s: pass at least 1s", maxAge)
			}
			var newMaxAge time.Duration
			if newManifest {
				newMaxAge = maxAge
			}
			return o.edit(cmd, dryRun, newMaxAge, revision, func(m *pkgroutes.Manifest) (string, error) {
				return addPattern(m, p), nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&p.HostSuffix, "host-suffix", "", "host suffix the agent label is prepended to, lower-case (required)")
	f.StringVar(&p.Workload, "workload", "", "allowlist workload name the agent's named leaf must carry (required)")
	f.Uint16Var(&p.Port, "port", 0, "application port the agent serves on (required)")
	f.DurationVar(&maxAge, "max-age", 24*time.Hour, "maxAgeSeconds of a manifest --new starts; otherwise the stored value is kept")
	f.BoolVar(&newManifest, "new", false, "start a new manifest when CDS stores none")
	bindRevisionFlag(f, &revision)
	f.BoolVar(&dryRun, "dry-run", false, "fetch the stored manifest from CDS and print the new one without storing it")
	cmdsutil.RequireFlags(cmd, "host-suffix", "workload", "port")
	return cmd
}

func newRmPatternCmd(o *options) *cobra.Command {
	var (
		hostSuffix string
		revision   uint64
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "rm-pattern",
		Short: "Remove one pattern rule and store the next revision",
		Long: `Fetch the stored manifest, verify it against --operator-keys (required), remove
the pattern rule for --host-suffix, and store the next revision.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.edit(cmd, dryRun, 0, revision, func(m *pkgroutes.Manifest) (string, error) {
				return removePattern(m, hostSuffix)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&hostSuffix, "host-suffix", "", "host suffix of the pattern (required)")
	bindRevisionFlag(f, &revision)
	f.BoolVar(&dryRun, "dry-run", false, "fetch the stored manifest from CDS and print the new one without storing it")
	cmdsutil.RequireFlags(cmd, "host-suffix")
	return cmd
}

func bindRevisionFlag(f *pflag.FlagSet, revision *uint64) {
	f.Uint64Var(revision, "revision", 0, "revision to write, above the stored one; default the later of the stored revision plus one and the current Unix time")
}

// NextRevision returns the revision after stored (C6): revision when nonzero,
// else the later of stored+1 and now in Unix seconds, so a manifest written
// after a CDS reset outranks the revisions routers keep once they apply
// manifests.
func NextRevision(stored, revision uint64, now time.Time) (uint64, error) {
	if revision == 0 {
		return max(stored+1, uint64(max(now.Unix(), 1))), nil
	}
	if revision <= stored {
		return 0, fmt.Errorf("revision %d is not above the stored revision %d; pass a higher one", revision, stored)
	}
	return revision, nil
}

// edit fetches the stored manifest, applies change, and stores the result at
// NextRevision. newMaxAge > 0 lets it start a new manifest when CDS stores
// none; otherwise it refuses.
func (o *options) edit(cmd *cobra.Command, dryRun bool, newMaxAge time.Duration, revision uint64, change func(*pkgroutes.Manifest) (string, error)) error {
	var signer operatorauth.Authorizer
	if dryRun {
		if err := o.RequirePinnedEndpoint(); err != nil {
			return err
		}
	} else {
		// Before connecting, so a missing key fails before the attestation probe.
		s, err := o.Signer()
		if err != nil {
			return err
		}
		signer = s
	}
	c, err := o.client(ctx(cmd))
	if err != nil {
		return err
	}
	env, m, verifiedAgainstOperatorKeys, err := o.fetch(ctx(cmd), c)
	if storesManifest := err == nil; storesManifest && !verifiedAgainstOperatorKeys {
		return fmt.Errorf("%s re-signs the stored routes; pass --operator-keys to verify them first", cmd.CommandPath())
	}
	var ifMatch string
	switch {
	case errors.Is(err, routesclient.ErrNotFound) && newMaxAge > 0:
		m = &pkgroutes.Manifest{MaxAge: newMaxAge, Hosts: map[string]pkgroutes.Host{}}
	case errors.Is(err, routesclient.ErrNotFound):
		// A CDS reset also looks like this. Once routers apply manifests, a
		// new one outranks the routes they hold and drops all but this one.
		return errors.New("CDS stores no route manifest. After a CDS reset, 'c8s routes put' the last manifest you stored; to start the first one, run 'c8s routes add --new'")
	case err != nil:
		return err
	default:
		ifMatch = digestHex(env.Manifest)
		if cmd.Flags().Changed("max-age") {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: --max-age ignored; keeping the stored maxAgeSeconds %d\n", int64(m.MaxAge/time.Second))
		}
		// A parsed manifest is read-only; AddRoute and removeRoute already
		// copy the route slices they change.
		edited := *m
		edited.Hosts = maps.Clone(m.Hosts)
		m = &edited
	}
	done, err := change(m)
	if err != nil {
		return err
	}
	now := time.Now()
	stored := m.Revision
	if m.Revision, err = NextRevision(stored, revision, now); err != nil {
		return err
	}
	// A staged notBefore stays staged (D3).
	if notBefore := now.UTC().Truncate(time.Second); notBefore.After(m.NotBefore) {
		m.NotBefore = notBefore
	}
	manifest, err := Encode(m)
	if err != nil {
		return err
	}
	if _, err := pkgroutes.Parse(manifest); err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if dryRun {
		_, err := out.Write(manifest)
		return err
	}
	printResign(cmd.ErrOrStderr(), stored, m)
	if err := put(ctx(cmd), &o.Options, c, manifest, signer, ifMatch, "another write landed first; re-run the command to apply the change to the stored revision"); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s; stored revision %d, digest %s\n", done, m.Revision, digestHex(manifest))
	return nil
}

// printResign lists every route the new revision carries, since signing it
// re-authorizes them all, including any the stored manifest brought back.
func printResign(w io.Writer, stored uint64, m *pkgroutes.Manifest) {
	fmt.Fprintf(w, "signing revision %d over stored revision %d, with every route it carries:\n", m.Revision, stored)
	for _, host := range slices.Sorted(maps.Keys(m.Hosts)) {
		for _, r := range m.Hosts[host].Routes {
			backend := "workload " + r.Backend.Workload
			if r.Backend.Workload == "" {
				backend = "server name " + r.Backend.ServerName
			}
			fmt.Fprintf(w, "  %s %s %s -> %s, %s\n", host, r.Path, r.Match, r.Backend.Address, backend)
		}
	}
	for _, p := range m.Patterns {
		fmt.Fprintf(w, "  <label>.%s / prefix -> agent <label>, workload %s, port %d\n", p.HostSuffix, p.Workload, p.Port)
	}
}
