package allowlist

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	mrand "math/rand/v2"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func newGetCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Print one entry as canonical JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			al, _, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			w, ok := al.Workloads[args[0]]
			if !ok {
				return fmt.Errorf("no workload entry named %q", args[0])
			}
			return writeJSON(cmd.OutOrStdout(), w)
		},
	}
}

func newApplyCmd(o *options) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply <file|->",
		Short: "Upsert entries from a file (whole-entry replace, one atomic write)",
		Long: `Upsert each entry in <file> (or stdin with '-'). The file is either a full or
partial allowlist document or a name-keyed map of entries. Each entry is
replaced whole — this never field-merges into a live entry.

apply reads the live allowlist, puts the entries into it, and writes the
result back as one whole-document write: every entry lands or none does. The
write is signed by the operator key like an upload, so the key signs the whole
resulting document, not only the entries in <file>. It is conditional on the
version apply read: if another write landed since, CDS refuses it, and apply
re-reads the allowlist, prints what the other write changed, and puts the
entries into the newer document, up to ` + fmt.Sprint(maxApplyAttempts) + ` writes in all. Other entries
the other write changed are kept; an entry in <file> is set to the file's value
even if the other write changed it. If every attempt is refused, nothing was
applied.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			data, err := readFileOrStdin(cmd, args[0])
			if err != nil {
				return err
			}
			entries, err := parseWorkloadEntries(data)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return fmt.Errorf("no workload entries in %q", args[0])
			}

			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			live, version, err := readForWrite(ctx(cmd), c)
			if err != nil {
				return err
			}

			findings := lintOffline(&pkgallowlist.Allowlist{Schema: live.Schema, Workloads: entries})
			// The ambiguity check is the one finding that cannot be made from
			// the file alone: the entry it collides with is usually one already
			// served. Only pairs that span both are added here, since a
			// collision inside the file is already reported above.
			findings = append(findings, collisionsWithLive(entries, live)...)
			for _, f := range findings {
				fmt.Fprintf(cmd.ErrOrStderr(), "lint: %s\n", f)
			}
			if errs := countErrors(findings); errs > 0 {
				return fmt.Errorf("refusing to apply: %d lint error(s)", errs)
			}

			names := slices.Sorted(maps.Keys(entries))
			for _, name := range names {
				if lw, ok := live.Workloads[name]; ok {
					ed := diffEntry(lw, entries[name])
					if ed.empty() {
						fmt.Fprintf(cmd.OutOrStdout(), "= %s (unchanged)\n", name)
						continue
					}
					fmt.Fprintf(cmd.OutOrStdout(), "~ %s\n", name)
					printEntryDiff(cmd.OutOrStdout(), ed)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "+ %s (new)\n", name)
				}
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would upsert %d workload entr(ies)\n", len(entries))
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := applyEntries(cmd, c, live, version, entries, signer); err != nil {
				return err
			}
			for _, name := range names {
				fmt.Fprintf(cmd.OutOrStdout(), "applied %s\n", name)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the diff without writing any entry")
	return cmd
}

func newEditCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "edit <name>",
		Short: "Fetch an entry, edit it in $EDITOR, and apply the result",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			name := args[0]
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			live, _, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}
			orig, ok := live.Workloads[name]
			if !ok {
				return fmt.Errorf("no workload entry named %q", name)
			}

			edited, err := editWorkloadInEditor(orig, name)
			if err != nil {
				return err
			}
			if diffEntry(orig, *edited).empty() {
				fmt.Fprintln(cmd.ErrOrStderr(), "no changes")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "~ %s\n", name)
			printEntryDiff(cmd.OutOrStdout(), diffEntry(orig, *edited))

			if !confirm(cmd, fmt.Sprintf("apply changes to %q?", name)) {
				fmt.Fprintln(cmd.ErrOrStderr(), "aborted")
				return nil
			}
			if err := signAndPutWorkload(ctx(cmd), o, c, name, *edited); err != nil {
				keepEditForRetry(cmd.ErrOrStderr(), name, *edited)
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "applied %s\n", name)
			return nil
		},
	}
}

func newDeleteCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name> [<name>...]",
		Short: "Delete one or more entries",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			for i, name := range args {
				if err := c.DeleteWorkload(ctx(cmd), name, signer); err != nil {
					var se *operatorauth.StatusError
					if errors.As(err, &se) && se.Status == 404 {
						err = fmt.Errorf("no workload entry named %q", name)
					}
					if len(args) == 1 {
						return err
					}
					return fmt.Errorf("%w (deleted: %v; not deleted: %v)", err, args[:i], args[i:])
				}
				fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", name)
			}
			return nil
		},
	}
}

// collisionsWithLive reports entries being applied that no running set could
// tell apart from an entry already served, which would refuse both. Groups
// entirely inside the applied set are left out: lintOffline over the file has
// already named those.
func collisionsWithLive(entries map[string]pkgallowlist.Workload, live *pkgallowlist.Allowlist) []finding {
	merged := make(map[string]pkgallowlist.Workload, len(live.Workloads)+len(entries))
	maps.Copy(merged, live.Workloads)
	maps.Copy(merged, entries)
	groups, err := indistinguishableGroups(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: merged})
	if err != nil {
		return []finding{errorf("workload entries could not be compared with the served allowlist: %v", err)}
	}
	var out []finding
	for _, names := range groups {
		applied, served := 0, 0
		for _, n := range names {
			if _, ok := entries[n]; ok {
				applied++
			} else {
				served++
			}
		}
		if applied > 0 && served > 0 {
			out = append(out, ambiguousGroupFinding(names))
		}
	}
	for _, pair := range shadowPairs(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: merged}) {
		_, wideApplied := entries[pair[0]]
		_, narrowApplied := entries[pair[1]]
		if wideApplied != narrowApplied {
			out = append(out, shadowFinding(pair[0], pair[1]))
		}
	}
	return out
}

// maxApplyAttempts bounds how many times apply writes its entries onto a
// newer allowlist after another write landed since its read.
const maxApplyAttempts = 5

// applyEntries writes live with entries put in, conditional on version. When
// another write landed since the read, it re-reads the allowlist and puts the
// same entries into the newer document: apply sets exactly these entries, so
// the result is still what the operator asked for, and the condition still
// keeps every other write. A concurrent write to one of these entries is
// replaced by the file's value, as a later apply would replace it.
//
// Writing again is safe only because apply is idempotent: putting the same
// entries into a document that already holds them changes nothing. So a
// write of ours that landed unconfirmed, then had another write land on top,
// is found again in the re-read, and the re-merge, which then equals the
// served document, is not written.
//
// INVARIANT: every write is conditional on the version of the document it was
// built from, and every document it builds is lint-checked against that read.
func applyEntries(cmd *cobra.Command, c allowlistclient.Client, live *pkgallowlist.Allowlist, version string,
	entries map[string]pkgallowlist.Workload, signer allowlistclient.Authorizer) error {
	for attempt := 1; ; attempt++ {
		merged := maps.Clone(live.Workloads)
		if merged == nil {
			merged = map[string]pkgallowlist.Workload{}
		}
		maps.Copy(merged, entries)
		doc := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: merged}
		if attempt > 1 {
			same, err := sameDocument(doc, live)
			if err != nil {
				return err
			}
			if same {
				return nil
			}
		}
		err := replaceIfUnchanged(ctx(cmd), c, doc, version, signer)
		if err == nil {
			return nil
		}
		var unconfirmed *unconfirmedError
		if errors.As(err, &unconfirmed) {
			return fmt.Errorf("apply %d entr(ies) in one write: %w", len(entries), err)
		}
		if !errors.Is(err, errAllowlistChanged) {
			return fmt.Errorf("nothing was applied: %w", err)
		}
		if attempt == maxApplyAttempts {
			return fmt.Errorf("nothing was applied: other writes kept landing, %d attempts each re-read the allowlist and lost the race: %w",
				attempt, err)
		}
		// Writers that raced once tend to race again; a random pause
		// spreads them apart.
		select {
		case <-ctx(cmd).Done():
			return fmt.Errorf("nothing was applied: %w", ctx(cmd).Err())
		case <-time.After(time.Duration(50+mrand.IntN(100*attempt)) * time.Millisecond):
		}
		newer, newVersion, err := readForWrite(ctx(cmd), c)
		if err != nil {
			return fmt.Errorf("nothing was applied: re-read the allowlist after another write landed: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "the allowlist changed since it was read (version %s -> %s); applying the entries onto it again:\n",
			version, newVersion)
		_ = printDiff(cmd.ErrOrStderr(), "", diffAllowlists(live, newer))
		findings := collisionsWithLive(entries, newer)
		for _, f := range findings {
			fmt.Fprintf(cmd.ErrOrStderr(), "lint: %s\n", f)
		}
		if errs := countErrors(findings); errs > 0 {
			return fmt.Errorf("nothing was applied: refusing to apply onto the changed allowlist: %d lint error(s)", errs)
		}
		live, version = newer, newVersion
	}
}

// sameDocument reports whether a and b have the same canonical bytes.
func sameDocument(a, b *pkgallowlist.Allowlist) (bool, error) {
	ab, err := a.Canonical()
	if err != nil {
		return false, err
	}
	bb, err := (&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: b.Workloads}).Canonical()
	if err != nil {
		return false, err
	}
	return bytes.Equal(ab, bb), nil
}

// --- shared helpers ---

// readForWrite reads the live allowlist a whole-document write is built from,
// and the version that write is made conditional on.
//
// INVARIANT: every entry the write does not name goes back with all of its
// fields. The served parse is lenient: it drops fields this c8s does not know
// and entries no longer valid (an over-long legacy name). The write path's
// strict parse refuses both instead, so nothing is lost by writing back.
func readForWrite(ctx context.Context, c allowlistclient.Client) (*pkgallowlist.Allowlist, string, error) {
	raw, version, err := c.CanonicalBytes(ctx)
	if err != nil {
		return nil, "", err
	}
	live, err := pkgallowlist.ParseJSON(raw)
	if err != nil {
		return nil, "", fmt.Errorf("the served allowlist holds content this c8s cannot write back unchanged "+
			"(a field it does not know, or an entry no longer valid such as a name over 63 bytes); "+
			"use a c8s as new as CDS, or delete the invalid entry first: %w", err)
	}
	return live, version, nil
}

// parseWorkloadEntries accepts either a full/partial allowlist document or a
// bare name-keyed map of workload entries. The bare map is wrapped into a
// document so both shapes reach ParseJSON under one set of rules: duplicate
// keys, a single document, entry-name grammar, and argv-pinned secrets.
func parseWorkloadEntries(data []byte) (map[string]pkgallowlist.Workload, error) {
	al, docErr := pkgallowlist.ParseJSON(data)
	if docErr == nil {
		if al.Workloads == nil {
			al.Workloads = map[string]pkgallowlist.Workload{}
		}
		return al.Workloads, nil
	}

	const prefix = `{"schema":"` + pkgallowlist.Schema + `","workloads":`
	wrapped := make([]byte, 0, len(prefix)+len(data)+1)
	wrapped = append(wrapped, prefix...)
	wrapped = append(wrapped, data...)
	wrapped = append(wrapped, '}')
	mapped, mapErr := pkgallowlist.ParseJSON(wrapped)
	if mapErr != nil {
		return nil, fmt.Errorf("parse workload entries: not a name-keyed workload map (%v); not an allowlist document (%v)", mapErr, docErr)
	}
	// An allowlist document may legitimately carry no entries; a body with
	// neither a schema nor an entry says nothing at all.
	if len(mapped.Workloads) == 0 {
		return nil, fmt.Errorf("parse workload entries: no schema field and no entries")
	}
	return mapped.Workloads, nil
}

func readFileOrStdin(cmd *cobra.Command, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(cmd.InOrStdin())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return data, nil
}

// signAndPutWorkload signs one entry with the operator key and writes it.
func signAndPutWorkload(ctx context.Context, o *options, c allowlistclient.Client, name string, w pkgallowlist.Workload) error {
	signer, err := o.signer()
	if err != nil {
		return err
	}
	return c.PutWorkload(ctx, name, w, signer)
}

// keepEditForRetry saves an edit that was not written as an allowlist
// document holding only that entry, which `apply` writes as is.
func keepEditForRetry(stderr io.Writer, name string, edited pkgallowlist.Workload) {
	doc := pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{name: edited}}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "your edit could not be saved: %v\n", err)
		return
	}
	path, err := writeTempFile(name, data)
	if err != nil {
		fmt.Fprintf(stderr, "your edit could not be saved: %v\n", err)
		return
	}
	fmt.Fprintf(stderr, "your edit is saved in %s; retry with 'c8s allowlist apply %s' and the same flags\n", path, path)
}

// writeTempFile writes data and a newline to a new temp file named after the
// entry and returns its path.
func writeTempFile(name string, data []byte) (string, error) {
	tmp, err := os.CreateTemp("", "c8s-workload-"+sanitizeFileName(name)+"-*.json")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// editWorkloadInEditor writes the entry to a temp file, opens $EDITOR (vi if
// unset) on it, and re-validates the result via ParseWorkloadJSON.
func editWorkloadInEditor(w pkgallowlist.Workload, name string) (*pkgallowlist.Workload, error) {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return nil, err
	}
	path, err := writeTempFile(name, data)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)

	if err := runEditor(path); err != nil {
		return nil, err
	}
	edited, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pkgallowlist.ParseWorkloadJSON(edited)
}

func runEditor(path string) error {
	editor := os.Getenv("EDITOR")
	if strings.TrimSpace(editor) == "" {
		editor = "vi"
	}
	fields := strings.Fields(editor)
	args := append(fields[1:], path)
	c := exec.Command(fields[0], args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("editor %q: %w", editor, err)
	}
	return nil
}

func sanitizeFileName(name string) string {
	return strings.Map(func(r rune) rune {
		if isSafeFileNameRune(r) {
			return r
		}
		return '_'
	}, name)
}

func isSafeFileNameRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
}

func confirm(cmd *cobra.Command, prompt string) bool {
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", prompt)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
