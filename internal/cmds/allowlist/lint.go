package allowlist

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newLintCmd(o *options) *cobra.Command {
	var online, strict bool
	var seedPath string
	cmd := &cobra.Command{
		Use:   "lint <file|->",
		Short: "Validate an allowlist file and report semantic warnings",
		Long: `Parse and validate an allowlist file (or stdin with '-') and report semantic
findings: entries with no containers, a container that can never start, digests
whose effective policy is unconstrained, tag-form image labels (TOCTOU),
root-subtree path grants, pinned search paths that overlap data mounts, and
C8s component containers that leave args or mounts open.
--online additionally checks each digest exists in
its registry via crane.

The file is either a full or partial allowlist document or a name-keyed map of
entries, the shapes 'apply' accepts and 'derive' emits.

Two entries declaring the same containers with the same launch policies are an
error: release requires exactly one entry to match, so both are refused
forever. Errors exit non-zero on their own; --strict makes warnings do the
same.

--seed names the release's allowlist seed (allowlist-seed.json in the CDS seed
ConfigMap). Lint then names each chart-generated entry, "<image>-<digest>-<policy>",
whose image the seed generates under another name: the stale shape of an
earlier configuration, safe to delete once no pod runs it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileOrStdin(cmd, args[0])
			if err != nil {
				return err
			}
			entries, err := parseWorkloadEntries(data)
			if err != nil {
				return err
			}
			al := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: entries}
			findings := lintOffline(al)
			if seedPath != "" {
				data, err := readFileOrStdin(cmd, seedPath)
				if err != nil {
					return err
				}
				seed, err := pkgallowlist.ParseJSON(data)
				if err != nil {
					return fmt.Errorf("seed: %w", err)
				}
				findings = append(findings, staleShapes(al, seed)...)
			}
			if online {
				if err := crane.Require(); err != nil {
					return err
				}
				findings = append(findings, lintOnline(ctx(cmd), al)...)
			}
			for _, f := range findings {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", f)
			}
			if len(findings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "ok: no findings")
			}
			if errs := countErrors(findings); errs > 0 {
				cmd.SilenceErrors = true
				return fmt.Errorf("%d lint error(s)", errs)
			}
			if strict && len(findings) > 0 {
				cmd.SilenceErrors = true
				return fmt.Errorf("%d lint warning(s) with --strict", len(findings))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&online, "online", false, "also check each digest exists in its registry via crane")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit non-zero if there are any warnings")
	cmd.Flags().StringVar(&seedPath, "seed", "", "the release's allowlist seed, to name stale chart-generated entries")
	cmd.Flags().String("cvm-mode", "", "deprecated; has no effect")
	_ = cmd.Flags().MarkDeprecated("cvm-mode", "mount and environment policies are enforced by NRI; this flag has no effect")
	return cmd
}

func newInspectImageCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "inspect-image <ref>",
		Short: "Show an image's resolved digest and baked Entrypoint/Cmd (viewer only)",
		Long: `Resolve an image reference via crane and print its digest plus the image's
default Entrypoint and Cmd, so you can see the baked argv before writing an exact
policy. This reads the registry only; it never contacts CDS.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := crane.Require(); err != nil {
				return err
			}
			ref := args[0]
			digest, err := crane.Digest(ctx(cmd), ref)
			if err != nil {
				return err
			}
			cfg, err := crane.Config(ctx(cmd), ref)
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), map[string]any{
					"ref":        ref,
					"digest":     digest,
					"entrypoint": cfg.Config.Entrypoint,
					"cmd":        cfg.Config.Cmd,
				})
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "ref:        %s\n", ref)
			fmt.Fprintf(w, "digest:     %s\n", digest)
			fmt.Fprintf(w, "entrypoint: %s\n", shellJoin(cfg.Config.Entrypoint))
			fmt.Fprintf(w, "cmd:        %s\n", shellJoin(cfg.Config.Cmd))
			return nil
		},
	}
}

// finding is one lint result.
//
// An error is a document that cannot work rather than a judgement an operator
// may accept, so it fails a lint whatever --strict says and blocks a write.
type finding struct {
	err bool
	msg string
}

func (f finding) String() string {
	if f.err {
		return "error: " + f.msg
	}
	return "warning: " + f.msg
}

func warnf(format string, args ...any) finding {
	return finding{msg: fmt.Sprintf(format, args...)}
}

func errorf(format string, args ...any) finding {
	return finding{err: true, msg: fmt.Sprintf(format, args...)}
}

// countErrors reports how many findings are errors.
func countErrors(findings []finding) int {
	n := 0
	for _, f := range findings {
		if f.err {
			n++
		}
	}
	return n
}

// lintOffline reports semantic findings for an allowlist without any registry or
// CDS access. Its entries are assumed already parsed and validated.
func lintOffline(al *pkgallowlist.Allowlist) []finding {
	var warnings []finding

	// digest -> set of distinct entry names; and whether some occurrence admits
	// an unconstrained launch.
	entriesByDigest := map[string]map[string]bool{}
	fullyAny := map[string]bool{}

	for _, name := range slices.Sorted(maps.Keys(al.Workloads)) {
		w := al.Workloads[name]
		if len(w.InitContainers) == 0 && len(w.Containers) == 0 {
			warnings = append(warnings, warnf("workload %q has no init or main containers", name))
		}
		if w.Label != "" && isTagForm(w.Label) {
			warnings = append(warnings, warnf("workload %q label %q is a tag, not a digest (informational, but tags are mutable — TOCTOU)", name, w.Label))
		}
		for _, c := range allContainers(w) {
			d := c.Digest.String()
			if entriesByDigest[d] == nil {
				entriesByDigest[d] = map[string]bool{}
			}
			entriesByDigest[d][name] = true
			if c.IsUnconstrained() {
				fullyAny[d] = true
			}
			if argvPolicyName(c.Command) == pkgallowlist.PolicyDeny {
				warnings = append(warnings, warnf("workload %q container %s command is deny; the effective argv must be empty, so the container can never start", name, d))
			}
			warnings = append(warnings, componentFindings(name, c)...)
			if c.Image != "" && isTagForm(c.Image) {
				warnings = append(warnings, warnf("workload %q container %s image %q is a tag, not a digest (informational, but tags are mutable — TOCTOU)", name, d, c.Image))
			}
		}
		if w.Secrets != nil {
			for _, c := range allContainers(w) {
				if c.Env.Policy == pkgallowlist.PolicyAny || c.Env.Policy == "" {
					warnings = append(warnings, warnf("workload %q grants secrets without pinning environment values for container %s", name, c.Digest))
				}
			}
			for _, g := range append(append([]string{}, w.Secrets.Read...), w.Secrets.Write...) {
				if g == "/**" {
					warnings = append(warnings, warnf("workload %q grants the root secret subtree %q (every secret in the store)", name, g))
				}
			}
		}
	}

	for _, d := range slices.Sorted(maps.Keys(fullyAny)) {
		if len(entriesByDigest[d]) > 1 {
			warnings = append(warnings, warnf("digest %s appears in %d entries and one grants 'any'; the effective admission for that digest is 'any' (union across entries)", d, len(entriesByDigest[d])))
		}
	}

	warnings = append(warnings, indistinguishableEntries(al)...)
	warnings = append(warnings, shadowedEntries(al)...)
	warnings = append(warnings, searchPathFindings(al)...)
	return warnings
}

// generatedName matches the chart's generated entry names, capturing the
// part one image keeps across configurations: DigestEntryName's image segment
// and digest prefix before an 8-hex policy hash, or the router entry's prefix.
var generatedName = regexp.MustCompile(`^(?:(.+-[0-9a-f]{12})-[0-9a-f]{8}|(c8s-router)-[0-9a-f]{12})$`)

// generatedKey is the part of a generated entry name one image keeps across
// configurations, or "" for any other name.
func generatedKey(name string) string {
	m := generatedName.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

// staleShapes names each generated entry of al that seed lacks while seed
// generates another entry for the same image: a shape an earlier
// configuration seeded, which CDS keeps until an operator deletes it.
func staleShapes(al, seed *pkgallowlist.Allowlist) []finding {
	current := map[string]string{}
	for name := range seed.Workloads {
		if key := generatedKey(name); key != "" {
			current[key] = name
		}
	}
	var out []finding
	for _, name := range slices.Sorted(maps.Keys(al.Workloads)) {
		key := generatedKey(name)
		if key == "" {
			continue
		}
		if _, ok := seed.Workloads[name]; ok {
			continue
		}
		if now, ok := current[key]; ok {
			out = append(out, warnf("workload %q is a stale shape: the seed now generates %q for its image; once no pod runs it, run 'c8s allowlist delete %s'", name, now, name))
		}
	}
	return out
}

// componentInvocations are the executables the chart's component entries pin:
// the C8s binary (/c8s in the operator and CDS images, /app/c8s in the mesh
// and volumed images), attestation-api, and nginx through its entrypoint
// script.
var componentInvocations = [][]string{{secrets.InjectedBinary}, {"/app/c8s"}, {"/attestation-api"}, {"/docker-entrypoint.sh", "nginx"}}

// componentFindings reports a container pinned to a component executable that
// leaves its args or mounts to the pod. Either lets a pod point the component
// at code of its choosing: --kubeconfig runs an exec credential plugin, nginx's
// -g loads a module, and a volume replaces what the binary reads. A shape of
// the sidecars the webhook injects may leave its args open, since they are per
// pod, but not its mounts. The invocation is matched against the command and
// any exact args after it, since an entry may split nginx's argv either way;
// a command that open args could complete into an invocation counts too.
func componentFindings(name string, c pkgallowlist.Container) []finding {
	if c.Command.Policy != pkgallowlist.PolicyExact {
		return nil
	}
	argv := c.Command.Argv
	invocation := argv
	if c.Args.Policy == pkgallowlist.PolicyExact {
		invocation = slices.Concat(invocation, c.Args.Argv)
	}
	openArgs := c.Args.Policy == pkgallowlist.PolicyAny || c.Args.Policy == ""
	if !slices.ContainsFunc(componentInvocations, func(prefix []string) bool {
		if len(invocation) >= len(prefix) {
			return slices.Equal(invocation[:len(prefix)], prefix)
		}
		return openArgs && len(argv) > 0 && slices.Equal(prefix[:len(argv)], argv)
	}) {
		return nil
	}
	sidecar := len(argv) == 2 && argv[0] == secrets.InjectedBinary && slices.Contains(secrets.InjectedModes, argv[1])
	var out []finding
	if c.Args.Policy == pkgallowlist.PolicyAny && !sidecar {
		out = append(out, errorf("workload %q container %s pins the component executable %q but leaves args any; pin them exact, as the chart's component entries do", name, c.Digest, strings.Join(argv, " ")))
	}
	if c.Mounts.Policy == pkgallowlist.PolicyAny {
		out = append(out, errorf("workload %q container %s pins the component executable %q but leaves mounts any; pin them exact, as the chart's component entries do", name, c.Digest, strings.Join(argv, " ")))
	}
	return out
}

// shadowedEntries reports entries that can never be the unique match because
// another entry describes every running set they describe. Like an
// indistinguishable pair this is an error: release and the matched-workload
// stamp are refused for every pod the narrower entry was written for.
func shadowedEntries(al *pkgallowlist.Allowlist) []finding {
	var out []finding
	for _, pair := range shadowPairs(al) {
		out = append(out, shadowFinding(pair[0], pair[1]))
	}
	return out
}

// shadowPairs returns every (wide, narrow) name pair where wide shadows narrow
// and not the reverse — a mutual pair is the same shape, which
// indistinguishableEntries already reports.
func shadowPairs(al *pkgallowlist.Allowlist) [][2]string {
	var out [][2]string
	names := slices.Sorted(maps.Keys(al.Workloads))
	for _, wide := range names {
		for _, narrow := range names {
			if wide == narrow {
				continue
			}
			if shadows(al.Workloads[wide], al.Workloads[narrow]) && !shadows(al.Workloads[narrow], al.Workloads[wide]) {
				out = append(out, [2]string{wide, narrow})
			}
		}
	}
	return out
}

func shadowFinding(wide, narrow string) finding {
	return errorf(
		"workload %q can never be the unique match: %q admits every launch of every container it declares and needs nothing more running, so every pod %q describes matches both (edit %q instead of adding a narrower entry beside it, or delete it)",
		narrow, wide, narrow, wide)
}

// shadows reports whether wide describes every running set narrow describes:
// each of wide's mains is one of narrow's mains, and each container narrow
// declares has a wide container of the same digest whose policy subsumes it.
func shadows(wide, narrow pkgallowlist.Workload) bool {
	narrowMains := map[string]bool{}
	for _, c := range narrow.Containers {
		narrowMains[c.Digest.String()] = true
	}
	for _, c := range wide.Containers {
		if !narrowMains[c.Digest.String()] {
			return false
		}
	}
	for _, n := range allContainers(narrow) {
		if !slices.ContainsFunc(allContainers(wide), func(w pkgallowlist.Container) bool { return subsumes(w, n) }) {
			return false
		}
	}
	return true
}

// subsumes reports whether every launch narrow admits, wide admits too: the
// same digest, and for each of argv, mounts and env either wide leaves it to
// the host or both pin it the same way. For argv, an exact command whose
// arguments are open also subsumes any exact command it is a prefix of — the
// seeded component shape, `/c8s` under any args, subsumes `/c8s cds-attest`
// under any policy.
func subsumes(wide, narrow pkgallowlist.Container) bool {
	if wide.Digest != narrow.Digest {
		return false
	}
	if !wide.AnyArgv() && !argvPrefixSubsumes(wide, narrow) && !reflect.DeepEqual(processOf(wide), processOf(narrow)) {
		return false
	}
	if wide.Mounts.Policy != pkgallowlist.PolicyAny && !reflect.DeepEqual(wide.Mounts, narrow.Mounts) {
		return false
	}
	if wide.Env.Policy != pkgallowlist.PolicyAny && !reflect.DeepEqual(wide.Env, narrow.Env) {
		return false
	}
	return true
}

func argvPrefixSubsumes(wide, narrow pkgallowlist.Container) bool {
	if wide.Args.Policy != pkgallowlist.PolicyAny || wide.Command.Policy != pkgallowlist.PolicyExact || narrow.Command.Policy != pkgallowlist.PolicyExact {
		return false
	}
	return len(narrow.Command.Argv) >= len(wide.Command.Argv) && slices.Equal(narrow.Command.Argv[:len(wide.Command.Argv)], wide.Command.Argv)
}

func processOf(c pkgallowlist.Container) [2]pkgallowlist.ArgvPolicy {
	return [2]pkgallowlist.ArgvPolicy{c.Command, c.Args}
}

// searchPathFindings rejects pinned loader and interpreter search paths that
// overlap operator-supplied data, which could otherwise be loaded as code.
func searchPathFindings(al *pkgallowlist.Allowlist) []finding {
	var out []finding
	for _, name := range slices.Sorted(maps.Keys(al.Workloads)) {
		for _, c := range allContainers(al.Workloads[name]) {
			if c.Env.Policy != pkgallowlist.PolicyExact || c.Mounts.Policy != pkgallowlist.PolicyExact {
				continue
			}
			for _, variable := range []string{"PATH", "LD_LIBRARY_PATH", "PYTHONPATH", "NODE_PATH"} {
				value, set := c.Env.Values[variable]
				if !set {
					continue
				}
				for _, rule := range c.Mounts.Rules {
					if searchPathLoadsMountedContent(value, rule) {
						out = append(out, errorf("workload %q container %s pins %s to a search path overlapping %s mount %q; operator-supplied content could be loaded as code", name, c.Digest.String(), variable, rule.Kind, rule.Destination))
					}
				}
			}
		}
	}
	return out
}

func searchPathLoadsMountedContent(value string, rule pkgallowlist.MountRule) bool {
	operatorSupplied := rule.Kind == pkgallowlist.MountData || rule.Kind == pkgallowlist.MountHost
	return operatorSupplied && searchPathReachesMount(value, rule.Destination)
}

func searchPathReachesMount(value, destination string) bool {
	destination = path.Clean(destination)
	for _, element := range strings.Split(value, ":") {
		element = path.Clean(element)
		if element == destination || strings.HasPrefix(element, strings.TrimSuffix(destination, "/")+"/") || strings.HasPrefix(destination, strings.TrimSuffix(element, "/")+"/") {
			return true
		}
	}
	return false
}

// indistinguishableEntries reports entries that no running set can tell apart.
//
// Release requires exactly one entry to describe the containers a sandbox runs,
// so entries with the same shape both match or neither does — the match is
// ambiguous forever and every pod resolving to them is refused, whichever grant
// an operator meant. Nothing a workload can do fixes it, so this is an error.
func indistinguishableEntries(al *pkgallowlist.Allowlist) []finding {
	groups, err := indistinguishableGroups(al)
	if err != nil {
		return []finding{errorf("workload entries could not be compared: %v", err)}
	}
	out := make([]finding, 0, len(groups))
	for _, names := range groups {
		out = append(out, ambiguousGroupFinding(names))
	}
	return out
}

// indistinguishableGroups returns each set of two or more entry names sharing a
// shape, in a stable order.
func indistinguishableGroups(al *pkgallowlist.Allowlist) ([][]string, error) {
	byShape := map[string][]string{}
	for _, name := range slices.Sorted(maps.Keys(al.Workloads)) {
		shape, err := entryShape(al.Workloads[name])
		if err != nil {
			// A shape that will not marshal cannot be compared; say so rather
			// than silently treating the entry as unique.
			return nil, fmt.Errorf("workload %q: %w", name, err)
		}
		byShape[shape] = append(byShape[shape], name)
	}
	var out [][]string
	for _, shape := range slices.Sorted(maps.Keys(byShape)) {
		if names := byShape[shape]; len(names) > 1 {
			out = append(out, names)
		}
	}
	return out, nil
}

func ambiguousGroupFinding(names []string) finding {
	return errorf(
		"workloads [%s] declare the same containers with the same command, args, mounts and env policy; release requires exactly one entry to match, so all of them are refused (merge them, or narrow the launch policy so a running pod resolves to one)",
		strings.Join(names, ", "))
}

// entryShape is the part of an entry a release decision reads: the digests and
// launch policies of each container list. Image labels and the secret grant are
// excluded — two entries differing only in those are exactly the dangerous
// case, since the grant an operator intended is the thing that never resolves.
func entryShape(w pkgallowlist.Workload) (string, error) {
	type containerShape struct {
		Digest  string                   `json:"digest"`
		Command pkgallowlist.ArgvPolicy  `json:"command"`
		Args    pkgallowlist.ArgvPolicy  `json:"args"`
		Env     pkgallowlist.EnvPolicy   `json:"env"`
		Mounts  pkgallowlist.MountPolicy `json:"mounts"`
	}
	shape := func(cs []pkgallowlist.Container) ([]string, error) {
		out := make([]string, 0, len(cs))
		for _, c := range cs {
			env := c.Env
			if env.Policy == "" {
				env = pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyAny}
			}
			mounts := c.Mounts
			if mounts.Policy == "" {
				mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}
			}
			b, err := json.Marshal(containerShape{Digest: c.Digest.String(), Command: c.Command, Args: c.Args, Env: env, Mounts: mounts})
			if err != nil {
				return nil, err
			}
			out = append(out, string(b))
		}
		// Sorted so declaration order is not mistaken for a difference.
		sort.Strings(out)
		return out, nil
	}
	mains, err := shape(w.Containers)
	if err != nil {
		return "", err
	}
	inits, err := shape(w.InitContainers)
	if err != nil {
		return "", err
	}
	// The two lists stay distinct: a main is required to be present and an init
	// is not, so moving a container between them changes what matches.
	b, err := json.Marshal([][]string{mains, inits})
	return string(b), err
}

// lintOnline checks each workload container digest is resolvable in its
// registry via crane. It needs the container image label to know the repo.
func lintOnline(ctx context.Context, al *pkgallowlist.Allowlist) []finding {
	var warnings []finding
	checked := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(al.Workloads)) {
		w := al.Workloads[name]
		for _, c := range allContainers(w) {
			if c.Image == "" {
				warnings = append(warnings, warnf("workload %q container %s has no image label; cannot check the digest online", name, c.Digest))
				continue
			}
			named, err := reference.ParseDockerRef(c.Image)
			if err != nil {
				warnings = append(warnings, warnf("workload %q container %s image %q: %v", name, c.Digest, c.Image, err))
				continue
			}
			ref := reference.TrimNamed(named).String() + "@" + c.Digest.String()
			if checked[ref] {
				continue
			}
			checked[ref] = true
			if err := crane.ManifestExists(ctx, ref); err != nil {
				warnings = append(warnings, warnf("workload %q container digest not found in registry: %s (%v)", name, ref, err))
			}
		}
	}
	return warnings
}

// isTagForm reports whether an image reference carries a tag rather than a
// digest. A parse failure is treated as not-a-tag (the label is informational).
func isTagForm(image string) bool {
	named, err := reference.ParseDockerRef(image)
	if err != nil {
		return false
	}
	_, digested := named.(reference.Digested)
	return !digested
}
