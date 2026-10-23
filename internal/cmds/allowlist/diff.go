package allowlist

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// changedEntry is a before/after pair for a single value.
type changedEntry struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// containerDiff names one container-level change within a workload entry. Kind
// is "init" or "main"; From/To are container policy summaries.
type containerDiff struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

// entryDiff is the field-level change set for one changed workload entry.
type entryDiff struct {
	Label   *changedEntry   `json:"label,omitempty"`
	Secrets *changedEntry   `json:"secrets,omitempty"`
	Added   []containerDiff `json:"containersAdded,omitempty"`
	Removed []containerDiff `json:"containersRemoved,omitempty"`
	Changed []containerDiff `json:"containersChanged,omitempty"`
}

func (e entryDiff) empty() bool {
	return e.Label == nil && e.Secrets == nil && len(e.Added) == 0 && len(e.Removed) == 0 && len(e.Changed) == 0
}

// allowlistDiff is the entry-level diff of two allowlists.
type allowlistDiff struct {
	WorkloadsAdded   []string             `json:"workloadsAdded"`
	WorkloadsRemoved []string             `json:"workloadsRemoved"`
	WorkloadsChanged map[string]entryDiff `json:"workloadsChanged"`
}

func (d allowlistDiff) empty() bool {
	return len(d.WorkloadsAdded) == 0 && len(d.WorkloadsRemoved) == 0 && len(d.WorkloadsChanged) == 0
}

// diffAllowlists computes the entry- and field-level diff of desired over live.
func diffAllowlists(live, desired *pkgallowlist.Allowlist) allowlistDiff {
	d := allowlistDiff{WorkloadsChanged: map[string]entryDiff{}}
	for name, dw := range desired.Workloads {
		lw, ok := live.Workloads[name]
		if !ok {
			d.WorkloadsAdded = append(d.WorkloadsAdded, name)
			continue
		}
		if ed := diffEntry(lw, dw); !ed.empty() {
			d.WorkloadsChanged[name] = ed
		}
	}
	for name := range live.Workloads {
		if _, ok := desired.Workloads[name]; !ok {
			d.WorkloadsRemoved = append(d.WorkloadsRemoved, name)
		}
	}
	sort.Strings(d.WorkloadsAdded)
	sort.Strings(d.WorkloadsRemoved)
	return d
}

// diffEntry compares two workload entries field by field.
func diffEntry(live, desired pkgallowlist.Workload) entryDiff {
	var ed entryDiff
	if live.Label != desired.Label {
		ed.Label = &changedEntry{From: live.Label, To: desired.Label}
	}
	if from, to := secretsGrant(live.Secrets), secretsGrant(desired.Secrets); from != to {
		ed.Secrets = &changedEntry{From: from, To: to}
	}
	added, removed, changed := diffContainers("init", live.InitContainers, desired.InitContainers)
	ed.Added, ed.Removed, ed.Changed = added, removed, changed
	a2, r2, c2 := diffContainers("main", live.Containers, desired.Containers)
	ed.Added = append(ed.Added, a2...)
	ed.Removed = append(ed.Removed, r2...)
	ed.Changed = append(ed.Changed, c2...)
	return ed
}

// diffContainers diffs two container lists grouped by digest. When a digest has
// exactly one dropped and one introduced policy it is reported as a change;
// otherwise the policies are reported as separate additions/removals.
func diffContainers(kind string, live, desired []pkgallowlist.Container) (added, removed, changed []containerDiff) {
	liveByDigest := groupPolicies(live)
	desiredByDigest := groupPolicies(desired)

	digests := map[string]bool{}
	for d := range liveByDigest {
		digests[d] = true
	}
	for d := range desiredByDigest {
		digests[d] = true
	}
	ordered := slices.Sorted(maps.Keys(digests))

	for _, digest := range ordered {
		onlyDesired := multisetSub(desiredByDigest[digest], liveByDigest[digest])
		onlyLive := multisetSub(liveByDigest[digest], desiredByDigest[digest])
		if len(onlyDesired) == 1 && len(onlyLive) == 1 {
			changed = append(changed, containerDiff{Kind: kind, Digest: digest, From: policySummary(onlyLive[0]), To: policySummary(onlyDesired[0])})
			continue
		}
		for _, s := range onlyDesired {
			added = append(added, containerDiff{Kind: kind, Digest: digest, To: policySummary(s)})
		}
		for _, s := range onlyLive {
			removed = append(removed, containerDiff{Kind: kind, Digest: digest, From: policySummary(s)})
		}
	}
	return added, removed, changed
}

func groupPolicies(cs []pkgallowlist.Container) map[string][]string {
	out := map[string][]string{}
	for _, c := range cs {
		d := c.Digest.String()
		// Comparison uses framed JSON, not an ambiguous human argv rendering.
		b, _ := json.Marshal(struct {
			Command pkgallowlist.ArgvPolicy  `json:"command"`
			Args    pkgallowlist.ArgvPolicy  `json:"args"`
			Mounts  pkgallowlist.MountPolicy `json:"mounts"`
			Env     pkgallowlist.EnvPolicy   `json:"env"`
		}{c.Command, c.Args, c.Mounts, c.Env})
		out[d] = append(out[d], string(b))
	}
	return out
}

func policySummary(key string) string {
	var c pkgallowlist.Container
	_ = json.Unmarshal([]byte(key), &c)
	return containerSummary(c)
}

// secretsGrant renders a grant in full for display and comparison; parsing has
// already sorted and deduplicated its globs. Paths are quoted, since a path may
// itself contain a comma.
func secretsGrant(p *pkgallowlist.SecretsPolicy) string {
	if p == nil {
		return pkgallowlist.PolicyDeny
	}
	s := fmt.Sprintf("%s read=%q", p.Policy, p.Read)
	if len(p.Write) > 0 {
		s += fmt.Sprintf(" write=%q", p.Write)
	}
	return s
}

// multisetSub returns the elements of a not covered by an equal element of b,
// respecting multiplicity.
func multisetSub(a, b []string) []string {
	counts := map[string]int{}
	for _, s := range b {
		counts[s]++
	}
	var out []string
	for _, s := range a {
		if counts[s] > 0 {
			counts[s]--
			continue
		}
		out = append(out, s)
	}
	return out
}

func printDiff(w io.Writer, format string, d allowlistDiff) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	}
	if d.empty() {
		fmt.Fprintln(w, "no changes")
		return nil
	}

	fmt.Fprintln(w, "workloads:")
	for _, name := range d.WorkloadsAdded {
		fmt.Fprintf(w, "+ %s\n", name)
	}
	for _, name := range d.WorkloadsRemoved {
		fmt.Fprintf(w, "- %s\n", name)
	}
	changedNames := slices.Sorted(maps.Keys(d.WorkloadsChanged))
	for _, name := range changedNames {
		fmt.Fprintf(w, "~ %s\n", name)
		printEntryDiff(w, d.WorkloadsChanged[name])
	}
	return nil
}

func printEntryDiff(w io.Writer, e entryDiff) {
	if e.Label != nil {
		fmt.Fprintf(w, "    label: %q -> %q\n", e.Label.From, e.Label.To)
	}
	if e.Secrets != nil {
		fmt.Fprintf(w, "    secrets: %s -> %s\n", e.Secrets.From, e.Secrets.To)
	}
	for _, c := range e.Added {
		fmt.Fprintf(w, "    + %s %s %s\n", c.Kind, c.Digest, c.To)
	}
	for _, c := range e.Removed {
		fmt.Fprintf(w, "    - %s %s %s\n", c.Kind, c.Digest, c.From)
	}
	for _, c := range e.Changed {
		fmt.Fprintf(w, "    ~ %s %s  %s -> %s\n", c.Kind, c.Digest, c.From, c.To)
	}
}
