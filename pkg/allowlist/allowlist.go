// Package allowlist defines the CDS-served image allowlist and its deterministic
// canonical serialization.
//
// The allowlist is a map of named workload entries. Each entry pins an
// init/main container set; every container binds a digest to the process
// (argv), bind-mount and environment policy permitted for those bytes, and the
// entry as a whole carries a secret-store grant. An image that may run however
// it is invoked — a standalone or injected c8s component, whose argv is
// per-pod — is an entry whose container policy is any. Policy is always looked
// up by container digest — the entry name and image labels are informational,
// never a trust-bearing key, because the image reference a pod presents is
// chosen by the untrusted host while the digest is bound to the bytes that run.
//
// Canonical is Go's json.Marshal of the normalized struct: fixed field order,
// map keys sorted by encoding/json, container and path lists sorted by
// normalize. Workers compare it byte-for-byte across pulls, so any
// nondeterminism would show up as spurious churn — normalize exists to remove
// it.
package allowlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Schema identifies the allowlist document format. It is the first field of the
// canonical form.
const Schema = "c8s.allowlist/v1"

// Policy values. Argv policies use Deny/Any/Exact; secrets grants use
// Deny/Allow — never Any (normalizeSecrets).
const (
	PolicyDeny  = "deny"
	PolicyAny   = "any"
	PolicyExact = "exact"
	PolicyMatch = "match"
	PolicyAllow = "allow"
)

// The yaml tags mirror the json ones so a document embeds in a YAML config
// (the NRI plugin's base allowlist) in the same shape it has on the wire.
//
// Allowlist is the complete image allowlist.
type Allowlist struct {
	Schema    string              `json:"schema" yaml:"schema"`
	Workloads map[string]Workload `json:"workloads" yaml:"workloads"`
}

// Workload is a named policy entry. Label is an informational image reference.
// Secrets is nil when the entry grants nothing, which is what a "deny" grant
// normalizes to: an entry that releases nothing carries no "secrets" key at
// all, so a consumer that does not know the field never sees it.
type Workload struct {
	Label          string         `json:"label,omitempty" yaml:"label,omitempty"`
	InitContainers []Container    `json:"initContainers" yaml:"initContainers,omitempty"`
	Containers     []Container    `json:"containers" yaml:"containers"`
	Secrets        *SecretsPolicy `json:"secrets,omitempty" yaml:"secrets,omitempty"`
}

// Container binds a digest to the process policy permitted for it.
type Container struct {
	Digest  types.Digest `json:"digest" yaml:"digest"`
	Image   string       `json:"image,omitempty" yaml:"image,omitempty"`
	Command ArgvPolicy   `json:"command" yaml:"command"`
	Args    ArgvPolicy   `json:"args" yaml:"args"`
	Mounts  MountPolicy  `json:"mounts" yaml:"mounts,omitempty"`
	Env     EnvPolicy    `json:"env" yaml:"env,omitempty"`
}

// ArgvPolicy governs part of a container's effective argv (the OCI process.args
// a pod actually runs), mirroring the Kubernetes command/args split: Command is
// matched as an exact prefix of the argv, and Args governs the remainder after
// it. Exact requires equality, Any leaves it unconstrained, Deny requires it to
// be empty. An absent policy defaults to Deny.
type ArgvPolicy struct {
	Policy string   `json:"policy" yaml:"policy"`
	Argv   []string `json:"argv,omitempty" yaml:"argv,omitempty"`
}

// MountPolicy governs bind mounts present at final OCI launch. An absent policy
// is Deny: only verified platform mounts are admitted. Exact requires the
// observed non-platform mount set to equal Rules. Any explicitly leaves mounts
// unconstrained.
type MountPolicy struct {
	Policy string      `json:"policy" yaml:"policy"`
	Rules  []MountRule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

// MountRule pins one non-platform mount by destination and source kind.
type MountRule struct {
	Destination string     `json:"destination" yaml:"destination"`
	Kind        MountClass `json:"kind" yaml:"kind"`
	Source      string     `json:"source,omitempty" yaml:"source,omitempty"`
	ReadOnly    bool       `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
}

// MountClass identifies who controls the content behind a bind mount.
type MountClass string

const (
	MountPlatform MountClass = "platform"
	MountEmptyDir MountClass = "emptyDir"
	MountData     MountClass = "data"
	MountHost     MountClass = "host"
)

// MountStorage records the storage guarantee established by the node.
type MountStorage string

const (
	MountMemory    MountStorage = "memory"
	MountEncrypted MountStorage = "encrypted"
	MountUnknown   MountStorage = "unknown"
)

// DataMountPrefix is reserved for operator-supplied data.
const DataMountPrefix = "/mnt/c8s-data/"

// EnvPolicy constrains the complete OCI launch environment. An absent policy means Any.
type EnvPolicy struct {
	Policy    string                `json:"policy" yaml:"policy"`
	Values    map[string]string     `json:"values,omitempty" yaml:"values,omitempty"`
	Variables map[string]EnvMatcher `json:"variables,omitzero" yaml:"variables,omitempty"`
}

// SecretsPolicy grants secret-store read/write globs to a whole workload entry.
// The subject is the entry, not a container: the value is delivered on a volume
// every container in the pod can read, so a per-container grant would not
// describe what is actually released. See docs/secrets.md.
type SecretsPolicy struct {
	Policy string   `json:"policy" yaml:"policy"`
	Read   []string `json:"read,omitempty" yaml:"read,omitempty"`
	Write  []string `json:"write,omitempty" yaml:"write,omitempty"`
}

// ParseJSON decodes and validates an operator-authored allowlist, rejecting
// unknown fields so a typo or a foreign document fails loud instead of parsing
// as empty. The result is normalized (digests lowercased and deduplicated,
// container and path lists sorted) so Canonical is a function of content alone.
//
// Use ParseServedJSON for a document pulled from CDS.
func ParseJSON(data []byte) (*Allowlist, error) {
	return parseJSON(data, true)
}

// ParseServedJSON decodes a document served by CDS, ignoring fields it does not
// know. Its consumers pin a schema version in a launch measurement, so a strict
// parse would make any newer field freeze their policy until a node-image
// rebuild. See docs/secrets.md — "Upgrading".
func ParseServedJSON(data []byte) (*Allowlist, error) {
	return parseJSON(data, false)
}

func parseJSON(data []byte, strict bool) (*Allowlist, error) {
	if err := validateJSON(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if strict {
		dec.DisallowUnknownFields()
	}
	var a Allowlist
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("decode allowlist: %w", err)
	}
	if err := a.normalize(strict); err != nil {
		return nil, err
	}
	return &a, nil
}

// Normalize validates and canonicalizes a document decoded outside ParseJSON
// (the NRI plugin's YAML boot config), under the same strict ingest posture.
func (a *Allowlist) Normalize() error {
	return a.normalize(true)
}

// ParseWorkloadJSON decodes and validates a single workload entry — the body of
// a PUT /allowlist/workloads/{name} — applying the same normalization as
// ParseJSON so a stored entry is canonical.
func ParseWorkloadJSON(data []byte) (*Workload, error) {
	if err := validateJSON(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w Workload
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("decode workload: %w", err)
	}
	if err := normalizeContainers("entry", "initContainers", w.InitContainers); err != nil {
		return nil, err
	}
	if err := normalizeContainers("entry", "containers", w.Containers); err != nil {
		return nil, err
	}
	if err := normalizeSecrets(&w.Secrets); err != nil {
		return nil, fmt.Errorf("entry secrets: %w", err)
	}
	if w.Secrets != nil && !w.ArgvPinned() {
		return nil, fmt.Errorf("entry: %w", errGrantUnpinned)
	}
	sortContainers(w.InitContainers)
	sortContainers(w.Containers)
	return &w, nil
}

// errGrantUnpinned refuses a secrets grant on an entry that leaves any
// container's argv to the host.
var errGrantUnpinned = fmt.Errorf("a secrets grant requires every container's command and args policy to be exact or deny")

// Digests returns every container digest in the workload (init and main), for
// building a digest index.
func (w Workload) Digests() []types.Digest {
	out := make([]types.Digest, 0, len(w.InitContainers)+len(w.Containers))
	for _, c := range w.InitContainers {
		out = append(out, c.Digest)
	}
	for _, c := range w.Containers {
		out = append(out, c.Digest)
	}
	return out
}

// AnyArgv reports whether the container is admitted whatever it runs: command
// and args both any.
func (c Container) AnyArgv() bool {
	return (processConstraint{command: &c.Command, args: &c.Args}).isUnconstrained()
}

// IsUnconstrained reports whether process, mounts and environment are all left
// to the host. Absent mounts normalize to Deny; absent environment normalizes
// to Any.
func (c Container) IsUnconstrained() bool {
	for _, constraint := range c.constraints() {
		if !constraint.isUnconstrained() {
			return false
		}
	}
	return true
}

// ArgvPinned reports whether every container's command and args policy is
// exact or deny, so nothing about the entry's argv is left to the host. A
// secrets grant requires it (docs/secrets.md).
func (w Workload) ArgvPinned() bool {
	for _, c := range w.containers() {
		if !(processConstraint{command: &c.Command, args: &c.Args}).hostIndependent() {
			return false
		}
	}
	return true
}

// HostIndependent reports whether every runtime field that can change what a
// container executes or reads is constrained independently of the host.
func (w Workload) HostIndependent() bool {
	containers := w.containers()
	for i := range containers {
		c := containers[i]
		for _, constraint := range c.constraints() {
			if !constraint.hostIndependent() {
				return false
			}
		}
	}
	return true
}

// containers is the init containers followed by the main containers.
func (w Workload) containers() []Container {
	return slices.Concat(w.InitContainers, w.Containers)
}

// AdmitsAnyArgv reports whether some entry admits the digest under an
// unconstrained argv policy. The injected-container drop set (internal/secrets)
// keys on it: c8s's own images run with per-pod arguments, so they are only
// ever admitted this way.
func (a *Allowlist) AdmitsAnyArgv(digest string) bool {
	d, err := types.ParseDigest(digest)
	if err != nil {
		return false
	}
	for _, w := range a.Workloads {
		for _, c := range w.containers() {
			if c.Digest == d && c.AnyArgv() {
				return true
			}
		}
	}
	return false
}

// DigestEntry is the entry that admits an image under any command line: one
// container at digest, labelled with the image reference. The chart seeds one
// per bootstrap digest and `c8s allowlist add` writes one.
func DigestEntry(digest types.Digest, image string) Workload {
	return Workload{
		Label:          image,
		InitContainers: []Container{},
		Containers: []Container{{
			Digest:  digest,
			Image:   image,
			Command: ArgvPolicy{Policy: PolicyAny},
			Args:    ArgvPolicy{Policy: PolicyAny},
			Mounts:  MountPolicy{Policy: PolicyAny},
			Env:     EnvPolicy{Policy: PolicyAny},
		}},
	}
}

// DigestEntryName names a DigestEntry: the image reference's last path segment
// with any tag or digest stripped ("image" when that is not a legal name), then
// the first 12 hex digits of the digest. Must match the chart's
// c8s.digestWorkloadName.
func DigestEntryName(digest types.Digest, image string) string {
	base, _, _ := strings.Cut(image, "@")
	base = base[strings.LastIndex(base, "/")+1:]
	base, _, _ = strings.Cut(base, ":")
	if len(base) > 50 {
		base = base[:50]
	}
	if !ValidWorkloadName(base) {
		base = "image"
	}
	return base + "-" + digest.Hex()[:12]
}

// Canonical returns the canonical byte serialization: json.Marshal of the
// normalized struct.
func (a *Allowlist) Canonical() ([]byte, error) {
	return json.Marshal(a)
}

// CanonicalDigest returns SHA-256 over Canonical() — the policy digest clients
// pin and the matched-workload stamp carries (docs/ratls.md).
func (a *Allowlist) CanonicalDigest() ([]byte, error) {
	canonical, err := a.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

// normalize canonicalizes the document. strict is the write/ingest posture
// (ParseJSON): it enforces MaxWorkloadNameLen, so no entry that the cw selector
// or the leaf stamp cannot represent ever enters the store. A served document
// (ParseServedJSON) is not ours to reject over that bound — it arrived after
// entries could already have been written, and failing the whole document would
// break every allowlist pull in the cluster over one legacy name — so an
// over-long entry is dropped instead. See docs/allowlist-and-capabilities.md.
func (a *Allowlist) normalize(strict bool) error {
	if a.Schema != Schema {
		return fmt.Errorf("allowlist: unknown schema %q (expected %q)", a.Schema, Schema)
	}
	for name, w := range a.Workloads {
		// The grammar is not negotiable on either path: the name is used
		// verbatim as a URL path segment.
		if !workloadNameGrammarOK(name) {
			return fmt.Errorf("workload name %q must match [A-Za-z0-9][A-Za-z0-9._-]* (it is a URL path segment)", name)
		}
		if len(name) > MaxWorkloadNameLen {
			if strict {
				return fmt.Errorf("workload name %q is %d bytes; the maximum is %d (it is mirrored as a Kubernetes label value)", name, len(name), MaxWorkloadNameLen)
			}
			// Dropping is fail-closed: the entry's digests stop being admitted
			// by this consumer. It could never have been named on a leaf either
			// (ratls.MatchedWorkload.Validate applies the same bound), so
			// nothing that depended on it is lost.
			slog.Warn("allowlist: dropping a served workload entry whose name exceeds the label-value bound",
				"name", name, "bytes", len(name), "max", MaxWorkloadNameLen)
			delete(a.Workloads, name)
			continue
		}
		if err := normalizeContainers(name, "initContainers", w.InitContainers); err != nil {
			return err
		}
		if err := normalizeContainers(name, "containers", w.Containers); err != nil {
			return err
		}
		if err := normalizeSecrets(&w.Secrets); err != nil {
			return fmt.Errorf("workload %q secrets: %w", name, err)
		}
		if strict && w.Secrets != nil && !w.ArgvPinned() {
			return fmt.Errorf("workload %q: %w", name, errGrantUnpinned)
		}
		sortContainers(w.InitContainers)
		sortContainers(w.Containers)
		a.Workloads[name] = w
	}
	return nil
}

func normalizeContainers(workload, field string, cs []Container) error {
	for i := range cs {
		c := &cs[i]
		if c.Digest.String() == "" {
			return fmt.Errorf("workload %q %s[%d]: digest is required", workload, field, i)
		}
		for _, constraint := range c.constraints() {
			if policyField, err := constraint.normalize(); err != nil {
				return fmt.Errorf("workload %q %s %s %s: %w", workload, field, c.Digest, policyField, err)
			}
		}
	}
	return nil
}

// normalizeMounts validates and canonicalizes a mount policy. An absent policy
// becomes Deny; verified platform mounts are part of that policy's baseline.
func normalizeMounts(p *MountPolicy) error {
	switch p.Policy {
	case PolicyAny, PolicyDeny, "":
		if len(p.Rules) != 0 {
			return fmt.Errorf("%s policy takes no rules", p.Policy)
		}
		if p.Policy == "" {
			p.Policy = PolicyDeny
		}
		p.Rules = nil
	case PolicyExact:
		return normalizeMountRules(p.Rules)
	default:
		return fmt.Errorf("unknown mount policy %q (want deny, any, or exact)", p.Policy)
	}
	return nil
}

func normalizeMountRules(rules []MountRule) error {
	if len(rules) == 0 {
		return fmt.Errorf("exact policy requires at least one rule")
	}
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if !path.IsAbs(r.Destination) || path.Clean(r.Destination) != r.Destination {
			return fmt.Errorf("destination %q is not a clean absolute path", r.Destination)
		}
		if seen[r.Destination] {
			return fmt.Errorf("duplicate mount destination %q", r.Destination)
		}
		seen[r.Destination] = true
		if err := validateMountRuleKind(r); err != nil {
			return err
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Destination < rules[j].Destination })
	return nil
}

func validateMountRuleKind(r MountRule) error {
	behavior := r.behavior()
	if behavior == nil {
		return fmt.Errorf("mount destination %q has unsupported kind %q", r.Destination, r.Kind)
	}
	return behavior.validate()
}

// normalizeArgv validates an argv policy and canonicalizes an absent policy to
// Deny, so a minimally-specified container is maximally restrictive.
func normalizeArgv(p *ArgvPolicy) error {
	switch p.Policy {
	case PolicyDeny, PolicyAny:
		if len(p.Argv) != 0 {
			return fmt.Errorf("%s policy takes no argv", p.Policy)
		}
		p.Argv = nil
	case PolicyExact:
		if len(p.Argv) == 0 {
			return fmt.Errorf("exact policy requires a non-empty argv")
		}
	case "":
		p.Policy = PolicyDeny
		p.Argv = nil
	default:
		return fmt.Errorf("unknown argv policy %q (want deny, any, or exact)", p.Policy)
	}
	return nil
}

// normalizeSecrets validates an entry's secrets grant, canonicalizing "grants
// nothing" to a nil grant so it does not appear on the wire at all.
//
// Unlike argv policy there is no "any": an unbounded secret grant is never what
// an operator means, and the same three characters that are inert today would
// otherwise become "every secret in the cluster".
func normalizeSecrets(pp **SecretsPolicy) error {
	p := *pp
	if p == nil {
		return nil
	}
	switch p.Policy {
	case PolicyDeny, "":
		if len(p.Read) != 0 || len(p.Write) != 0 {
			return fmt.Errorf("deny policy grants no paths")
		}
		*pp = nil
	case PolicyAllow:
		read, err := normalizeGlobs(p.Read)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		write, err := normalizeGlobs(p.Write)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
		if len(read) == 0 {
			// The only client creates with POST and then re-reads: a write-only
			// grant leaves every replica that loses the create race permanently
			// without the value.
			return fmt.Errorf("allow policy requires at least one read path")
		}
		p.Read, p.Write = read, write
	default:
		return fmt.Errorf("unknown secrets policy %q (want deny or allow)", p.Policy)
	}
	return nil
}

// normalizeGlobs validates that every path is absolute and clean, dedupes, and
// sorts. A trailing "/**" (subtree match) is the only wildcard form permitted.
func normalizeGlobs(globs []string) ([]string, error) {
	seen := make(map[string]struct{}, len(globs))
	out := make([]string, 0, len(globs))
	for _, g := range globs {
		if !strings.HasPrefix(g, "/") {
			return nil, fmt.Errorf("path %q must be absolute", g)
		}
		base := strings.TrimSuffix(g, "/**")
		if base == "" {
			base = "/"
		}
		if strings.Contains(base, "*") {
			return nil, fmt.Errorf("path %q: the only wildcard is a trailing /**", g)
		}
		if path.Clean(base) != base {
			return nil, fmt.Errorf("path %q is not clean (no . or ..)", g)
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// sortContainers orders a container list by digest, then by a stable rendering
// of its policy, so a set is serialized identically regardless of input order.
// Duplicate digests are permitted: one image may run under several argv policies
// (e.g. a shared base image invoked differently by different workloads).
func sortContainers(cs []Container) {
	sort.SliceStable(cs, func(i, j int) bool {
		di, dj := cs[i].Digest.String(), cs[j].Digest.String()
		if di != dj {
			return di < dj
		}
		return policyKey(cs[i]) < policyKey(cs[j])
	})
}

func policyKey(c Container) string {
	b, _ := json.Marshal([]any{c.Command, c.Args, c.Mounts, c.Env})
	return string(b)
}

// MaxWorkloadNameLen bounds an entry name to the Kubernetes label-value length,
// so the confidential.ai/cw selector, an allowlist entry name, and the
// matched-workload leaf stamp (pkg/ratls) can all represent it. It is enforced
// where entries are written, not where a served document is read — see
// normalize.
const MaxWorkloadNameLen = 63

// workloadNameGrammarOK restricts entry names to a URL-safe segment so a name
// can be used verbatim as a path parameter without escaping ambiguity. It does
// not apply MaxWorkloadNameLen; ValidWorkloadName is the bounded form.
func workloadNameGrammarOK(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case (b == '.' || b == '_' || b == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// ValidWorkloadName reports whether name is a legal workload entry name: the
// URL-path-segment grammar, bounded to MaxWorkloadNameLen. It is the check the
// write path, the admission selector, and the matched-workload certificate
// stamp share.
//
// It is not identical to what every consumer accepts: a name may end in '.',
// '_' or '-' here and still fail k8s validation.IsValidLabelValue, which the
// injection webhook applies to the cw label. Tightening the grammar to close
// that gap would retroactively invalidate stored entries, so the narrower rule
// stays where it is enforced.
func ValidWorkloadName(name string) bool {
	return workloadNameGrammarOK(name) && len(name) <= MaxWorkloadNameLen
}
