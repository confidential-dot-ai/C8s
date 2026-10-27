// Package allowlist defines the CDS-served image allowlist and its deterministic
// canonical serialization.
//
// The allowlist is a map of named workload entries. Each entry pins an
// init/main container set; every container binds a digest to the process
// (argv), bind-mount and environment policy permitted for those bytes, and the
// entry as a whole carries a secret-store grant and its declared exits. An image that may run however
// it is invoked is an entry whose container policy is any. Policy is always looked
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
	"net/netip"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadname"
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
	// Egress are the exits a pod this entry matches may reach outside the
	// mesh. Like a secrets grant it belongs to the whole entry.
	Egress EgressList `json:"egress,omitempty" yaml:"egress,omitempty"`
}

// minEgressBits4 and minEgressBits6 are the broadest range an exit may name.
// A single address (/32, /128) is the expected use.
const (
	minEgressBits4 = 16
	minEgressBits6 = 48
)

// MaxEgress bounds an entry's exits: each is a way out of the TEE that a
// relying party has to weigh, and one rule per exit in every chain.
const MaxEgress = 8

// Egress is one declared exit: a range and a TCP port. The canonical text of
// the range is its RFC 5952 form (lower case, zeros compressed), whatever
// spelling the author wrote.
type Egress struct {
	CIDR netip.Prefix `json:"cidr" yaml:"cidr"`
	Port uint16       `json:"port" yaml:"port"`
}

// EgressList is an entry's exits. Each exit decodes strictly: an exit with a
// member other than cidr and port, or a value of the wrong type, and an egress
// value that is not a list, decode as one empty exit, which normalizeEgress
// refuses. So a strict parse rejects the document, and a lenient parse drops
// the list (the entry grants no exit) instead of failing the whole document or
// granting an exit without a member a newer schema narrows it with.
type EgressList []Egress

// UnmarshalJSON never fails: what does not decode is the empty exit above.
func (l *EgressList) UnmarshalJSON(data []byte) error {
	*l = EgressList{{}}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil
	}
	list := make(EgressList, 0, len(items))
	for _, item := range items {
		dec := json.NewDecoder(bytes.NewReader(item))
		dec.DisallowUnknownFields()
		var e Egress
		if err := dec.Decode(&e); err != nil {
			return nil
		}
		list = append(list, e)
	}
	*l = list
	return nil
}

// Container binds a digest to the process policy permitted for it.
//
// Role names the platform role an enforcer grants to these bytes under this
// policy. It is YAML-only: a document on the wire carries no role, so a role
// comes from a measured boot config and nothing a CDS serves can claim one.
type Container struct {
	Digest  types.Digest `json:"digest" yaml:"digest"`
	Image   string       `json:"image,omitempty" yaml:"image,omitempty"`
	Role    string       `json:"-" yaml:"role,omitempty"`
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
	// Node marks a data rule of a node component's own volume, which may sit
	// outside DataMountPrefix. YAML-only, like Container.Role: only a measured
	// boot config sets it, and the JSON ingest rejects it.
	Node bool `json:"-" yaml:"node,omitempty"`
	// VerityDigest is reserved for fs-verity and rejected for now.
	VerityDigest string `json:"verityDigest,omitempty" yaml:"verityDigest,omitempty"`
}

// MountClass identifies who controls the content behind a bind mount.
type MountClass string

const (
	MountPlatform MountClass = "platform"
	MountEmptyDir MountClass = "emptyDir"
	MountData     MountClass = "data"
	MountHost     MountClass = "host"
	// MountNodeRootFile is a rule kind only: it admits a read-only host file
	// bind that carries ProvenanceNodeRoot evidence. It is a kind rather than a
	// field on a host rule so that an enforcer predating it refuses the served
	// document instead of applying the rule as a plain host rule.
	MountNodeRootFile MountClass = "nodeRootFile"
)

// ProvenanceNodeRoot is mount evidence for a regular file reached through the
// node's measured, read-only dm-verity root.
const ProvenanceNodeRoot = "node-root"

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
	// ServiceLinks lets a match policy admit, unlisted, the variables the
	// kubelet derives from the Services of the pod's namespace
	// (ServiceLinkName). Which of them a container gets depends on which
	// Services existed when it started, so a node component's entry cannot
	// list them. YAML-only, like Container.Role: only a measured boot config
	// sets it, and the JSON ingest rejects it.
	ServiceLinks bool `json:"-" yaml:"serviceLinks,omitempty"`
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
	if err := strictjson.Validate(data); err != nil {
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
	if err := a.refuseVolumeBindings(); err != nil {
		return nil, err
	}
	if err := a.normalize(strict); err != nil {
		return nil, err
	}
	return &a, nil
}

// refuseVolumeBindings refuses a document that names a pod volume on an
// emptyDir or data rule. The binding belongs to a measured boot config, which
// is YAML: nothing that arrives as JSON names a volume, so a served or
// authored document carrying one is refused rather than read as a narrower
// policy than the format defines.
func (a *Allowlist) refuseVolumeBindings() error {
	for name, w := range a.Workloads {
		if err := w.refuseVolumeBindings(); err != nil {
			return fmt.Errorf("workload %q: %w", name, err)
		}
	}
	return nil
}

func (w Workload) refuseVolumeBindings() error {
	for _, c := range w.containers() {
		for _, rule := range c.Mounts.Rules {
			if rule.Source == "" || !rule.bindsVolume() {
				continue
			}
			return fmt.Errorf("mount kind %q at %s names a volume, which only a measured base binds", rule.Kind, rule.Destination)
		}
	}
	return nil
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
	if err := strictjson.Validate(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w Workload
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("decode workload: %w", err)
	}
	if err := w.refuseVolumeBindings(); err != nil {
		return nil, fmt.Errorf("entry: %w", err)
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
	if w.Secrets != nil {
		if err := w.PinnedForGrant(); err != nil {
			return nil, fmt.Errorf("entry: %w", err)
		}
	}
	if err := w.CheckVariableEvidenceBudget(); err != nil {
		return nil, fmt.Errorf("entry: %w", err)
	}
	if err := normalizeEgress(&w.Egress); err != nil {
		return nil, fmt.Errorf("entry egress: %w", err)
	}
	if err := w.PinnedForEgress(); err != nil {
		return nil, fmt.Errorf("entry: %w", err)
	}
	sortContainers(w.InitContainers)
	sortContainers(w.Containers)
	return &w, nil
}

var (
	errGrantUnpinnedArgv   = fmt.Errorf("a secrets grant requires every container's command and args policy to be exact or deny")
	errGrantUnpinnedMounts = fmt.Errorf("a secrets grant requires every container's mounts policy to be deny, or exact without host rules (read-only nodeRootFile rules are allowed)")
)

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

// MountsPinned reports whether every container's mounts policy is deny, or
// exact with no host rule other than a read-only nodeRootFile, so the host adds
// no mount and chooses no content. A data rule still mounts content the cluster
// chooses (a ConfigMap, a PVC) at a destination the entry declares. A secrets
// grant requires it (docs/secrets.md).
func (w Workload) MountsPinned() bool {
	for _, c := range w.containers() {
		if !(mountConstraint{policy: &c.Mounts}).grantPinned() {
			return false
		}
	}
	return true
}

// PinnedForGrant reports why a secrets grant on w would release a value to a
// launch the host shaped, or nil when the entry pins its argv and mounts. Env
// is not required until a policy can pin it on a real pod: exact fingerprints
// the whole environment, including the pod-specific HOSTNAME.
func (w Workload) PinnedForGrant() error {
	if !w.ArgvPinned() {
		return errGrantUnpinnedArgv
	}
	if !w.MountsPinned() {
		return errGrantUnpinnedMounts
	}
	return nil
}

// PinnedForEgress reports why declared exits on w would carry out of the TEE
// whatever a launch the host shaped sends, or nil when the entry declares
// none or pins its argv and mounts as a secrets grant must.
func (w Workload) PinnedForEgress() error {
	if len(w.Egress) == 0 {
		return nil
	}
	if err := w.PinnedForGrant(); err != nil {
		return fmt.Errorf("declared egress needs the launch pinned as a secrets grant does: %w", err)
	}
	return nil
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

// DigestEntry is the entry that admits an image under any command line: one
// container at digest, labelled with the image reference. `c8s allowlist add`
// writes one; the chart's component entries pin their entrypoint instead.
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
	if !workloadname.Valid(base) {
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
// pin and the matched-workload stamp carries (docs/armtls.md).
func (a *Allowlist) CanonicalDigest() ([]byte, error) {
	canonical, err := a.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return sum[:], nil
}

// normalize canonicalizes the document. strict is the write/ingest posture
// (ParseJSON): it enforces workloadname.MaxLen, so no entry that the cw selector
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
		if !workloadname.ValidGrammar(name) {
			return fmt.Errorf("workload name %q must match [A-Za-z0-9][A-Za-z0-9._-]* (it is a URL path segment)", name)
		}
		if len(name) > workloadname.MaxLen {
			if strict {
				return fmt.Errorf("workload name %q is %d bytes; the maximum is %d (it is mirrored as a Kubernetes label value)", name, len(name), workloadname.MaxLen)
			}
			// Dropping is fail-closed: the entry's digests stop being admitted
			// by this consumer. It could never have been named on a leaf either
			// (armtls.MatchedWorkload.Validate applies the same bound), so
			// nothing that depended on it is lost.
			slog.Warn("allowlist: dropping a served workload entry whose name exceeds the label-value bound",
				"name", name, "bytes", len(name), "max", workloadname.MaxLen)
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
		if strict && w.Secrets != nil {
			if err := w.PinnedForGrant(); err != nil {
				return fmt.Errorf("workload %q: %w", name, err)
			}
		}
		if err := w.CheckVariableEvidenceBudget(); strict && err != nil {
			return fmt.Errorf("workload %q: %w", name, err)
		}
		if err := normalizeEgress(&w.Egress); err != nil {
			if strict {
				return fmt.Errorf("workload %q egress: %w", name, err)
			}
			// Dropping is fail-closed: the entry grants no exit.
			slog.Warn("allowlist: dropping a served workload entry's egress this consumer cannot validate",
				"name", name, "error", err)
			w.Egress = nil
		}
		if err := w.PinnedForEgress(); strict && err != nil {
			return fmt.Errorf("workload %q: %w", name, err)
		}
		sortContainers(w.InitContainers)
		sortContainers(w.Containers)
		a.Workloads[name] = w
	}
	return nil
}

// nonUnicastRanges are what an exit must not overlap: this network, loopback,
// link-local, multicast, reserved and broadcast, and the IPv6 forms that
// stand for or embed IPv4 addresses (IPv4-compatible, IPv4-mapped, SIIT,
// NAT64, Teredo, 6to4). Overlapping one of them also refuses /0.
var nonUnicastRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// NonUnicastOverlap returns the first range of addresses no exit may name
// that p overlaps.
func NonUnicastOverlap(p netip.Prefix) (netip.Prefix, bool) {
	for _, special := range nonUnicastRanges {
		if p.Overlaps(special) {
			return special, true
		}
	}
	return netip.Prefix{}, false
}

// normalizeEgress validates an entry's exits and sorts them. An empty list
// becomes nil, so an entry with no exit carries no "egress" key.
func normalizeEgress(exits *EgressList) error {
	list := *exits
	if len(list) == 0 {
		*exits = nil
		return nil
	}
	if len(list) > MaxEgress {
		return fmt.Errorf("%d exits; the maximum is %d", len(list), MaxEgress)
	}
	for _, e := range list {
		switch {
		case !e.CIDR.IsValid():
			return fmt.Errorf(`an exit is {"cidr": "<range>", "port": <1-65535>} and nothing else`)
		case e.CIDR.Addr().Is4In6():
			return fmt.Errorf("cidr %s is a 4-in-6 range; write it as IPv4", e.CIDR)
		case e.CIDR != e.CIDR.Masked():
			return fmt.Errorf("cidr %s carries host bits (did you mean %s?)", e.CIDR, e.CIDR.Masked())
		case e.Port == 0:
			return fmt.Errorf("exit %s needs a TCP port", e.CIDR)
		case e.CIDR.Addr().Is4() && e.CIDR.Bits() < minEgressBits4,
			e.CIDR.Addr().Is6() && e.CIDR.Bits() < minEgressBits6:
			return fmt.Errorf("cidr %s is broader than /%d (IPv4) or /%d (IPv6); an exit names a relay, usually one address", e.CIDR, minEgressBits4, minEgressBits6)
		}
		if special, overlaps := NonUnicastOverlap(e.CIDR); overlaps {
			return fmt.Errorf("cidr %s overlaps %s, which is not a range of unicast hosts an exit can name", e.CIDR, special)
		}
	}
	slices.SortFunc(list, func(a, b Egress) int {
		if c := a.CIDR.Addr().Compare(b.CIDR.Addr()); c != 0 {
			return c
		}
		if c := a.CIDR.Bits() - b.CIDR.Bits(); c != 0 {
			return c
		}
		return int(a.Port) - int(b.Port)
	})
	for i := 1; i < len(list); i++ {
		if list[i] == list[i-1] {
			return fmt.Errorf("exit %s port %d is declared twice", list[i].CIDR, list[i].Port)
		}
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
