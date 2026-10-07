package cmdsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// ImagePolicySource selects one complete refvalues JSON document. File and JSON
// use the same format; neither is a newline-separated digest list.
type ImagePolicySource struct {
	File string
	JSON string
}

// IsSet reports whether a complete policy was supplied.
func (s ImagePolicySource) IsSet() bool { return s.File != "" || s.JSON != "" }

// MeasurementPins holds the independent digest/register inputs. Registers
// carries the raw --rtmrs values; which family they apply to is refvalues'. Prefix is "cds-"
// for commands whose flags name CDS explicitly; otherwise it is empty.
type MeasurementPins struct {
	Measurements     []string
	MeasurementsFile string
	Registers        []string
	Prefix           string
}

// MeasurementPinsFromStrings adapts commands that accept comma-separated strings.
func MeasurementPinsFromStrings(measurements, rtmrs, prefix string) MeasurementPins {
	pins := MeasurementPins{Prefix: prefix}
	if measurements != "" {
		pins.Measurements = strings.Split(measurements, ",")
	}
	if rtmrs != "" {
		pins.Registers = strings.Split(rtmrs, ",")
	}
	return pins
}

func (p MeasurementPins) flags() []string {
	var flags []string
	if len(p.Measurements) > 0 {
		flags = append(flags, "--"+p.Prefix+"measurements")
	}
	if p.MeasurementsFile != "" {
		flags = append(flags, "--measurements-file")
	}
	if len(p.Registers) > 0 {
		flags = append(flags, "--"+p.Prefix+"rtmrs")
	}
	return flags
}

// LoadValues loads complete image identities, rejecting independent pin inputs
// before reading a policy. Without a source it returns an empty set.
func (s ImagePolicySource) LoadValues(pins MeasurementPins) (refvalues.ReferenceValues, error) {
	if !s.IsSet() {
		return refvalues.ReferenceValues{}, nil
	}
	if s.File != "" && s.JSON != "" {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file cannot be combined with --image-policy-json")
	}
	if flags := pins.flags(); len(flags) != 0 {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file/--image-policy-json cannot be combined with %s", strings.Join(flags, " or "))
	}
	if s.JSON != "" {
		set, err := refvalues.Parse([]byte(s.JSON))
		if err != nil {
			return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-json: %w", err)
		}
		return set, nil
	}
	set, err := refvalues.Load(s.File)
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file: %w", err)
	}
	return set, nil
}

// ImagePolicyValuesConfig supplies a complete policy and optional platform check.
// PlatformFlag names the caller's platform flag in validation errors.
type ImagePolicyValuesConfig struct {
	Source       ImagePolicySource
	Pins         MeasurementPins
	Platform     string
	PlatformFlag string
}

// LoadImagePolicyValues loads complete identities and checks their TEE against
// the configured platform when one is supplied.
func LoadImagePolicyValues(cfg ImagePolicyValuesConfig) (refvalues.ReferenceValues, error) {
	values, err := cfg.Source.LoadValues(cfg.Pins)
	if err != nil || !cfg.Source.IsSet() {
		return values, err
	}
	if cfg.Platform != "" {
		flag := cfg.platformFlag()
		family, err := teetypes.ParseFamily(cfg.Platform)
		if err != nil {
			return refvalues.ReferenceValues{}, fmt.Errorf("%s: %w", flag, err)
		}
		if family != values.Family {
			return refvalues.ReferenceValues{}, fmt.Errorf("image policy declares tee %q but %s is %q", values.Family, flag, family)
		}
	}
	return values, nil
}

// LoadImagePolicySet is one reference set from whichever form the caller
// configured: a complete policy document, or independent launch digests on the
// configured platform's family, each carrying the register pins. An empty set
// pins nothing; refvalues refuses a register pin the family does not carry
// when the set is rendered or enforced.
func LoadImagePolicySet(cfg ImagePolicyValuesConfig) (refvalues.ReferenceValues, error) {
	if cfg.Source.IsSet() {
		return LoadImagePolicyValues(cfg)
	}
	digests, err := LoadMeasurements(cfg.Pins.Measurements, cfg.Pins.MeasurementsFile)
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("--%smeasurements: %w", cfg.Pins.Prefix, err)
	}
	registers, err := refvalues.ParseRegisterPins(cfg.Pins.Registers)
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("--%srtmrs: %w", cfg.Pins.Prefix, err)
	}
	if len(digests) == 0 {
		if len(registers) > 0 {
			return refvalues.ReferenceValues{}, fmt.Errorf("--%srtmrs pins %d register(s) with no --%smeasurements digest to pin them to", cfg.Pins.Prefix, len(registers), cfg.Pins.Prefix)
		}
		return refvalues.ReferenceValues{}, nil
	}
	family, err := teetypes.ParseFamily(cfg.Platform)
	if err != nil {
		return refvalues.ReferenceValues{}, fmt.Errorf("%s: %w", cfg.platformFlag(), err)
	}
	set := refvalues.FromFlags(digests, registers)
	set.Family = family
	return set, nil
}

// platformFlag names the caller's platform input in an error.
func (cfg ImagePolicyValuesConfig) platformFlag() string {
	if cfg.PlatformFlag == "" {
		return "--platform"
	}
	return cfg.PlatformFlag
}

// ResolveCDSPins returns the pins a client holds its CDS to, and whether the
// node's own policy decided them. resolveNodePolicy states the rule.
func ResolveCDSPins(nodePolicy string, source ImagePolicySource, pins MeasurementPins) (remote.Policy, bool, error) {
	values, fromNode, err := resolveNodePolicy(nodePolicy, suppliedPolicyFlags(source, pins), refvalues.Parse)
	if err != nil {
		return remote.Policy{}, false, err
	}
	if fromNode {
		return values.Policy(), true, nil
	}
	policy, err := source.Load(pins)
	return policy, false, err
}

// RequireNodeVerifier holds a credential client to the node's own
// attestation-api while the enforcer mounts its CDS policy at nodePolicy and
// presents that attestation-api at socket. The verifier is what decides
// whether the CDS a client dials satisfies those pins, so a client answering
// to a named verifier is not pinned at all.
//
// Both paths are the node's own mounts, and the rule is ResolveCDSPins': while
// they are there they are the only source, and a supplied verifier is refused.
// Where the node hands out no policy, or runs no attestation-api a pod can
// reach, the caller's own argument stands.
func RequireNodeVerifier(nodePolicy, socket, supplied string) error {
	pinned, err := nodeProvides(nodePolicy)
	if err != nil {
		return err
	}
	served, err := nodeProvides(socket)
	if err != nil {
		return err
	}
	if !pinned || !served {
		return nil
	}
	if endpoint := "unix://" + socket; supplied != endpoint {
		return fmt.Errorf("this node pins CDS in %s and serves its attestation-api at %s, so --attestation-api-url must be %s; got %q",
			nodePolicy, socket, endpoint, supplied)
	}
	return nil
}

// nodeProvides reports whether the node mounts path. An error other than an
// absent path fails the caller: a mount it cannot read still binds it.
func nodeProvides(path string) (bool, error) {
	switch _, err := os.Stat(path); {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("node mount %s: %w", path, err)
	}
	return true, nil
}

// suppliedPolicyFlags names the pin inputs the caller set, for an error that
// says which argument to drop.
func suppliedPolicyFlags(source ImagePolicySource, pins MeasurementPins) []string {
	var flags []string
	if source.File != "" {
		flags = append(flags, "--image-policy-file")
	}
	if source.JSON != "" {
		flags = append(flags, "--image-policy-json")
	}
	return append(flags, pins.flags()...)
}

// Load returns complete image identities or independent digest/register pins.
// Complete identities are never flattened into independent lists.
func (s ImagePolicySource) Load(pins MeasurementPins) (remote.Policy, error) {
	if s.IsSet() {
		values, err := s.LoadValues(pins)
		return values.Policy(), err
	}
	measurements, err := LoadMeasurements(pins.Measurements, pins.MeasurementsFile)
	if err != nil {
		return remote.Policy{}, fmt.Errorf("--%smeasurements: %w", pins.Prefix, err)
	}
	rtmrs, err := refvalues.ParseRegisterPins(pins.Registers)
	if err != nil {
		return remote.Policy{}, fmt.Errorf("--%srtmrs: %w", pins.Prefix, err)
	}
	return remote.Policy{Measurements: measurements, Registers: rtmrs}, nil
}

// LoadMeasurements combines digest flags and a newline-separated digest
// file. JSON image policies belong to ImagePolicySource instead.
func LoadMeasurements(values []string, path string) ([][]byte, error) {
	values = append([]string(nil), values...)
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read --measurements-file: %w", err)
		}
		values = append(values, strings.Split(string(data), "\n")...)
	}
	return refvalues.ParseHexMeasurementsList(values)
}

// BindImagePolicyFlags registers canonical JSON sources. A nil inline pointer
// exposes only file input; prefix is "cds-" for the mesh's independent CDS policy.
// Only one source may be used.
func BindImagePolicyFlags(fs *pflag.FlagSet, file, inline *string, prefix, purpose string) {
	selected := ""
	bind := func(target *string, name, usage string) {
		fs.Var(&policySourceFlag{target: target, selected: &selected, name: name}, name, usage)
	}
	fileName := prefix + "image-policy-file"
	jsonName := prefix + "image-policy-json"
	*file = ""
	bind(file, fileName, "path to a complete JSON image policy (image, RTMR and launch-key pins); "+purpose)
	if inline != nil {
		*inline = ""
		bind(inline, jsonName, "inline complete JSON image policy, in the same format as --"+fileName+"; "+purpose)
	}
}

type policySourceFlag struct {
	target   *string
	selected *string
	name     string
}

func (v *policySourceFlag) String() string { return *v.target }
func (v *policySourceFlag) Type() string   { return "string" }
func (v *policySourceFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("--%s requires a non-empty JSON policy source", v.name)
	}
	if *v.selected != "" && *v.selected != v.name {
		return fmt.Errorf("--%s cannot be combined with --%s: select one JSON policy source", *v.selected, v.name)
	}
	*v.selected = v.name
	*v.target = value
	return nil
}
