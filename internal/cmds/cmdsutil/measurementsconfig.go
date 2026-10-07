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
		flag := cfg.PlatformFlag
		if flag == "" {
			flag = "--platform"
		}
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

// ResolveCDSPins returns the pins a client holds its CDS to, and the source it
// read them from so the client can log which one decided.
//
// THE RULE: while the enforcer's policy mount is at nodePolicy, it is the only
// source, and a supplied pin is refused rather than merged or silently
// ignored (armTLS W2) — the control plane must not be able to choose which CDS
// a pod trusts. An absent mount leaves the caller's own inputs: a
// chart-rendered platform client and the CLI have no enforcer to read, and a
// pod without the enforcer's mounts gets no identity assertion either, so it
// can obtain nothing to misuse. Any other error reading that path fails: a
// policy the client cannot read is not a policy it may ignore.
func ResolveCDSPins(nodePolicy string, source ImagePolicySource, pins MeasurementPins) (remote.Policy, string, error) {
	switch _, err := os.Stat(nodePolicy); {
	case errors.Is(err, fs.ErrNotExist):
		policy, err := source.Load(pins)
		return policy, "arguments", err
	case err != nil:
		return remote.Policy{}, "", fmt.Errorf("node CDS policy %s: %w", nodePolicy, err)
	}
	if supplied := suppliedPolicyFlags(source, pins); len(supplied) > 0 {
		return remote.Policy{}, "", fmt.Errorf("this node pins CDS in %s; remove %s",
			nodePolicy, strings.Join(supplied, " and "))
	}
	values, err := refvalues.Load(nodePolicy)
	if err != nil {
		return remote.Policy{}, "", fmt.Errorf("node CDS policy: %w", err)
	}
	return values.Policy(), nodePolicy, nil
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
