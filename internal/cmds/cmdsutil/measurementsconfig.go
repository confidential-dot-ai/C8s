package cmdsutil

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
)

// ImagePolicySource selects one complete refvalues JSON document. File and JSON
// use the same format; neither is a newline-separated digest list.
type ImagePolicySource struct {
	File string
	JSON string
}

// IsSet reports whether a complete policy was supplied.
func (s ImagePolicySource) IsSet() bool {
	return s.File != "" || s.JSON != ""
}

// MeasurementPins holds the independent launch-digest inputs a target is
// pinned by where a complete document does not name it.
type MeasurementPins struct {
	Measurements     []string
	MeasurementsFile string
}

// Flags names the launch-digest inputs the caller set, for an error that says
// which argument to drop.
func (p MeasurementPins) Flags() []string {
	var flags []string
	if len(p.Measurements) > 0 {
		flags = append(flags, "--measurements")
	}
	if p.MeasurementsFile != "" {
		flags = append(flags, "--measurements-file")
	}
	return flags
}

// Values loads the complete image identities this source names. An unset
// source names none, which is an empty set rather than an error.
func (s ImagePolicySource) Values() (refvalues.ReferenceValues, error) {
	if !s.IsSet() {
		return refvalues.ReferenceValues{}, nil
	}
	if s.File != "" && s.JSON != "" {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file cannot be combined with --image-policy-json")
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

// ValuesExcluding is Values for a command that also takes flat launch digests:
// a complete document and a digest list are alternatives, so naming both is a
// usage error rather than a union.
func (s ImagePolicySource) ValuesExcluding(pins MeasurementPins) (refvalues.ReferenceValues, error) {
	if flags := pins.Flags(); s.IsSet() && len(flags) != 0 {
		return refvalues.ReferenceValues{}, fmt.Errorf("--image-policy-file/--image-policy-json cannot be combined with %s", strings.Join(flags, " or "))
	}
	return s.Values()
}

// ErrTAPinUnbound marks a pin set that does not name one Trust Authority VM.
var ErrTAPinUnbound = errors.New("is not one Trust Authority VM's identity")

// TALaunchFile is the configuration a pin set identifies its Trust Authority by
// (CheckCDSPins).
func TALaunchFile(values refvalues.ReferenceValues) ([]byte, error) {
	if err := CheckCDSPins(values); err != nil {
		return nil, err
	}
	return values.Images[0].LaunchFile, nil
}

// CheckCDSPins requires every image to pin its family's guest registers and
// bind the same Trust Authority launch file. The launch binding identifies the cluster;
// an image alone does not.
func CheckCDSPins(values refvalues.ReferenceValues) error {
	if values.Empty() {
		return fmt.Errorf("%w: it pins no image, so nothing tells this cluster's Trust Authority from any other attested TEE", ErrTAPinUnbound)
	}
	if err := armtls.RequireImageRegisters(values.Family, values.Images); err != nil {
		return fmt.Errorf("%w: %w", ErrTAPinUnbound, err)
	}
	file := values.Images[0].LaunchFile
	for _, image := range values.Images {
		if len(image.LaunchFile) == 0 {
			return fmt.Errorf("%w: entry %q binds no launch file, and a Trust Authority is pinned to the configuration it runs on", ErrTAPinUnbound, image.Name)
		}
		if !bytes.Equal(image.LaunchFile, file) {
			return fmt.Errorf("%w: entry %q binds another configuration, and one pin names one Trust Authority", ErrTAPinUnbound, image.Name)
		}
		if image.LaunchFileInInitData && !pinsUntouchedRTMR3(image) {
			return fmt.Errorf("%w: entry %q reads its launch file from MRCONFIGID without pinning RTMR[3] to all zero, and a Trust Authority starts from MRCONFIGID only beside an untouched RTMR[3]", ErrTAPinUnbound, image.Name)
		}
	}
	return nil
}

// pinsUntouchedRTMR3 reports whether image pins RTMR[3] to all zero. A pin
// that reads the launch file from MRCONFIGID leaves the register unread
// otherwise, and a guest whose RTMR[3] holds another file's seed runs that
// file whatever MRCONFIGID holds.
func pinsUntouchedRTMR3(image remote.ImagePin) bool {
	register, pinned := image.Registers[3]
	return pinned && len(register) > 0 && bytes.Equal(register, make([]byte, len(register)))
}

// ResolveTAPins returns the pins a client holds its Trust Authority to, and whether the
// node's own policy decided them. resolveNodePolicy states the rule.
func ResolveTAPins(nodePolicy string, source ImagePolicySource) (remote.Policy, bool, error) {
	values, fromNode, err := resolveNodePolicy(nodePolicy, suppliedPolicyFlags(source), refvalues.Parse)
	if err != nil {
		return remote.Policy{}, fromNode, err
	}
	if !fromNode {
		if values, err = source.Values(); err != nil {
			return remote.Policy{}, false, err
		}
	}
	if err := CheckCDSPins(values); err != nil {
		return remote.Policy{}, fromNode, fmt.Errorf("%s %w", taPinSource(nodePolicy, fromNode, source), err)
	}
	return values.Policy(), fromNode, nil
}

// ClientTAPins is ResolveTAPins and the line a credential client logs about
// the set it resolved. The conformance probe resolves silently
// (internal/cmds/secretprobe).
func ClientTAPins(nodePolicy string, source ImagePolicySource) (armtls.Pins, error) {
	policy, fromNode, err := ResolveTAPins(nodePolicy, source)
	if err != nil {
		return armtls.Pins{}, err
	}
	slog.Info("Trust Authority pins resolved", "from_node", fromNode)
	return armtls.Pins(policy), nil
}

// TAPins resolves the pins as ResolveTAPins does: a client calling it before each
// request or handshake follows the node's pins, which the node rewrites in place when its
// Trust Authority replica set accepts other builds.
func TAPins(nodePolicy string, source ImagePolicySource) (armtls.Pins, error) {
	policy, _, err := ResolveTAPins(nodePolicy, source)
	return armtls.Pins(policy), err
}

// taPinSource names where the refused pins came from, so a client is told
// which input to fix.
func taPinSource(nodePolicy string, fromNode bool, source ImagePolicySource) string {
	switch {
	case fromNode:
		return "node policy " + nodePolicy
	case source.IsSet():
		return strings.Join(suppliedPolicyFlags(source), " and ")
	}
	return "--image-policy-file"
}

// NodeProvidesTAPins reports whether the enforcer mounts this node's Trust Authority pins
// at path, so a client can say which half of its Trust Authority configuration is short
// before resolving either.
func NodeProvidesTAPins(path string) (bool, error) {
	return nodeProvides(path)
}

// RequireNodeVerifier holds a credential client to the node's own
// attestation-api while the enforcer mounts its Trust Authority policy at nodePolicy and
// presents that attestation-api at socket. The verifier is what decides
// whether the Trust Authority a client dials satisfies those pins, so a client answering
// to a named verifier is not pinned at all.
//
// Both paths are the node's own mounts, and the rule is ResolveTAPins': while
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
		return fmt.Errorf("this node pins Trust Authority in %s and serves its attestation-api at %s, so --attestation-api-url must be %s; got %q",
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
func suppliedPolicyFlags(source ImagePolicySource) []string {
	var flags []string
	if source.File != "" {
		flags = append(flags, "--image-policy-file")
	}
	if source.JSON != "" {
		flags = append(flags, "--image-policy-json")
	}
	return flags
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
// exposes only file input. Only one source may be used.
func BindImagePolicyFlags(fs *pflag.FlagSet, file, inline *string, purpose string) {
	bindImagePolicyFlags(fs, file, inline, "image-policy", purpose)
}

// BindTAImagePolicyFlags binds a policy for a Trust Authority endpoint.
func BindTAImagePolicyFlags(fs *pflag.FlagSet, file, inline *string, purpose string) {
	bindImagePolicyFlags(fs, file, inline, "ta-image-policy", purpose)
	AliasFlag(fs, "ta-image-policy-file", "image-policy-file")
	if inline != nil {
		AliasFlag(fs, "ta-image-policy-json", "image-policy-json")
	}
}

func bindImagePolicyFlags(fs *pflag.FlagSet, file, inline *string, prefix, purpose string) {
	selected := ""
	bind := func(target *string, name, usage string) {
		fs.Var(&policySourceFlag{target: target, selected: &selected, name: name}, name, usage)
	}
	*file = ""
	bind(file, prefix+"-file", "path to a complete JSON image policy (image, RTMR and launch-key pins); "+purpose)
	if inline != nil {
		*inline = ""
		bind(inline, prefix+"-json", "inline complete JSON image policy, in the same format as --"+prefix+"-file; "+purpose)
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
