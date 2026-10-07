package cmdsutil

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

const identityPolicyFile = "../../../internal/testdata/node-identities.json"

func TestImagePolicySourceKeepsCompleteIdentities(t *testing.T) {
	doc, err := os.ReadFile(identityPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	var previous any
	for _, source := range []ImagePolicySource{{File: identityPolicyFile}, {JSON: string(doc)}} {
		policy, err := source.Load(MeasurementPins{})
		if err != nil {
			t.Fatal(err)
		}
		if len(policy.Measurements) != 0 || len(policy.Registers) != 0 || len(policy.Images) != 2 {
			t.Fatalf("complete identities were flattened: %+v", policy)
		}
		for _, pin := range policy.Images {
			if len(pin.Digest) != 48 || len(pin.Registers[1]) != 48 || len(pin.Registers[2]) != 48 || len(pin.Anchor) == 0 {
				t.Fatalf("incomplete image tuple: %+v", pin)
			}
		}
		if bytes.Equal(policy.Images[0].Anchor, policy.Images[1].Anchor) {
			t.Fatal("server and agent keys collapsed into one identity")
		}
		if previous != nil && !reflect.DeepEqual(previous, policy) {
			t.Fatal("file and inline JSON formats produced different policies")
		}
		previous = policy
	}
}

func TestImagePolicySourceRejectsConflictingInputsBeforeReading(t *testing.T) {
	for _, source := range []ImagePolicySource{{File: "missing"}, {JSON: "invalid"}} {
		for _, pins := range []MeasurementPins{
			{Measurements: []string{"invalid"}},
			{MeasurementsFile: "missing"},
			{Registers: []string{"invalid"}},
			{Measurements: []string{"invalid"}, Prefix: "cds-"},
			{Registers: []string{"invalid"}, Prefix: "cds-"},
		} {
			_, err := source.Load(pins)
			if err == nil || !strings.Contains(err.Error(), "cannot be combined") || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("source %+v with %+v: expected usage error before I/O, got %v", source, pins, err)
			}
		}
	}
	_, err := (ImagePolicySource{File: "missing", JSON: "invalid"}).LoadValues(MeasurementPins{})
	if err == nil || !strings.Contains(err.Error(), "--image-policy-file cannot be combined with --image-policy-json") {
		t.Fatalf("file plus inline: %v", err)
	}
}

func TestImagePolicySourceErrorsDoNotFallBack(t *testing.T) {
	_, err := (ImagePolicySource{File: filepath.Join(t.TempDir(), "missing")}).Load(MeasurementPins{})
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "--image-policy-file") {
		t.Fatalf("missing policy lost its path error: %v", err)
	}
	for _, inline := range []string{"{}", "not JSON", identityPolicyFile, strings.Repeat("ab", 48)} {
		if _, err := (ImagePolicySource{JSON: inline}).Load(MeasurementPins{}); err == nil || !strings.Contains(err.Error(), "--image-policy-json") {
			t.Fatalf("invalid inline policy accepted or mislabeled: %q: %v", inline, err)
		}
	}
	digestFile := filepath.Join(t.TempDir(), "digests.txt")
	if err := os.WriteFile(digestFile, []byte(strings.Repeat("ab", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (ImagePolicySource{File: digestFile}).Load(MeasurementPins{}); err == nil {
		t.Fatal("newline digest file accepted as a complete JSON policy")
	}
	if _, err := LoadMeasurements(nil, identityPolicyFile); err == nil {
		t.Fatal("complete JSON policy accepted as a digest list")
	}
}

func TestMeasurementPolicySupportsDigestFileAndRegisterOnlyPins(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	register := strings.Repeat("cd", 48)
	path := filepath.Join(t.TempDir(), "digests.txt")
	if err := os.WriteFile(path, []byte("\n"+digest+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := ImagePolicySource{}
	policy, err := source.Load(MeasurementPins{Measurements: []string{register}, MeasurementsFile: path, Registers: []string{"1=" + register}})
	if err != nil || len(policy.Measurements) != 2 || len(policy.Registers[1]) != 48 || len(policy.Images) != 0 {
		t.Fatalf("union/register policy changed: %+v, %v", policy, err)
	}
	policy, err = source.Load(MeasurementPinsFromStrings("", "1="+register, "cds-"))
	if err != nil || len(policy.Measurements) != 0 || len(policy.Registers[1]) != 48 || len(policy.Images) != 0 {
		t.Fatalf("register-only policy was dropped: %+v, %v", policy, err)
	}
	policy, err = source.Load(MeasurementPinsFromStrings("", "", ""))
	if err != nil || len(policy.Measurements) != 0 || len(policy.Registers) != 0 || len(policy.Images) != 0 {
		t.Fatalf("empty policy changed: %+v, %v", policy, err)
	}
	for _, tc := range []struct{ measurements, rtmrs, flag string }{
		{"bad", "", "--cds-measurements"},
		{"", "bad", "--cds-rtmrs"},
	} {
		if _, err := source.Load(MeasurementPinsFromStrings(tc.measurements, tc.rtmrs, "cds-")); err == nil || !strings.Contains(err.Error(), tc.flag) {
			t.Fatalf("invalid flag %s: %v", tc.flag, err)
		}
	}
}

func TestImagePolicyFlagsCanonicalSources(t *testing.T) {
	doc, err := os.ReadFile(identityPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"image-policy-file", "image-policy-json"} {
		t.Run(flag, func(t *testing.T) {
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			var source ImagePolicySource
			BindImagePolicyFlags(fs, &source.File, &source.JSON, "test identity policy")
			value := identityPolicyFile
			if strings.HasSuffix(flag, "json") {
				value = string(doc)
			}
			if err := fs.Parse([]string{"--" + flag, value}); err != nil {
				t.Fatal(err)
			}
			policy, err := source.Load(MeasurementPins{})
			if err != nil || len(policy.Images) != 2 || len(policy.Images[0].Anchor) == 0 {
				t.Fatalf("flag lost identity policy: %+v, %v", policy, err)
			}
			if fs.Lookup(flag).Value.String() != value || fs.Lookup(flag).Value.Type() != "string" {
				t.Fatal("flag did not retain its source value")
			}
		})
	}
}

func TestImagePolicyFlagsRejectMixedSources(t *testing.T) {
	names := []string{"image-policy-file", "image-policy-json"}
	for _, first := range names {
		for _, second := range names {
			if first == second {
				continue
			}
			t.Run(first+"+"+second, func(t *testing.T) {
				fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
				var source ImagePolicySource
				BindImagePolicyFlags(fs, &source.File, &source.JSON, "test")
				err := fs.Parse([]string{"--" + first, "first", "--" + second, "second"})
				if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
					t.Fatalf("ambiguous policy flags accepted: %v", err)
				}
			})
		}
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		var source ImagePolicySource
		BindImagePolicyFlags(fs, &source.File, &source.JSON, "test")
		if err := fs.Parse([]string{"--" + first, ""}); err == nil {
			t.Fatalf("explicit empty %s silently disabled pinning", first)
		}
	}
}

func TestImagePolicyFileFlagExposesNoInlineJSON(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var peers string
	BindImagePolicyFlags(fs, &peers, nil, "mesh peers")
	if fs.Lookup("image-policy-json") != nil {
		t.Fatal("file-only command unexpectedly exposed inline JSON")
	}
	if err := fs.Parse([]string{"--image-policy-file", "peers.json"}); err != nil {
		t.Fatal(err)
	}
	if peers != "peers.json" {
		t.Fatalf("--image-policy-file = %q, want %q", peers, "peers.json")
	}
}

func TestImagePolicyFlagsRejectRemovedAliases(t *testing.T) {
	for _, name := range []string{"measurements-config", "measurements-config-json"} {
		t.Run(name, func(t *testing.T) {
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			var source ImagePolicySource
			BindImagePolicyFlags(fs, &source.File, &source.JSON, "test")
			if err := fs.Parse([]string{"--" + name, "policy.json"}); err == nil || !strings.Contains(err.Error(), "unknown flag") {
				t.Fatalf("removed alias accepted: %v", err)
			}
		})
	}
}

func TestLoadImagePolicyValuesPlatform(t *testing.T) {
	for _, tc := range []struct {
		platform string
		wantErr  bool
	}{
		{"", false}, {"tdx", false}, {"az-tdx", false}, {"gcp-tdx", false},
		{"snp", true}, {"az-snp", true}, {"gcp-snp", true}, {"sev-snp", true}, {"invalid", true},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			values, err := LoadImagePolicyValues(ImagePolicyValuesConfig{
				Source:       ImagePolicySource{File: identityPolicyFile},
				Platform:     tc.platform,
				PlatformFlag: "--armtls-platform",
			})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "--armtls-platform") || !values.Empty() {
					t.Fatalf("wrong-platform policy was accepted: %+v, %v", values, err)
				}
				return
			}
			if err != nil || len(values.Images) != 2 || !values.HasAnchors() {
				t.Fatalf("complete identity was lost: %+v, %v", values, err)
			}
		})
	}
}

func TestLoadImagePolicyValuesRejectsInputsBeforeReading(t *testing.T) {
	_, err := LoadImagePolicyValues(ImagePolicyValuesConfig{
		Source:   ImagePolicySource{File: "missing"},
		Pins:     MeasurementPins{Measurements: []string{"invalid"}},
		Platform: "invalid",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("policy conflict was not reported before reading: %v", err)
	}
	values, err := LoadImagePolicyValues(ImagePolicyValuesConfig{})
	if err != nil || !values.Empty() {
		t.Fatalf("absent policy: %+v, %v", values, err)
	}
}

func TestLoadImagePolicyValuesKeepsPerImageRTMRs(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	first, second := strings.Repeat("cd", 48), strings.Repeat("ef", 48)
	doc := `{"schema_version":"1","tee":"tdx","measurements":[` +
		`{"name":"first","mrtd":"` + digest + `","rtmr":[null,"` + first + `"]},` +
		`{"name":"second","mrtd":"` + digest + `","rtmr":[null,"` + second + `"]}]}`
	values, err := LoadImagePolicyValues(ImagePolicyValuesConfig{
		Source:   ImagePolicySource{JSON: doc},
		Platform: "tdx",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(values.Images) != 2 || len(values.Images[0].Registers) != 1 || len(values.Images[1].Registers) != 1 || bytes.Equal(values.Images[0].Registers[1], values.Images[1].Registers[1]) {
		t.Fatalf("per-image register tuples were lost: %+v", values.Images)
	}
}

// An injected client holds its CDS to the node's policy, not to anything its
// pod or the control plane passes: while the mount is there the arguments are
// refused, so a weaker pin cannot replace a measured one silently.
func TestResolveCDSPinsPrefersTheNodePolicy(t *testing.T) {
	document, err := os.ReadFile(identityPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cds-pins.json")
	if err := os.WriteFile(path, document, 0o644); err != nil {
		t.Fatal(err)
	}

	policy, fromNode, err := ResolveCDSPins(path, ImagePolicySource{}, MeasurementPins{})
	if err != nil {
		t.Fatalf("ResolveCDSPins: %v", err)
	}
	if len(policy.Images) == 0 {
		t.Fatal("node policy loaded no images")
	}
	if !fromNode {
		t.Fatal("the node policy did not decide")
	}

	// One exact message, so the client is told which argument to drop.
	_, _, err = ResolveCDSPins(path, ImagePolicySource{File: "/tmp/other.json"}, MeasurementPins{})
	want := "this node provides " + path + "; remove --image-policy-file"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}

	for _, tc := range []struct {
		name   string
		source ImagePolicySource
		pins   MeasurementPins
		want   string
	}{
		{"inline policy", ImagePolicySource{JSON: "{}"}, MeasurementPins{}, "--image-policy-json"},
		{"launch digests", ImagePolicySource{}, MeasurementPins{Measurements: []string{strings.Repeat("ab", 48)}, Prefix: "cds-"}, "--cds-measurements"},
		{"register pins", ImagePolicySource{}, MeasurementPins{Registers: []string{"1=" + strings.Repeat("cd", 48)}}, "--rtmrs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ResolveCDSPins(path, tc.source, tc.pins); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to name %s", err, tc.want)
			}
		})
	}
}

// Without the mount the caller's own inputs apply: a chart-rendered platform
// client and the CLI have no enforcer to read.
func TestResolveCDSPinsFallsBackToArguments(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	path := filepath.Join(t.TempDir(), "absent.json")

	policy, fromNode, err := ResolveCDSPins(path, ImagePolicySource{}, MeasurementPins{Measurements: []string{digest}, Prefix: "cds-"})
	if err != nil {
		t.Fatalf("ResolveCDSPins: %v", err)
	}
	if len(policy.Measurements) != 1 {
		t.Fatalf("policy measurements = %v, want the supplied digest", policy.Measurements)
	}
	if fromNode {
		t.Fatal("a node that mounts no policy decided")
	}
}

// The verifier decides whether the CDS a client dials satisfies the node's
// pins, so a pod that named its own verifier would hold CDS to nothing. While
// the node pins CDS and serves its own attestation-api, that socket is the
// only verifier.
func TestRequireNodeVerifierRefusesANamedVerifier(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "cds-pins.json")
	socket := filepath.Join(dir, "attestation-api.sock")
	for _, path := range []string{policy, socket} {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := RequireNodeVerifier(policy, socket, "unix://"+socket); err != nil {
		t.Fatalf("the node's own attestation-api was refused: %v", err)
	}

	for _, verifier := range []string{
		"http://10.53.0.10:53",
		"http://127.0.0.1:8400",
		"unix://" + filepath.Join(dir, "rogue.sock"),
		"",
	} {
		err := RequireNodeVerifier(policy, socket, verifier)
		if err == nil {
			t.Fatalf("verifier %q was accepted while the node pins CDS", verifier)
		}
		if !strings.Contains(err.Error(), "unix://"+socket) {
			t.Fatalf("error %q should name the verifier to use", err)
		}
	}
}

// Without both mounts the caller's own argument applies: a chart-rendered
// platform client reaches its node's attestation-api over the network, and a
// node serving no attestation-api of its own hands out no verifier.
func TestRequireNodeVerifierFallsBackToTheArgument(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "cds-pins.json")
	socket := filepath.Join(dir, "attestation-api.sock")
	if err := os.WriteFile(policy, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := RequireNodeVerifier(policy, socket, "http://$(HOST_IP):8400"); err != nil {
		t.Fatalf("a node serving no attestation-api must leave the argument: %v", err)
	}
	if err := RequireNodeVerifier(filepath.Join(dir, "absent.json"), socket, "http://$(HOST_IP):8400"); err != nil {
		t.Fatalf("a node pinning no CDS must leave the argument: %v", err)
	}
}

// A path that exists but cannot be read is not an absent policy: falling back
// to the arguments there would let a broken mount unpin a pod.
func TestResolveCDSPinsFailsOnAnUnreadablePolicy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sealed")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root reads through a 0000 directory")
	}

	_, _, err := ResolveCDSPins(filepath.Join(dir, "cds-pins.json"), ImagePolicySource{}, MeasurementPins{})
	if err == nil {
		t.Fatal("ResolveCDSPins accepted an unreadable policy path")
	}
	if !strings.Contains(err.Error(), "node policy") {
		t.Fatalf("error = %v, want it to name the node policy", err)
	}
}

// Independent digests and register pins become one set on the configured
// platform's family: each digest carries the registers, which is what the
// independent form meant.
func TestLoadImagePolicySetFromIndependentPins(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	register := strings.Repeat("cd", 48)
	cfg := ImagePolicyValuesConfig{
		Pins: MeasurementPins{
			Measurements: []string{digest},
			Registers:    []string{"1=" + register},
			Prefix:       "cds-",
		},
		Platform: "tdx",
	}

	set, err := LoadImagePolicySet(cfg)
	if err != nil {
		t.Fatalf("LoadImagePolicySet: %v", err)
	}
	if set.Family != teetypes.FamilyTDX {
		t.Fatalf("family = %q, want the configured platform", set.Family)
	}
	if len(set.Images) != 1 || hex.EncodeToString(set.Images[0].Digest) != digest {
		t.Fatalf("images = %+v, want one per configured digest", set.Images)
	}
	if hex.EncodeToString(set.Images[0].Registers[1]) != register {
		t.Fatalf("image registers = %v, want the configured register pin", set.Images[0].Registers)
	}

	// Whether a family carries registers at all is refvalues' answer, given
	// when the set is rendered.
	cfg.Platform = teetypes.FamilySNP.String()
	snp, err := LoadImagePolicySet(cfg)
	if err != nil {
		t.Fatalf("LoadImagePolicySet: %v", err)
	}
	if _, err := refvalues.Format(snp); err == nil {
		t.Fatal("a register pin was rendered for a family whose evidence carries none")
	}
}

// A register pin matches nothing without a launch digest to pin it to, so it
// is refused rather than dropped from the set.
func TestLoadImagePolicySetRefusesRegistersWithoutADigest(t *testing.T) {
	_, err := LoadImagePolicySet(ImagePolicyValuesConfig{
		Pins: MeasurementPins{
			Registers: []string{"1=" + strings.Repeat("cd", 48)},
			Prefix:    "cds-",
		},
		Platform: "tdx",
	})
	if err == nil || !strings.Contains(err.Error(), "--cds-rtmrs") {
		t.Fatalf("error = %v, want it to name the register pins", err)
	}
}

// A complete document is the same set, loaded whole: the platform check and
// the per-image tuples are those of LoadImagePolicyValues.
func TestLoadImagePolicySetFromADocument(t *testing.T) {
	cfg := ImagePolicyValuesConfig{
		Source:       ImagePolicySource{File: identityPolicyFile},
		Platform:     "tdx",
		PlatformFlag: "platform",
	}

	set, err := LoadImagePolicySet(cfg)
	if err != nil {
		t.Fatalf("LoadImagePolicySet: %v", err)
	}
	if len(set.Images) != 2 || len(set.Images[0].Anchor) == 0 || len(set.Images[0].Registers) != 2 {
		t.Fatalf("the document's image tuples were lost: %+v", set.Images)
	}
	cfg.Platform = teetypes.FamilySNP.String()
	if _, err := LoadImagePolicySet(cfg); err == nil {
		t.Fatal("a document for another family was accepted")
	}
}

// Nothing configured pins nothing, which a caller reports rather than
// mistaking for a policy.
func TestLoadImagePolicySetWithoutInputs(t *testing.T) {
	set, err := LoadImagePolicySet(ImagePolicyValuesConfig{Platform: "tdx"})
	if err != nil {
		t.Fatalf("LoadImagePolicySet: %v", err)
	}
	if !set.Empty() {
		t.Fatalf("set = %+v, want it to pin nothing", set)
	}
}
