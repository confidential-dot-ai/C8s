package cmdsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

const identityPolicyFile = "../../../internal/testdata/node-identities.json"

func TestImagePolicySourceKeepsCompleteIdentities(t *testing.T) {
	doc, err := os.ReadFile(identityPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	var previous any
	for _, source := range []ImagePolicySource{{File: identityPolicyFile}, {JSON: string(doc)}} {
		values, err := source.Values()
		if err != nil {
			t.Fatal(err)
		}
		policy := values.Policy()
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
		} {
			_, err := source.ValuesExcluding(pins)
			if err == nil || !strings.Contains(err.Error(), "cannot be combined") || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("source %+v with %+v: expected usage error before I/O, got %v", source, pins, err)
			}
		}
	}
	_, err := (ImagePolicySource{File: "missing", JSON: "invalid"}).Values()
	if err == nil || !strings.Contains(err.Error(), "--image-policy-file cannot be combined with --image-policy-json") {
		t.Fatalf("file plus inline: %v", err)
	}
}

func TestImagePolicySourceErrorsDoNotFallBack(t *testing.T) {
	_, err := (ImagePolicySource{File: filepath.Join(t.TempDir(), "missing")}).Values()
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "--image-policy-file") {
		t.Fatalf("missing policy lost its path error: %v", err)
	}
	for _, inline := range []string{"{}", "not JSON", identityPolicyFile, strings.Repeat("ab", 48)} {
		if _, err := (ImagePolicySource{JSON: inline}).Values(); err == nil || !strings.Contains(err.Error(), "--image-policy-json") {
			t.Fatalf("invalid inline policy accepted or mislabeled: %q: %v", inline, err)
		}
	}
	digestFile := filepath.Join(t.TempDir(), "digests.txt")
	if err := os.WriteFile(digestFile, []byte(strings.Repeat("ab", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (ImagePolicySource{File: digestFile}).Values(); err == nil {
		t.Fatal("newline digest file accepted as a complete JSON policy")
	}
	if _, err := LoadMeasurements(nil, identityPolicyFile); err == nil {
		t.Fatal("complete JSON policy accepted as a digest list")
	}
}

// A digest list and a digest file name one allowlist together: both are ways
// of spelling the same flat pin.
func TestLoadMeasurementsUnionsFlagAndFile(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	other := strings.Repeat("cd", 48)
	path := filepath.Join(t.TempDir(), "digests.txt")
	if err := os.WriteFile(path, []byte("\n"+digest+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digests, err := LoadMeasurements([]string{other}, path)
	if err != nil || len(digests) != 2 {
		t.Fatalf("digests = %d, %v; want the flag's and the file's", len(digests), err)
	}
	if _, err := LoadMeasurements([]string{"bad"}, ""); err == nil {
		t.Fatal("a digest that is not hex was accepted")
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
			values, err := source.Values()
			if err != nil || len(values.Images) != 2 || len(values.Images[0].Anchor) == 0 {
				t.Fatalf("flag lost identity policy: %+v, %v", values, err)
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

// writeCDSPins stages a CDS pin document where the enforcer mounts one.
func writeCDSPins(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds-pins.json")
	if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// An injected client holds its CDS to the node's policy, not to anything its
// pod or the control plane passes: while the mount is there the arguments are
// refused, so a weaker pin cannot replace a measured one silently.
func TestResolveCDSPinsPrefersTheNodePolicy(t *testing.T) {
	path := writeCDSPins(t, testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile))

	pins, fromNode, err := ResolveCDSPins(t.Context(), path, ImagePolicySource{})
	if err != nil {
		t.Fatalf("ResolveCDSPins: %v", err)
	}
	if images := pins.Current().Images; len(images) != 1 || len(images[0].LaunchFile) == 0 {
		t.Fatalf("node policy = %+v, want the launch-bound image", images)
	}
	if !fromNode {
		t.Fatal("the node policy did not decide")
	}

	// One exact message, so the client is told which argument to drop.
	_, _, err = ResolveCDSPins(t.Context(), path, ImagePolicySource{File: "/tmp/other.json"})
	want := "this node provides " + path + "; remove --image-policy-file"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}

	_, _, err = ResolveCDSPins(t.Context(), path, ImagePolicySource{JSON: "{}"})
	if err == nil || !strings.Contains(err.Error(), "--image-policy-json") {
		t.Fatalf("error = %v, want it to name --image-policy-json", err)
	}
}

// A CDS is pinned to the configuration it runs on, so a document naming only
// its image admits any CDS VM, whichever cluster it was launched for.
func TestResolveCDSPinsRequiresALaunchBinding(t *testing.T) {
	unbound := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + testutil.TestMeasurement + `"}]}`
	for name, path := range map[string]string{
		"node policy":         writeCDSPins(t, unbound),
		"no policy at all":    filepath.Join(t.TempDir(), "absent.json"),
		"empty node document": writeCDSPins(t, `{"schema_version":"1","tee":"sev-snp","measurements":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ResolveCDSPins(t.Context(), path, ImagePolicySource{}); err == nil {
				t.Fatal("a pin that is not one CDS VM's identity was accepted")
			}
		})
	}
}

// Without the mount the caller's own document applies: the CLI and a
// chart-rendered platform client have no enforcer to read.
func TestResolveCDSPinsFallsBackToTheArgument(t *testing.T) {
	pins, fromNode, err := ResolveCDSPins(t.Context(), filepath.Join(t.TempDir(), "absent.json"), ImagePolicySource{JSON: testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)})
	if err != nil {
		t.Fatalf("ResolveCDSPins: %v", err)
	}
	if images := pins.Current().Images; len(images) != 1 {
		t.Fatalf("policy images = %+v, want the supplied document's", images)
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

	_, _, err := ResolveCDSPins(t.Context(), filepath.Join(dir, "cds-pins.json"), ImagePolicySource{})
	if err == nil {
		t.Fatal("ResolveCDSPins accepted an unreadable policy path")
	}
	if !strings.Contains(err.Error(), "node policy") {
		t.Fatalf("error = %v, want it to name the node policy", err)
	}
}
