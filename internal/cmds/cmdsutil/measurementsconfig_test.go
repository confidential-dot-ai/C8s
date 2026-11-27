package cmdsutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
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

// writeTAPins stages a Trust Authority pin document where the enforcer mounts one.
func writeTAPins(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ta-pins.json")
	if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// An injected client holds its Trust Authority to the node's policy, not to anything its
// pod or the control plane passes: while the mount is there the arguments are
// refused, so a weaker pin cannot replace a measured one silently.
func TestResolveTAPinsPrefersTheNodePolicy(t *testing.T) {
	path := writeTAPins(t, testutil.TAPinDocument(testutil.TestMeasurement, testutil.TALaunchFile))

	pins, fromNode, err := ResolveTAPins(t.Context(), path, ImagePolicySource{})
	if err != nil {
		t.Fatalf("ResolveTAPins: %v", err)
	}
	if images := pins.Current().Images; len(images) != 1 || len(images[0].LaunchFile) == 0 {
		t.Fatalf("node policy = %+v, want the launch-bound image", images)
	}
	if !fromNode {
		t.Fatal("the node policy did not decide")
	}

	// One exact message, so the client is told which argument to drop.
	_, _, err = ResolveTAPins(t.Context(), path, ImagePolicySource{File: "/tmp/other.json"})
	want := "this node provides " + path + "; remove --image-policy-file"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}

	_, _, err = ResolveTAPins(t.Context(), path, ImagePolicySource{JSON: "{}"})
	if err == nil || !strings.Contains(err.Error(), "--image-policy-json") {
		t.Fatalf("error = %v, want it to name --image-policy-json", err)
	}
}

// A Trust Authority is pinned to the configuration it runs on, so a document naming only
// its image admits any Trust Authority VM, whichever cluster it was launched for.
func TestResolveTAPinsRequiresALaunchBinding(t *testing.T) {
	unbound := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"ta","measurement":"` + testutil.TestMeasurement + `"}]}`
	for name, path := range map[string]string{
		"node policy":         writeTAPins(t, unbound),
		"no policy at all":    filepath.Join(t.TempDir(), "absent.json"),
		"empty node document": writeTAPins(t, `{"schema_version":"1","tee":"sev-snp","measurements":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ResolveTAPins(t.Context(), path, ImagePolicySource{}); err == nil {
				t.Fatal("a pin that is not one Trust Authority VM's identity was accepted")
			}
		})
	}
}

// Without the mount the caller's own document applies: the CLI and a
// chart-rendered platform client have no enforcer to read.
func TestResolveTAPinsFallsBackToTheArgument(t *testing.T) {
	pins, fromNode, err := ResolveTAPins(t.Context(), filepath.Join(t.TempDir(), "absent.json"), ImagePolicySource{JSON: testutil.TAPinDocument(testutil.TestMeasurement, testutil.TALaunchFile)})
	if err != nil {
		t.Fatalf("ResolveTAPins: %v", err)
	}
	if images := pins.Current().Images; len(images) != 1 {
		t.Fatalf("policy images = %+v, want the supplied document's", images)
	}
	if fromNode {
		t.Fatal("a node that mounts no policy decided")
	}
}

// A credential client says which set it resolved and who decided it, so a
// pod's log names the Trust Authority image it will accept.
func TestClientTAPinsLogsWhatItResolved(t *testing.T) {
	document := testutil.TAPinDocument(testutil.TestMeasurement, testutil.TALaunchFile)
	mounted := filepath.Join(t.TempDir(), "ta-pins.json")
	if err := os.WriteFile(mounted, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		nodePolicy string
		source     ImagePolicySource
		want       string
	}{
		{
			name:       "the node's policy",
			nodePolicy: mounted,
			want:       "from_node=true",
		},
		{
			name:       "the caller's own document",
			nodePolicy: filepath.Join(t.TempDir(), "absent.json"),
			source:     ImagePolicySource{JSON: document},
			want:       "from_node=false",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })
			pins, err := ClientTAPins(t.Context(), tc.nodePolicy, tc.source)
			if err != nil {
				t.Fatalf("ClientTAPins: %v", err)
			}
			if images := pins.Current().Images; len(images) != 1 {
				t.Fatalf("policy images = %+v, want the one pinned image", images)
			}
			line := logged.String()
			if !strings.Contains(line, `msg="Trust Authority pins resolved"`) || !strings.Contains(line, tc.want) {
				t.Fatalf("logged %q, want the resolved line with %s", line, tc.want)
			}
		})
	}
}

// The verifier decides whether the Trust Authority a client dials satisfies the node's
// pins, so a pod that named its own verifier would hold Trust Authority to nothing. While
// the node pins Trust Authority and serves its own attestation-api, that socket is the
// only verifier.
func TestRequireNodeVerifierRefusesANamedVerifier(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "ta-pins.json")
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
			t.Fatalf("verifier %q was accepted while the node pins Trust Authority", verifier)
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
	policy := filepath.Join(dir, "ta-pins.json")
	socket := filepath.Join(dir, "attestation-api.sock")
	if err := os.WriteFile(policy, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := RequireNodeVerifier(policy, socket, "http://$(HOST_IP):8400"); err != nil {
		t.Fatalf("a node serving no attestation-api must leave the argument: %v", err)
	}
	if err := RequireNodeVerifier(filepath.Join(dir, "absent.json"), socket, "http://$(HOST_IP):8400"); err != nil {
		t.Fatalf("a node pinning no Trust Authority must leave the argument: %v", err)
	}
}

// A path that exists but cannot be read is not an absent policy: falling back
// to the arguments there would let a broken mount unpin a pod.
func TestResolveTAPinsFailsOnAnUnreadablePolicy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sealed")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root reads through a 0000 directory")
	}

	_, _, err := ResolveTAPins(t.Context(), filepath.Join(dir, "ta-pins.json"), ImagePolicySource{})
	if err == nil {
		t.Fatal("ResolveTAPins accepted an unreadable policy path")
	}
	if !strings.Contains(err.Error(), "node policy") {
		t.Fatalf("error = %v, want it to name the node policy", err)
	}
}

// A pin that reads the launch file from MRCONFIGID does not read RTMR[3], and
// a guest seeded from another launch file runs that file. So such a pin names
// one Trust Authority only when it also pins RTMR[3] untouched.
func TestTALaunchFileRequiresAnUntouchedRTMR3BesideMRCONFIGID(t *testing.T) {
	hex96 := func(b string) string { return strings.Repeat(b, 48) }
	document := func(rtmr3, field string) []byte {
		return []byte(`{"schema_version":"3","tee":"tdx","measurements":[{"name":"ta","mrtd":"` + hex96("aa") +
			`","rtmr":[null,"` + hex96("bb") + `","` + hex96("cc") + `"` + rtmr3 + `],"launch_file":"clusterID: test\n"` + field + `}]}`)
	}
	initData := `,"launch_file_field":"init_data"`
	for _, tc := range []struct {
		name, rtmr3, field string
		wantErr            bool
	}{
		{name: "MRCONFIGID, RTMR[3] pinned untouched", rtmr3: `,""`, field: initData},
		{name: "MRCONFIGID, RTMR[3] unpinned", field: initData, wantErr: true},
		{name: "MRCONFIGID, RTMR[3] null", rtmr3: `,null`, field: initData, wantErr: true},
		{name: "MRCONFIGID, RTMR[3] pinned to a value", rtmr3: `,"` + hex96("dd") + `"`, field: initData, wantErr: true},
		{name: "the RTMR[3] seed, RTMR[3] unpinned"},
	} {
		values, err := refvalues.Parse(document(tc.rtmr3, tc.field))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		_, err = TALaunchFile(values)
		if tc.wantErr != errors.Is(err, ErrTAPinUnbound) || (!tc.wantErr && err != nil) {
			t.Errorf("%s: TALaunchFile = %v, want refusal %v", tc.name, err, tc.wantErr)
		}
		if tc.wantErr && err != nil && !strings.Contains(err.Error(), "RTMR[3]") {
			t.Errorf("%s: refusal %q does not name RTMR[3]", tc.name, err)
		}
	}
}

// Every reader of a Trust Authority pin comes through TALaunchFile, so a pin
// embedding an initdata document no Trust Authority starts from is refused
// here: one with no agent policy, or one declaring another family's digest.
func TestTALaunchFileRefusesAnInitdataDocumentNoTrustAuthorityStartsFrom(t *testing.T) {
	hex96 := func(b string) string { return strings.Repeat(b, 48) }
	const policy = "\"policy.rego\" = \"package agent_policy\"\n"
	initdata := func(algorithm, entries string) string {
		return "algorithm = \"" + algorithm + "\"\n[data]\n\"ta-config.yaml\" = \"clusterID: test\"\n" + entries
	}
	for _, tc := range []struct {
		name, launchFile, want string
		// othersGuest marks bytes that could be another guest's launch file:
		// a set that may pin other guests does not judge them.
		othersGuest bool
		// oversizedTA marks a file over the cap that names the Trust
		// Authority entry, which every set refuses.
		oversizedTA bool
	}{
		{name: "a document with a policy", launchFile: initdata("sha384", policy)},
		{name: "a bare configuration", launchFile: "clusterID: test\n"},
		{name: "a document with no policy", launchFile: initdata("sha384", ""), want: "policy.rego"},
		{name: "another family's digest", launchFile: initdata("sha256", policy), want: "sha384"},
		{name: "a file over the cap", launchFile: "# " + strings.Repeat("x", 1024*1024) + "\n", want: "bytes"},
		{name: "a data table under another case", launchFile: "algorithm = \"sha384\"\n[Data]\n\"ta-config.yaml\" = \"clusterID: test\"\n", want: "configuration", othersGuest: true},
		{name: "a document over the cap", launchFile: initdata("sha384", policy) + "# " + strings.Repeat("x", 1024*1024) + "\n", want: "bytes", oversizedTA: true},
		{name: "a document with another entry", launchFile: initdata("sha384", policy) + "\"other\" = 1\n", want: ""},
		{name: "bytes that are no configuration", launchFile: "x", want: "YAML mapping", othersGuest: true},
	} {
		launchFile, err := json.Marshal(tc.launchFile)
		if err != nil {
			t.Fatal(err)
		}
		values, err := refvalues.Parse([]byte(`{"schema_version":"2","tee":"tdx","measurements":[{"name":"ta","mrtd":"` + hex96("aa") +
			`","rtmr":[null,"` + hex96("bb") + `","` + hex96("cc") + `"],"launch_file":` + string(launchFile) + `}]}`))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		got, err := TALaunchFile(values)
		switch {
		case tc.want == "" && (err != nil || string(got) != tc.launchFile):
			t.Errorf("%s: TALaunchFile = %q, %v, want the launch file", tc.name, got, err)
		case tc.want != "" && (!errors.Is(err, ErrTAPinUnbound) || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: TALaunchFile = %v, want a refusal naming %q", tc.name, err, tc.want)
		}
		// A set that may also pin other guests refuses the same entries.
		refused := tc.want != "" && !tc.othersGuest && (tc.oversizedTA || !strings.Contains(tc.want, "bytes"))
		if err := CheckLaunchFiles(values); (err != nil) != refused {
			t.Errorf("%s: CheckLaunchFiles = %v, want refusal %v", tc.name, err, refused)
		}
	}
}
