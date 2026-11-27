package taconfig

import (
	"reflect"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// The launch binding proves an initdata document's bytes, not the digest it
// declares, so the declaration is held to the family that launched it.
func TestCheckInitdataFamilyHoldsTheDeclaredDigestToTheFamily(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	configuration := render(t, testDocument(t, operatorPEM, anchorPEM))
	entries := map[string]string{ConfigFile: string(configuration)}
	for _, tc := range []struct {
		name      string
		launch    []byte
		family    teetypes.Family
		wantError bool
	}{
		{"sha256 on SEV-SNP", initdataDocument(t, InitdataAlgorithmSNP, entries), teetypes.FamilySNP, false},
		{"sha384 on TDX", initdataDocument(t, InitdataAlgorithmTDX, entries), teetypes.FamilyTDX, false},
		{"sha384 on SEV-SNP", initdataDocument(t, InitdataAlgorithmTDX, entries), teetypes.FamilySNP, true},
		{"sha256 on TDX", initdataDocument(t, InitdataAlgorithmSNP, entries), teetypes.FamilyTDX, true},
		{"the configuration itself", configuration, teetypes.FamilyTDX, false},
		{"sha256 on an unknown family", initdataDocument(t, InitdataAlgorithmSNP, entries), teetypes.FamilyUnknown, true},
		{"the configuration itself on an unknown family", configuration, teetypes.FamilyUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckInitdataFamily(tc.launch, tc.family); (err != nil) != tc.wantError {
				t.Fatalf("got %v, want an error: %v", err, tc.wantError)
			}
		})
	}
}

// testPolicy is the least an agent policy entry holds: the package the
// guest agent evaluates.
const testPolicy = "package agent_policy\n"

// initdataDocument renders the initdata document a Kata Containers runtime
// binds, as its operator writes it, with an agent policy unless entries
// bring their own.
func initdataDocument(t *testing.T, algorithm string, entries map[string]string) []byte {
	t.Helper()
	withPolicy := map[string]string{PolicyFile: testPolicy}
	for name, entry := range entries {
		withPolicy[name] = entry
	}
	return bareInitdataDocument(t, algorithm, withPolicy)
}

// bareInitdataDocument is initdataDocument with the entries given and no more.
func bareInitdataDocument(t *testing.T, algorithm string, entries map[string]string) []byte {
	t.Helper()
	data, err := toml.Marshal(map[string]any{
		"version":   "0.1.0",
		"algorithm": algorithm,
		"data":      entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseReadsTheConfigurationAnInitdataDocumentCarries(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	configuration := render(t, testDocument(t, operatorPEM, anchorPEM))
	want, err := Parse(configuration)
	if err != nil {
		t.Fatal(err)
	}
	// The runtime's own entries ride in the same document.
	for _, algorithm := range []string{InitdataAlgorithmSNP, InitdataAlgorithmTDX} {
		got, err := Parse(initdataDocument(t, algorithm, map[string]string{
			ConfigFile:    string(configuration),
			"policy.rego": "package agent_policy\n",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s initdata document parsed to %+v, want the configuration it carries, %+v", algorithm, got, want)
		}
	}
}

func TestParseRefusesAnInitdataDocumentItCannotServe(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	configuration := string(render(t, testDocument(t, operatorPEM, anchorPEM)))
	tests := []struct {
		name      string
		algorithm string
		entries   map[string]string
		want      string
	}{
		{"digest the launch binding does not use", "sha512", map[string]string{ConfigFile: configuration}, "algorithm"},
		{"no declared digest", "", map[string]string{ConfigFile: configuration}, "algorithm"},
		{"no configuration entry", InitdataAlgorithmSNP, map[string]string{"policy.rego": "package agent_policy\n"}, ConfigFile},
		{"configuration under another name", InitdataAlgorithmSNP, map[string]string{"config.yaml": configuration}, ConfigFile},
		{"malformed configuration", InitdataAlgorithmSNP, map[string]string{ConfigFile: "clusterID: [\n"}, "YAML"},
		{"undeclared setting", InitdataAlgorithmSNP, map[string]string{ConfigFile: configuration + "cdsAddress: 10.0.0.1:8443\n"}, "cdsAddress"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(initdataDocument(t, tc.algorithm, tc.entries))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// The keys are read exactly as the runtime reads them: another spelling is
// another key, which carries no configuration and declares no digest.
func TestParseReadsInitdataKeysExactly(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	first := testDocument(t, operatorPEM, anchorPEM)
	second := first
	second.ClusterID = "other"
	entry := func(table string, document wire) string {
		return "[" + table + "]\n\"" + ConfigFile + "\" = '''\n" + string(render(t, document)) + "'''\n\"" + PolicyFile + "\" = \"\"\"" + testPolicy + "\"\"\"\n"
	}
	head := "algorithm = \"sha256\"\n"

	for _, launchFile := range []string{
		head + entry("data", first) + entry("DATA", second),
		head + entry("DATA", second) + entry("data", first),
	} {
		cfg, err := Parse([]byte(launchFile))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClusterID != first.ClusterID {
			t.Fatalf("cluster %q, want the [data] entry's %q", cfg.ClusterID, first.ClusterID)
		}
	}
	for name, launchFile := range map[string]string{
		"digest under another spelling": "ALGORITHM = \"sha256\"\nalgorithm = \"sha512\"\n" + entry("data", first),
		"table under another spelling":  head + entry("Data", first),
		"entry that is not a string":    head + "[data]\n\"" + ConfigFile + "\" = 1\n",
		"empty table":                   head + "[data]\n",
		"entry as a dotted key":         head + "\"data." + ConfigFile + "\" = '''\n" + string(render(t, first)) + "'''\n",
		"entry as a sub-table":          head + "[data.\"" + ConfigFile + "\"]\nclusterID = \"x\"\n",
		"oversized document":            head + entry("data", first) + "# " + strings.Repeat("x", maxInitdataSize) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(launchFile)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// The size cap is inclusive: a document of exactly the cap is read as
// initdata, and one byte more is not.
func TestParseReadsAnInitdataDocumentUpToTheCap(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	document := testDocument(t, operatorPEM, anchorPEM)
	head := "algorithm = \"sha256\"\n[data]\n\"" + ConfigFile + "\" = '''\n" + string(render(t, document)) + "'''\n\"" + PolicyFile + "\" = \"\"\"" + testPolicy + "\"\"\"\n# "
	atCap := head + strings.Repeat("x", maxInitdataSize-len(head)-1) + "\n"
	if len(atCap) != maxInitdataSize {
		t.Fatalf("fixture is %d bytes, want %d", len(atCap), maxInitdataSize)
	}
	cfg, err := Parse([]byte(atCap))
	if err != nil {
		t.Fatalf("a document of exactly the cap was refused: %v", err)
	}
	if cfg.ClusterID != document.ClusterID {
		t.Fatalf("cluster %q, want %q", cfg.ClusterID, document.ClusterID)
	}
	if _, err := Parse([]byte(atCap + "\n")); err == nil {
		t.Fatal("a document one byte over the cap was read as initdata")
	}
}

// A client reads its cluster from the same launch file the Trust Authority
// booted on, whichever form it takes. The file names a replica set, so a read
// that missed the carried configuration would report a single Trust Authority
// and stop the client following its decrees.
func TestReadClusterReadsAnInitdataDocument(t *testing.T) {
	operator, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	document := testHADocument(t, operatorPEM, anchorPEM)
	configuration := render(t, document)
	got, err := ReadCluster(initdataDocument(t, InitdataAlgorithmSNP, map[string]string{ConfigFile: string(configuration)}))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Replicated || got.ClusterID != document.ClusterID {
		t.Fatalf("read %+v, want the replicated cluster %q", got, document.ClusterID)
	}
	if len(got.OperatorKeys) != 1 || !got.OperatorKeys[0].Equal(operator) {
		t.Fatalf("operator keys = %v, want the carried configuration's one key", got.OperatorKeys)
	}
}

// The two forms cannot be confused: a configuration is a YAML mapping, whose
// `key: value` lines are not TOML, so it is never read as an initdata document.
func TestAConfigurationIsNotTOML(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	for name, configuration := range map[string][]byte{
		"a rendered configuration": render(t, testDocument(t, operatorPEM, anchorPEM)),
		"bare mapping lines":       []byte("schemaVersion: c8s-ta/v1\nclusterID: x\n"),
	} {
		t.Run(name, func(t *testing.T) {
			var document map[string]any
			if err := toml.Unmarshal(configuration, &document); err == nil {
				t.Fatal("a configuration parsed as TOML")
			}
			read, algorithm, err := readInitdata(configuration)
			if err != nil || algorithm != "" || string(read) != string(configuration) {
				t.Fatalf("read as %q declaring %q, %v; want the file itself", read, algorithm, err)
			}
		})
	}
}

// A pin is written for one TEE family, so it is not written around a launch
// file the Trust Authority of that family refuses.
func TestPinRefusesAnInitdataDigestOfAnotherFamily(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	entries := map[string]string{ConfigFile: string(render(t, testDocument(t, operatorPEM, anchorPEM)))}
	launchFile := initdataDocument(t, InitdataAlgorithmTDX, entries)
	if _, err := Pin("unread-manifest.json", teetypes.FamilySNP, nil, launchFile); err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("got %v, want a refusal naming the algorithm", err)
	}
}

// An initdata document over the cap is refused with the cap named, not with a
// bare YAML error.
func TestAnOversizedInitdataDocumentIsRefusedNamingTheCap(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	configuration := render(t, testDocument(t, operatorPEM, anchorPEM))
	launchFile := append(initdataDocument(t, InitdataAlgorithmSNP, map[string]string{ConfigFile: string(configuration)}),
		[]byte("# "+strings.Repeat("x", maxInitdataSize)+"\n")...)
	if _, err := Parse(launchFile); err == nil || !strings.Contains(err.Error(), "an initdata document may be") {
		t.Fatalf("Parse = %v, want a refusal naming the cap", err)
	}
	if _, err := ReadCluster(launchFile); err == nil || !strings.Contains(err.Error(), "an initdata document may be") {
		t.Fatalf("ReadCluster = %v, want a refusal naming the cap", err)
	}
}

// The launch binding covers the guest and this document, and the host names
// the containers afterwards. A document with no agent policy would identify a
// configuration and no program, so it is refused wherever it is read.
func TestAnInitdataDocumentMustCarryAnAgentPolicy(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	configuration := string(render(t, testDocument(t, operatorPEM, anchorPEM)))
	for name, tc := range map[string]struct {
		entries map[string]string
		want    string
	}{
		"no policy entry":       {map[string]string{ConfigFile: configuration}, "no \"policy.rego\" entry"},
		"an empty policy":       {map[string]string{ConfigFile: configuration, PolicyFile: ""}, "package agent_policy"},
		"another package":       {map[string]string{ConfigFile: configuration, PolicyFile: "package other\n"}, "package agent_policy"},
		"the package commented": {map[string]string{ConfigFile: configuration, PolicyFile: "# package agent_policy\n"}, "package agent_policy"},
	} {
		launchFile := bareInitdataDocument(t, InitdataAlgorithmSNP, tc.entries)
		if _, err := Parse(launchFile); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Parse = %v, want a refusal naming %q", name, err, tc.want)
		}
		if err := CheckInitdataFamily(launchFile, teetypes.FamilySNP); err == nil {
			t.Errorf("%s: a pin reader accepted the document", name)
		}
	}
	withPolicy := bareInitdataDocument(t, InitdataAlgorithmSNP, map[string]string{
		ConfigFile: configuration,
		PolicyFile: "# generated\n  package agent_policy  \ndefault CreateContainerRequest := false\n",
	})
	if _, err := Parse(withPolicy); err != nil {
		t.Fatalf("a document with a policy was refused: %v", err)
	}
}
