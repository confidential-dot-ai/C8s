package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// nodesDocument pins one TDX node image. The CDS VM in these tests attests on
// SEV-SNP: the family it serves is the nodes', not its own.
var nodesDocument = `{"schema_version":"1","tee":"tdx","measurements":[{"name":"node","mrtd":"` +
	strings.Repeat("ab", 48) + `"}]}`

// measuredDocument renders one cluster's complete CDS configuration document.
func measuredDocument(t *testing.T) []byte {
	t.Helper()
	operatorPEM, err := os.ReadFile(writeOperatorKeysPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	document, err := yaml.Marshal(map[string]any{
		"schemaVersion":      cdsconfig.SchemaVersion,
		"clusterID":          "lane",
		"operatorPublicKeys": string(operatorPEM),
		"workloads":          anySeed(map[string]string{"attestation-api": digestA}),
		"nodes":              nodesDocument,
		"nodeCIDRs":          []string{"10.0.0.0/24"},
		"leafDNSNames":       []string{"cds.example.com"},
		"leafDNSPatterns":    []string{`^[a-z0-9-]+[.][a-z0-9-]+[.]svc$`},
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// measuredConfig parses the document, as a CDS VM does at boot.
func measuredConfig(t *testing.T) *cdsconfig.Config {
	t.Helper()
	measured, err := cdsconfig.Parse(measuredDocument(t))
	if err != nil {
		t.Fatalf("parse CDS configuration: %v", err)
	}
	return measured
}

// Every setting the document decides must reach the server through the
// resolver that reads it, and the platform must be the one the hardware proved
// rather than one an argument claimed.
func TestMeasuredConfigDecidesWhatTheExcludedFlagsWould(t *testing.T) {
	measured := measuredConfig(t)
	cfg := withMeasuredConfig(config{measuredPolicies: armtls.NodeJournal}, measured, teetypes.FamilySNP)

	if cfg.armtlsPlatform != teetypes.FamilySNP.String() {
		t.Errorf("armTLS platform = %q, want %q", cfg.armtlsPlatform, teetypes.FamilySNP)
	}
	// A CDS VM extends no register, so the node journal the flag defaults to
	// must not follow it into the VM.
	if cfg.measuredPolicies != "" {
		t.Errorf("measured policies file = %q, want none", cfg.measuredPolicies)
	}

	operatorKeys, err := loadOperatorKeys(cfg)
	if err != nil {
		t.Fatalf("loadOperatorKeys: %v", err)
	}
	if len(operatorKeys.Keys()) != 1 || !bytes.Equal(operatorKeys.PEM(), measured.OperatorKeys.PEM()) {
		t.Errorf("operator keys = %d, PEM = %q, want the document's key and bytes", len(operatorKeys.Keys()), operatorKeys.PEM())
	}

	pins, err := loadNodePins(cfg)
	if err != nil {
		t.Fatalf("loadNodePins: %v", err)
	}
	if pins.Family != teetypes.FamilyTDX || len(pins.Images) != 1 {
		t.Errorf("node pins = %+v, want the document's one TDX image", pins)
	}

	patterns, err := leafDNSPatterns(cfg)
	if err != nil {
		t.Fatalf("leafDNSPatterns: %v", err)
	}
	if len(patterns) != 2 {
		t.Errorf("leaf DNS rules = %v, want the document's pattern and name", patterns)
	}

	hosts, err := buildInventoryHosts(t.Context(), cfg.measured.NodeCIDRs, nil)
	if err != nil {
		t.Fatalf("buildInventoryHosts: %v", err)
	}
	if !hosts.Contains("10.0.0.7") || hosts.Contains("10.244.1.5") {
		t.Errorf("inventory bound = %v, want the document's node subnets", hosts)
	}
}

// A setting the document decides must not also come from argv: the two could
// disagree, and only one of them is measured. "true" parses as every excluded
// flag's type, so the refusal is the exclusion and not a value rejected.
func TestConfigExcludesTheInputsItDecides(t *testing.T) {
	for _, name := range excludedByConfig {
		t.Run(name, func(t *testing.T) {
			err := executeCDS(t, "--config=/nonexistent", "--"+name+"=true")
			set := []string{"config", name}
			slices.Sort(set)
			want := fmt.Sprintf("if any flags in the group [config %s] are set none of the others can be; %v were all set", name, set)
			if err == nil || err.Error() != want {
				t.Fatalf("`c8s cds --config ... --%s` = %v, want %q", name, err, want)
			}
		})
	}
}

// The platform CDS attests on comes from the document's launch or from the
// flag; with neither, there is nothing to serve armTLS on.
func TestPlatformComesFromTheConfigOrTheFlag(t *testing.T) {
	if err := executeCDS(t); err == nil {
		t.Fatal("`c8s cds` started with no platform and no configuration")
	}
}

// The document is a host-writable file, so CDS serves the cluster it describes
// only while the launch binding names those exact bytes. Any other value is a
// swapped configuration.
func TestRunMeasuredConfigRefusesADocumentTheLaunchDidNotBind(t *testing.T) {
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformSNP)
	verdict := mockapi.PassingVerdict(strings.Repeat("ab", 48))
	elsewhere := runtimemeasure.HostData([]byte("a configuration the operator did not write"))
	verdict.Claims.InitData = elsewhere[:]
	stub.SetVerdict(verdict)

	cfg := config{
		configPath:        writeMeasuredDocument(t),
		attestationApiURL: stub.URL(),
	}
	err := runMeasuredConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "launched with") {
		t.Fatalf("runMeasuredConfig = %v, want a launch-binding refusal", err)
	}
}

// The self-report admitting the configuration comes from the attester inside
// this VM; one fetched over the network is another guest's.
func TestRunMeasuredConfigRequiresALoopbackAttester(t *testing.T) {
	cfg := config{
		configPath:        writeMeasuredDocument(t),
		attestationApiURL: "http://10.0.0.7:8400",
	}
	err := runMeasuredConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("runMeasuredConfig = %v, want a non-loopback attester refusal", err)
	}
}

// writeMeasuredDocument stages the document where a launched VM reads it.
func writeMeasuredDocument(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds-config.yaml")
	if err := os.WriteFile(path, measuredDocument(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A CDS serving a measured configuration publishes what the document holds,
// with no flag naming a workload, a node pin or an operator key.
func TestRunServesTheMeasuredConfiguration(t *testing.T) {
	cfg := validRunConfig(t, mockapi.New(t).URL())
	cfg.port = freePort(t)
	cfg = withMeasuredConfig(cfg, measuredConfig(t), teetypes.FamilySNP)

	base := fmt.Sprintf("https://127.0.0.1:%d", cfg.port)
	client := armTLSClient(nil)
	startRunServerOn(t, cfg, base, client)

	var listing struct {
		Workloads map[string]json.RawMessage `json:"workloads"`
	}
	fetchJSON(t, client, base+"/allowlist", &listing)
	if _, ok := listing.Workloads["attestation-api"]; !ok {
		t.Errorf("the document's workloads are not served: %v", listing.Workloads)
	}

	served, err := refvalues.ParseRendered(fetch(t, client, base+"/measurements"))
	if err != nil {
		t.Fatalf("GET /measurements does not parse: %v", err)
	}
	// The nodes CDS admits run on their own family, which an external CDS VM
	// need not share.
	if served.Family != teetypes.FamilyTDX || len(served.Images) != 1 {
		t.Errorf("served pins = %+v, want the document's one TDX image", served)
	}
}

// executeCDS runs the command with the arguments every mode requires, so what
// a case exercises is the arguments it adds.
func executeCDS(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{
		"--attestation-api-url=http://127.0.0.1:1",
		"--allowlist-db=" + filepath.Join(t.TempDir(), "allowlist.db"),
	}, args...))
	return cmd.Execute()
}

func fetch(t *testing.T, client *http.Client, url string) []byte {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d (%s), want 200", url, resp.StatusCode, body)
	}
	return body
}

func fetchJSON(t *testing.T, client *http.Client, url string, into any) {
	t.Helper()
	if err := json.Unmarshal(fetch(t, client, url), into); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}
