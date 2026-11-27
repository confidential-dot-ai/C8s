package ta

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taconfig"
)

// nodeMRTD is the TDVF firmware measurement the node images in these tests
// were built against.
var nodeMRTD = strings.Repeat("ab", refvalues.DigestSize)

// nodesDocument pins one TDX node image. The Trust Authority VM in these tests attests on
// SEV-SNP: the family it serves is the nodes', not its own.
var nodesDocument = `{"schema_version":"1","tee":"tdx","measurements":[` +
	tdxNodeEntry("node", nodeMRTD, "", "") + `]}`

// upgradingNodesDocument pins the node image being replaced and the one being
// rolled out: one firmware, each image with its own kernel and command-line
// registers.
var upgradingNodesDocument = `{"schema_version":"1","tee":"tdx","measurements":[` +
	tdxNodeEntry("node", nodeMRTD, strings.Repeat("c1", refvalues.DigestSize), strings.Repeat("c2", refvalues.DigestSize)) + `,` +
	tdxNodeEntry("node-next", nodeMRTD, strings.Repeat("d1", refvalues.DigestSize), strings.Repeat("d2", refvalues.DigestSize)) + `]}`

// tdxNodeEntry is one node image's entry in a measurements document: the
// firmware measurement, and the kernel and command-line registers from the
// same build. Empty registers pin the firmware alone.
func tdxNodeEntry(name, mrtd, kernel, commandLine string) string {
	if kernel == "" && commandLine == "" {
		return fmt.Sprintf(`{"name":%q,"mrtd":%q}`, name, mrtd)
	}
	return fmt.Sprintf(`{"name":%q,"mrtd":%q,"rtmr":[null,%q,%q,null]}`, name, mrtd, kernel, commandLine)
}

// cluster is what a test varies in the configuration a Trust Authority VM is launched
// with: the operator bundle authorizing writes, the workloads Trust Authority serves and
// the node images it admits.
type cluster struct {
	operatorPEM []byte
	workloads   map[string]string
	nodes       string
}

// nodePins is the cluster's node pin document, defaulting to the one-image
// nodesDocument.
func (c cluster) nodePins() string {
	if c.nodes == "" {
		return nodesDocument
	}
	return c.nodes
}

// measuredDocument renders one cluster's complete Trust Authority configuration document.
func measuredDocument(t *testing.T, c cluster) []byte {
	t.Helper()
	document, err := yaml.Marshal(map[string]any{
		"schemaVersion":      taconfig.SchemaVersion,
		"clusterID":          "lane",
		"operatorPublicKeys": string(c.operatorPEM),
		"workloads":          anySeed(c.workloads),
		"nodes":              c.nodePins(),
		"nodeCIDRs":          []string{"10.0.0.0/24"},
		"leafDNSNames":       []string{"ta.example.com"},
		"leafDNSPatterns":    []string{`^[a-z0-9-]+[.][a-z0-9-]+[.]svc$`},
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// measuredConfig parses the document, as a Trust Authority VM does at boot.
func measuredConfig(t *testing.T, c cluster) *taconfig.Config {
	t.Helper()
	measured, err := taconfig.Parse(measuredDocument(t, c))
	if err != nil {
		t.Fatalf("parse Trust Authority configuration: %v", err)
	}
	return measured
}

// pastTheBinding is a log level no Trust Authority takes: startup reads it
// first once the launch binding holds, so a run that stops on it passed the
// binding check.
const pastTheBinding = "past-the-binding"

func stoppedPastTheBinding(err error) bool {
	return err != nil && strings.Contains(err.Error(), "--log-level")
}

// initdataLaunchFile returns a Kata Containers initdata document and the
// configuration it carries.
func initdataLaunchFile(t *testing.T, algorithm string) (launchFile, configuration []byte) {
	t.Helper()
	configuration = measuredDocument(t, cluster{operatorPEM: operatorKeysPEM(t), workloads: map[string]string{"attestation-api": digestA}})
	launchFile, err := toml.Marshal(map[string]any{
		"version":   "0.1.0",
		"algorithm": algorithm,
		"data":      map[string]string{taconfig.ConfigFile: string(configuration)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return launchFile, configuration
}

// The launch binding is over the initdata document: a report binding only the
// configuration inside it is of a guest launched with something else.
func TestRunMeasuredConfigBindsTheWholeInitdataDocument(t *testing.T) {
	launchFile, configuration := initdataLaunchFile(t, taconfig.InitdataAlgorithmSNP)
	path := filepath.Join(t.TempDir(), "initdata.toml")
	if err := os.WriteFile(path, launchFile, 0o600); err != nil {
		t.Fatal(err)
	}
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformSNP)
	bind := func(bound []byte) {
		verdict := mockapi.PassingVerdict(strings.Repeat("ab", 48))
		hostData := runtimemeasure.HostData(bound)
		verdict.Claims.InitData = hostData[:]
		stub.SetVerdict(verdict)
	}
	// Startup past the binding check stops at the first step after it.
	cfg := config{configPath: path, attestationApiURL: stub.URL(), logLevel: pastTheBinding}

	bind(launchFile)
	if err := runMeasuredConfig(t.Context(), cfg); !stoppedPastTheBinding(err) {
		t.Fatalf("a report binding the whole document = %v, want startup to pass the launch-binding check", err)
	}
	bind(configuration)
	if err := runMeasuredConfig(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "launched with") {
		t.Fatalf("a report binding only the carried configuration = %v, want a launch-binding refusal", err)
	}
}

// On TDX a Kata Containers runtime commits the document in MRCONFIGID and
// extends no register, so that field alone holds the binding.
func TestRunMeasuredConfigReadsAnInitdataDocumentFromMRCONFIGID(t *testing.T) {
	launchFile, configuration := initdataLaunchFile(t, taconfig.InitdataAlgorithmTDX)
	path := filepath.Join(t.TempDir(), "initdata.toml")
	if err := os.WriteFile(path, launchFile, 0o600); err != nil {
		t.Fatal(err)
	}
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformTDX)
	untouched := strings.Repeat("00", 48)
	bind := func(bound []byte, register string) {
		t.Helper()
		digest, err := runtimemeasure.LaunchFileDigest(teetypes.FamilyTDX, bound)
		if err != nil {
			t.Fatal(err)
		}
		verdict := mockapi.PassingVerdict(strings.Repeat("ab", 48))
		verdict.Claims.InitData = digest
		verdict.Claims.PlatformData = map[string]any{"rtmr_3": register}
		stub.SetVerdict(verdict)
	}
	cfg := config{configPath: path, attestationApiURL: stub.URL(), logLevel: pastTheBinding}

	bind(launchFile, untouched)
	if err := runMeasuredConfig(t.Context(), cfg); !stoppedPastTheBinding(err) {
		t.Fatalf("a report whose MRCONFIGID binds the document = %v, want startup to pass the launch-binding check", err)
	}
	bind(configuration, untouched)
	if err := runMeasuredConfig(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "launched with") {
		t.Fatalf("a report binding only the carried configuration = %v, want a launch-binding refusal", err)
	}
	// MRCONFIGID says nothing about RTMR[3]: a register something extended
	// means a measurer the launch file does not account for ran.
	bind(launchFile, strings.Repeat("cd", 48))
	if err := runMeasuredConfig(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "RTMR[3]") {
		t.Fatalf("an extended RTMR[3] beside a matching MRCONFIGID = %v, want a refusal naming the register", err)
	}
	// A measured initrd that seeded RTMR[3] from the same document starts it
	// too, whatever MRCONFIGID holds.
	seed := runtimemeasure.Seed(launchFile)
	bind(configuration, hex.EncodeToString(seed[:]))
	if err := runMeasuredConfig(t.Context(), cfg); !stoppedPastTheBinding(err) {
		t.Fatalf("a report whose RTMR[3] seed binds the document = %v, want startup to pass the launch-binding check", err)
	}
}

// Every setting the document decides must reach the server through the
// resolver that reads it, and the platform must be the one the hardware proved
// rather than one an argument claimed.
func TestMeasuredConfigDecidesEverySetting(t *testing.T) {
	operatorPEM := operatorKeysPEM(t)
	measured := measuredConfig(t, cluster{operatorPEM: operatorPEM, workloads: map[string]string{"attestation-api": digestA}})
	cfg := withMeasuredConfig(config{}, measured, teetypes.FamilySNP)

	if cfg.armtlsPlatform != teetypes.FamilySNP {
		t.Errorf("armTLS platform = %q, want %q", cfg.armtlsPlatform, teetypes.FamilySNP)
	}
	if len(measured.OperatorKeys.Keys()) != 1 || !bytes.Equal(measured.OperatorKeys.PEM(), operatorPEM) {
		t.Errorf("operator keys = %d, PEM = %q, want the document's key and bytes", len(measured.OperatorKeys.Keys()), measured.OperatorKeys.PEM())
	}
	if measured.Nodes.Family != teetypes.FamilyTDX || len(measured.Nodes.Images) != 1 {
		t.Errorf("node pins = %+v, want the document's one TDX image", measured.Nodes)
	}
	if len(measured.DNSSANPatterns) != 2 {
		t.Errorf("leaf DNS rules = %v, want the document's pattern and name", measured.DNSSANPatterns)
	}
	if !measured.NodeCIDRs.Contains("10.0.0.7") || measured.NodeCIDRs.Contains("10.244.1.5") {
		t.Errorf("inventory bound = %v, want the document's node subnets", measured.NodeCIDRs)
	}
}

// Trust Authority serves one cluster's measured configuration, so there is no mode that
// starts without one.
func TestConfigIsRequired(t *testing.T) {
	if err := executeTA(t); err == nil {
		t.Fatal("`c8s ta` started with no configuration")
	}
}

// The document is a host-writable file, so the Trust Authority serves the cluster it describes
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
// this VM; one fetched over the network is another guest's, and one this
// process cannot parse reaches no attester at all.
func TestRunMeasuredConfigRequiresALoopbackAttester(t *testing.T) {
	for name, url := range map[string]string{
		"another guest":  "http://10.0.0.7:8400",
		"not a URL":      "not a url",
		"no scheme":      "127.0.0.1:8400",
		"no attestation": "",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config{configPath: writeMeasuredDocument(t), attestationApiURL: url}
			if err := runMeasuredConfig(context.Background(), cfg); err == nil {
				t.Fatal("runMeasuredConfig accepted an attester outside this VM")
			}
		})
	}
}

// writeMeasuredDocument stages the document where a launched VM reads it.
func writeMeasuredDocument(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ta-config.yaml")
	document := measuredDocument(t, cluster{operatorPEM: operatorKeysPEM(t), workloads: map[string]string{"attestation-api": digestA}})
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A Trust Authority serving a measured configuration publishes what the document holds,
// with no flag naming a workload, a node pin or an operator key.
func TestRunServesTheMeasuredConfiguration(t *testing.T) {
	cfg := validRunConfig(t, mockapi.New(t).URL())
	cfg.port = freePort(t)
	cfg = withMeasuredConfig(cfg, measuredConfig(t, cluster{operatorPEM: operatorKeysPEM(t), workloads: map[string]string{"attestation-api": digestA}}), teetypes.FamilySNP)

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
	// The nodes Trust Authority admits run on their own family, which an external Trust Authority VM
	// need not share.
	if served.Family != teetypes.FamilyTDX || len(served.Images) != 1 {
		t.Errorf("served pins = %+v, want the document's one TDX image", served)
	}
}

// executeTA runs the command with the arguments every mode requires, so what
// a case exercises is the arguments it adds.
func executeTA(t *testing.T, args ...string) error {
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

// A TDX report that binds the document in neither field is refused naming
// both, so the operator sees which fields were read.
func TestRunMeasuredConfigNamesBothTDXFieldsWhenNeitherBinds(t *testing.T) {
	launchFile, _ := initdataLaunchFile(t, taconfig.InitdataAlgorithmTDX)
	path := filepath.Join(t.TempDir(), "initdata.toml")
	if err := os.WriteFile(path, launchFile, 0o600); err != nil {
		t.Fatal(err)
	}
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformTDX)
	verdict := mockapi.PassingVerdict(strings.Repeat("ab", 48))
	verdict.Claims.PlatformData = map[string]any{"rtmr_3": strings.Repeat("00", 48)}
	stub.SetVerdict(verdict)
	err := runMeasuredConfig(t.Context(), config{configPath: path, attestationApiURL: stub.URL()})
	if err == nil || !strings.Contains(err.Error(), "launched with") || !strings.Contains(err.Error(), "RTMR[3]") || !strings.Contains(err.Error(), "MRCONFIGID") {
		t.Fatalf("got %v, want a launch-binding refusal naming RTMR[3] and MRCONFIGID", err)
	}
}

// A document its launcher bound but the Trust Authority cannot read is refused
// for what is wrong with it, not as a file the VM was not launched with.
func TestRunMeasuredConfigNamesAnUnreadableInitdataDocument(t *testing.T) {
	launchFile, _ := initdataLaunchFile(t, "md5")
	path := filepath.Join(t.TempDir(), "initdata.toml")
	if err := os.WriteFile(path, launchFile, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := runtimemeasure.LaunchFileDigest(teetypes.FamilyTDX, launchFile)
	if err != nil {
		t.Fatal(err)
	}
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformTDX)
	verdict := mockapi.PassingVerdict(strings.Repeat("ab", 48))
	verdict.Claims.InitData = digest
	verdict.Claims.PlatformData = map[string]any{"rtmr_3": strings.Repeat("00", 48)}
	stub.SetVerdict(verdict)
	err = runMeasuredConfig(t.Context(), config{configPath: path, attestationApiURL: stub.URL()})
	if err == nil || !strings.Contains(err.Error(), "algorithm") || strings.Contains(err.Error(), "launched with") {
		t.Fatalf("got %v, want a refusal naming the algorithm", err)
	}
}
