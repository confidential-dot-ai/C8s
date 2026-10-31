package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
)

// nodeMRTD is the TDVF firmware measurement the node images in these tests
// were built against.
var nodeMRTD = strings.Repeat("ab", refvalues.DigestSize)

// nodesDocument pins one TDX node image. The CDS VM in these tests attests on
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

// cluster is what a test varies in the configuration a CDS VM is launched
// with: the operator bundle authorizing writes, the workloads CDS serves and
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

// measuredDocument renders one cluster's complete CDS configuration document.
func measuredDocument(t *testing.T, c cluster) []byte {
	t.Helper()
	document, err := yaml.Marshal(map[string]any{
		"schemaVersion":      cdsconfig.SchemaVersion,
		"clusterID":          "lane",
		"operatorPublicKeys": string(c.operatorPEM),
		"workloads":          anySeed(c.workloads),
		"nodes":              c.nodePins(),
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
func measuredConfig(t *testing.T, c cluster) *cdsconfig.Config {
	t.Helper()
	measured, err := cdsconfig.Parse(measuredDocument(t, c))
	if err != nil {
		t.Fatalf("parse CDS configuration: %v", err)
	}
	return measured
}

// Every setting the document decides must reach the server through the
// resolver that reads it, and the platform must be the one the hardware proved
// rather than one an argument claimed.
func TestMeasuredConfigDecidesEverySetting(t *testing.T) {
	operatorPEM := operatorKeysPEM(t)
	launched := cluster{
		operatorPEM: operatorPEM,
		workloads:   map[string]string{"attestation-api": digestA},
	}
	cfg, err := withMeasuredConfig(config{}, measuredDocument(t, launched), teetypes.FamilySNP)
	if err != nil {
		t.Fatal(err)
	}
	measured := cfg.measured

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

// CDS serves one cluster's measured configuration, so there is no mode that
// starts without one.
func TestConfigIsRequired(t *testing.T) {
	if err := executeCDS(t); err == nil {
		t.Fatal("`c8s cds` started with no configuration")
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

func TestRunMeasuredConfigRequiresAutoHostAddress(t *testing.T) {
	path := writeMeasuredDocument(t)
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformSNP)
	verdict := mockapi.PassingVerdict(strings.Repeat("ab", 48))
	bound := runtimemeasure.HostData(document)
	verdict.Claims.InitData = bound[:]
	stub.SetVerdict(verdict)

	noRoute := errors.New("no default route")
	previous := chooseHostInterface
	t.Cleanup(func() { chooseHostInterface = previous })
	chooseHostInterface = func() (net.IP, error) { return nil, noRoute }
	err = runMeasuredConfig(t.Context(), config{
		configPath: path, attestationApiURL: stub.URL(), host: "auto",
	})
	if !errors.Is(err, noRoute) {
		t.Fatalf("startup error = %v, want the host-address selection failure", err)
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

// replicatedDocument is the measured document of a cluster whose CDS runs as
// a replica set, with the operator keys a test signs decrees with.
func replicatedDocument(t *testing.T, operatorPEM []byte) []byte {
	t.Helper()
	var document map[string]any
	measured := measuredDocument(t, cluster{
		operatorPEM: operatorPEM,
		workloads:   map[string]string{"attestation-api": digestA},
	})
	if err := yaml.Unmarshal(measured, &document); err != nil {
		t.Fatal(err)
	}
	document["ha"] = map[string]any{
		// A loopback address no replica answers at: the replica under test
		// reaches none of its cluster and joins nothing.
		"replicas": []string{"127.0.0.9"},
		"voters":   1,
		"board": map[string]any{
			"endpoint": "https://s3.example.org",
			"bucket":   "c8s-boards",
		},
		"recoveryKey": string(operatorKeysPEM(t)),
	}
	data, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// writeMeasuredDocument stages the document where a launched VM reads it.
func writeMeasuredDocument(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds-config.yaml")
	document := measuredDocument(t, cluster{operatorPEM: operatorKeysPEM(t), workloads: map[string]string{"attestation-api": digestA}})
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A CDS serving a measured configuration publishes what the document holds,
// with no flag naming a workload, a node pin or an operator key.
func TestRunServesTheMeasuredConfiguration(t *testing.T) {
	cfg := validRunConfig(t, mockapi.New(t).URL())
	cfg.port = freePort(t)
	launched := cluster{
		operatorPEM: operatorKeysPEM(t),
		workloads:   map[string]string{"attestation-api": digestA},
	}
	cfg, err := withMeasuredConfig(cfg, measuredDocument(t, launched), teetypes.FamilySNP)
	if err != nil {
		t.Fatal(err)
	}

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
