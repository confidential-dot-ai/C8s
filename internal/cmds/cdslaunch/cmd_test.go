package cdslaunch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
)

const componentSeed = `{"schema":"c8s.allowlist/v1","workloads":{"c8s-router":{"containers":[{"digest":"sha256:` +
	"1111111111111111111111111111111111111111111111111111111111111111" + `"}]}}}`

const tenantWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"tenant-app":{"containers":[{"digest":"sha256:` +
	"2222222222222222222222222222222222222222222222222222222222222222" + `"}]}}}`

func publicKeyPEM(t *testing.T) string {
	t.Helper()
	return publicKeyPEMOf(t, elliptic.P256())
}

func publicKeyPEMOf(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func nodePins(t *testing.T) string {
	t.Helper()
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name:   "server",
			Digest: bytes.Repeat([]byte{0x11}, refvalues.DigestSize),
			Anchor: []byte(publicKeyPEM(t)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(document)
}

func imageManifest(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`{"version":3,"build":{"platform":"snp"},"snp_variants":[{"smp":4,"measurement":{"algorithm":"sha384","snp_launch_digest":%q}}]}`,
		strings.Repeat("ab", refvalues.DigestSize))
}

func writeInput(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// inputs are the flags every test varies from.
func inputs(t *testing.T, out string) []string {
	t.Helper()
	return []string{"new",
		"--out", out,
		"--cluster-id", "acme-prod",
		"--operator-keys", writeInput(t, "operator-keys.pem", publicKeyPEM(t)),
		"--allowlist-seed", writeInput(t, "seed.json", componentSeed),
		"--node-pins", writeInput(t, "nodes.json", nodePins(t)),
		"--node-cidr", "10.0.0.0/24",
		"--pod-cidr", "10.42.0.0/16",
		"--service-cidr", "10.43.0.0/16",
		"--image-manifest", writeInput(t, "manifest.json", imageManifest(t)),
		"--platform", "sev-snp",
		"--vcpus", "4",
	}
}

func run(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	return cmd.Execute()
}

// The pin is only an identity for this CDS if it binds the configuration the
// VM boots on byte for byte.
func TestNewWritesAConfigurationItsPinBinds(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cds")
	args := append(inputs(t, out), "--workloads", writeInput(t, "workloads.json", tenantWorkloads))
	if err := run(t, args...); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(out, "cds-config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile(filepath.Join(out, "cds-pin.json"))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := refvalues.Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(pin.Images) != 1 {
		t.Fatalf("pin = %+v", pin)
	}
	if !bytes.Equal(pin.Images[0].LaunchFile, config) {
		t.Fatal("the pin does not bind the configuration that was written")
	}
	cfg, err := cdsconfig.Parse(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Workloads.Workloads["c8s-router"]; !ok {
		t.Fatalf("workloads lost the component entries: %v", cfg.Workloads.Workloads)
	}
	if _, ok := cfg.Workloads.Workloads["tenant-app"]; !ok {
		t.Fatalf("workloads lost the tenant entries: %v", cfg.Workloads.Workloads)
	}
	// The CDS image passes no DNS SAN pattern, so mesh CSRs validate against
	// what the configuration carries.
	if len(cfg.DNSSANPatterns) != 1 || !cfg.DNSSANPatterns[0].MatchString("mesh.c8s.svc") {
		t.Fatalf("DNS SAN rules = %v", cfg.DNSSANPatterns)
	}
}

func TestNewRefusesANodeSubnetHoldingClusterAddresses(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cds")
	args := append(inputs(t, out), "--pod-cidr", "10.0.0.0/16")
	if err := run(t, args...); err == nil {
		t.Fatal("a node subnet overlapping the pod range was accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("the refused run still wrote its outputs")
	}
}

func TestNewRefusesATenantEntryTakingAComponentName(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cds")
	args := append(inputs(t, out), "--workloads", writeInput(t, "workloads.json", componentSeed))
	if err := run(t, args...); err == nil {
		t.Fatal("a tenant workload replaced a component entry")
	}
}

// A given pattern replaces the default rather than joining it, so the written
// rules are the ones named.
func TestNewLeafDNSPatternReplacesTheDefault(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cds")
	args := append(inputs(t, out), "--leaf-dns-pattern", `^cds[.]acme[.]example$`)
	if err := run(t, args...); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(out, "cds-config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := cdsconfig.Parse(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNSSANPatterns) != 1 || cfg.DNSSANPatterns[0].MatchString("mesh.c8s.svc") {
		t.Fatalf("DNS SAN rules = %v", cfg.DNSSANPatterns)
	}
}

// Every replica of a cluster boots one configuration, so the generator takes
// the replica set and writes no replica's own name into the document.
func TestNewWritesTheReplicaSetOfACluster(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cds")
	args := append(inputs(t, out),
		"--replica", "cds-1.acme.example",
		"--replica", "cds-2.acme.example",
		"--replica", "cds-3.acme.example",
		"--voters", "3",
		"--board-endpoint", "https://store.acme.example",
		"--board-bucket", "c8s-boards",
		"--board-prefix", "acme/prod",
		"--recovery-key", writeInput(t, "recovery-pub.pem", publicKeyPEM(t)))
	if err := run(t, args...); err != nil {
		t.Fatal(err)
	}
	cfg := parseWritten(t, out)
	if cfg.HA == nil {
		t.Fatal("the configuration runs the singleton CDS, want the replica set")
	}
	if len(cfg.HA.Replicas) != 3 || cfg.HA.Voters != 3 || cfg.HA.RecoveryKey == nil {
		t.Fatalf("replica set = %+v", cfg.HA)
	}
	want := cdsconfig.Board{
		Endpoint: "https://store.acme.example",
		Bucket:   "c8s-boards",
		Prefix:   "acme/prod",
	}
	if cfg.HA.Board != want {
		t.Fatalf("board = %+v, want %+v", cfg.HA.Board, want)
	}
}

// A cluster named with no replica runs one CDS, and its configuration says so
// by carrying no replica set at all.
func TestNewWritesNoReplicaSetByDefault(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cds")
	if err := run(t, inputs(t, out)...); err != nil {
		t.Fatal(err)
	}
	if cfg := parseWritten(t, out); cfg.HA != nil {
		t.Fatalf("replica set = %+v, want the singleton CDS", cfg.HA)
	}
}

// The voter seats, the board and the key its backups seal to are the
// cluster's, so an input no replica set can run on is refused before anything
// is written.
func TestNewRefusesAReplicaSetItCannotRun(t *testing.T) {
	key := writeInput(t, "recovery-pub.pem", publicKeyPEM(t))
	onAnotherCurve := writeInput(t, "p384-pub.pem", publicKeyPEMOf(t, elliptic.P384()))
	for name, flags := range map[string][]string{
		"an even voter count":         {"--replica", "cds-1.acme.example", "--voters", "2"},
		"no voter seat":               {"--replica", "cds-1.acme.example"},
		"no replica":                  {"--voters", "3"},
		"a replica twice":             {"--replica", "cds-1.acme.example", "--replica", "cds-1.acme.example", "--voters", "1"},
		"a replica's port":            {"--replica", "cds-1.acme.example:8443", "--voters", "1"},
		"a plain HTTP board":          {"--replica", "cds-1.acme.example", "--voters", "1", "--board-endpoint", "http://store.acme.example", "--board-bucket", "c8s-boards"},
		"a recovery key and no board": {"--replica", "cds-1.acme.example", "--voters", "1", "--recovery-key", key},
		"a recovery key of another curve": {"--replica", "cds-1.acme.example", "--voters", "1", "--board-endpoint", "https://store.acme.example", "--board-bucket", "c8s-boards",
			"--recovery-key", onAnotherCurve},
	} {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "cds")
			if err := run(t, append(inputs(t, out), flags...)...); err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("the refused run still wrote its outputs")
			}
		})
	}
}

// parseWritten is the configuration a run wrote, as a replica parses it.
func parseWritten(t *testing.T, out string) *cdsconfig.Config {
	t.Helper()
	config, err := os.ReadFile(filepath.Join(out, cdsconfig.ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := cdsconfig.Parse(config)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
