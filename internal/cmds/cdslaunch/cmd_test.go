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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
