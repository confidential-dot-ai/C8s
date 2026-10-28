//go:build !c8s_node

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testSeedEntry is one component entry, in the form both the chart's seed and
// a CDS configuration's workloads carry it.
const testSeedEntry = `{"label":"registry/app@sha256:` + testSeedDigest + `","containers":[{"digest":"sha256:` + testSeedDigest + `","image":"registry/app@sha256:` + testSeedDigest + `","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}]}`

const testSeedDigest = "1111111111111111111111111111111111111111111111111111111111111111"

// testSeedDocument is the seed a stubbed helm render answers with.
func testSeedDocument(name string) string {
	return `{"schema":"c8s.allowlist/v1","workloads":{"` + name + `":` + testSeedEntry + `}}`
}

// cdsPinDocument is the pin document `c8s cds config new` produces: the CDS
// image, and the configuration its VM proves, serving the entries named here
// and dialling inventories in subnets.
func cdsPinDocument(t *testing.T, entries []string, subnets string) []byte {
	t.Helper()
	workloads := make([]string, 0, len(entries))
	for _, name := range entries {
		workloads = append(workloads, `"`+name+`":`+testSeedEntry)
	}
	config := strings.Join([]string{
		"schemaVersion: c8s-cds/v1",
		"clusterID: test",
		"operatorPublicKeys: |\n  " + strings.ReplaceAll(strings.TrimSpace(testOperatorPublicKey(t)), "\n", "\n  "),
		`workloads: '{"schema":"c8s.allowlist/v1","workloads":{` + strings.Join(workloads, ",") + `}}'`,
		`nodes: '{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":"` + strings.Repeat("ab", 48) + `"}]}'`,
		"nodeCIDRs:\n  - " + subnets,
		"leafDNSNames:\n  - router.example.com",
	}, "\n") + "\n"
	file, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` +
		strings.Repeat("cd", 48) + `","launch_file":` + string(file) + `}]}`)
}

// cdsPinFile is that document where `--cds-pin` reads it.
func cdsPinFile(t *testing.T, entries []string, subnets string) string {
	t.Helper()
	return writePin(t, string(cdsPinDocument(t, entries, subnets)))
}

// writePin puts a pin document in a file of its own.
func writePin(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds-pin.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testOperatorPublicKey is a PEM public key the configuration parser accepts.
func testOperatorPublicKey(t *testing.T) string {
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

func TestCDSPinNamesOneConfiguration(t *testing.T) {
	config, err := cdsPinConfig(cdsPinDocument(t, []string{"app"}, "192.0.2.0/24"))
	if err != nil {
		t.Fatalf("cdsPinConfig: %v", err)
	}
	if _, ok := config.Workloads.Workloads["app"]; !ok {
		t.Fatalf("configuration serves %v, want the app entry", config.Workloads.Workloads)
	}
	if len(config.NodeCIDRs) != 1 {
		t.Fatalf("node subnets = %v, want the one the configuration names", config.NodeCIDRs)
	}
}

func TestCDSPinRefusesWhatNoClientCouldHold(t *testing.T) {
	for name, document := range map[string]string{
		"no launch file": `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + strings.Repeat("cd", 48) + `"}]}`,
		"not a pin":      `{}`,
		"not a configuration": `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` +
			strings.Repeat("cd", 48) + `","launch_file":"clusterID: test\n"}]}`,
		"two configurations": `{"schema_version":"2","tee":"sev-snp","measurements":[` +
			`{"name":"a","measurement":"` + strings.Repeat("cd", 48) + `","launch_file":"schemaVersion: c8s-cds/v1\n"},` +
			`{"name":"b","measurement":"` + strings.Repeat("ef", 48) + `","launch_file":"schemaVersion: c8s-cds/v2\n"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := cdsPinConfig([]byte(document)); err == nil {
				t.Fatal("accepted a pin no client could hold a CDS to")
			}
		})
	}
}

// helm resolves --set-file itself, so the pin path must not depend on the
// directory the install ran from, and the address must be the literal endpoint
// a client's packet rules admit.
func TestCDSInstallArgs(t *testing.T) {
	pin := cdsPinFile(t, []string{"app"}, "192.0.2.0/24")
	args, err := cdsInstallArgs("10.9.9.9:8443", pin)
	if err != nil {
		t.Fatalf("cdsInstallArgs: %v", err)
	}
	if !slices.Contains(args, "cds.address=10.9.9.9:8443") || !slices.Contains(args, "cds.measurementsConfig="+pin) {
		t.Fatalf("args = %v, want the address and the pin file", args)
	}
	t.Chdir(filepath.Dir(pin))
	args, err = cdsInstallArgs("10.9.9.9:8443", filepath.Base(pin))
	if err != nil {
		t.Fatalf("cdsInstallArgs with a relative pin: %v", err)
	}
	i := slices.IndexFunc(args, func(arg string) bool { return strings.HasPrefix(arg, "cds.measurementsConfig=") })
	if i < 0 {
		t.Fatalf("args = %v, want the pin file", args)
	}
	if _, path, _ := strings.Cut(args[i], "="); !filepath.IsAbs(path) {
		t.Errorf("pin path %q is not absolute", path)
	}

	// A node-image render names no CDS: the image runs its own.
	if args, err := cdsInstallArgs("", ""); err != nil || args != nil {
		t.Fatalf("cdsInstallArgs() = %v, %v, want no arguments", args, err)
	}

	for _, tc := range []struct{ name, address, pin string }{
		{name: "a name, not an address", address: "cds.example.com:8443", pin: pin},
		{name: "no port", address: "10.9.9.9", pin: pin},
		{name: "no pin", address: "10.9.9.9:8443"},
		{name: "no address", pin: pin},
		{name: "a pin that is not there", address: "10.9.9.9:8443", pin: filepath.Join(t.TempDir(), "absent.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cdsInstallArgs(tc.address, tc.pin); err == nil {
				t.Fatal("accepted a CDS no client could reach or hold")
			}
		})
	}
}

// installSeedEntryName is the one entry the stubbed helm render seeds, and the
// one a stubbed CDS configuration serves.
const installSeedEntryName = "app"

// installSeedConfigMap is the seed ConfigMap a stubbed `helm template` answers
// with, as the chart renders it.
var installSeedConfigMap = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c8s-allowlist-seed"},"data":{"allowlist-seed.json":` +
	mustJSONString(testSeedDocument(installSeedEntryName)) + `}}`

func mustJSONString(s string) string {
	quoted, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(quoted)
}
