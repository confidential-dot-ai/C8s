package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Public synthetic staging bytes; the baseline service owns their authentication.
const baselineStagedFixture = `{"schema_version":"c8s-launch/v1","cluster_id":"fixture","role":"pod","image":{"platform":"tdx","measurement":"measured","rtmrs":{"1":"kernel","2":"operator"}},"node":{"name":"generic"},"rke2":{"agent_token":""},"server":{"address":"192.0.2.1","operator_public_key":"server"},"agent_operator_public_keys":null,"pod_operator_public_key":"pod","tls_san":"c8s.local"}`

func TestRecoveryFixtureOnlyReadsItsHistoricalGenericSchema(t *testing.T) {
	if err := checkBaselineLaunch([]byte(baselineStagedFixture)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, raw string }{
		{"new schema", strings.Replace(baselineStagedFixture, "c8s-launch/v1", "c8s-launch/v2", 1)},
		{"server", strings.Replace(baselineStagedFixture, `"role":"pod"`, `"role":"server"`, 1)},
		{"static Pod", strings.TrimSuffix(baselineStagedFixture, "}") + `,"pod":{}}`},
		{"workload authority", strings.TrimSuffix(baselineStagedFixture, "}") + `,"workloads":"{}"}`},
		{"node credentials", strings.Replace(baselineStagedFixture, `"agent_token":""`, `"agent_token":"secret"`, 1)},
		{"unknown field", strings.TrimSuffix(baselineStagedFixture, "}") + `,"cds":{}}`},
		{"unknown nested field", strings.Replace(baselineStagedFixture, `"agent_token":""`, `"agent_token":"","nodePassword":"secret"`, 1)},
		{"trailing", baselineStagedFixture + `{}`},
		{"empty", ``},
		{"oversized", strings.Repeat(" ", baselineStagedLimit+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkBaselineLaunch([]byte(tc.raw)); err == nil {
				t.Fatal("unsupported baseline launch accepted")
			}
		})
	}
}

func TestRecoveryFixtureRequiresProtectedRegularStaging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(baselineStagedFixture), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireBaselineLaunch(path); (err == nil) != (os.Geteuid() == 0) {
		t.Fatalf("staged owner check: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := requireBaselineLaunch(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := requireBaselineLaunch(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := requireBaselineLaunch(path); err == nil {
		t.Fatal("writable staged file accepted")
	}
}
