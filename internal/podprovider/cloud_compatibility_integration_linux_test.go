//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCloudAcceptanceLaunchCompatibility(t *testing.T) {
	for _, schema := range []string{"c8s-launch/v1", "c8s-launch/v2", "c8s-launch/v99", ""} {
		for _, mode := range []string{"run", "cleanup", "unknown"} {
			t.Run(mode+"/"+schema, func(t *testing.T) {
				want := mode == "cleanup" || (mode == "run" && schema == "c8s-launch/v2")
				if err := cloudLaunchCompatibility(mode, schema); (err == nil) != want {
					t.Fatalf("compatibility mismatch: %v", err)
				}
			})
		}
	}
}

func TestCloudAcceptanceCleanupUsesReceiptsWithoutLocalLaunchProof(t *testing.T) {
	r, owned, receipt := cloudOwnershipFixture(t)
	if err := os.Chmod(r.dir, 0700); err != nil {
		t.Fatal(err)
	}
	const token = "offline-original-credential"
	r.cfg.Source = strings.Repeat("1", 40)
	r.cfg.CloudURL = "https://api.cloud.confidential.ai"
	r.cfg.TokenFile = filepath.Join(r.dir, "credential")
	r.cfg.MeshImage = "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:" + strings.Repeat("c", 64)
	r.cfg.VCPUs, r.cfg.MemoryMiB = 2, 8192
	if err := os.WriteFile(r.cfg.TokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	r.ledger.Config, r.ledger.CredentialHash = r.cfg, credentialHash(token)
	owned.Receipt = &receipt
	configPath := filepath.Join(r.dir, "config.json")
	if err := cloudWrite(configPath, r.cfg); err != nil {
		t.Fatal(err)
	}
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("C8S_PODCLOUD_LIVE", "1")
	// The current source may no longer load historical provider/launch files.
	// Cleanup must retain the exact ledger authority and use Cloud receipts.
	t.Setenv("C8S_PODPROVIDER_KUBECONFIG", filepath.Join(r.dir, "unavailable-kubeconfig"))
	if err := cloudLaunchCompatibility("cleanup", "c8s-launch/v2"); err != nil {
		t.Fatal(err)
	}
	opened, err := openCloudRun(configPath, r.dir, "cleanup")
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	if err = opened.recoverUnattempted(t.Context(), nil); err == nil {
		t.Fatal("missing historical local proof unexpectedly succeeded")
	}
	if !opened.ledger.Owned["a"].Attempted || opened.ledger.Owned["a"].Terminated {
		t.Fatal("unavailable local proof changed cleanup authority")
	}
	var reads, mutations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/instances/"+receipt.ID {
			mutations.Add(1)
			http.Error(w, "unexpected mutation or discovery", http.StatusMethodNotAllowed)
			return
		}
		reads.Add(1)
		raw, _ := json.Marshal(receipt)
		var item map[string]any
		_ = json.Unmarshal(raw, &item)
		item["status"] = "terminated"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(item)
	}))
	defer server.Close()
	opened.api = &cloudClient{base: server.URL, token: token, http: server.Client()}
	if err = opened.cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 2 || mutations.Load() != 0 || !opened.ledger.Complete || !opened.ledger.Owned["a"].Terminated {
		t.Fatal("receipt cleanup did not confirm the exact owned Cloud receipt")
	}
}
