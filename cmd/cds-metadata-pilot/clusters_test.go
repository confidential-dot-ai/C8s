package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestClusterManifestUsesPrivateTokenFilesAndStrictBoundedConfig(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("synthetic-cluster-specific-token-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clusters.json")
	body, _ := json.Marshal([]map[string]string{{"namespace": "cluster-a", "token_file": token}})
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	configs, err := clusterConfigs(path)
	if err != nil || len(configs) != 1 || configs[0].Namespace != "cluster-a" || configs[0].Token != "synthetic-cluster-specific-token-value" {
		t.Fatal("valid private manifest did not load")
	}
	if err := os.Chmod(token, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := clusterConfigs(path); err == nil {
		t.Fatal("accepted readable token file")
	}
	if err := os.Chmod(token, 0600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`[{"namespace":"a","token":"inline-secret"}]`, `[]`, string(body) + ` []`} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := clusterConfigs(path); err == nil {
			t.Fatal("accepted invalid manifest")
		}
	}
}
