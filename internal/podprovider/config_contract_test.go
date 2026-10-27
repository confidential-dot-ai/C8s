package podprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationRejectsUnsafeOrIncompleteOriginsAndCapacity(t *testing.T) {
	base := fixtureConfig(t)
	for _, kind := range []string{"provider-id", "namespace", "node-name", "http", "url-credentials", "url-path", "url-query", "image", "size", "location", "cluster", "public-ip", "vcpus", "memory", "reserve", "pods", "server-ip", "missing-file"} {
		t.Run(kind, func(t *testing.T) {
			cfg := *base
			switch kind {
			case "provider-id":
				cfg.ProviderID = "INVALID"
			case "namespace":
				cfg.Namespace = ""
			case "node-name":
				cfg.NodeName = "node/invalid"
			case "http":
				cfg.CloudURL = "http://cloud.example"
			case "url-credentials":
				cfg.CloudURL = "https://user:password@cloud.example"
			case "url-path":
				cfg.CloudURL = "https://cloud.example/nested"
			case "url-query":
				cfg.CloudURL = "https://cloud.example?token=secret"
			case "image":
				cfg.Image = "c8s-pod:latest"
			case "size":
				cfg.Size = ""
			case "location":
				cfg.Location = ""
			case "cluster":
				cfg.ClusterID = ""
			case "public-ip":
				cfg.PublicIP = "private"
			case "vcpus":
				cfg.VCPUs = 0
			case "memory":
				cfg.MemoryMiB = 1 << 23
			case "reserve":
				cfg.ReservedMemoryMiB = cfg.MemoryMiB
			case "pods":
				cfg.MaxPods = 10001
			case "server-ip":
				cfg.ServerAddress = "server.example"
			case "missing-file":
				cfg.WorkloadsFile = ""
			}
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("unsafe/incomplete configuration accepted")
			}
		})
	}
	base.ReservedMemoryMiB = 0
	base.PublicIP = ""
	base.CloudURL += "/"
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	if base.ReservedMemoryMiB != 1024 || base.PublicIP != "shared" || strings.HasSuffix(base.CloudURL, "/") {
		t.Fatal("documented defaults not applied")
	}
}

func TestTrustFilesFailBeforeSigningOrRegistration(t *testing.T) {
	for _, kind := range []string{"missing-token", "empty-token", "multiline-token", "missing-key", "invalid-key", "wrong-curve", "missing-server", "invalid-server", "missing-policy", "invalid-policy", "empty-policy", "missing-manifest", "invalid-manifest", "unsupported-snp", "oversized-file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			cfg := fixtureConfig(t)
			path := filepath.Join(filepath.Dir(cfg.CloudTokenFile), "config.json")
			target := ""
			var data []byte
			switch kind {
			case "missing-token":
				cfg.CloudTokenFile += ".missing"
			case "empty-token":
				target = cfg.CloudTokenFile
				data = []byte(" \n")
			case "multiline-token":
				target = cfg.CloudTokenFile
				data = []byte("one\ntwo")
			case "missing-key":
				cfg.LaunchKeyFile += ".missing"
			case "invalid-key":
				target = cfg.LaunchKeyFile
				data = []byte("not a key")
			case "wrong-curve":
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalECPrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				target = cfg.LaunchKeyFile
				data = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
			case "missing-server":
				cfg.ServerPublicKeyFile += ".missing"
			case "invalid-server":
				target = cfg.ServerPublicKeyFile
				data = []byte("not a public key")
			case "missing-policy":
				cfg.WorkloadsFile += ".missing"
			case "invalid-policy":
				target = cfg.WorkloadsFile
				data = []byte(`{"wrong":"policy"}`)
			case "empty-policy":
				target = cfg.WorkloadsFile
				data = []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`)
			case "missing-manifest":
				cfg.ImageManifestFile += ".missing"
			case "invalid-manifest":
				target = cfg.ImageManifestFile
				data = []byte(`{"invalid":"manifest"}`)
			case "unsupported-snp":
				target = cfg.ImageManifestFile
				data = []byte(`{"snp_variants":[{"smp":2,"measurement":{"snp_launch_digest":"` + strings.Repeat("44", 48) + `","algorithm":"sha384"}}]}`)
			case "oversized-file":
				target = cfg.WorkloadsFile
				data = []byte(strings.Repeat("a", maxFile+1))
			case "directory":
				cfg.CloudTokenFile = t.TempDir()
			}
			if target != "" {
				if err := os.WriteFile(target, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("invalid trust material accepted")
			}
		})
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing-config.json")); err == nil {
		t.Fatal("missing configuration accepted")
	}
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path); err == nil {
		t.Fatal("empty mounted input accepted")
	}
}
