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

func TestLoadConfigRefusesUnsafeInputs(t *testing.T) {
	for _, kind := range []string{"invalid-key", "wrong-curve", "unbound-cds-policy"} {
		t.Run(kind, func(t *testing.T) {
			cfg := fixtureConfig(t)
			path := filepath.Join(filepath.Dir(cfg.CloudTokenFile), "config.json")
			target := ""
			var data []byte
			switch kind {
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
			case "unbound-cds-policy":
				target, data = cfg.CDSImagePolicyFile, providerCDSPolicy(t, nil)
			}
			if target != "" {
				if err := os.WriteFile(target, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			body, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("unsafe/incomplete configuration accepted")
			}
		})
	}
}

func TestConfigurationBoundsAndDefaults(t *testing.T) {
	for _, seconds := range []int64{-1, 0, 29, 30, 600, 86400, 86401} {
		cfg := fixtureConfig(t)
		cfg.VerificationTimeoutSeconds = seconds
		err := cfg.validate()
		valid := seconds == 0 || seconds >= 30 && seconds <= 86400
		if (err == nil) != valid {
			t.Fatalf("timeout %d: %v", seconds, err)
		}
		if seconds == 0 && cfg.VerificationTimeoutSeconds != 600 {
			t.Fatal("missing default")
		}
	}
	base := fixtureConfig(t)
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
