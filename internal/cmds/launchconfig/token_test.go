package launchconfig

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

func TestServerCredentialSurvivesRestagingWithoutPublicDisclosure(t *testing.T) {
	doc, key, pub := testDocument(t, "tdx", Server)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(cfg.path(AgentTokenPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatal("agent password was not generated")
	}
	info, err := os.Stat(cfg.path(AgentTokenPath))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("agent credential is not private")
	}
	for _, path := range []string{cfg.DocumentPath, cfg.path(DefaultStagedPath), cfg.path(Dir + "/peers.json"), cfg.path(Dir + "/agents.json")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, token) {
			t.Fatalf("credential disclosed in %s", path)
		}
	}
	agents, err := refvalues.Load(cfg.path(Dir + "/agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(agents.Images) != 1 || !bytes.Equal(agents.Images[0].Anchor, []byte(doc.AgentOperatorPublicKeys[0])) {
		t.Fatal("enrollment policy does not contain only authorized agents")
	}
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SignaturePath, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Stage(context.Background(), cfg); err == nil {
		t.Fatal("tampered restage accepted")
	}
	signDocument(t, cfg, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cfg.path(AgentTokenPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, token) {
		t.Fatal("restaging rotated the running cluster credential")
	}
	// Removing agent authorization closes the enrollment listener on restart.
	doc.AgentOperatorPublicKeys = nil
	signDocument(t, cfg, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, cfg.path(Dir+"/agents.json"))
	// A separate boot gets an independently generated credential.
	fresh := testConfig(t, doc, key)
	if err := Stage(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(fresh.path(AgentTokenPath))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other, token) {
		t.Fatal("independent boots reused an agent credential")
	}
}

func TestServerCredentialStorageFailsClosed(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			doc, key, pub := testDocument(t, "snp", Server)
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			if existing {
				if err := Stage(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
			}
			denied := errors.New("not RAM-backed")
			openTokenDir = func(string, string) (*os.Root, error) { return nil, denied }
			if err := Stage(context.Background(), cfg); !errors.Is(err, denied) {
				t.Fatalf("got %v", err)
			}
			requireAbsent(t, cfg.path(serverMarker))
			requireAbsent(t, cfg.path(agentMarker))
			if !existing {
				requireAbsent(t, cfg.path(AgentTokenPath))
			}
		})
	}
}

func TestServerRejectsUnsafeExistingCredential(t *testing.T) {
	for _, kind := range []string{"permissions", "malformed", "directory", "symlink", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			doc, key, pub := testDocument(t, "snp", Server)
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			path := cfg.path(AgentTokenPath)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				err = os.Symlink("missing", path)
			case "permissions":
				err = os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0644)
			case "malformed":
				err = os.WriteFile(path, []byte(strings.Repeat("z", 64)), 0600)
			case "oversized":
				err = os.WriteFile(path, []byte(strings.Repeat("a", 65)), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := Stage(context.Background(), cfg); err == nil {
				t.Fatal("unsafe token accepted")
			}
			requireAbsent(t, cfg.path(serverMarker))
		})
	}
}
