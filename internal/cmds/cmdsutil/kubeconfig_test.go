package cmdsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticKubeconfig(t *testing.T) {
	for _, tc := range []struct {
		name, auth string
		denied     bool
	}{
		{"token", "token: static-token", false},
		{"basic credentials", "username: static-user\n    password: static-password", false},
		{"exec", "exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /operator/evil\n      interactiveMode: Never", true},
		{"auth provider", "auth-provider:\n      name: oidc\n      config:\n        cmd-path: /operator/evil", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			text := "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://127.0.0.1:1\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: u\ncurrent-context: c\nusers:\n- name: u\n  user:\n    " + tc.auth + "\n"
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := StaticKubeconfig(path)
			if tc.denied {
				if err == nil || cfg != nil || !strings.Contains(err.Error(), "plugins") {
					t.Fatalf("plugin config accepted: cfg=%v err=%v", cfg, err)
				}
			} else if err != nil || cfg == nil {
				t.Fatalf("static credentials refused: %v", err)
			}
		})
	}
	if _, err := StaticKubeconfig(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}
