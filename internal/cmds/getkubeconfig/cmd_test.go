package getkubeconfig

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
)

// execCmd runs the get-kubeconfig command with the given args and returns the
// error, keeping cobra's own output out of the test log.
func execCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestNewCmdValidation(t *testing.T) {
	t.Run("missing operator-key, image-manifest and out", func(t *testing.T) {
		err := execCmd(t, "--node", "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "--operator-key, --image-manifest and --out are required") {
			t.Fatalf("want required-flags error, got %v", err)
		}
	})

	t.Run("missing image-manifest alone", func(t *testing.T) {
		// The image tuple is not optional: without it the gate would rest on
		// the host-reproducible operator-key register alone.
		err := execCmd(t, "--node", "127.0.0.1", "--operator-key", "k.pem", "--out", "kc")
		if err == nil || !strings.Contains(err.Error(), "--image-manifest") {
			t.Fatalf("want required-flags error naming --image-manifest, got %v", err)
		}
	})

	t.Run("unknown role", func(t *testing.T) {
		err := execCmd(t, "--node", "127.0.0.1", "--operator-key", "k.pem", "--image-manifest", "m.json", "--out", "kc", "--role", "cluster-admin")
		if err == nil || !strings.Contains(err.Error(), "--role: unknown role \"cluster-admin\" (want operator or log-reader)") {
			t.Fatalf("want role error, got %v", err)
		}
	})

	t.Run("missing node and URLs", func(t *testing.T) {
		err := execCmd(t, "--operator-key", "k.pem", "--image-manifest", "m.json", "--out", "kc")
		if err == nil || !strings.Contains(err.Error(), "set --node") {
			t.Fatalf("want set-node error, got %v", err)
		}
	})

	t.Run("vmi resolves to node", func(t *testing.T) {
		restore := resolveVMIAddress
		resolveVMIAddress = func(_ context.Context, ref string) (string, error) {
			if ref != "mn-server" {
				t.Fatalf("want ref mn-server, got %q", ref)
			}
			return "10.42.0.158", nil
		}
		t.Cleanup(func() { resolveVMIAddress = restore })
		// A nonexistent operator key makes Run fail at its first step, which
		// proves the resolved address satisfied the URL validation.
		err := execCmd(t,
			"--vmi", "mn-server",
			"--operator-key", filepath.Join(t.TempDir(), "nope.key"),
			"--image-manifest", filepath.Join(t.TempDir(), "m.json"),
			"--out", filepath.Join(t.TempDir(), "kc"))
		if err == nil || !strings.Contains(err.Error(), "read operator key") {
			t.Fatalf("want read-key error from Run, got %v", err)
		}
	})

	t.Run("vmi resolution failure aborts", func(t *testing.T) {
		restore := resolveVMIAddress
		resolveVMIAddress = func(_ context.Context, _ string) (string, error) {
			return "", errors.New("guest confai-images/mn-server has no reported address")
		}
		t.Cleanup(func() { resolveVMIAddress = restore })
		err := execCmd(t,
			"--vmi", "mn-server",
			"--operator-key", "k.pem", "--image-manifest", "m.json", "--out", "kc")
		if err == nil || !strings.Contains(err.Error(), `resolve --vmi "mn-server"`) ||
			!strings.Contains(err.Error(), "no reported address") {
			t.Fatalf("want wrapped resolution error, got %v", err)
		}
	})

	t.Run("vmi and node are mutually exclusive", func(t *testing.T) {
		err := execCmd(t,
			"--vmi", "mn-server", "--node", "127.0.0.1",
			"--operator-key", "k.pem", "--image-manifest", "m.json", "--out", "kc")
		if err == nil || !strings.Contains(err.Error(), "none of the others can be") {
			t.Fatalf("want mutual-exclusion error, got %v", err)
		}
	})

	t.Run("hostile node is refused", func(t *testing.T) {
		err := execCmd(t,
			"--node", "10.0.0.5:6443\n    insecure-skip-tls-verify: true",
			"--operator-key", "k.pem", "--image-manifest", "m.json", "--out", "kc")
		if err == nil || !strings.Contains(err.Error(), "is not an IP or host name") {
			t.Fatalf("want --node refusal, got %v", err)
		}
	})

	t.Run("IPv6 node fills URLs", func(t *testing.T) {
		err := execCmd(t,
			"--node", "::1",
			"--operator-key", filepath.Join(t.TempDir(), "nope.key"),
			"--image-manifest", filepath.Join(t.TempDir(), "m.json"),
			"--out", filepath.Join(t.TempDir(), "kc"))
		if err == nil || !strings.Contains(err.Error(), "read operator key") {
			t.Fatalf("want read-key error from Run, got %v", err)
		}
	})

	t.Run("node fills URLs", func(t *testing.T) {
		// A nonexistent operator key makes Run fail at its first step, which
		// proves --node satisfied the URL validation and Run was reached.
		err := execCmd(t,
			"--node", "127.0.0.1",
			"--operator-key", filepath.Join(t.TempDir(), "nope.key"),
			"--image-manifest", filepath.Join(t.TempDir(), "m.json"),
			"--out", filepath.Join(t.TempDir(), "kc"))
		if err == nil || !strings.Contains(err.Error(), "read operator key") {
			t.Fatalf("want read-key error from Run, got %v", err)
		}
	})
}

// TestNewCmdEndToEnd runs the whole command against the fake node: flags,
// attest gate, armTLS release, kubeconfig on disk. The role reaches the
// release body, so the server (not the client) picks the Subject.
func TestNewCmdEndToEnd(t *testing.T) {
	for _, tt := range []struct {
		name     string
		roleArgs []string
		wantRole string
	}{
		{"default role", nil, credrelease.RoleOperator},
		{"log-reader", []string{"--role", "log-reader"}, credrelease.RoleLogReader},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t, newAttestStub(t).URL()+"/attest", http.StatusOK, goodRelease)

			err := execCmd(t, append([]string{
				"--attest-url", env.attestURL,
				"--release-url", env.releaseURL,
				"--apiserver-url", "https://node:6443",
				"--operator-key", env.keyPath,
				"--image-manifest", env.manifestPath,
				"--out", env.outPath,
				"--context", "testctx",
				"--tls-server-name", "c8s-cvm",
				"--timeout", "10s",
			}, tt.roleArgs...)...)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := env.releaseRole.Load(); got != tt.wantRole {
				t.Errorf("release role = %q, want %q", got, tt.wantRole)
			}

			kc, err := os.ReadFile(env.outPath)
			if err != nil {
				t.Fatal(err)
			}
			cluster, user := loadKubeconfig(t, kc, "testctx")
			if cluster.Server != "https://node:6443" {
				t.Errorf("server = %q, want https://node:6443", cluster.Server)
			}
			if string(user.ClientCertificateData) != "CERTPEM" {
				t.Errorf("client-certificate-data = %q, want CERTPEM", user.ClientCertificateData)
			}
		})
	}
}

func TestURLHost(t *testing.T) {
	for _, tc := range []struct {
		name, node, want string
		wantErr          bool
	}{
		{name: "IPv4", node: "10.0.0.5", want: "10.0.0.5"},
		{name: "IPv6", node: "fd00::5", want: "fd00::5"},
		{name: "bracketed IPv6", node: "[fd00::5]", want: "fd00::5"},
		{name: "host name", node: "cvm.example", want: "cvm.example"},
		{name: "port", node: "cvm.example:6443", wantErr: true},
		{name: "empty port", node: "cvm.example:", wantErr: true},
		{name: "path", node: "cvm.example/x", wantErr: true},
		{name: "userinfo", node: "u@cvm.example", wantErr: true},
		{name: "query", node: "cvm.example?x", wantErr: true},
		{name: "escape", node: "cvm%2eexample", wantErr: true},
		{name: "newline", node: "10.0.0.5\n  insecure-skip-tls-verify: true", wantErr: true},
		{name: "space", node: "cvm example", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := urlHost(tc.node)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("urlHost(%q) = %q, want error", tc.node, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("urlHost(%q) = %q, %v; want %q", tc.node, got, err, tc.want)
			}
		})
	}
}
