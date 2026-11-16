package worker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

const (
	testToken       = "abcdef.0123456789abcdef"
	testTokenSecret = "0123456789abcdef"
)

func TestReadBootstrapToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		ok   bool
	}{
		{"a token", testToken, true},
		{"a token and a newline", testToken + "\n", true},
		{"a token and CRLF", testToken + "\r\n", false},
		{"two newlines", testToken + "\n\n", false},
		{"a leading space", " " + testToken, false},
		{"uppercase", strings.ToUpper(testToken), false},
		{"a short id", testToken[1:], false},
		{"a long id", "a" + testToken, false},
		{"a long secret", testToken + "0", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bootstrap-token")
			if err := os.WriteFile(path, []byte(tc.file), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := readBootstrapToken(path)
			if tc.ok {
				if err != nil || got != testToken {
					t.Fatalf("readBootstrapToken = %q, %v; want %q", got, err, testToken)
				}
				return
			}
			if err == nil {
				t.Fatalf("readBootstrapToken accepted %q", tc.file)
			}
			if strings.Contains(strings.ToLower(err.Error()), testTokenSecret[:8]) {
				t.Fatalf("error %q carries the token's secret", err)
			}
		})
	}
}

func TestReadBootstrapTokenBoundsTheRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(path, []byte(testToken+strings.Repeat("\n", maxBootstrapTokenFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapToken(path); !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("readBootstrapToken = %v, want the byte limit", err)
	}
}

// A token passed where its file belongs is not echoed back.
func TestReadBootstrapTokenNamesNoMissingPath(t *testing.T) {
	_, err := readBootstrapToken(testToken)
	if err == nil || strings.Contains(err.Error(), testTokenSecret[:8]) {
		t.Fatalf("readBootstrapToken = %v, want a refusal without the path", err)
	}
}

// The launch disk is the host's: a link into the guest or a FIFO, with or
// without a writer, is refused, not followed or waited on.
func TestReadBootstrapTokenRefusesLinksAndFIFOs(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "guest-file")
	if err := os.WriteFile(target, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	idle, fed := filepath.Join(dir, "idle-fifo"), filepath.Join(dir, "fed-fifo")
	for _, fifo := range []string{idle, fed} {
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := os.OpenFile(fed, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.WriteString(testToken); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, idle, fed} {
		done := make(chan error, 1)
		go func() {
			_, err := readBootstrapToken(path)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("readBootstrapToken(%s) read a token", filepath.Base(path))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("readBootstrapToken(%s) blocked", filepath.Base(path))
		}
	}
}

// lookup is the value at a dotted path of a decoded YAML document.
func lookup(doc map[string]any, path string) any {
	var v any = doc
	for _, key := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[key]
	}
	return v
}

// The kubelet serves no exec, attach, port-forward, logs, checkpoint or
// profiling.
// The keys are spelt as in upstream's v1beta1 types: the kubelet decodes a
// misspelt one leniently, leaving its default, true.
func TestKubeletConfigServesNoDebugging(t *testing.T) {
	data, err := kubeletConfig(Kubernetes{ClusterDNS: "10.200.0.10"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := k8syaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]any{
		"enableDebuggingHandlers":          false,
		"enableSystemLogHandler":           false,
		"enableProfilingHandler":           false,
		"enableDebugFlagsHandler":          false,
		"readOnlyPort":                     float64(0),
		"authentication.anonymous.enabled": false,
		"authentication.webhook.enabled":   true,
		"authorization.mode":               "Webhook",
		"staticPodPath":                    staticPodPath,
	} {
		if v := lookup(got, path); v != want {
			t.Errorf("%s = %v, want %v", path, v, want)
		}
	}
	if dns, ok := got["clusterDNS"].([]any); !ok || len(dns) != 1 || dns[0] != "10.200.0.10" {
		t.Errorf("clusterDNS = %v, want the document's address", got["clusterDNS"])
	}
}

func TestBootstrapKubeconfig(t *testing.T) {
	k := Kubernetes{APIServer: "api.acme.example:6443", CACertificate: "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"}
	data, err := bootstrapKubeconfig(k, testToken)
	if err != nil {
		t.Fatal(err)
	}
	config, err := clientcmd.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	context := config.Contexts[config.CurrentContext]
	if context == nil {
		t.Fatalf("no current context in %s", data)
	}
	cluster, user := config.Clusters[context.Cluster], config.AuthInfos[context.AuthInfo]
	if cluster == nil || cluster.Server != "https://"+k.APIServer || string(cluster.CertificateAuthorityData) != k.CACertificate || cluster.CertificateAuthority != "" || cluster.InsecureSkipTLSVerify {
		t.Errorf("cluster = %+v; want the document's API server, verified against only its CA", cluster)
	}
	if user == nil || user.Token != testToken {
		t.Errorf("user = %+v; want the bootstrap token", user)
	}
}
