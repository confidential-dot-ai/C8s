package cdsha

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// The store credential is a kubeconfig cut down to data; anything that
// runs a program, reads a file or skips TLS verification is refused.
func TestKubeCredentialRefusesKubeconfigFeatures(t *testing.T) {
	mesh, err := issuer.NewMeshCA("store-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca := base64.StdEncoding.EncodeToString(mesh.Current().CertPEM)
	ok := strings.ReplaceAll(`apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://10.0.0.1:6443
    certificate-authority-data: Y2E=
users:
- name: u
  user:
    token: secret
contexts:
- name: x
  context: {cluster: c, user: u, namespace: c8s-cds}
current-context: x
`, "Y2E=", ca)
	if _, err := OpenKube([]byte(ok), "lane"); err != nil {
		t.Fatalf("negative control: %v", err)
	}
	for name, bad := range map[string]string{
		"exec plugin":   strings.Replace(ok, "    token: secret", "    exec: {command: /bin/sh}", 1),
		"token file":    strings.Replace(ok, "    token: secret", "    tokenFile: /proc/self/mem", 1),
		"client key":    strings.Replace(ok, "    token: secret", "    token: secret\n    client-key: /etc/key", 1),
		"CA file":       strings.Replace(ok, "certificate-authority-data: "+ca, "certificate-authority: /etc/ca", 1),
		"skip verify":   strings.Replace(ok, "    certificate-authority-data: "+ca, "    certificate-authority-data: "+ca+"\n    insecure-skip-tls-verify: true", 1),
		"proxy":         strings.Replace(ok, "    certificate-authority-data: "+ca, "    certificate-authority-data: "+ca+"\n    proxy-url: http://x", 1),
		"plain http":    strings.Replace(ok, "https://", "http://", 1),
		"bad namespace": strings.Replace(ok, "c8s-cds", "Not_A_Label", 1),
	} {
		if _, err := OpenKube([]byte(bad), "lane"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An API server answer is capped.
func TestKubeAnswersAreCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 2*MaxStoreAnswer))
	}))
	defer srv.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := capped{http.DefaultTransport}.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() // before srv.Close: the server is still writing
	data, _ := io.ReadAll(resp.Body)
	if len(data) != MaxStoreAnswer {
		t.Fatalf("read %d bytes, cap %d", len(data), MaxStoreAnswer)
	}
}
