package cdsha

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// TestStoreContract runs the four calls' contract on every backend; etcd
// runs against a real etcd at C8S_TEST_ETCD_URL.
func TestStoreContract(t *testing.T) {
	stores := map[string]Store{
		"memory": NewMemory(),
		"kube":   &Kube{ConfigMaps: fake.NewClientset().CoreV1().ConfigMaps("c8s-cds"), Cluster: "lane"},
	}
	if url := os.Getenv("C8S_TEST_ETCD_URL"); url != "" {
		e, err := OpenEtcd(clientv3.Config{Endpoints: []string{url}, DialTimeout: 5 * time.Second}, "contract-"+strings.ToLower(time.Now().Format("150405.000000")))
		if err != nil {
			t.Fatal(err)
		}
		stores["etcd"] = e
	}
	ctx := context.Background()
	for name, st := range stores {
		t.Run(name, func(t *testing.T) {
			if head, err := st.GetHead(ctx); err != nil || head != nil {
				t.Fatalf("empty store head = %q, %v", head, err)
			}
			if err := st.CASHead(ctx, []byte("x"), []byte("a")); !errors.Is(err, ErrConflict) {
				t.Fatalf("CAS on an absent head from a value: %v", err)
			}
			if err := st.CASHead(ctx, nil, []byte("a")); err != nil {
				t.Fatal(err)
			}
			if err := st.CASHead(ctx, nil, []byte("b")); !errors.Is(err, ErrConflict) {
				t.Fatalf("create over a head: %v", err)
			}
			if err := st.CASHead(ctx, []byte("b"), []byte("c")); !errors.Is(err, ErrConflict) {
				t.Fatalf("CAS from another head: %v", err)
			}
			if err := st.CASHead(ctx, []byte("a"), []byte("c")); err != nil {
				t.Fatal(err)
			}
			if head, _ := st.GetHead(ctx); string(head) != "c" {
				t.Fatalf("head = %q", head)
			}
			h := cdschain.Hash{9}
			if data, err := st.GetEntry(ctx, h); err != nil || data != nil {
				t.Fatalf("absent entry = %q, %v", data, err)
			}
			for range 2 {
				if err := st.PutEntry(ctx, h, []byte("entry")); err != nil {
					t.Fatalf("put (idempotent): %v", err)
				}
			}
			if data, _ := st.GetEntry(ctx, h); string(data) != "entry" {
				t.Fatalf("entry = %q", data)
			}
		})
	}
}

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

// A store back after a long outage answers within seconds: the client's
// reconnect backoff is capped (gRPC's default grows to 120 s). Runs with
// C8S_TEST_ETCD naming the etcd binary.
func TestEtcdAnswersSoonAfterAnOutage(t *testing.T) {
	bin := os.Getenv("C8S_TEST_ETCD")
	if bin == "" {
		t.Skip("C8S_TEST_ETCD names the etcd binary")
	}
	dir := t.TempDir()
	client, peer := localURL(t), localURL(t)
	start := func() *exec.Cmd {
		cmd := exec.Command(bin, "--data-dir", dir, "--listen-client-urls", client, "--advertise-client-urls", client,
			"--listen-peer-urls", peer, "--initial-advertise-peer-urls", peer, "--initial-cluster", "default="+peer)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	etcd := start()
	st, err := OpenEtcd(clientv3.Config{Endpoints: []string{client}, DialTimeout: time.Second}, "lane")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Client.Close()
	read := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := st.GetHead(ctx)
		return err
	}
	answersWithin := func(d time.Duration) bool {
		for end := time.Now().Add(d); time.Now().Before(end); {
			if read() == nil {
				return true
			}
		}
		return false
	}
	if !answersWithin(30 * time.Second) {
		t.Fatal("etcd never answered")
	}
	_ = etcd.Process.Kill()
	_ = etcd.Wait()
	// Reads fail through the outage, long enough for gRPC's default backoff
	// to pass 15 s.
	if answersWithin(45 * time.Second) {
		t.Fatal("negative control: the store answered while down")
	}
	start()
	if !answersWithin(8 * time.Second) {
		t.Fatal("the store did not answer within 8 s of its return")
	}
}

func localURL(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return "http://" + l.Addr().String()
}
