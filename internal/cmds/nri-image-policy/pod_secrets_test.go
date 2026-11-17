package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
)

func secretPlugin(pod *api.PodSandbox) *plugin {
	return &plugin{cfg: &config{Pod: &podConfig{UID: "assigned", Namespace: pod.Namespace, Name: pod.Name}}}
}

func secretReaderFixture() (*api.PodSandbox, *api.Container, []allowlist.ObservedMount) {
	pod := sandboxedPod()
	pod.Annotations = map[string]string{podSecretsAnnotation: "agent-token"}
	ctr := &api.Container{Name: "agent", Mounts: []*api.Mount{readOnlyBind(podSecretSource(pod), "/run/secrets/c8s")}}
	mounts := []allowlist.ObservedMount{{Destination: "/run/secrets/c8s", Class: allowlist.MountEmptyDir, Storage: allowlist.MountMemory, ReadOnly: true, Volume: podSecretVolume}}
	return pod, ctr, mounts
}

func TestPodSecretVolumeOnlyForWorkloadReadersOnMemory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*api.PodSandbox, *api.Container, *[]allowlist.ObservedMount, *string)
	}{
		{name: "valid"},
		{"platform role", func(_ *api.PodSandbox, _ *api.Container, _ *[]allowlist.ObservedMount, role *string) {
			*role = meshRole
		}},
		{"writable", func(_ *api.PodSandbox, c *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			c.Mounts[0].Options = append(c.Mounts[0].Options, "rw")
		}},
		{"subpath", func(_ *api.PodSandbox, c *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			c.Mounts[0].Source += "/agent-token"
		}},
		{"ancestor source", func(_ *api.PodSandbox, c *api.Container, m *[]allowlist.ObservedMount, _ *string) {
			c.Mounts[0].Source = path.Dir(c.Mounts[0].Source)
			*m = nil
		}},
		{"no evidence", func(_ *api.PodSandbox, _ *api.Container, m *[]allowlist.ObservedMount, _ *string) { *m = nil }},
		{"encrypted disk", func(_ *api.PodSandbox, _ *api.Container, m *[]allowlist.ObservedMount, _ *string) {
			(*m)[0].Storage = allowlist.MountEncrypted
		}},
		{"no requested secret", func(p *api.PodSandbox, _ *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			p.Annotations = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, ctr, mounts := secretReaderFixture()
			role := ""
			if tc.change != nil {
				tc.change(pod, ctr, &mounts, &role)
			}
			err := secretPlugin(pod).podSecretReader(pod, ctr, role, mounts)
			if (err == nil) != (tc.name == "valid") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A container without the volume is untouched, whatever its role.
func TestPodSecretVolumeIgnoresOtherContainers(t *testing.T) {
	pod, _, _ := secretReaderFixture()
	if err := secretPlugin(pod).podSecretReader(pod, &api.Container{Name: "other"}, meshRole, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPodSecretNamesParseTheManifest(t *testing.T) {
	pod := sandboxedPod()
	pod.Annotations = map[string]string{podSecretsAnnotation: "agent-token, db.password"}
	got, err := podSecretNames(pod)
	if err != nil || len(got) != 2 || got[1] != "db.password" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{",", "a,a", "a/b", "..", "a=/x", strings.Repeat("a,", maxPodSecrets) + "z"} {
		pod.Annotations[podSecretsAnnotation] = bad
		if _, err := podSecretNames(pod); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// The broker sends the secret name and the client document, and reads the
// value back; a refusal is an error carrying CDS's answer.
func TestRequestPodSecret(t *testing.T) {
	doc := []byte(`{"agent_id":"a"}`)
	cds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req secretbroker.PodRequest
		if r.URL.Path != secretbroker.PodRoute || json.NewDecoder(r.Body).Decode(&req) != nil || string(req.ClientDocument) != string(doc) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Secret != "agent-token" {
			http.Error(w, `{"error":"secret_refused","message":"the KMS refused: not yours"}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(secretbroker.PodResponse{Value: []byte("v")})
	}))
	defer cds.Close()
	value, err := requestPodSecret(t.Context(), cds.Client(), cds.URL+"/", "agent-token", doc)
	if err != nil || string(value) != "v" {
		t.Fatalf("%q %v", value, err)
	}
	if _, err := requestPodSecret(t.Context(), cds.Client(), cds.URL, "other", doc); err == nil || !strings.Contains(err.Error(), "not yours") {
		t.Fatalf("refusal: %v", err)
	}
}

func TestPodSecretReaderSkipsUnrelatedMountsAndNodeRoles(t *testing.T) {
	pod, ctr, mounts := secretReaderFixture()
	ctr.Mounts = append([]*api.Mount{readOnlyBind("/var/lib/data", "/data")}, ctr.Mounts...)
	mounts = append([]allowlist.ObservedMount{{Destination: "/data", Class: allowlist.MountEmptyDir, Volume: "data"}}, mounts...)
	if err := secretPlugin(pod).podSecretReader(pod, ctr, "", mounts); err != nil {
		t.Fatalf("workload reader: %v", err)
	}
	node := &plugin{cfg: &config{}}
	if err := node.podSecretReader(pod, ctr, meshRole, mounts); err != nil {
		t.Fatalf("node role: %v", err)
	}
}

func TestPodSecretNamesBoundTheCount(t *testing.T) {
	pod := sandboxedPod()
	names := make([]string, maxPodSecrets+1)
	for i := range names {
		names[i] = fmt.Sprintf("s%d", i)
	}
	pod.Annotations = map[string]string{podSecretsAnnotation: strings.Join(names, ",")}
	if _, err := podSecretNames(pod); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("got %v", err)
	}
}

func writePodLeaf(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := certutil.NewLeafTemplate("pod", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certutil.EncodeCertPEM(der), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestPodLeafCertificatePresentsThePublishedLeaf(t *testing.T) {
	for _, tc := range []struct {
		name    string
		publish func(t *testing.T, dir string)
		want    string
	}{
		{name: "published", publish: func(t *testing.T, dir string) { writePodLeaf(t, dir) }},
		{name: "no leaf", publish: func(*testing.T, string) {}, want: "no published Pod leaf"},
		{name: "no key", publish: func(t *testing.T, dir string) {
			writePodLeaf(t, dir)
			if err := os.Remove(filepath.Join(dir, "tls.key")); err != nil {
				t.Fatal(err)
			}
		}, want: "no published Pod key"},
		{name: "mismatched key", publish: func(t *testing.T, dir string) {
			other := t.TempDir()
			writePodLeaf(t, other)
			writePodLeaf(t, dir)
			key, err := os.ReadFile(filepath.Join(other, "tls.key"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "tls.key"), key, 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "private key does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.publish(t, dir)
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			p := &plugin{podBroker: &podCredentialBroker{root: root}}
			cert, err := p.podLeafCertificate(nil)
			if tc.want == "" {
				if err != nil || cert == nil || len(cert.Certificate) != 1 {
					t.Fatalf("%v %v", cert, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPodLeafCertificateNeedsACredentialVolume(t *testing.T) {
	for _, p := range []*plugin{{}, {podBroker: &podCredentialBroker{}}} {
		if _, err := p.podLeafCertificate(nil); err == nil || !strings.Contains(err.Error(), "no Pod credential volume") {
			t.Fatalf("got %v", err)
		}
	}
}

// secretCDS answers each secret request with the value "v-<name>" once
// refuse has returned false for it.
func secretCDS(t *testing.T, refuse func(secret string) bool) *httptest.Server {
	t.Helper()
	cds := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req secretbroker.PodRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if refuse(req.Secret) {
			http.Error(w, "refused "+req.Secret, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(secretbroker.PodResponse{Value: []byte("v-" + req.Secret)})
	}))
	t.Cleanup(cds.Close)
	return cds
}

func secretFetcher(t *testing.T, cds *httptest.Server, names string) (*plugin, string) {
	t.Helper()
	pod := sandboxedPod()
	pod.Annotations = map[string]string{podSecretsAnnotation: names}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	p := &plugin{
		cfg:       &config{cdsAddress: strings.TrimPrefix(cds.URL, "https://"), Pod: &podConfig{ClientDocument: clientDocument(`{"agent_id":"a"}`)}},
		logger:    discardLogger(),
		podBroker: &podCredentialBroker{ctx: ctx, cancel: cancel, pod: pod, secretsClient: cds.Client()},
	}
	dir := t.TempDir()
	previous := openPodSecretRoot
	openPodSecretRoot = func(source string) (*os.Root, error) {
		if source != podSecretSource(pod) {
			return nil, fmt.Errorf("opened %s", source)
		}
		return os.OpenRoot(dir)
	}
	t.Cleanup(func() { openPodSecretRoot = previous })
	return p, dir
}

func readPodSecret(t *testing.T, dir, name string) string {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != podSecretFileMode {
		t.Fatalf("%s mode %v", name, info.Mode())
	}
	value, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func TestFetchPodSecretsPublishesTheWholeSet(t *testing.T) {
	cds := secretCDS(t, func(string) bool { return false })
	p, dir := secretFetcher(t, cds, "a,b")
	if err := p.fetchPodSecrets(t.Context(), cds.Client(), []string{"a", "b"}, nil); err != nil {
		t.Fatal(err)
	}
	if readPodSecret(t, dir, "a") != "v-a" || readPodSecret(t, dir, "b") != "v-b" {
		t.Fatal("published values differ from CDS's")
	}
}

func TestFetchPodSecretsPublishesNothingOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		refuse string
		change func(*plugin, string)
		want   string
	}{
		{name: "refused", refuse: "b", want: "secret b: CDS answered 403: refused b"},
		{name: "ended identity", change: func(p *plugin, _ string) { p.podBroker.terminal = errors.New("identity ended") }, want: "identity ended"},
		{name: "no volume", change: func(*plugin, string) {
			openPodSecretRoot = func(string) (*os.Root, error) { return nil, errors.New("not RAM-backed") }
		}, want: "not RAM-backed"},
		{name: "unwritable", change: func(_ *plugin, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "b", "x"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, want: "write Pod secret b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cds := secretCDS(t, func(s string) bool { return s == tc.refuse })
			p, dir := secretFetcher(t, cds, "a,b")
			if tc.change != nil {
				tc.change(p, dir)
			}
			err := p.fetchPodSecrets(t.Context(), cds.Client(), []string{"a", "b"}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if tc.name != "unwritable" {
				if _, err := os.Stat(filepath.Join(dir, "a")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("a was published: %v", err)
				}
			}
		})
	}
}

func TestRequestPodSecretFailures(t *testing.T) {
	garbled := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer garbled.Close()
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	closed.Close()
	oversized := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 2*secretbroker.MaxValue+4097))
	}))
	defer oversized.Close()
	for _, tc := range []struct {
		name, url string
		client    *http.Client
		want      string
	}{
		{"malformed URL", "https://cds\x7f", garbled.Client(), "invalid control character"},
		{"unreachable", closed.URL, closed.Client(), "connect"},
		{"undecodable answer", garbled.URL, garbled.Client(), "decode Pod secret response"},
		{"answer past the cap", oversized.URL, oversized.Client(), "read Pod secret response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := requestPodSecret(t.Context(), tc.client, tc.url, "a", nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunPodSecretWorkerStartsOnlyForAValidRequest(t *testing.T) {
	cds := secretCDS(t, func(string) bool { return false })
	for _, tc := range []struct {
		name   string
		names  string
		client bool
	}{
		{"malformed names", "a/b", true},
		{"no names", "", true},
		{"no client", "a", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, dir := secretFetcher(t, cds, tc.names)
			if !tc.client {
				p.podBroker.secretsClient = nil
			}
			p.runPodSecretWorker()
			p.podBroker.wg.Wait()
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("published %v %v", entries, err)
			}
		})
	}
}

func TestRunPodSecretWorkerRetriesUntilReleased(t *testing.T) {
	var asked atomic.Int32
	cds := secretCDS(t, func(string) bool { return asked.Add(1) == 1 })
	p, dir := secretFetcher(t, cds, "agent-token")
	p.runPodSecretWorker()
	p.podBroker.wg.Wait()
	if asked.Load() != 2 || readPodSecret(t, dir, "agent-token") != "v-agent-token" {
		t.Fatalf("asked %d times", asked.Load())
	}
}

func TestRunPodSecretWorkerStopsWithTheBroker(t *testing.T) {
	asked := make(chan struct{}, 1)
	cds := secretCDS(t, func(string) bool {
		select {
		case asked <- struct{}{}:
		default:
		}
		return true
	})
	p, dir := secretFetcher(t, cds, "agent-token")
	p.runPodSecretWorker()
	<-asked
	time.Sleep(50 * time.Millisecond)
	p.podBroker.cancel()
	p.podBroker.wg.Wait()
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("published %v %v", entries, err)
	}
}

func TestRunPodSecretWorkerStopsWhenCancelledMidRequest(t *testing.T) {
	var p *plugin
	cds := secretCDS(t, func(string) bool {
		p.podBroker.cancel()
		return true
	})
	p, _ = secretFetcher(t, cds, "agent-token")
	p.runPodSecretWorker()
	p.podBroker.wg.Wait()
}
