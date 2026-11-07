package nriimagepolicy

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var (
	secretAppDigest  = "sha256:" + strings.Repeat("1", 64)
	secretSideDigest = "sha256:" + strings.Repeat("2", 64)
)

func secretPlugin(pod *api.PodSandbox) *plugin {
	return &plugin{cfg: &config{Pod: &podConfig{UID: "assigned", Namespace: pod.Namespace, Name: pod.Name}},
		podBroker: &podCredentialBroker{secrets: &podSecretState{changes: make(chan struct{}, 1), readers: map[string]bool{}}}}
}

func secretReaderFixture() (*api.PodSandbox, *api.Container, []allowlist.ObservedMount) {
	pod := sandboxedPod()
	pod.Annotations = map[string]string{podSecretsAnnotation: "data-key=/users/a/data"}
	ctr := &api.Container{Name: "opencode", Mounts: []*api.Mount{readOnlyBind(podSecretSource(pod), "/run/secrets/c8s")}}
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
			c.Mounts[0].Source += "/data-key"
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
			p := secretPlugin(pod)
			role := ""
			if tc.change != nil {
				tc.change(pod, ctr, &mounts, &role)
			}
			err := p.podSecretReader(pod, ctr, role, secretAppDigest, mounts, true)
			if tc.name == "valid" {
				if err != nil || !p.podBroker.secrets.readers[secretAppDigest] {
					t.Fatalf("valid reader: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe secret mount was accepted")
			}
		})
	}
}

// A container without the volume is untouched, and the mesh endpoint never
// becomes a reader.
func TestPodSecretVolumeIgnoresOtherContainers(t *testing.T) {
	pod, _, _ := secretReaderFixture()
	p := secretPlugin(pod)
	if err := p.podSecretReader(pod, &api.Container{Name: "other"}, meshRole, secretSideDigest, nil, true); err != nil || len(p.podBroker.secrets.readers) != 0 {
		t.Fatalf("unrelated container: %v", err)
	}
}

func TestPodSecretPublishHoldsReadersToTheGrant(t *testing.T) {
	pod, ctr, mounts := secretReaderFixture()
	p := secretPlugin(pod)
	state := p.podBroker.secrets
	if err := p.podSecretReader(pod, ctr, "", secretAppDigest, mounts, true); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	requests := []podSecretRequest{{name: "data-key", path: "/users/a/data"}}
	foreign := []workloadclaims.PodSecret{{Value: []byte("v"), Readers: []string{secretSideDigest}}}
	if err := state.publish(root, requests, foreign); err == nil {
		t.Fatal("published to a reader the grant does not name")
	}
	if _, err := os.Stat(dir + "/data-key"); err == nil {
		t.Fatal("refused publication left a file")
	}
	released := []workloadclaims.PodSecret{{Value: []byte("per-user key"), Readers: []string{secretAppDigest}}}
	if err := state.publish(root, requests, released); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dir + "/data-key")
	if err != nil || string(got) != "per-user key" {
		t.Fatalf("published %q, %v", got, err)
	}
	if info, _ := os.Stat(dir + "/data-key"); info.Mode().Perm() != podSecretFileMode {
		t.Fatalf("mode %v", info.Mode())
	}
	if err := p.podSecretReader(pod, ctr, "", secretSideDigest, mounts, true); err == nil {
		t.Fatal("a later container outside the grant mounted the published secrets")
	}
	if err := p.podSecretReader(pod, ctr, "", secretAppDigest, mounts, true); err != nil {
		t.Fatalf("a granted restart was refused: %v", err)
	}
}

func TestPodSecretRequestsParseTheManifest(t *testing.T) {
	pod := sandboxedPod()
	pod.Annotations = map[string]string{podSecretsAnnotation: "a=/users/a/one, b=/users/a/two"}
	got, err := podSecretRequests(pod)
	if err != nil || len(got) != 2 || got[1] != (podSecretRequest{name: "b", path: "/users/a/two"}) {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"a", "=/x", "a/b=/x", "a=/x,a=/y", "a=x", "a=/x/../y"} {
		pod.Annotations[podSecretsAnnotation] = bad
		if _, err := podSecretRequests(pod); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
