package nriimagepolicy

import (
	"context"
	"errors"
	"path"
	"slices"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestPodCredentialVolumeRequiresMeasuredRoleAndExactMemoryMount(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*api.PodSandbox, *api.Container, *[]allowlist.ObservedMount, *string)
	}{
		{name: "valid"},
		{"forged name", func(_ *api.PodSandbox, _ *api.Container, _ *[]allowlist.ObservedMount, role *string) { *role = "" }},
		{"other namespace", func(p *api.PodSandbox, _ *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			p.Namespace = "other"
		}},
		{"other static Pod", func(p *api.PodSandbox, _ *api.Container, _ *[]allowlist.ObservedMount, _ *string) { p.Name = "other" }},
		{"UID traversal", func(p *api.PodSandbox, _ *api.Container, _ *[]allowlist.ObservedMount, _ *string) { p.Uid = "../other" }},
		{"writable", func(_ *api.PodSandbox, c *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			c.Mounts[0].Options = append(c.Mounts[0].Options, "rw")
		}},
		{"subpath", func(_ *api.PodSandbox, c *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			c.Mounts[0].Source += "/current"
		}},
		{"ancestor source", func(_ *api.PodSandbox, c *api.Container, mounts *[]allowlist.ObservedMount, role *string) {
			c.Mounts[0].Source = path.Dir(c.Mounts[0].Source)
			c.Mounts[0].Destination = "/tenant"
			*mounts = nil
			*role = ""
		}},
		{"other Pod volume", func(_ *api.PodSandbox, c *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			c.Mounts[0].Source = "/var/lib/kubelet/pods/other/volumes/kubernetes.io~empty-dir/c8s-certs"
		}},
		{"other destination", func(_ *api.PodSandbox, c *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			c.Mounts[0].Destination = "/tmp/key"
		}},
		{"duplicate", func(_ *api.PodSandbox, c *api.Container, _ *[]allowlist.ObservedMount, _ *string) {
			c.Mounts = append(c.Mounts, c.Mounts[0])
		}},
		{"no mount", func(_ *api.PodSandbox, c *api.Container, _ *[]allowlist.ObservedMount, _ *string) { c.Mounts = nil }},
		{"no evidence", func(_ *api.PodSandbox, _ *api.Container, m *[]allowlist.ObservedMount, _ *string) { *m = nil }},
		{"encrypted disk", func(_ *api.PodSandbox, _ *api.Container, m *[]allowlist.ObservedMount, _ *string) {
			(*m)[0].Storage = allowlist.MountEncrypted
		}},
		{"wrong volume evidence", func(_ *api.PodSandbox, _ *api.Container, m *[]allowlist.ObservedMount, _ *string) {
			(*m)[0].Volume = "tenant"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := sandboxedPod()
			p := &plugin{cfg: &config{Pod: &podConfig{UID: "assigned", Namespace: pod.Namespace, Name: pod.Name}}}
			source := kubeletRoot + "/pods/" + pod.Uid + "/volumes/" + emptyDirPlugin + "/" + podmesh.CertVolumeName
			ctr := &api.Container{Name: workloadclaims.MeshContainerName, Mounts: []*api.Mount{readOnlyBind(source, podmesh.CertDir)}}
			mounts := []allowlist.ObservedMount{{Destination: podmesh.CertDir, Class: allowlist.MountEmptyDir, Storage: allowlist.MountMemory, ReadOnly: true, Volume: podmesh.CertVolumeName}}
			role := meshRole
			if tc.change != nil {
				tc.change(pod, ctr, &mounts, &role)
			}
			got, err := p.podCredentialSource(pod, ctr, role, mounts)
			if tc.name == "valid" {
				if err != nil || got != source {
					t.Fatalf("valid endpoint: %q, %v", got, err)
				}
			} else if err == nil {
				t.Fatal("unsafe credential mount was accepted")
			}
		})
	}
}

func TestPodCommitProtectionLossEndsIdentity(t *testing.T) {
	pod := sandboxedPod()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gate, state := gateWithPod(pod)
	state.refusal = errors.New("guest packet protection changed during issuance")
	p := &plugin{cfg: &config{Pod: &podConfig{UID: "assigned"}}, mesh: gate,
		inventory: newAdmissionInventory(t.TempDir()),
		podBroker: &podCredentialBroker{ctx: ctx, cancel: cancel, pod: pod}}
	published := false
	if err := p.commitPodCredentials(workloadclaims.PodClaims{}, func() error { published = true; return nil }); err == nil || published {
		t.Fatal("publication crossed a lost-protection boundary")
	}
	if ctx.Err() == nil || p.podBroker.terminal == nil {
		t.Fatal("lost protection did not stop the credential worker")
	}
}

func TestPodSnapshotRetainsStoppedAndRemovedLaunches(t *testing.T) {
	inv := newAdmissionInventory(t.TempDir())
	inv.recordSandbox("pod")
	env, err := allowlist.ObserveLaunchEnv([]string{"MODE=one"})
	if err != nil {
		t.Fatal(err)
	}
	mounts := []allowlist.ObservedMount{}
	inv.recordObserved("first", "pod", "app", pushDigestA, "", []string{"/app", "one"}, env, mounts)
	before, revision, err := inv.podSnapshot("pod")
	if err != nil || len(before) != 1 {
		t.Fatalf("initial snapshot: %+v, %v", before, err)
	}
	inv.stop("first")
	inv.remove("first")
	inv.recordObserved("second", "pod", "app", pushDigestA, "", []string{"/app", "two"}, env, mounts)
	after, next, err := inv.podSnapshot("pod")
	if err != nil || next <= revision || len(after) != 2 || !slices.ContainsFunc(after, func(c workloadclaims.SandboxContainer) bool { return slices.Equal(c.Argv, before[0].Argv) }) {
		t.Fatalf("removed launch omitted: %+v, revision %d -> %d, %v", after, revision, next, err)
	}
	inv.removeSandbox("pod")
	if _, _, err := inv.podSnapshot("pod"); err == nil {
		t.Fatal("removed sandbox supplied a complete snapshot")
	}
}

// The revision stales an issuance in flight, as the armTLS rotation guard
// does: it moves when the retained history gains an observation or the
// sandbox's identity ends, not on a stop or removal, which change no claim.
func TestPodSnapshotRevisionMovesWithObservationsOnly(t *testing.T) {
	inv := newAdmissionInventory(t.TempDir())
	inv.recordSandbox("pod")
	env, err := allowlist.ObserveLaunchEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	inv.recordObserved("first", "pod", "app", pushDigestA, "", []string{"/app"}, env, nil)
	_, observed, err := inv.podSnapshot("pod")
	if err != nil {
		t.Fatal(err)
	}
	inv.stop("first")
	inv.remove("first")
	inv.recordSandbox("other")
	if _, unchanged, err := inv.podSnapshot("pod"); err != nil || unchanged != observed {
		t.Fatalf("revision %d -> %d after a stop, a removal and another sandbox, %v", observed, unchanged, err)
	}
	inv.recordObserved("second", "pod", "app", pushDigestA, "", []string{"/app"}, env, nil)
	_, grown, err := inv.podSnapshot("pod")
	if err != nil || grown <= observed {
		t.Fatalf("revision %d -> %d after an observation, %v", observed, grown, err)
	}
	inv.denyOnRecord("pod", "", errors.New("refused"))
	if _, denied, err := inv.podSnapshot("pod"); err != nil || denied <= grown {
		t.Fatalf("revision %d -> %d after a denial, %v", grown, denied, err)
	}
}

// A stop or removal changes no claim, so it does not wake the broker; a
// change does.
func TestStopAndRemovalDoNotWakeThePodBroker(t *testing.T) {
	p := &plugin{cfg: &config{Pod: &podConfig{}}, podBroker: &podCredentialBroker{changes: make(chan struct{}, 1)}, logger: discardLogger()}
	pod := sandboxedPod()
	ctr := &api.Container{Id: "ctr", PodSandboxId: pod.GetId()}
	if _, err := p.StopContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if err := p.RemoveContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if len(p.podBroker.changes) != 0 {
		t.Fatal("a stop or removal woke the broker")
	}
	p.podChanged()
	if len(p.podBroker.changes) != 1 {
		t.Fatal("a change did not wake the broker")
	}
}
