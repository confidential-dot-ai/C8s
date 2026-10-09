package nriimagepolicy

import (
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

type fixedStorage allowlist.MountStorage

func (s fixedStorage) Inspect(string) allowlist.MountStorage { return allowlist.MountStorage(s) }

func TestMountObserverBindsSourcesToCurrentPodAndSandbox(t *testing.T) {
	pod := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a"}
	ctr := &api.Container{Name: "app", PodSandboxId: pod.Id, Mounts: []*api.Mount{
		{Source: kubeletRoot + "/pods/pod-a/etc-hosts", Destination: "/etc/hosts"},
		{Source: kubeletRoot + "/pods/pod-b/etc-hosts", Destination: "/etc/hosts"},
		{Source: containerdRoots[0] + "/io.containerd.grpc.v1.cri/sandboxes/sandbox-a/hostname", Destination: "/etc/hostname"},
		{Source: containerdRoots[0] + "/io.containerd.grpc.v1.cri/sandboxes/sandbox-b/resolv.conf", Destination: "/etc/resolv.conf"},
	}}
	got := newMountObserver(fixedStorage(allowlist.MountMemory)).Observe(pod, ctr)
	want := []allowlist.MountClass{allowlist.MountPlatform, allowlist.MountHost, allowlist.MountPlatform, allowlist.MountHost}
	for j := range want {
		if got[j].Class != want[j] {
			t.Errorf("mount %d class = %q, want %q", j, got[j].Class, want[j])
		}
	}
}

func TestMountObserverClassifiesOnlyCurrentPodEmptyDir(t *testing.T) {
	pod := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a"}
	ctr := &api.Container{Name: "app", PodSandboxId: pod.Id, Mounts: []*api.Mount{
		{Source: kubeletRoot + "/pods/pod-a/volumes/" + emptyDirPlugin + "/cache", Destination: "/cache"},
		{Source: kubeletRoot + "/pods/pod-b/volumes/" + emptyDirPlugin + "/cache", Destination: "/stolen"},
		{Source: kubeletRoot + "/pods/pod-a/volumes/" + emptyDirPlugin + "/cache/subdir", Destination: "/subpath"},
	}}
	got := newMountObserver(fixedStorage(allowlist.MountEncrypted)).Observe(pod, ctr)
	if got[0].Class != allowlist.MountEmptyDir || got[0].Storage != allowlist.MountEncrypted {
		t.Fatalf("same-pod emptyDir = %+v", got[0])
	}
	if got[1].Class != allowlist.MountHost || got[1].Storage != allowlist.MountUnknown {
		t.Errorf("other-pod mount = %+v, want fail-closed host/unknown", got[1])
	}
	if got[2].Class != allowlist.MountEmptyDir || got[2].Storage != allowlist.MountEncrypted {
		t.Errorf("same-pod emptyDir descendant = %+v, want emptyDir/encrypted", got[2])
	}
}

// An exact rule binds a mount to the volume the node names, so that name is
// the volume the kubelet staged it from and not the last segment of the
// source: a mount of a directory inside another volume names that other
// volume, whatever its path ends in.
func TestMountObserverNamesTheVolumeBehindAMount(t *testing.T) {
	pod := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a"}
	ctr := &api.Container{Name: "app", PodSandboxId: pod.Id, Mounts: []*api.Mount{
		{Source: kubeletRoot + "/pods/pod-a/volumes/" + emptyDirPlugin + "/acme-tls", Destination: "/etc/c8s-acme-tls"},
		{Source: kubeletRoot + "/pods/pod-a/volumes/" + emptyDirPlugin + "/acme-key/acme-tls", Destination: "/etc/c8s-acme-tls"},
		{Source: kubeletRoot + "/pods/pod-a/volumes/kubernetes.io~secret/public-tls", Destination: "/mnt/c8s-data/public-tls"},
		{Source: kubeletRoot + "/pods/pod-a/volume-subpaths/cache/app/0", Destination: "/sub"},
	}}
	got := newMountObserver(fixedStorage(allowlist.MountMemory)).Observe(pod, ctr)
	want := []string{"acme-tls", "acme-key", "public-tls", "cache"}
	for i := range want {
		if got[i].Volume != want[i] {
			t.Errorf("mount %d (%s) names the volume %q, want %q", i, got[i].Destination, got[i].Volume, want[i])
		}
	}
}

func TestMountObserverClassifiesVolumePlaceholdersAsData(t *testing.T) {
	pod := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a"}
	for _, storage := range []allowlist.MountStorage{allowlist.MountMemory, allowlist.MountEncrypted, allowlist.MountUnknown} {
		t.Run(string(storage), func(t *testing.T) {
			for _, tc := range []struct {
				podUID string
				volume string
				class  allowlist.MountClass
			}{
				{"pod-a", volume.KubeVolumeName("weights"), allowlist.MountData},
				{"pod-a", volume.KubeVolumeName("weights") + "/subdir", allowlist.MountData},
				{"pod-b", volume.KubeVolumeName("weights"), allowlist.MountHost},
				{"pod-a", "c8s-certs", allowlist.MountEmptyDir},
				{"pod-a", "cache/" + volume.KubeVolumeName("weights"), allowlist.MountEmptyDir},
			} {
				ctr := &api.Container{Name: "app", PodSandboxId: pod.Id, Mounts: []*api.Mount{{
					Source:      kubeletRoot + "/pods/" + tc.podUID + "/volumes/" + emptyDirPlugin + "/" + tc.volume,
					Destination: "/models",
				}}}
				got := newMountObserver(fixedStorage(storage)).Observe(pod, ctr)
				wantStorage := storage
				if tc.class == allowlist.MountHost {
					wantStorage = allowlist.MountUnknown
				}
				if len(got) != 1 || got[0].Class != tc.class || got[0].Storage != wantStorage {
					t.Fatalf("%s/%s observed = %+v; want %s/%s", tc.podUID, tc.volume, got, tc.class, wantStorage)
				}
			}
		})
	}
}

func TestMountObserverBindsSubpathToPodAndContainer(t *testing.T) {
	pod := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a"}
	ctr := &api.Container{Name: "app", PodSandboxId: pod.Id, Mounts: []*api.Mount{
		{Source: kubeletRoot + "/pods/pod-a/volume-subpaths/config/app/0", Destination: "/config"},
		{Source: kubeletRoot + "/pods/pod-a/volume-subpaths/config/other/0", Destination: "/stolen"},
		{Source: kubeletRoot + "/pods/pod-b/volume-subpaths/config/app/0", Destination: "/foreign"},
	}}
	got := newMountObserver(fixedStorage(allowlist.MountEncrypted)).Observe(pod, ctr)
	if got[0].Class != allowlist.MountData || got[0].Storage != allowlist.MountEncrypted {
		t.Fatalf("current container subpath = %+v", got[0])
	}
	for i := 1; i < len(got); i++ {
		if got[i].Class != allowlist.MountHost || got[i].Storage != allowlist.MountUnknown {
			t.Errorf("foreign subpath %d = %+v, want host/unknown", i, got[i])
		}
	}
}

func TestMountObserverRejectsUncleanAndLookalikePaths(t *testing.T) {
	pod := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a"}
	ctr := &api.Container{PodSandboxId: pod.Id, Mounts: []*api.Mount{
		{Source: kubeletRoot + "/pods/pod-a/x/../etc-hosts", Destination: "/etc/hosts"},
		{Source: "/tmp/io.containerd.grpc.v1.cri/sandboxes/sandbox-a/hostname", Destination: "/etc/hostname"},
	}}
	for _, got := range newMountObserver(nil).Observe(pod, ctr) {
		if got.Class != allowlist.MountHost {
			t.Errorf("lookalike classified as %q", got.Class)
		}
	}
}

func TestHostMountSourceAndAccess(t *testing.T) {
	for _, tc := range []struct {
		name, source    string
		options         []string
		readOnly, valid bool
	}{
		{"read-only", "/etc/service", []string{"rbind", "ro"}, true, true},
		{"writable", "/etc/service", []string{"bind", "rw"}, false, true},
		{"last read-only", "/etc/service", []string{"rw", "ro"}, true, true},
		{"last writable", "/etc/service", []string{"ro", "rw"}, false, true},
		{"recursive writable", "/etc/service", []string{"ro", "rrw"}, true, false},
		{"recursive read-only", "/etc/service", []string{"rro"}, false, false},
		{"relative bind", "service", []string{"bind"}, false, false},
		{"unclean", "/etc/../service", []string{"bind"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctr := &api.Container{Mounts: []*api.Mount{{Type: "bind", Source: tc.source, Destination: "/config", Options: tc.options}}}
			got := newMountObserver(nil).Observe(&api.PodSandbox{}, ctr)
			if len(got) != 1 || got[0].Class != allowlist.MountHost {
				t.Fatalf("host bind disappeared: %+v", got)
			}
			if (got[0].HostSourceDigest != "") != tc.valid || got[0].ReadOnly != tc.readOnly {
				t.Fatalf("unexpected host evidence: %+v", got[0])
			}
		})
	}
}
