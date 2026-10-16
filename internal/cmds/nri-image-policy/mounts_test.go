package nriimagepolicy

import (
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
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
	got := newMountObserver(fixedStorage(allowlist.MountMemory), "").Observe(pod, ctr)
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
	got := newMountObserver(fixedStorage(allowlist.MountEncrypted), "").Observe(pod, ctr)
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
				got := newMountObserver(fixedStorage(storage), "").Observe(pod, ctr)
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
	got := newMountObserver(fixedStorage(allowlist.MountEncrypted), "").Observe(pod, ctr)
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
	for _, got := range newMountObserver(nil, "").Observe(pod, ctr) {
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
		// runc applies the recursive attribute after the ro remount, so the
		// mount stays writable below the top whatever comes later.
		{"recursive writable before read-only", "/etc/service", []string{"rbind", "rrw", "ro"}, false, false},
		{"recursive read-only", "/etc/service", []string{"rro"}, false, false},
		{"relative bind", "service", []string{"bind"}, false, false},
		{"unclean", "/etc/../service", []string{"bind"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctr := &api.Container{Mounts: []*api.Mount{{Type: "bind", Source: tc.source, Destination: "/config", Options: tc.options}}}
			got := newMountObserver(nil, "").Observe(&api.PodSandbox{}, ctr)
			if len(got) != 1 || got[0].Class != allowlist.MountHost {
				t.Fatalf("host bind disappeared: %+v", got)
			}
			if (got[0].HostSourceDigest != "") != tc.valid || got[0].ReadOnly != tc.readOnly {
				t.Fatalf("unexpected host evidence: %+v", got[0])
			}
		})
	}
}

func TestMountObserverClassifiesItsOwnSocketDirAsPlatform(t *testing.T) {
	const socketDir = "/var/run/nri-image-policy"
	injected := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a", Annotations: map[string]string{workloadclaims.AnnotationInjected: "true"}}
	plain := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a"}
	mount := func(src string, options ...string) *api.Mount {
		return &api.Mount{Source: src, Destination: workloadclaims.SidecarSocketDir, Type: "bind", Options: options}
	}
	for _, tc := range []struct {
		name  string
		pod   *api.PodSandbox
		ctr   string
		dir   string
		m     *api.Mount
		class allowlist.MountClass
	}{
		{"attest consumer", injected, workloadclaims.AttestContainerName, socketDir, mount(socketDir, "rbind", "ro"), allowlist.MountPlatform},
		{"injected sidecar", injected, workloadclaims.VolumeContainerName, socketDir, mount(socketDir, "rbind", "ro"), allowlist.MountPlatform},
		{"application container", injected, "app", socketDir, mount(socketDir, "rbind", "ro"), allowlist.MountHost},
		{"pod not injected", plain, workloadclaims.AttestContainerName, socketDir, mount(socketDir, "rbind", "ro"), allowlist.MountHost},
		{"another source", injected, workloadclaims.AttestContainerName, socketDir, mount("/var/run/other", "rbind", "ro"), allowlist.MountHost},
		{"writable", injected, workloadclaims.AttestContainerName, socketDir, mount(socketDir, "rbind", "rw"), allowlist.MountHost},
		{"ro then rw", injected, workloadclaims.AttestContainerName, socketDir, mount(socketDir, "rbind", "ro", "rw"), allowlist.MountHost},
		{"rw then ro", injected, workloadclaims.AttestContainerName, socketDir, mount(socketDir, "rbind", "rw", "ro"), allowlist.MountPlatform},
		{"inventory disabled", injected, workloadclaims.AttestContainerName, "", mount(socketDir, "rbind", "ro"), allowlist.MountHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctr := &api.Container{Name: tc.ctr, PodSandboxId: "sandbox-a", Mounts: []*api.Mount{tc.m}}
			got := newMountObserver(fixedStorage(allowlist.MountMemory), tc.dir).Observe(tc.pod, ctr)
			if len(got) != 1 || got[0].Class != tc.class {
				t.Fatalf("observed = %+v, want %s", got, tc.class)
			}
			if tc.class == allowlist.MountPlatform && !got[0].ReadOnly {
				t.Fatalf("platform socket mount = %+v, want read-only", got[0])
			}
		})
	}
}
