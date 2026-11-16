//go:build linux

package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/podmesh"
)

func preparePodBootstrapRuntime(t *testing.T, cfg *config, dir string) (*api.PodSandbox, string) {
	t.Helper()
	requireNetNS(t)
	guest := sandboxProcess(t)
	handle, err := netns.GetFromPid(int(guest))
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	network, err := netlink.NewHandleAt(handle)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	if err := network.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: podmesh.GuestBridge}}); err != nil {
		t.Fatal(err)
	}
	oldGuestNS := guestNetworkNamespace
	guestNetworkNamespace = sandboxNetNSPath(guest)
	t.Cleanup(func() { guestNetworkNamespace = oldGuestNS })
	pod := sandboxedPod()
	pod.Pid = sandboxProcess(t)
	pod.Namespace, pod.Name, pod.Uid = cfg.Pod.Namespace, cfg.Pod.Name, filepath.Base(dir)
	for _, ns := range pod.Linux.Namespaces {
		if ns.Type == "network" {
			ns.Path = sandboxNetNSPath(pod.Pid)
		}
	}
	credentialSource := filepath.Join(kubeletRoot, "pods", pod.Uid, "volumes", emptyDirPlugin, podmesh.CertVolumeName)
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(kubeletRoot, "pods", pod.Uid)) })
	for _, path := range []string{cfg.WorkloadClaims.SocketDir, credentialSource} {
		mountPodTestRAM(t, path)
	}
	return pod, credentialSource
}

func mountPodTestRAM(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(path, 0); err != nil {
			t.Error(err)
		}
	})
}
