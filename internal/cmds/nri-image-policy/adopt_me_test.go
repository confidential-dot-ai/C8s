package nriimagepolicy

import (
	"os"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/webhook"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// TestAdoptMeEntryDescribesTheInjectedPod: the entry c8s install writes for
// the kind harness's adopted workload describes what this plugin observes of
// its injected app container, and stops describing it once the node adds a
// mount.
func TestAdoptMeEntryDescribesTheInjectedPod(t *testing.T) {
	data, err := os.ReadFile("../../../test/integration/cluster/testdata/adopt-me-entry.json")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := allowlist.ParseWorkloadJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	pod := &api.PodSandbox{Id: "sandbox-a", Uid: "pod-a"}
	podDir := kubeletRoot + "/pods/" + pod.Uid
	sandboxDir := containerdRoots[0] + "/io.containerd.grpc.v1.cri/sandboxes/" + pod.Id
	app := &api.Container{Name: "app", PodSandboxId: pod.Id, Args: []string{"/bin/sh", "-c", "exec nginx"}, Mounts: []*api.Mount{
		{Source: podDir + "/etc-hosts", Destination: "/etc/hosts", Options: []string{"rbind"}},
		{Source: podDir + "/containers/app/0a1b2c3d", Destination: "/dev/termination-log", Options: []string{"rbind"}},
		{Source: sandboxDir + "/hostname", Destination: "/etc/hostname", Options: []string{"rbind"}},
		{Source: sandboxDir + "/resolv.conf", Destination: "/etc/resolv.conf", Options: []string{"rbind"}},
		{Source: sandboxDir + "/shm", Destination: "/dev/shm", Options: []string{"rbind"}},
		{Source: podDir + "/volumes/" + projectedPlugin + "/kube-api-access-x7k2p", Destination: serviceAccountDestination, Options: []string{"rbind", "ro"}},
		{Source: podDir + "/volumes/" + emptyDirPlugin + "/" + webhook.DefaultCertVolumeName, Destination: webhook.DefaultWorkloadCertDir, Options: []string{"rbind", "ro"}},
	}}
	observer := newMountObserver(fixedStorage(allowlist.MountMemory))
	running := func() []allowlist.RunningContainer {
		return []allowlist.RunningContainer{{Digest: entry.Containers[0].Digest.String(), Argv: app.Args, Mounts: observer.Observe(pod, app)}}
	}
	if d := entry.Diff(running()); !d.Describes() {
		t.Fatalf("install's adopt-me entry does not describe the injected app: %+v", d)
	}
	app.Mounts = append(app.Mounts, &api.Mount{Source: "/srv/app", Destination: "/usr/share/nginx/html", Options: []string{"rbind", "ro"}})
	if entry.Diff(running()).Describes() {
		t.Fatal("install's adopt-me entry describes the app with a host mount added")
	}
}
