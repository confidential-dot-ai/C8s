package containerd

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	sandboxapi "github.com/containerd/containerd/api/services/sandbox/v1"
	"github.com/containerd/containerd/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// The golden value is a v1 sandbox metadata extension as containerd
// v2.3.4-k3s1.36's CRI plugin writes it: k8s.io/cri-api v0.36.3's
// PodSandboxConfig, JSON-encoded inside the versioned metadata.
const (
	goldenSandbox = "5f0c6a1e9b2d"
	goldenPath    = "testdata/cri-sandbox-metadata-v1.json"
)

var goldenPod = SandboxPod{Name: "router-7d9f", Namespace: "c8s-router", UID: "0d4c1b2a-1111-4222-8333-444455556666"}

func golden(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestSandboxNetworkReadsTheCRIRecord(t *testing.T) {
	got, err := sandboxNetwork(criMetadataType, []byte(golden(t)), goldenSandbox, goldenPod)
	if err != nil {
		t.Fatal(err)
	}
	want := []HostPort{
		{Protocol: "TCP", ContainerPort: 8443, HostPort: 443},
		{Protocol: "TCP", ContainerPort: 8080, HostPort: 80},
	}
	if got.HostNetwork || len(got.HostPorts) != len(want) || got.HostPorts[0] != want[0] || got.HostPorts[1] != want[1] {
		t.Fatalf("sandboxNetwork = %+v, want the pod's network mapping %+v (the UDP port maps no host port)", got, want)
	}
}

// A sandbox on the node's network maps no host port of its own: the kubelet
// records its container ports as host ports, which name the node's.
func TestSandboxNetworkOnTheNodesNetwork(t *testing.T) {
	value := strings.Replace(golden(t), `"linux":{"cgroup_parent":"/kubepods"}`, `"linux":{"cgroup_parent":"/kubepods","security_context":{"namespace_options":{"network":2}}}`, 1)
	got, err := sandboxNetwork(criMetadataType, []byte(value), goldenSandbox, goldenPod)
	if err != nil || !got.HostNetwork || len(got.HostPorts) != 0 {
		t.Fatalf("sandboxNetwork = %+v, %v; want the node's network and no host ports", got, err)
	}
}

// Every format but the one recorded for this sandbox and pod is an error,
// never an empty answer.
func TestSandboxNetworkRefusesAnythingElse(t *testing.T) {
	g := golden(t)
	for _, tc := range []struct {
		name, typeURL, value string
		pod                  SandboxPod
		want                 string
	}{
		{"another type", "github.com/containerd/cri/pkg/store/sandbox/Other", g, goldenPod, "not"},
		{"another version", criMetadataType, strings.Replace(g, `"Version":"v1"`, `"Version":"v2"`, 1), goldenPod, "version"},
		{"another sandbox", criMetadataType, strings.Replace(g, `"ID":"5f0c6a1e9b2d"`, `"ID":"other"`, 1), goldenPod, "names sandbox"},
		{"another pod name", criMetadataType, g, SandboxPod{Name: "other", Namespace: goldenPod.Namespace, UID: goldenPod.UID}, "recorded for pod"},
		{"another pod namespace", criMetadataType, g, SandboxPod{Name: goldenPod.Name, Namespace: "default", UID: goldenPod.UID}, "recorded for pod"},
		{"another pod uid", criMetadataType, g, SandboxPod{Name: goldenPod.Name, Namespace: goldenPod.Namespace, UID: "other"}, "recorded for pod"},
		{"no config", criMetadataType, `{"Version":"v1","Metadata":{"ID":"5f0c6a1e9b2d"}}`, goldenPod, "no CRI pod config"},
		{"a config without its pod", criMetadataType, `{"Version":"v1","Metadata":{"ID":"5f0c6a1e9b2d","Config":{"hostname":"x"}}}`, goldenPod, "no CRI pod config"},
		{"a container's network mode", criMetadataType, strings.Replace(g, `"linux":{"cgroup_parent":"/kubepods"}`, `"linux":{"security_context":{"namespace_options":{"network":1}}}`, 1), goldenPod, "network namespace mode 1"},
		{"renamed mapping fields", criMetadataType, strings.Replace(g, `"container_port":8443,"host_port":443`, `"containerPort":8443,"hostPort":443`, 1), goldenPod, "unknown field"},
		{"an unknown protocol", criMetadataType, strings.Replace(g, `{"protocol":1,`, `{"protocol":3,`, 1), goldenPod, "protocol 3"},
		{"a negative protocol", criMetadataType, strings.Replace(g, `{"protocol":1,`, `{"protocol":-1,`, 1), goldenPod, "protocol -1"},
		{"a host port out of range", criMetadataType, strings.Replace(g, `"host_port":443`, `"host_port":70000`, 1), goldenPod, "out of range"},
		{"a negative host port", criMetadataType, strings.Replace(g, `"host_port":443`, `"host_port":-443`, 1), goldenPod, "out of range"},
		{"no container port", criMetadataType, strings.Replace(g, `"container_port":8443,`, ``, 1), goldenPod, "container port 0"},
		{"not JSON", criMetadataType, "{", goldenPod, "metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sandboxNetwork(tc.typeURL, []byte(tc.value), goldenSandbox, tc.pod)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("sandboxNetwork = %+v, %v; want an error naming %q", got, err, tc.want)
			}
		})
	}
}

func TestSandboxNetworkKeepsTheHostIP(t *testing.T) {
	value := strings.Replace(golden(t), `"host_port":443`, `"host_port":443,"host_ip":"127.0.0.1"`, 1)
	got, err := sandboxNetwork(criMetadataType, []byte(value), goldenSandbox, goldenPod)
	if err != nil || len(got.HostPorts) == 0 || got.HostPorts[0].HostIP != "127.0.0.1" {
		t.Fatalf("sandboxNetwork = %+v, %v; want the recorded host IP", got, err)
	}
}

// fakeSandboxStore serves sandboxes by id; any other id is not found.
type fakeSandboxStore struct {
	sandboxapi.UnimplementedStoreServer
	sandboxes map[string]*types.Sandbox
}

func (f *fakeSandboxStore) Get(_ context.Context, req *sandboxapi.StoreGetRequest) (*sandboxapi.StoreGetResponse, error) {
	sb, ok := f.sandboxes[req.GetSandboxID()]
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	return &sandboxapi.StoreGetResponse{Sandbox: sb}, nil
}

func startFakeSandboxStore(t *testing.T, store *fakeSandboxStore) string {
	t.Helper()
	socket := tempSocketPath(t)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on %s: %v", socket, err)
	}
	srv := grpc.NewServer()
	sandboxapi.RegisterStoreServer(srv, store)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return socket
}

// The store's record is read over containerd's API; a sandbox it does not
// hold, or one without the CRI plugin's record, is an error.
func TestSandboxNetworkReadsTheStore(t *testing.T) {
	store := &fakeSandboxStore{sandboxes: map[string]*types.Sandbox{
		goldenSandbox: {SandboxID: goldenSandbox, Runtime: &types.Sandbox_Runtime{Name: "io.containerd.runc.v2"}, Extensions: map[string]*anypb.Any{
			criMetadataExtension: {TypeUrl: criMetadataType, Value: []byte(golden(t))},
		}},
		"bare": {SandboxID: "bare", Runtime: &types.Sandbox_Runtime{Name: "io.containerd.runc.v2"}},
	}}
	r := newTestResolver(t, startFakeSandboxStore(t, store))
	got, err := r.SandboxNetwork(context.Background(), goldenSandbox, goldenPod)
	if err != nil || len(got.HostPorts) != 2 {
		t.Fatalf("SandboxNetwork = %+v, %v; want the recorded host ports", got, err)
	}
	for id, want := range map[string]string{"bare": "no CRI metadata", "missing": "not found"} {
		if got, err := r.SandboxNetwork(context.Background(), id, goldenPod); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("SandboxNetwork(%s) = %+v, %v; want an error naming %q", id, got, err, want)
		}
	}
}
