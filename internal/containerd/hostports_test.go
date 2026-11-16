package containerd

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/containerd/api/types"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	goldenSandbox = "5f0c6a1e9b2d"
	goldenPath    = "testdata/cri-sandbox-metadata-v1.json"
	otherType     = "github.com/containerd/cri/pkg/store/sandbox/Other"
)

var goldenPod = SandboxPod{Name: "router-7d9f", Namespace: "c8s-router", UID: "0d4c1b2a-1111-4222-8333-444455556666"}

var goldenHostPorts = []HostPort{
	{Protocol: ProtocolTCP, ContainerPort: 8443, HostPort: 443},
	{Protocol: ProtocolTCP, ContainerPort: 8080, HostPort: 80},
}

// fixture mirrors the record at goldenPath, which the cases below vary.
type fixture struct {
	Version  string
	Metadata struct {
		ID     string
		Config *fixtureConfig
	}
}

type fixtureConfig struct {
	Metadata     *fixturePod       `json:"metadata,omitempty"`
	Hostname     string            `json:"hostname,omitempty"`
	PortMappings []fixturePort     `json:"port_mappings,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Linux        *fixtureLinux     `json:"linux,omitempty"`
}

type fixturePod struct {
	Name      string `json:"name,omitempty"`
	UID       string `json:"uid,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type fixturePort struct {
	Protocol      int32  `json:"protocol,omitempty"`
	ContainerPort int32  `json:"container_port,omitempty"`
	HostPort      int32  `json:"host_port,omitempty"`
	HostIP        string `json:"host_ip,omitempty"`
}

type fixtureLinux struct {
	CgroupParent    string                  `json:"cgroup_parent,omitempty"`
	SecurityContext *fixtureSecurityContext `json:"security_context,omitempty"`
}

type fixtureSecurityContext struct {
	NamespaceOptions *fixtureNamespaceOptions `json:"namespace_options,omitempty"`
}

type fixtureNamespaceOptions struct {
	Network int32 `json:"network,omitempty"`
}

// newFixture mirrors the record on disk: two mapped host ports and one that maps none.
func newFixture() *fixture {
	f := &fixture{Version: criMetadataVersion}
	f.Metadata.ID = goldenSandbox
	f.Metadata.Config = &fixtureConfig{
		Metadata: &fixturePod{Name: goldenPod.Name, UID: goldenPod.UID, Namespace: goldenPod.Namespace},
		Hostname: goldenPod.Name,
		PortMappings: []fixturePort{
			{ContainerPort: 8443, HostPort: 443},
			{ContainerPort: 8080, HostPort: 80},
			{Protocol: 1, ContainerPort: 9000},
		},
		Labels: map[string]string{"app": "router"},
		Linux:  &fixtureLinux{CgroupParent: "/kubepods"},
	}
	return f
}

func (f *fixture) value(t *testing.T) typeurl.Any {
	t.Helper()
	value, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return &anypb.Any{TypeUrl: criMetadataType, Value: value}
}

// record is a fixture with mutate applied.
func record(t *testing.T, mutate func(*fixture)) typeurl.Any {
	t.Helper()
	f := newFixture()
	mutate(f)
	return f.value(t)
}

// withNetworkMode records the sandbox in a network namespace mode.
func withNetworkMode(mode int32) func(*fixture) {
	return func(f *fixture) {
		f.Metadata.Config.Linux.SecurityContext = &fixtureSecurityContext{
			NamespaceOptions: &fixtureNamespaceOptions{Network: mode},
		}
	}
}

// replaced rewrites one occurrence of old in a record's JSON, for shapes no
// fixture field expresses.
func replaced(t *testing.T, metadata typeurl.Any, old, new string) typeurl.Any {
	t.Helper()
	value := string(metadata.GetValue())
	if !strings.Contains(value, old) {
		t.Fatalf("record does not contain %q", old)
	}
	return &anypb.Any{TypeUrl: metadata.GetTypeUrl(), Value: []byte(strings.Replace(value, old, new, 1))}
}

// goldenRecord is the record containerd wrote, read from disk.
func goldenRecord(t *testing.T) typeurl.Any {
	t.Helper()
	value, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	return &anypb.Any{TypeUrl: criMetadataType, Value: []byte(strings.TrimSpace(string(value)))}
}

func TestSandboxNetworkReadsTheCRIRecord(t *testing.T) {
	got, err := decodeSandboxNetwork(goldenRecord(t), goldenSandbox, goldenPod)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostNetwork || !slices.Equal(got.HostPorts, goldenHostPorts) {
		t.Fatalf("decodeSandboxNetwork = %+v, want the pod's network mapping %+v (the UDP port maps no host port, and neither names a host IP)", got, goldenHostPorts)
	}
}

// The fixture the cases below vary must read as the record on disk does.
func TestFixtureMatchesTheRecordOnDisk(t *testing.T) {
	want, err := decodeSandboxNetwork(goldenRecord(t), goldenSandbox, goldenPod)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeSandboxNetwork(newFixture().value(t), goldenSandbox, goldenPod)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostNetwork != want.HostNetwork || !slices.Equal(got.HostPorts, want.HostPorts) {
		t.Fatalf("the fixture reads as %+v, the record on disk as %+v", got, want)
	}
}

// A sandbox on the node's network maps no host port of its own, and its
// mappings are not read.
func TestSandboxNetworkOnTheNodesNetwork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fixture)
	}{
		{"as recorded", withNetworkMode(2)},
		{"with a mapping out of range", func(f *fixture) {
			withNetworkMode(2)(f)
			f.Metadata.Config.PortMappings[0].HostPort = 70000
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSandboxNetwork(record(t, tc.mutate), goldenSandbox, goldenPod)
			if err != nil || !got.HostNetwork || len(got.HostPorts) != 0 {
				t.Fatalf("decodeSandboxNetwork = %+v, %v; want the node's network and no host ports", got, err)
			}
		})
	}
}

func TestSandboxNetworkKeepsTheHostIP(t *testing.T) {
	metadata := record(t, func(f *fixture) {
		f.Metadata.Config.PortMappings[0].HostIP = "127.0.0.1"
	})
	got, err := decodeSandboxNetwork(metadata, goldenSandbox, goldenPod)
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddr("127.0.0.1")
	if len(got.HostPorts) == 0 || got.HostPorts[0].HostIP != want {
		t.Fatalf("decodeSandboxNetwork = %+v; want the host port published on %v", got, want)
	}
}

// Every record but the one recorded for this sandbox and pod is an error,
// never an empty answer.
func TestSandboxNetworkRefusesAnythingElse(t *testing.T) {
	golden := goldenRecord(t)
	for _, tc := range []struct {
		name     string
		metadata typeurl.Any
		pod      SandboxPod
		want     string
	}{
		{"another type", &anypb.Any{TypeUrl: otherType, Value: golden.GetValue()}, goldenPod,
			`metadata is "` + otherType + `", not "` + criMetadataType + `"`},
		{"another version", record(t, func(f *fixture) { f.Version = "v2" }), goldenPod,
			`metadata is version "v2", not "v1"`},
		{"another sandbox", record(t, func(f *fixture) { f.Metadata.ID = "other" }), goldenPod,
			`metadata names sandbox "other"`},
		{"another pod name", golden, SandboxPod{Name: "other", Namespace: goldenPod.Namespace, UID: goldenPod.UID},
			"was recorded for pod"},
		{"another pod namespace", golden, SandboxPod{Name: goldenPod.Name, Namespace: "default", UID: goldenPod.UID},
			"was recorded for pod"},
		{"another pod uid", golden, SandboxPod{Name: goldenPod.Name, Namespace: goldenPod.Namespace, UID: "other"},
			"was recorded for pod"},
		{"no config", record(t, func(f *fixture) { f.Metadata.Config = nil }), goldenPod,
			"carries no CRI pod config"},
		{"a config without its pod", record(t, func(f *fixture) { f.Metadata.Config.Metadata = nil }), goldenPod,
			"carries no CRI pod config"},
		{"a container's network mode", record(t, withNetworkMode(1)), goldenPod,
			"network namespace mode 1 is another sandbox's"},
		{"another sandbox's network mode", record(t, withNetworkMode(3)), goldenPod,
			"network namespace mode 3 is another sandbox's"},
		{"an unknown network mode", record(t, withNetworkMode(7)), goldenPod,
			"network namespace mode 7 is no CRI namespace mode"},
		{"a renamed port_mappings", replaced(t, golden, `"port_mappings"`, `"portMappings"`), goldenPod,
			`unknown field "portMappings"`},
		{"renamed mapping fields", replaced(t, golden, `"container_port":8443`, `"containerPort":8443`), goldenPod,
			`unknown field "containerPort"`},
		{"an unknown protocol", record(t, func(f *fixture) { f.Metadata.Config.PortMappings[0].Protocol = 3 }), goldenPod,
			"protocol 3 is not a CRI protocol"},
		{"a negative protocol", record(t, func(f *fixture) { f.Metadata.Config.PortMappings[0].Protocol = -1 }), goldenPod,
			"protocol -1 is not a CRI protocol"},
		{"a host port out of range", record(t, func(f *fixture) { f.Metadata.Config.PortMappings[0].HostPort = 70000 }), goldenPod,
			"host port 70000 is out of range"},
		{"a negative host port", record(t, func(f *fixture) { f.Metadata.Config.PortMappings[0].HostPort = -443 }), goldenPod,
			"host port -443 is out of range"},
		{"no container port", record(t, func(f *fixture) { f.Metadata.Config.PortMappings[0].ContainerPort = 0 }), goldenPod,
			"names no container port"},
		{"a host IP that is not one", record(t, func(f *fixture) { f.Metadata.Config.PortMappings[0].HostIP = "localhost" }), goldenPod,
			`host IP "localhost"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSandboxNetwork(tc.metadata, goldenSandbox, tc.pod)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decodeSandboxNetwork = %+v, %v; want an error naming %q", got, err, tc.want)
			}
		})
	}
}

func TestSandboxNetworkRefusesARecordThatIsNotJSON(t *testing.T) {
	metadata := &anypb.Any{TypeUrl: criMetadataType, Value: []byte("{")}
	got, err := decodeSandboxNetwork(metadata, goldenSandbox, goldenPod)
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("decodeSandboxNetwork = %+v, %v; want a JSON syntax error", got, err)
	}
}

// Over containerd's API: an unknown sandbox, one answered under another id, and
// one without the CRI record are errors.
func TestSandboxNetworkReadsTheStore(t *testing.T) {
	sandboxes := &fakeSandboxes{sandboxes: map[string]*types.Sandbox{
		goldenSandbox: servedSandbox(goldenSandbox, map[string]*anypb.Any{
			criMetadataExtension: {TypeUrl: criMetadataType, Value: goldenRecord(t).GetValue()},
		}),
		"bare": servedSandbox("bare", nil),
		"liar": servedSandbox("other", nil),
	}}
	r := newTestResolver(t, startFakeContainerd(t, nil, nil, nil, sandboxes))

	got, err := r.SandboxNetwork(context.Background(), goldenSandbox, goldenPod)
	if err != nil || !slices.Equal(got.HostPorts, goldenHostPorts) {
		t.Fatalf("SandboxNetwork = %+v, %v; want the recorded host ports", got, err)
	}
	for id, want := range map[string]string{
		"bare": "carries no CRI metadata",
		"liar": `store answered with sandbox "other"`,
	} {
		if got, err := r.SandboxNetwork(context.Background(), id, goldenPod); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("SandboxNetwork(%s) = %+v, %v; want an error naming %q", id, got, err, want)
		}
	}
	if _, err := r.SandboxNetwork(context.Background(), "missing", goldenPod); !errdefs.IsNotFound(err) {
		t.Errorf("SandboxNetwork(missing) = %v; want a not-found error", err)
	}
}
