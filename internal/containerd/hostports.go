package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/containerd/containerd/v2/core/sandbox"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/typeurl/v2"
)

// Protocol is a port mapping's transport protocol.
type Protocol string

const (
	ProtocolTCP  Protocol = "TCP"
	ProtocolUDP  Protocol = "UDP"
	ProtocolSCTP Protocol = "SCTP"
)

// HostPort is one host port a pod sandbox maps, as the CRI plugin recorded it.
type HostPort struct {
	Protocol      Protocol
	ContainerPort uint16
	HostPort      uint16
	// HostIP is the address the port is published on; the zero Addr is every address.
	HostIP netip.Addr
}

func (p HostPort) mapsHostPort() bool { return p.HostPort != 0 }

// SandboxPod is the pod a sandbox must have been recorded for.
type SandboxPod struct {
	Name, Namespace, UID string
}

// SandboxNetwork is what containerd recorded of a pod sandbox's network.
type SandboxNetwork struct {
	// HostNetwork is a sandbox on the node's network, whose ports are the node's own.
	HostNetwork bool
	// HostPorts are the host ports a sandbox on its own network maps.
	HostPorts []HostPort
}

// The CRI plugin records each sandbox's metadata as this extension.
// INVARIANT: the node image's containerd (v2.3.4-k3s1.36) writes v1 holding
// k8s.io/cri-api v0.36.3's PodSandboxConfig.
const (
	criMetadataExtension = "metadata"
	criMetadataType      = "github.com/containerd/cri/pkg/store/sandbox/Metadata"
	criMetadataVersion   = "v1"
)

// criProtocols are the CRI Protocol enum's values.
var criProtocols = map[int32]Protocol{
	0: ProtocolTCP,
	1: ProtocolUDP,
	2: ProtocolSCTP,
}

// criNetworkMode is the CRI NamespaceMode of a pod sandbox's network namespace.
type criNetworkMode int32

const (
	criNetworkPod       criNetworkMode = 0
	criNetworkContainer criNetworkMode = 1
	criNetworkNode      criNetworkMode = 2
	criNetworkTarget    criNetworkMode = 3
)

// SandboxNetwork returns what containerd recorded of sandboxID's network,
// after checking it was recorded for pod.
func (r *Resolver) SandboxNetwork(ctx context.Context, sandboxID string, pod SandboxPod) (SandboxNetwork, error) {
	nsCtx := namespaces.WithNamespace(ctx, r.namespace)
	var sb sandbox.Sandbox
	if err := r.withReconnect(func() error {
		var err error
		sb, err = r.client.SandboxStore().Get(nsCtx, sandboxID)
		return err
	}); err != nil {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s: %w", sandboxID, err)
	}
	if sb.ID != sandboxID {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s: store answered with sandbox %q", sandboxID, sb.ID)
	}
	metadata, ok := sb.Extensions[criMetadataExtension]
	if !ok {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s carries no CRI metadata", sandboxID)
	}
	return decodeSandboxNetwork(metadata, sandboxID, pod)
}

// recordedSandbox is the versioned sandbox metadata as containerd encodes it.
type recordedSandbox struct {
	Version  string `json:"Version"`
	Metadata struct {
		ID     string          `json:"ID"`
		Config *recordedConfig `json:"Config"`
	} `json:"Metadata"`
}

// recordedConfig is the CRI PodSandboxConfig the sandbox was created from. It
// names every field of the pinned CRI API version, so another shape is refused.
type recordedConfig struct {
	Metadata     *recordedPod    `json:"metadata"`
	PortMappings []recordedPort  `json:"port_mappings"`
	Linux        json.RawMessage `json:"linux"`

	Hostname     string            `json:"hostname"`
	LogDirectory string            `json:"log_directory"`
	DNSConfig    json.RawMessage   `json:"dns_config"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	Windows      json.RawMessage   `json:"windows"`
}

// UnmarshalJSON refuses a field recordedConfig does not name. The conversion
// strips this method, which would otherwise recurse.
func (c *recordedConfig) UnmarshalJSON(data []byte) error {
	type strictConfig recordedConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode((*strictConfig)(c))
}

// recordedPod is the CRI PodSandboxMetadata.
type recordedPod struct {
	Name      string `json:"name"`
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	Attempt   uint32 `json:"attempt"`
}

// recordedPort is one CRI PortMapping.
type recordedPort struct {
	Protocol      int32  `json:"protocol"`
	ContainerPort int32  `json:"container_port"`
	HostPort      int32  `json:"host_port"`
	HostIP        string `json:"host_ip"`
}

type recordedLinux struct {
	SecurityContext *recordedSecurityContext `json:"security_context"`
}

type recordedSecurityContext struct {
	NamespaceOptions *recordedNamespaceOptions `json:"namespace_options"`
}

type recordedNamespaceOptions struct {
	Network criNetworkMode `json:"network"`
}

// networkMode: CRI omits a default value, so an absent level is the pod's own network.
func (c *recordedConfig) networkMode() (criNetworkMode, error) {
	if len(c.Linux) == 0 {
		return criNetworkPod, nil
	}
	var linux recordedLinux
	if err := json.Unmarshal(c.Linux, &linux); err != nil {
		return criNetworkPod, fmt.Errorf("linux config: %w", err)
	}
	if linux.SecurityContext == nil || linux.SecurityContext.NamespaceOptions == nil {
		return criNetworkPod, nil
	}
	return linux.SecurityContext.NamespaceOptions.Network, nil
}

// decodeSandboxNetwork reads the CRI metadata recorded for sandboxID. Any other
// record is an error, never an empty answer; a mapping with no host port is left out.
func decodeSandboxNetwork(metadata typeurl.Any, sandboxID string, pod SandboxPod) (SandboxNetwork, error) {
	if metadata.GetTypeUrl() != criMetadataType {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s metadata is %q, not %q", sandboxID, metadata.GetTypeUrl(), criMetadataType)
	}
	var recorded recordedSandbox
	if err := json.Unmarshal(metadata.GetValue(), &recorded); err != nil {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s metadata: %w", sandboxID, err)
	}
	if recorded.Version != criMetadataVersion {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s metadata is version %q, not %q", sandboxID, recorded.Version, criMetadataVersion)
	}
	if recorded.Metadata.ID != sandboxID {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s metadata names sandbox %q", sandboxID, recorded.Metadata.ID)
	}
	config := recorded.Metadata.Config
	if config == nil || config.Metadata == nil {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s metadata carries no CRI pod config", sandboxID)
	}
	if got := (SandboxPod{Name: config.Metadata.Name, Namespace: config.Metadata.Namespace, UID: config.Metadata.UID}); got != pod {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s was recorded for pod %+v, not %+v", sandboxID, got, pod)
	}
	mode, err := config.networkMode()
	if err != nil {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s metadata: %w", sandboxID, err)
	}
	switch mode {
	case criNetworkPod:
		// the sandbox's own network: the mappings below are its host ports
	case criNetworkNode:
		return SandboxNetwork{HostNetwork: true}, nil
	case criNetworkContainer, criNetworkTarget:
		return SandboxNetwork{}, fmt.Errorf("sandbox %s network namespace mode %d is another sandbox's, neither the pod's nor the node's", sandboxID, mode)
	default:
		return SandboxNetwork{}, fmt.Errorf("sandbox %s network namespace mode %d is no CRI namespace mode", sandboxID, mode)
	}
	var ports []HostPort
	for _, mapping := range config.PortMappings {
		port, err := mapping.hostPort()
		if err != nil {
			return SandboxNetwork{}, fmt.Errorf("sandbox %s port mapping: %w", sandboxID, err)
		}
		if port.mapsHostPort() {
			ports = append(ports, port)
		}
	}
	return SandboxNetwork{HostPorts: ports}, nil
}

// hostPort is the mapping as a host port; a value no CRI mapping holds is an error.
func (p recordedPort) hostPort() (HostPort, error) {
	protocol, ok := criProtocols[p.Protocol]
	if !ok {
		return HostPort{}, fmt.Errorf("protocol %d is not a CRI protocol", p.Protocol)
	}
	containerPort, err := port16("container port", p.ContainerPort)
	if err != nil {
		return HostPort{}, err
	}
	if containerPort == 0 {
		return HostPort{}, errors.New("names no container port")
	}
	hostPort, err := port16("host port", p.HostPort)
	if err != nil {
		return HostPort{}, err
	}
	hostIP, err := recordedHostIP(p.HostIP)
	if err != nil {
		return HostPort{}, fmt.Errorf("host IP %q: %w", p.HostIP, err)
	}
	return HostPort{Protocol: protocol, ContainerPort: containerPort, HostPort: hostPort, HostIP: hostIP}, nil
}

func port16(what string, port int32) (uint16, error) {
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("%s %d is out of range", what, port)
	}
	return uint16(port), nil
}

// recordedHostIP is a mapping's host IP; CRI omits it for every address.
func recordedHostIP(recorded string) (netip.Addr, error) {
	if recorded == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(recorded)
}
