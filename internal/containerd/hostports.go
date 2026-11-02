package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/containerd/containerd/v2/core/sandbox"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

// HostPort is one host port a pod sandbox maps, as containerd's CRI plugin
// recorded it when it created the sandbox.
type HostPort struct {
	Protocol      string
	ContainerPort uint16
	HostPort      uint16
	HostIP        string
}

// SandboxPod is the pod a sandbox must have been recorded for.
type SandboxPod struct {
	Name, Namespace, UID string
}

// SandboxNetwork is what containerd recorded of a pod sandbox's network.
type SandboxNetwork struct {
	// HostNetwork is a sandbox on the node's network, whose ports are the
	// node's own.
	HostNetwork bool
	// HostPorts are the host ports a sandbox on its own network maps.
	HostPorts []HostPort
}

// The CRI plugin records each sandbox's metadata, its CRI config included,
// as this extension before it sets up the sandbox's network (containerd v2
// internal/cri/server/sandbox_run.go and store/sandbox/metadata.go).
//
// INVARIANT: the pinned RKE2's containerd (v2.3.4-k3s1.36) writes version v1.
// One that writes v2 refuses every worker pod until this reads it.
const (
	criMetadataExtension = "metadata"
	criMetadataType      = "github.com/containerd/cri/pkg/store/sandbox/Metadata"
	criMetadataVersion   = "v1"
)

// CRIProtocols are the CRI Protocol enum's values, in order.
var CRIProtocols = []string{"TCP", "UDP", "SCTP"}

// The CRI NamespaceMode values a pod's network takes.
const (
	criNetworkPod  = 0
	criNetworkNode = 2
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
	metadata, ok := sb.Extensions[criMetadataExtension]
	if !ok {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s carries no CRI metadata", sandboxID)
	}
	return sandboxNetwork(metadata.GetTypeUrl(), metadata.GetValue(), sandboxID, pod)
}

// recordedSandbox is the part of the CRI plugin's v1 sandbox metadata read
// here: its id and its CRI config, encoded with the CRI API's JSON names.
type recordedSandbox struct {
	Version  string
	Metadata struct {
		ID     string
		Config *struct {
			Metadata *struct {
				Name      string `json:"name"`
				UID       string `json:"uid"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			PortMappings []json.RawMessage `json:"port_mappings"`
			Linux        *struct {
				SecurityContext *struct {
					NamespaceOptions *struct {
						Network int32 `json:"network"`
					} `json:"namespace_options"`
				} `json:"security_context"`
			} `json:"linux"`
		}
	}
}

// recordedPort is one CRI PortMapping; any other field is a format this
// decoder does not know.
type recordedPort struct {
	Protocol      int32  `json:"protocol"`
	ContainerPort int32  `json:"container_port"`
	HostPort      int32  `json:"host_port"`
	HostIP        string `json:"host_ip"`
}

// sandboxNetwork decodes the CRI metadata value of sandboxID. Any format but
// the one described above is an error, never an empty answer. Mappings with
// host port 0 are left out.
func sandboxNetwork(typeURL string, value []byte, sandboxID string, pod SandboxPod) (SandboxNetwork, error) {
	if typeURL != criMetadataType {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s metadata is %q, not %q", sandboxID, typeURL, criMetadataType)
	}
	var recorded recordedSandbox
	if err := json.Unmarshal(value, &recorded); err != nil {
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
	network := int32(criNetworkPod)
	if l := config.Linux; l != nil && l.SecurityContext != nil && l.SecurityContext.NamespaceOptions != nil {
		network = l.SecurityContext.NamespaceOptions.Network
	}
	if network != criNetworkPod && network != criNetworkNode {
		return SandboxNetwork{}, fmt.Errorf("sandbox %s network namespace mode %d is neither the pod's nor the node's", sandboxID, network)
	}
	var ports []HostPort
	for _, raw := range config.PortMappings {
		port, err := decodePort(raw)
		if err != nil {
			return SandboxNetwork{}, fmt.Errorf("sandbox %s port mapping: %w", sandboxID, err)
		}
		if port.HostPort != 0 {
			ports = append(ports, port)
		}
	}
	if network == criNetworkNode {
		return SandboxNetwork{HostNetwork: true}, nil
	}
	return SandboxNetwork{HostPorts: ports}, nil
}

func decodePort(raw json.RawMessage) (HostPort, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var port recordedPort
	if err := dec.Decode(&port); err != nil {
		return HostPort{}, err
	}
	switch {
	case port.Protocol < 0 || int(port.Protocol) >= len(CRIProtocols):
		return HostPort{}, fmt.Errorf("protocol %d is not a CRI protocol", port.Protocol)
	case port.ContainerPort < 1 || port.ContainerPort > 65535:
		return HostPort{}, fmt.Errorf("container port %d is out of range", port.ContainerPort)
	case port.HostPort < 0 || port.HostPort > 65535:
		return HostPort{}, fmt.Errorf("host port %d is out of range", port.HostPort)
	}
	return HostPort{
		Protocol:      CRIProtocols[port.Protocol],
		ContainerPort: uint16(port.ContainerPort),
		HostPort:      uint16(port.HostPort),
		HostIP:        port.HostIP,
	}, nil
}
