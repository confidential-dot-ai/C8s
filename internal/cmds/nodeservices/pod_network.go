package nodeservices

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/confidential-dot-ai/c8s/internal/podmesh"
)

const (
	bakedPodCNIPath = "/usr/lib/c8s/pod-runtime/cni/10-c8s-pod.conflist"
	podCNIPath      = PodDir + "/cni/10-c8s-pod.conflist"
	// Keep the existing Ethernet ceiling; an uplink with jumbo frames must
	// not silently enlarge Pod packets. RFC 791 bounds IPv4 MTUs below.
	podDefaultMTU = 1500
	minIPv4MTU    = 68
	maxIPv4MTU    = 65535
)

func podNetworkMTU(linkMTU, routeMTU int) (int, error) {
	if linkMTU < minIPv4MTU || linkMTU > maxIPv4MTU {
		return 0, fmt.Errorf("invalid Pod uplink MTU %d", linkMTU)
	}
	mtu := min(podDefaultMTU, linkMTU)
	if routeMTU != 0 {
		if routeMTU < minIPv4MTU || routeMTU > maxIPv4MTU {
			return 0, fmt.Errorf("invalid Pod default-route MTU %d", routeMTU)
		}
		mtu = min(mtu, routeMTU)
	}
	return mtu, nil
}

func preparePodNetwork(rootDir string, resolveMTU func() (int, error)) ([]byte, error) {
	mtu, err := resolveMTU()
	if err != nil {
		return nil, fmt.Errorf("resolve Pod network MTU: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(rootDir, bakedPodCNIPath))
	if err != nil {
		return nil, fmt.Errorf("read baked Pod CNI: %w", err)
	}
	return renderPodNetwork(data, mtu)
}

// renderPodNetwork changes only the bridge MTU in the measured template.
// Raw JSON values preserve every other field, including future CNI options.
func renderPodNetwork(data []byte, mtu int) ([]byte, error) {
	if mtu < minIPv4MTU || mtu > podDefaultMTU {
		return nil, fmt.Errorf("invalid resolved Pod MTU %d", mtu)
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil || config == nil {
		return nil, fmt.Errorf("invalid baked Pod CNI configuration")
	}
	var plugins []map[string]json.RawMessage
	if err := json.Unmarshal(config["plugins"], &plugins); err != nil || len(plugins) != 1 || plugins[0] == nil {
		return nil, fmt.Errorf("baked Pod CNI requires exactly one bridge plugin")
	}
	var kind, bridge string
	if json.Unmarshal(plugins[0]["type"], &kind) != nil || kind != "bridge" ||
		json.Unmarshal(plugins[0]["bridge"], &bridge) != nil || bridge != podmesh.GuestBridge {
		return nil, fmt.Errorf("baked Pod CNI bridge differs from the guest contract")
	}
	if _, exists := plugins[0]["mtu"]; exists {
		return nil, fmt.Errorf("baked Pod CNI must leave MTU to uplink discovery")
	}
	plugins[0]["mtu"] = json.RawMessage(strconv.Itoa(mtu))
	encoded, err := json.Marshal(plugins)
	if err != nil {
		return nil, fmt.Errorf("render Pod CNI plugins: %w", err)
	}
	config["plugins"] = encoded
	return json.MarshalIndent(config, "", "  ")
}
