package gpuattestations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/readutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

const maxNodes = 1024
const concurrentReads = 8
const maxSnapshot = 32 << 20
const relayURL = "http://127.0.0.1:8801" + workloadclaims.GPUAttestationPrefix

type slot struct {
	address netip.Addr
	uid     string
}

type node struct {
	Metadata struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"metadata"`
	Status struct {
		Addresses []struct{ Type, Address string } `json:"addresses"`
	} `json:"status"`
}

type worker struct {
	Name string `json:"name"`
	record
}

func fetch(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return readutil.ReadAll(resp.Body, limit)
}

func (c *collector) discover(ctx context.Context) (map[string]slot, error) {
	body, err := fetch(ctx, c.api, c.nodesURL, 16<<20)
	if err != nil {
		return nil, err
	}
	var list struct {
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
		Items []node `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	if list.Items == nil {
		return nil, errors.New("incomplete Node list")
	}
	if list.Metadata.Continue != "" || len(list.Items) > maxNodes {
		return nil, errDiscoveryLimit
	}
	peers := make(map[string]slot)
	for _, n := range list.Items {
		name := n.Metadata.Name
		suffix, ok := strings.CutPrefix(name, "n-")
		ip, err := netip.ParseAddr(strings.ReplaceAll(suffix, "-", "."))
		if !ok || err != nil || !ip.Is4() || workloadclaims.WorkerNodeName(ip.As4()) != name {
			continue
		}
		if _, exists := peers[name]; exists {
			return nil, errors.New("duplicate worker name")
		}
		var target netip.Addr
		for _, addr := range n.Status.Addresses {
			if addr.Type == "InternalIP" && addr.Address == ip.String() {
				target = ip
				break
			}
		}
		peers[name] = slot{address: target, uid: n.Metadata.UID}
	}
	return peers, nil
}
