package workloadclaims

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/readutil"
)

const (
	GPUAttestationPrefix   = "/worker-gpu-attestations/"
	MaxGPUAttestationBytes = 2 << 20
	WorkerKubeletEnv       = "/run/kubernetes/kubelet.env"
	gpuBootCache           = "/run/c8s/gpu-attestation.json"
)

func serveGPUAttestation(cache, kubeletEnv string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(r.PathValue("host"))
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
			http.Error(w, "invalid worker address", http.StatusBadRequest)
			return
		}
		env, err := os.ReadFile(kubeletEnv)
		if err != nil || !slices.Contains(strings.Split(string(env), "\n"), "NODE_IP="+ip.String()) {
			http.Error(w, "worker address does not match its boot configuration", http.StatusNotFound)
			return
		}
		f, err := os.Open(cache)
		if err != nil {
			http.Error(w, "boot evidence unavailable", http.StatusServiceUnavailable)
			return
		}
		defer f.Close()
		record, err := readutil.ReadAll(f, MaxGPUAttestationBytes)
		if err != nil {
			http.Error(w, "boot evidence unreadable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(record)
	}
}

func (c *DigestsClient) GPUAttestation(ctx context.Context, ip netip.Addr) ([]byte, error) {
	resp, err := c.get(ctx, ip.String(), GPUAttestationPrefix+ip.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("worker boot evidence returned HTTP %d", resp.StatusCode)
	}
	return readutil.ReadAll(resp.Body, MaxGPUAttestationBytes)
}
