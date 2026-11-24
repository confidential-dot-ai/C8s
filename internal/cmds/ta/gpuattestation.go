package ta

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/certutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

func workerGPUAttestation(hosts workloadclaims.CIDRHosts, fetch func(context.Context, netip.Addr) ([]byte, error)) http.Handler {
	inFlight := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authenticatedSandbox(r) {
			http.Error(w, "a current sandbox credential is required", http.StatusForbidden)
			return
		}
		ip, err := netip.ParseAddr(chi.URLParam(r, "host"))
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || !hosts.Contains(ip.String()) {
			http.Error(w, "address outside worker networks", http.StatusBadRequest)
			return
		}
		select {
		case inFlight <- struct{}{}:
			defer func() { <-inFlight }()
		default:
			http.Error(w, "worker inventories busy", http.StatusServiceUnavailable)
			return
		}
		data, err := fetch(r.Context(), ip)
		if err != nil {
			http.Error(w, "worker evidence unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
}

func authenticatedSandbox(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	id, err := armtls.SandboxIDFromCert(leaf)
	return err == nil && id != "" && certutil.CheckValidity(leaf, time.Now()) == nil
}
