package allowlistproxy

import (
	"crypto/tls"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/readutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/routing"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

func workerEvidenceClient(pins armtls.PinSource, verifier string, timeout time.Duration) (*http.Client, error) {
	dir := workloadclaims.MemberCertDir
	member, err := routing.NewMeshIdentity(dir+"/tls.crt", dir+"/tls.key", workloadclaims.MemberCAPath)
	if err != nil {
		return nil, err
	}
	transport, err := armtls.NewRefreshingTransport(pins, func(current armtls.Pins) (*http.Transport, error) {
		t, err := armtls.ClientTransport(current, verifier)
		if err != nil {
			return nil, err
		}
		t.DisableKeepAlives = true
		t.MaxConnsPerHost = 8
		t.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			credential, err := member.Credential()
			return credential.Certificate, err
		}
		return t, nil
	})
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func relayWorkerEvidence(ta *url.URL, client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(r.PathValue("host"))
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
			http.Error(w, "invalid worker address", http.StatusBadRequest)
			return
		}
		target := ta.JoinPath(workloadclaims.GPUAttestationPrefix, ip.String())
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
		if err != nil {
			http.Error(w, "invalid Trust Authority endpoint", http.StatusInternalServerError)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "worker evidence unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			http.Error(w, "worker evidence unavailable", http.StatusBadGateway)
			return
		}
		body, err := readutil.ReadAll(resp.Body, workloadclaims.MaxGPUAttestationBytes)
		if err != nil {
			http.Error(w, "worker evidence unreadable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}
}
