package cds

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"sync/atomic"
)

type meshRoots struct {
	certificate []byte
	pool        *x509.CertPool
}

// currentMeshClients runs AFTER the backend's fresh-read barrier. TLS verified
// a client at handshake time; an established connection can outlive a CA key
// rotation or its leaf's expiry. Check its certificate against the current CA
// before letting a protected handler use that earlier authentication.
//
// Root pools are immutable atomic snapshots. A same-key certificate renewal
// keeps existing leaves valid; a key rotation requires new leaves. This does
// not replace crypto/tls's initial verification or the handler's authorization.
func currentMeshClients(mesh meshCA, next http.Handler) http.Handler {
	var cached atomic.Pointer[meshRoots]
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if servedUnjoined(r.URL.Path) || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "cds-ha: client certificate was not verified", http.StatusForbidden)
			return
		}
		current, available := mesh.Current()
		if !available || current.CA == nil || current.CA.Cert == nil {
			http.Error(w, "cds-ha: no current mesh CA", http.StatusServiceUnavailable)
			return
		}
		roots := cached.Load()
		if roots == nil || !bytes.Equal(roots.certificate, current.CA.Cert.Raw) {
			fresh := &meshRoots{certificate: current.CA.Cert.Raw, pool: x509.NewCertPool()}
			fresh.pool.AddCert(current.CA.Cert)
			cached.CompareAndSwap(roots, fresh)
			// Even if another request published a pool concurrently, use the
			// CA this request observed, not a possibly older cached value.
			roots = fresh
		}
		opts := x509.VerifyOptions{Roots: roots.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if len(r.TLS.PeerCertificates) > 1 {
			opts.Intermediates = x509.NewCertPool()
			for _, cert := range r.TLS.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
		}
		if _, err := r.TLS.PeerCertificates[0].Verify(opts); err != nil {
			http.Error(w, "cds-ha: client certificate is not valid under the current mesh CA", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
