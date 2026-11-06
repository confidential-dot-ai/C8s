// The disposable fixture forwards TLS bytes only to fixed collateral vendors.
// Certificate and attestation verification remain inside each measured guest.
package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/net/netutil"
)

func allowed(authority string) bool {
	switch authority {
	case "api.trustedservices.intel.com:443", "certificates.trustedservices.intel.com:443", "kdsintf.amd.com:443":
		return true
	}
	return false
}

func public(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

func dialVendor(ctx context.Context, authority string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(authority)
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !public(ip) {
			continue
		}
		// Dial the checked address, never resolve the hostname a second time.
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), "443"))
		if err == nil {
			return conn, nil
		}
	}
	return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: context.DeadlineExceeded}
}

type proxy struct {
	slots chan struct{}
	dial  func(context.Context, string) (net.Conn, error)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodConnect || !allowed(r.Host) || r.URL.Host != r.Host || r.URL.User != nil {
		http.Error(w, "fixed collateral destination required", http.StatusForbidden)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "collateral backpressure", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	upstream, err := p.dial(ctx, r.Host)
	if err != nil {
		http.Error(w, "collateral unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	client, buffered, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	deadline := time.Now().Add(time.Minute)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, io.LimitReader(buffered, 16<<20))
		_ = upstream.Close()
		done <- struct{}{}
	}()
	_, _ = io.Copy(client, io.LimitReader(upstream, 16<<20))
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

func main() {
	listener, err := net.Listen("tcp4", "0.0.0.0:3128")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: &proxy{make(chan struct{}, 16), dialVendor},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
	log.Fatal(server.Serve(netutil.LimitListener(listener, 32)))
}
