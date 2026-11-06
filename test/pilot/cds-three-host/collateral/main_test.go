package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestFixedVendorsAndPublicResolution(t *testing.T) {
	for _, authority := range []string{"127.0.0.1:443", "169.254.169.254:80", "api.trustedservices.intel.com:80", "api.trustedservices.intel.com.evil:443", "user@api.trustedservices.intel.com:443"} {
		if allowed(authority) {
			t.Fatalf("unexpected destination accepted: %s", authority)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.48.64.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "198.18.0.1", "192.0.2.1", "224.0.0.1", "240.0.0.1", "::1", "fc00::1"} {
		if public(netip.MustParseAddr(ip)) {
			t.Fatalf("nonpublic DNS result accepted: %s", ip)
		}
	}
	if !allowed("api.trustedservices.intel.com:443") || !public(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public collateral route refused")
	}
}

func TestAdmissionNeverDialsForbiddenOrOverloadedRequests(t *testing.T) {
	p := &proxy{slots: make(chan struct{}, 1), dial: func(context.Context, string) (net.Conn, error) {
		t.Fatal("request reached dial")
		return nil, nil
	}}
	for _, request := range []*http.Request{httptest.NewRequest("GET", "http://api.trustedservices.intel.com/", nil),
		httptest.NewRequest("CONNECT", "127.0.0.1:443", nil)} {
		response := httptest.NewRecorder()
		p.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("forbidden destination: HTTP %d", response.Code)
		}
	}
	p.slots <- struct{}{}
	response := httptest.NewRecorder()
	p.ServeHTTP(response, httptest.NewRequest("CONNECT", "api.trustedservices.intel.com:443", nil))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("backpressure: HTTP %d", response.Code)
	}
}
