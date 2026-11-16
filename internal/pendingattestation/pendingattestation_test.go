package pendingattestation

import (
	"crypto/tls"
	"testing"
)

// Every armTLS, discovery, attest-lb and attested-fetch dial rides this config.
func TestTLSPendingAttestationFloor(t *testing.T) {
	cfg := TLSConfig("router.example.com")
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("PKI verification must be skipped: the peer is authenticated by attestation")
	}
	if cfg.ServerName != "router.example.com" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if cfg.VerifyConnection != nil {
		t.Fatal("VerifyConnection must be the caller's to set")
	}
	if cfg.ClientSessionCache != nil {
		t.Fatal("a resumed handshake carries no CertificateVerify: no session cache")
	}
}

// An attested fetch sets VerifyConnection on the config it is handed.
func TestTLSConfigIsPerCaller(t *testing.T) {
	first := TLSConfig("router.example.com")
	first.VerifyConnection = func(tls.ConnectionState) error { return nil }
	if TLSConfig("router.example.com").VerifyConnection != nil {
		t.Fatal("one caller's VerifyConnection must not arm another caller's dial")
	}
}
