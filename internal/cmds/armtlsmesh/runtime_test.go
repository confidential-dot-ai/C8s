//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestMeshEnvironmentRouting(t *testing.T) {
	const localPod = "10.244.0.5"
	const remotePod = "10.244.1.5"
	cfg := defaultTestProxyConfig(t)
	cfg.nodeIP = "10.0.0.1"
	cfg.maxConns = 3
	cfg.maxConnsPerSource = 2
	bindProxyPorts(t, cfg)
	resolver := &k8sResolver{
		nodeIP: cfg.nodeIP, logger: testLogger(),
		podMap: map[string]podEntry{
			localPod:  {nodeIP: cfg.nodeIP, uid: "local"},
			remotePod: {nodeIP: "10.0.0.2", uid: "remote"},
		},
	}
	for _, tc := range []struct {
		name         string
		env          meshEnvironment
		remoteNode   string
		allowUnknown bool
	}{
		{"host", hostMesh{c: cfg, resolver: resolver}, "10.0.0.2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &meshRuntime{metrics: newMetrics()}
			p := tc.env.configure(r)
			if node, local := p.resolver.Resolve(remotePod); node != tc.remoteNode || local {
				t.Fatalf("remote route = (%q, %v), want (%q, false)", node, local, tc.remoteNode)
			}
			if !p.resolver.ValidateLocalDest(localPod) || p.resolver.ValidateLocalDest(remotePod) {
				t.Fatal("local ownership must reject remote pods")
			}
			if allowed, _ := p.resolver.ValidateOutboundDest("10.99.0.1"); allowed != tc.allowUnknown {
				t.Fatalf("unknown destination allowed = %v, want %v", allowed, tc.allowUnknown)
			}
			if allowed, _ := p.resolver.ValidateOutboundDest("127.0.0.1"); allowed {
				t.Fatal("loopback must not enter the mesh")
			}
			if tc.name == "host" {
				if p.inboundLn != cfg.listeners.inbound || p.outboundLn != cfg.listeners.outbound || r.healthListener != cfg.listeners.health {
					t.Fatal("host must adopt reserved listeners")
				}
				if cap(p.outboundSem) != cfg.maxConns || cap(p.inboundSem) != cfg.maxConns || p.maxConnsPerSrc != cfg.maxConnsPerSource {
					t.Fatal("host connection limits lost")
				}
			} else if p.inboundLn != nil || p.outboundLn != nil || r.healthListener != nil || p.outboundSem != nil || p.inboundSem != nil || p.maxConnsPerSrc != 0 {
				t.Fatal("guest must use its own listeners and default connection limits")
			}
		})
	}
}

func TestMeshRuntimeVerification(t *testing.T) {
	for _, cacheSize := range []int{0, 4} {
		r, err := newMeshRuntime(&armtls.ServerConfig{
			AttestFunc: func(context.Context, string) (string, error) { return "", errors.New("unexpected attestation request") },
			Platform:   "sev-snp", ClientPolicy: &armtls.VerifyPolicy{}, DynamicCACert: true,
		}, testLogger(), cacheSize)
		if err != nil {
			t.Fatal(err)
		}
		if (r.clientTLS.ClientSessionCache != nil) != (cacheSize > 0) {
			t.Fatalf("session cache setting %d not preserved", cacheSize)
		}
		for _, verify := range []func([][]byte, [][]*x509.Certificate) error{
			r.serverTLS.VerifyPeerCertificate, r.clientTLS.VerifyPeerCertificate,
		} {
			if verify == nil || verify([][]byte{[]byte("invalid certificate")}, nil) == nil {
				t.Fatal("both TLS roles must reject malformed peer certificates before CDS upgrade")
			}
		}
		if got := registryValue(t, r.metrics, "armtls_mesh_attestation_failures_total", nil); got != 2 {
			t.Fatalf("attestation failures = %v, want 2", got)
		}
	}
}
