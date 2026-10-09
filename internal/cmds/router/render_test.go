package router

import (
	"strings"
	"testing"
)

// validConfig is the front door the chart renders today: an adopted
// workload's Service behind the member credential.
func validConfig() Config {
	return Config{
		SANs:           []string{"router.example.com"},
		PublicCertFile: "/etc/c8s-tls/tls.crt",
		PublicKeyFile:  "/etc/c8s-tls/tls.key",
		CertFile:       "/etc/c8s-tls/tls.crt",
		KeyFile:        "/etc/c8s-tls/tls.key",
		MeshCAFile:     "/etc/c8s-tls/ca.crt",
		Backend: Backend{
			Address:  "c8s-vllm.default.svc.cluster.local:8000",
			Protocol: "http",
		},
		ReadTimeout: "3600s",
		Resolver:    "kube-dns.kube-system.svc.cluster.local",
	}
}

func TestRenderDefaultShape(t *testing.T) {
	conf, err := Render(validConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"error_log /dev/stderr warn;",
		"access_log /dev/stdout main;",
		"listen 8443 ssl;",
		"server_name router.example.com;",
		"ssl_certificate     /etc/c8s-tls/tls.crt;",
		"ssl_certificate_key /etc/c8s-tls/tls.key;",
		"ssl_protocols TLSv1.2 TLSv1.3;",
		"resolver kube-dns.kube-system.svc.cluster.local valid=5s;",
		"set $backend_addr c8s-vllm.default.svc.cluster.local:8000;",
		"proxy_pass http://$backend_addr;",
		"proxy_read_timeout 3600s;",
		"proxy_buffering off;",
		"location /healthz {",
		"default_type text/plain;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered configuration lacks %q", want)
		}
	}
	for _, unwanted := range []string{
		"upstream ",
		"listen 8080;",
		"proxy_ssl_",
		"/var/log/nginx",
	} {
		if strings.Contains(conf, unwanted) {
			t.Errorf("rendered configuration holds %q", unwanted)
		}
	}
}

// A resolved answer is reused for at most 5s, so a backend that becomes
// reachable is dialed again within one window instead of after whatever TTL
// the cluster DNS attached to the answer.
func TestRenderBoundsTheResolverCache(t *testing.T) {
	conf, err := Render(validConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(conf, "resolver kube-dns.kube-system.svc.cluster.local valid=5s;") {
		t.Error("the resolver does not bound how long an answer is reused")
	}
}

func TestRenderNoBackendKeepsFrontDoor(t *testing.T) {
	cfg := validConfig()
	cfg.Backend = Backend{}
	conf, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(conf, "location / {") {
		t.Error("an unset backend still published a catch-all")
	}
	if !strings.Contains(conf, "location /healthz {") {
		t.Error("the front door lost /healthz")
	}
}

func TestRenderHTTPSBackend(t *testing.T) {
	cfg := validConfig()
	cfg.Backend = Backend{
		Address:  "inference.example.com:8443",
		Protocol: "https",
	}
	conf, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"set $backend_addr inference.example.com:8443;",
		"proxy_pass https://$backend_addr;",
		"proxy_ssl_name inference.example.com;",
		"proxy_ssl_verify on;",
		"proxy_ssl_verify_depth 2;",
		"proxy_ssl_trusted_certificate /etc/c8s-tls/ca.crt;",
		"proxy_ssl_certificate /etc/c8s-tls/tls.crt;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered configuration lacks %q", want)
		}
	}
	if strings.Contains(conf, "proxy_ssl_verify off") {
		t.Error("an https backend rendered without verification")
	}
}

func TestRenderACME(t *testing.T) {
	cfg := validConfig()
	cfg.ACME = true
	conf, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"listen 8080;",
		"server_name _;",
		"location /.well-known/acme-challenge/ {",
		"proxy_pass http://127.0.0.1:8402;",
		"return 301 https://$host$request_uri;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered configuration lacks %q", want)
		}
	}
}

func TestRenderNoSANAcceptsAnyName(t *testing.T) {
	cfg := validConfig()
	cfg.SANs = nil
	conf, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(conf, "server_name _;") {
		t.Error("an empty SAN list did not render the any-name virtual host")
	}
}
