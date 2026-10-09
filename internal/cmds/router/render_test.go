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
		AttestPort:  8405,
		Allowlist: Allowlist{
			ProxyPort:       8801,
			WriteRate:       1,
			WriteBurst:      5,
			WriteTotalRate:  8,
			WriteTotalBurst: 15,
			ReadRate:        20,
			ReadBurst:       40,
		},
		Discovery: Discovery{
			Path:        "/v1/discovery",
			File:        "/discovery/discovery.json",
			CDSCertPath: "/.well-known/cds-cert.pem",
			MeshCAPath:  "/.well-known/mesh-ca.pem",
		},
		CORS: CORS{
			AllowMethods: []string{"GET", "POST", "OPTIONS"},
			AllowHeaders: []string{"Authorization"},
			MaxAge:       600,
		},
	}
}

// frontDoorOnly is the config with every operator-supplied input left out.
func frontDoorOnly() Config {
	cfg := validConfig()
	cfg.AttestPort = 0
	cfg.Allowlist.ProxyPort = 0
	cfg.Discovery = Discovery{}
	return cfg
}

func TestRenderDefaultShape(t *testing.T) {
	conf, err := Render(frontDoorOnly())
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
	cfg := frontDoorOnly()
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
	cfg := frontDoorOnly()
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
	cfg := frontDoorOnly()
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
	cfg := frontDoorOnly()
	cfg.SANs = nil
	conf, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(conf, "server_name _;") {
		t.Error("an empty SAN list did not render the any-name virtual host")
	}
}

func TestRenderOperatorInputs(t *testing.T) {
	conf, err := Render(validConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"location = /allowlist {",
		"location /allowlist/ {",
		"limit_req_zone $allowlist_write_key_or_empty zone=allowlist_write_per_client:10m rate=1r/s;",
		"limit_req zone=allowlist_read_per_client burst=40 nodelay;",
		"limit_req_status 429;",
		"proxy_pass http://127.0.0.1:8801$request_uri;",
		"proxy_set_header Authorization $http_authorization;",
		"location = /v1/discovery {",
		"default_type application/json;",
		"alias /discovery/discovery.json;",
		"location = /.well-known/cds-cert.pem {",
		"location = /.well-known/mesh-ca.pem {",
		`add_header Cache-Control "no-store" always;`,
		"location = /readyz {",
		"location /.well-known/c8s/ {",
		"proxy_pass http://127.0.0.1:8405;",
		`add_header Access-Control-Allow-Origin "*" always;`,
		`add_header Access-Control-Max-Age       "600" always;`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered configuration lacks %q", want)
		}
	}
}

func TestRenderRoutes(t *testing.T) {
	cfg := validConfig()
	cfg.Routes = []Route{
		{
			Path:  "/v1/models",
			Match: "exact",
			Backend: Backend{
				Address:  "cds.c8s-system.svc.cluster.local:8443",
				Protocol: "https",
			},
			CORS: true,
		},
		{
			Path:  "/metrics/",
			Match: "prefix",
			Backend: Backend{
				Address:  "metrics.c8s-system.svc.cluster.local:8443",
				Protocol: "https",
			},
		},
	}
	conf, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"location = /v1/models {",
		"set $backend_addr cds.c8s-system.svc.cluster.local:8443;",
		"location /metrics/ {",
		"set $backend_addr metrics.c8s-system.svc.cluster.local:8443;",
		"proxy_ssl_name cds.c8s-system.svc.cluster.local;",
		"proxy_ssl_verify on;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered configuration lacks %q", want)
		}
	}
	// Every route is dialed through the resolver, so a Service whose pods
	// churn is not pinned to the address it had at startup.
	if strings.Contains(conf, "upstream ") {
		t.Error("a route rendered a static upstream block")
	}
}

func TestRenderCORS(t *testing.T) {
	cfg := validConfig()
	cfg.CORS.AllowOrigins = []string{"https://app.example.com"}
	cfg.CORS.ExposeHeaders = []string{"X-Request-Id"}
	cfg.Routes = []Route{
		{
			Path:  "/open",
			Match: "prefix",
			Backend: Backend{
				Address:  "open.c8s-system.svc.cluster.local:8443",
				Protocol: "https",
			},
			CORS: true,
		},
		{
			Path:  "/closed",
			Match: "prefix",
			Backend: Backend{
				Address:  "closed.c8s-system.svc.cluster.local:8443",
				Protocol: "https",
			},
		},
	}
	conf, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		`"https://app.example.com" "https://app.example.com";`,
		`        "0" "GET, POST, OPTIONS";`,
		`        "0" "X-Request-Id";`,
		`        "1" "X-Request-Id$cors_upstream_expose_suffix";`,
		"add_header Vary                             Origin always;",
		"proxy_hide_header Access-Control-Allow-Origin;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered configuration lacks %q", want)
		}
	}
	open := conf[strings.Index(conf, "location /open {"):strings.Index(conf, "location /closed {")]
	// A backend that answers with its own origin keeps its whole header set,
	// and the configured expose list is merged in front of it.
	if !strings.Contains(open, "add_header Access-Control-Allow-Origin      $cors_out_origin always;") {
		t.Error("the CORS route lost its headers")
	}
	closed := conf[strings.Index(conf, "location /closed {"):]
	if strings.Contains(closed[:strings.Index(closed, "}")], "Access-Control") {
		t.Error("the opted-out route kept CORS headers")
	}
	// An explicit policy covers every location, so the C8s-owned endpoints
	// stand aside instead of answering any origin as well.
	if strings.Contains(conf, `add_header Access-Control-Allow-Origin "*" always;`) {
		t.Error("the any-origin block survived an explicit CORS policy")
	}
}
