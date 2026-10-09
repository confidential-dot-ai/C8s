package router

import (
	"slices"
	"strings"
	"testing"
)

func TestValidateRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mutte func(*Config)
		want  string
	}{
		{
			name: "san with a directive terminator",
			mutte: func(c *Config) {
				c.SANs = []string{"router.example.com; return 200"}
			},
			want: "--san",
		},
		{
			name: "credential path with a brace",
			mutte: func(c *Config) {
				c.CertFile = "/etc/c8s-tls/tls.crt} server {"
			},
			want: "--cert",
		},
		{
			name: "credential path with an nginx variable",
			mutte: func(c *Config) {
				c.PublicCertFile = "/etc/c8s-tls/$host.crt"
			},
			want: "--public-cert",
		},
		{
			name: "relative credential path",
			mutte: func(c *Config) {
				c.MeshCAFile = "ca.crt"
			},
			want: "--mesh-ca",
		},
		{
			name: "backend address with a scheme",
			mutte: func(c *Config) {
				c.Backend.Address = "http://backend.example.com:8000"
			},
			want: "--backend address",
		},
		{
			name: "backend address with an nginx variable",
			mutte: func(c *Config) {
				c.Backend.Address = "$host:8000"
			},
			want: "--backend address",
		},
		{
			name: "backend address without a port",
			mutte: func(c *Config) {
				c.Backend.Address = "backend.example.com"
			},
			want: "--backend address",
		},
		{
			name: "plaintext backend the mesh does not wrap",
			mutte: func(c *Config) {
				c.Backend.Address = "backend.example.com:8000"
			},
			want: "must authenticate itself over https",
		},
		{
			name: "https to an adopted workload's Service",
			mutte: func(c *Config) {
				c.Backend.Protocol = "https"
			},
			want: "is reached over http",
		},
		{
			name: "unknown backend protocol",
			mutte: func(c *Config) {
				c.Backend.Protocol = "grpc"
			},
			want: "is reached over http",
		},
		{
			name: "backend server name with whitespace",
			mutte: func(c *Config) {
				c.Backend.Address = "backend.example.com:8443"
				c.Backend.Protocol = "https"
				c.Backend.ServerName = "backend.example.com proxy_pass"
			},
			want: "server name",
		},
		{
			name: "read timeout that is not an nginx time",
			mutte: func(c *Config) {
				c.ReadTimeout = "1 hour"
			},
			want: "--backend-read-timeout",
		},
		{
			name: "read timeout unchecked without a backend",
			mutte: func(c *Config) {
				c.Backend = Backend{}
				c.ReadTimeout = "soon"
			},
			want: "--backend-read-timeout",
		},
		{
			name: "no resolver",
			mutte: func(c *Config) {
				c.Resolver = ""
			},
			want: "--resolver",
		},
		{
			name: "resolver unchecked while a route is dialed",
			mutte: func(c *Config) {
				c.Backend = Backend{}
				c.Routes = []Route{routeAt("/v1/models")}
				c.Resolver = "kube-dns; return 200"
			},
			want: "--resolver",
		},
		{
			name: "resolver with a directive terminator",
			mutte: func(c *Config) {
				c.Resolver = "kube-dns; return 200"
			},
			want: "--resolver",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutte(&cfg)
			conf, err := Render(cfg)
			if err == nil {
				t.Fatalf("Render accepted the input and produced:\n%s", conf)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

// Nothing is dialed, so there is nothing to re-resolve and no resolver is
// needed.
func TestValidateNeedsNoResolverWithoutABackend(t *testing.T) {
	cfg := validConfig()
	cfg.Backend = Backend{}
	cfg.Resolver = ""
	conf, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(conf, "resolver ") {
		t.Error("a front door with no backend rendered a resolver")
	}
}

func TestValidateAcceptsAnIPResolver(t *testing.T) {
	cfg := validConfig()
	cfg.Resolver = "10.53.0.10"
	if _, err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateReturnsTheNormalisedConfig(t *testing.T) {
	cfg := validConfig()
	cfg.Backend = Backend{
		Address:  "inference.example.com:8443",
		Protocol: "https",
	}
	validated, err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.Backend.ServerName != "inference.example.com" {
		t.Fatalf("server name is %q, want the address host", validated.Backend.ServerName)
	}
	if cfg.Backend.ServerName != "" {
		t.Error("Validate mutated its receiver instead of returning the normalised value")
	}
}

func TestWatchedFiles(t *testing.T) {
	cfg := validConfig()
	want := []string{"/etc/c8s-tls/tls.crt", "/etc/c8s-tls/tls.key", "/etc/c8s-tls/ca.crt"}
	if got := cfg.WatchedFiles(); !slices.Equal(got, want) {
		t.Fatalf("watching %v, want the member credential and its CA once each", got)
	}
	cfg.PublicCertFile = "/etc/c8s-acme-tls/cert.pem"
	cfg.PublicKeyFile = "/etc/c8s-acme-tls/key.pem"
	want = append(want, "/etc/c8s-acme-tls/cert.pem", "/etc/c8s-acme-tls/key.pem")
	if got := cfg.WatchedFiles(); !slices.Equal(got, want) {
		t.Fatalf("watching %v, want the public pair as well", got)
	}
}

func TestValidateOperatorInputRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mutte func(*Config)
		want  string
	}{
		{
			name: "attest port on the ACME listener",
			mutte: func(c *Config) {
				c.ACME = true
				c.AttestPort = 8080
			},
			want: "--attest-port must leave the ports nginx binds",
		},
		{
			name: "allowlist proxy port on the TLS listener",
			mutte: func(c *Config) {
				c.Allowlist.ProxyPort = 8443
			},
			want: "--allowlist-proxy-port must leave the ports nginx binds",
		},
		{
			name: "attest port shared with the allowlist proxy",
			mutte: func(c *Config) {
				c.Allowlist.ProxyPort = c.AttestPort
			},
			want: "--attest-port and --allowlist-proxy-port must differ",
		},
		{
			name: "zero allowlist rate",
			mutte: func(c *Config) {
				c.Allowlist.ReadRate = 0
			},
			want: "--allowlist-read-rate",
		},
		{
			name: "allowlist rate unchecked without the route",
			mutte: func(c *Config) {
				c.Allowlist.ProxyPort = 0
				c.Allowlist.WriteBurst = 0
			},
			want: "--allowlist-write-burst",
		},
		{
			name: "per-client write rate above the aggregate",
			mutte: func(c *Config) {
				c.Allowlist.WriteRate = c.Allowlist.WriteTotalRate + 1
			},
			want: "--allowlist-write-rate must not exceed",
		},
		{
			name: "per-client write burst above the aggregate",
			mutte: func(c *Config) {
				c.Allowlist.WriteBurst = c.Allowlist.WriteTotalBurst + 1
			},
			want: "--allowlist-write-burst must not exceed",
		},
		{
			name: "discovery path carrying a directive",
			mutte: func(c *Config) {
				c.Discovery.Path = "/v1/discovery { return 200 'x'; }"
			},
			want: "--discovery-path",
		},
		{
			name: "certificate path carrying a directive",
			mutte: func(c *Config) {
				c.Discovery.CDSCertPath = "/cert.pem\nserver_name evil"
			},
			want: "--discovery-cds-cert-path",
		},
		{
			name: "mesh CA path carrying a directive",
			mutte: func(c *Config) {
				c.Discovery.MeshCAPath = "/ca.pem; proxy_pass http://elsewhere"
			},
			want: "--discovery-mesh-ca-path",
		},
		{
			name: "discovery served from a relative file",
			mutte: func(c *Config) {
				c.Discovery.File = "discovery.json"
			},
			want: "--discovery-file",
		},
		{
			name: "discovery without the certificate it chains to",
			mutte: func(c *Config) {
				c.Discovery.CDSCertPath = ""
			},
			want: "--discovery-cds-cert-path must serve the certificate",
		},
		{
			name: "certificate path without the discovery document",
			mutte: func(c *Config) {
				c.Discovery.Path = ""
				c.Discovery.File = ""
				c.Discovery.MeshCAPath = ""
			},
			want: "needs --discovery-path",
		},
		{
			name: "route path outside the URI character set",
			mutte: func(c *Config) {
				c.Routes = []Route{routeAt("/v1 models")}
			},
			want: "--route path",
		},
		{
			name: "route path carrying an nginx variable",
			mutte: func(c *Config) {
				c.Routes = []Route{routeAt("/$host")}
			},
			want: "--route path",
		},
		{
			name: "unknown route match",
			mutte: func(c *Config) {
				route := routeAt("/v1/models")
				route.Match = "regex"
				c.Routes = []Route{route}
			},
			want: "match must be exact or prefix",
		},
		{
			name: "plaintext route",
			mutte: func(c *Config) {
				route := routeAt("/v1/models")
				route.Backend.Protocol = "http"
				c.Routes = []Route{route}
			},
			want: "must reach its backend over https",
		},
		{
			name: "route to an adopted workload",
			mutte: func(c *Config) {
				route := routeAt("/v1/models")
				route.Backend.Address = "c8s-vllm.default.svc.cluster.local:8000"
				c.Routes = []Route{route}
			},
			want: "names an adopted workload's Service",
		},
		{
			name: "two routes on one location",
			mutte: func(c *Config) {
				c.Routes = []Route{routeAt("/v1/models"), routeAt("/v1/models")}
			},
			want: `both serve location "/v1/models"`,
		},
		{
			name: "route over the built-in allowlist relay",
			mutte: func(c *Config) {
				route := routeAt("/allowlist")
				route.Match = "exact"
				c.Routes = []Route{route}
			},
			want: "the built-in allowlist relay",
		},
		{
			name: "route over the attestation sidecar",
			mutte: func(c *Config) {
				route := routeAt("/readyz")
				route.Match = "exact"
				c.Routes = []Route{route}
			},
			want: "the attestation sidecar",
		},
		{
			name: "route over the discovery document",
			mutte: func(c *Config) {
				route := routeAt(c.Discovery.Path)
				route.Match = "exact"
				c.Routes = []Route{route}
			},
			want: "the discovery document",
		},
		{
			name: "route over the catch-all backend",
			mutte: func(c *Config) {
				c.Routes = []Route{routeAt("/")}
			},
			want: "the catch-all backend",
		},
		{
			name: "origin that is not a URL",
			mutte: func(c *Config) {
				c.CORS.AllowOrigins = []string{"app.example.com"}
			},
			want: "--cors-allow-origin",
		},
		{
			name: "origin carrying a quote",
			mutte: func(c *Config) {
				c.CORS.AllowOrigins = []string{`https://app.example.com" always; add_header X "y`}
			},
			want: "--cors-allow-origin",
		},
		{
			name: "credentials with any origin",
			mutte: func(c *Config) {
				c.CORS.AllowOrigins = []string{"*"}
				c.CORS.AllowCredentials = true
			},
			want: "--cors-allow-credentials",
		},
		{
			name: "method that is not an HTTP token",
			mutte: func(c *Config) {
				c.CORS.AllowOrigins = []string{"https://app.example.com"}
				c.CORS.AllowMethods = []string{`GET" always; add_header X "y`}
			},
			want: "--cors-allow-method",
		},
		{
			name: "header carrying a newline",
			mutte: func(c *Config) {
				c.CORS.AllowOrigins = []string{"https://app.example.com"}
				c.CORS.AllowHeaders = []string{"Authorization\nreturn 200"}
			},
			want: "--cors-allow-header",
		},
		{
			name: "exposed header carrying a brace",
			mutte: func(c *Config) {
				c.CORS.AllowOrigins = []string{"https://app.example.com"}
				c.CORS.ExposeHeaders = []string{"X-Request-Id}"}
			},
			want: "--cors-expose-header",
		},
		{
			name: "negative preflight lifetime",
			mutte: func(c *Config) {
				c.CORS.MaxAge = -1
			},
			want: "--cors-max-age",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutte(&cfg)
			conf, err := Render(cfg)
			if err == nil {
				t.Fatalf("Render accepted the input and produced:\n%s", conf)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

func routeAt(path string) Route {
	return Route{
		Path:  path,
		Match: "prefix",
		Backend: Backend{
			Address:  "cds.c8s-system.svc.cluster.local:8443",
			Protocol: "https",
		},
	}
}

func TestParseRoutes(t *testing.T) {
	routes, err := parseRoutes([]string{
		"path=/v1/models,match=exact,backend=cds.c8s-system.svc.cluster.local:8443",
		"path=/metrics/,backend=metrics.example.com:443,server-name=metrics.example.com,cors=false",
	})
	if err != nil {
		t.Fatalf("parseRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("parsed %d routes, want 2", len(routes))
	}
	if routes[0].Match != "exact" || routes[0].Backend.Protocol != "https" || !routes[0].CORS {
		t.Errorf("first route is %+v", routes[0])
	}
	if routes[1].Match != "prefix" || routes[1].CORS {
		t.Errorf("second route is %+v", routes[1])
	}
}

func TestParseRoutesRefusals(t *testing.T) {
	for _, spec := range []string{
		"/v1/models",
		"path=/v1/models,upstream=elsewhere:443",
		"path=/v1/models,cors=maybe",
		"path=/v1/models",
		"backend=cds.c8s-system.svc.cluster.local:8443",
	} {
		if _, err := parseRoutes([]string{spec}); err == nil {
			t.Errorf("parseRoutes accepted %q", spec)
		}
	}
}

// A CORS list without an allowed origin states a policy no location applies.
func TestCORSFlagsNeedAnOrigin(t *testing.T) {
	cmd := NewCmd()
	cmd.SetArgs([]string{"--cors-allow-method=GET"})
	if err := cmd.Flags().Parse([]string{"--cors-allow-method=GET"}); err != nil {
		t.Fatal(err)
	}
	if err := requireOriginsForCORS(cmd); err == nil {
		t.Fatal("a CORS list was accepted without --cors-allow-origin")
	}
	origins := NewCmd()
	if err := origins.Flags().Parse([]string{"--cors-allow-origin=*", "--cors-allow-method=GET"}); err != nil {
		t.Fatal(err)
	}
	if err := requireOriginsForCORS(origins); err != nil {
		t.Fatalf("requireOriginsForCORS: %v", err)
	}
}
