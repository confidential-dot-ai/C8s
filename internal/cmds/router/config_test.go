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
			name: "resolver unchecked without a backend",
			mutte: func(c *Config) {
				c.Backend = Backend{}
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
