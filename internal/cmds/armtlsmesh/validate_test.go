//go:build linux

package armtlsmesh

import (
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name              string
		attestationApiURL string
		outboundPort      int
		inboundPort       int
		healthPort        int
		certTTL           time.Duration
		wantErr           string // substring match; "" means no error
	}{
		{
			name:              "valid config",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        15021,
			certTTL:           24 * time.Hour,
		},
		{
			name:              "valid https",
			attestationApiURL: "https://attestation.svc:8400",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        15021,
			certTTL:           24 * time.Hour,
		},
		{
			name:              "empty attestation-api-url",
			attestationApiURL: "",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        15021,
			certTTL:           24 * time.Hour,
			wantErr:           "--attestation-api-url is required",
		},
		{
			name:              "invalid url scheme",
			attestationApiURL: "localhost:8400",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        15021,
			certTTL:           24 * time.Hour,
			wantErr:           "must start with http:// or https://",
		},
		{
			name:              "outbound == inbound",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      15001,
			inboundPort:       15001,
			healthPort:        15021,
			certTTL:           24 * time.Hour,
			wantErr:           "--outbound-port and --inbound-port must differ",
		},
		{
			name:              "outbound == health",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        15001,
			certTTL:           24 * time.Hour,
			wantErr:           "--outbound-port and --health-port must differ",
		},
		{
			name:              "inbound == health",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        15006,
			certTTL:           24 * time.Hour,
			wantErr:           "--inbound-port and --health-port must differ",
		},
		{
			name:              "outbound port below range",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      0,
			inboundPort:       15006,
			healthPort:        15021,
			certTTL:           24 * time.Hour,
			wantErr:           "out of range",
		},
		{
			name:              "inbound port above range",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      15001,
			inboundPort:       70000,
			healthPort:        15021,
			certTTL:           24 * time.Hour,
			wantErr:           "out of range",
		},
		{
			name:              "health port out of range",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        -1,
			certTTL:           24 * time.Hour,
			wantErr:           "out of range",
		},
		{
			name:              "cert-ttl too short",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        15021,
			certTTL:           1 * time.Millisecond,
			wantErr:           "too short",
		},
		{
			name:              "cert-ttl exactly 1m",
			attestationApiURL: "http://localhost:8400",
			outboundPort:      15001,
			inboundPort:       15006,
			healthPort:        15021,
			certTTL:           1 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.attestationApiURL, tt.outboundPort, tt.inboundPort, tt.healthPort, tt.certTTL)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestARMTLSTEEType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    armtls.TEEType
		wantErr string
	}{
		{name: "sev snp", input: "sev-snp", want: armtls.TEETypeSEVSNP},
		{name: "tdx", input: "tdx", want: armtls.TEETypeTDX},
		{name: "empty", wantErr: "--platform is required"},
		{name: "unknown", input: "sgx", wantErr: "unsupported --platform"},
		// auto is intentionally not covered here — it stats /dev/*_guest
		// paths on the host running the test and would be flaky.
		// covered via the in-guest boot on tdx-host-1.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := armtlsTEEType(tt.input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("armtlsTEEType() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("armtlsTEEType() = %v, want %v", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestEffectiveCDSCAURL(t *testing.T) {
	tests := []struct {
		name     string
		certMode string
		cdsURL   string
		want     string
	}{
		{
			name:     "cds mode defaults to cds /ca endpoint",
			certMode: "cds",
			cdsURL:   "https://cds:8443",
			want:     "https://cds:8443/ca",
		},
		{
			name:     "cds mode trims cds URL slash",
			certMode: "cds",
			cdsURL:   "https://cds:8443/",
			want:     "https://cds:8443/ca",
		},
		{
			name:     "self signed keeps empty default",
			certMode: "self-signed",
			cdsURL:   "https://cds:8443",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveCDSCAURL(tt.certMode, tt.cdsURL)
			if got != tt.want {
				t.Fatalf("effectiveCDSCAURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
