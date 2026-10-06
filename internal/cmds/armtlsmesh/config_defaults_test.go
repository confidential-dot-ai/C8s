//go:build linux

package armtlsmesh

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

// The duration and interval defaults are load-bearing operational contracts:
// a zero dial timeout or a zero CA poll interval silently changes runtime
// behavior without any flag being passed.
func TestBindProxyFlagDurationDefaults(t *testing.T) {
	cfg := defaultTestProxyConfig(t)
	for _, tc := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"dial-timeout", cfg.dialTimeout, 5 * time.Second},
		{"tls-dial-timeout", cfg.tlsDialTimeout, 10 * time.Second},
		{"dest-header-timeout", cfg.destHeaderTimeout, 5 * time.Second},
		{"drain-timeout", cfg.drainTimeout, 30 * time.Second},
		{"keepalive", cfg.keepAlive, 30 * time.Second},
		{"cert-ttl", cfg.certTTL, 24 * time.Hour},
		{"rotation-timeout", cfg.rotationTimeout, 30 * time.Second},
		{"ca-poll-interval", cfg.caPollInterval, 5 * time.Minute},
		{"cds-retry-backoff", cfg.cdsRetryBackoff, 2 * time.Second},
		{"cds-retry-max-backoff", cfg.cdsRetryMaxBackoff, 60 * time.Second},
		{"health-read-timeout", cfg.healthReadTimeout, 5 * time.Second},
		{"health-write-timeout", cfg.healthWriteTimeout, 10 * time.Second},
		{"metrics-update-interval", cfg.metricsUpdateInterval, 10 * time.Second},
		{"local-cidr-boot-timeout", cfg.localCIDRBootTimeout, time.Second},
		{"cds-op-timeout", cfg.cdsOpTimeout, 30 * time.Second},
		{"cert-pipeline-probe-timeout", cfg.certPipelineProbeTimeout, 5 * time.Second},
		{"cert-pipeline-probe-interval", cfg.certPipelineProbeInterval, 60 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("--%s default = %v, want %v", tc.name, tc.got, tc.want)
			}
		})
	}
}

func TestIptablesSyncFlagDefaults(t *testing.T) {
	fs := newIptablesSyncCommand().Flags()
	for _, tc := range []struct {
		flag string
		want string
	}{
		{"resync-period", "30s"},
		{"watchdog-period", "2s"},
	} {
		f := fs.Lookup(tc.flag)
		if f == nil {
			t.Fatalf("flag --%s not registered", tc.flag)
		}
		if f.DefValue != tc.want {
			t.Errorf("--%s default = %q, want %q", tc.flag, f.DefValue, tc.want)
		}
	}
}

// --platform=auto must fail closed when neither TEE guest device exists,
// rather than silently picking a platform.
func TestArmtlsTEETypeAutoWithoutGuestDevices(t *testing.T) {
	for _, dev := range []string{"/dev/tdx_guest", "/dev/sev-guest"} {
		if _, err := os.Stat(dev); !errors.Is(err, fs.ErrNotExist) {
			t.Skipf("%s present or unexpected stat error (%v); auto-probe would succeed", dev, err)
		}
	}
	_, err := armtlsTEEType("auto")
	if err == nil {
		t.Fatal("armtlsTEEType(auto) succeeded without TEE devices")
	}
	if got := err.Error(); !strings.Contains(got, "found neither") {
		t.Errorf("error %q does not mention the missing devices", got)
	}
}
