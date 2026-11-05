package cmdsutil

import (
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// boundPin is the document `c8s cds config new` writes: this cluster's CDS
// image bound to the exact launch file it boots.
func boundPin() string {
	return testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)
}

// digestOnlyPin names the CDS image without binding the configuration it
// boots with, which no CDS client accepts.
const digestOnlyPin = `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` +
	testutil.TestMeasurement + `"}]}`

// A node's CDS block names an endpoint its clients can dial and a pin that is
// one VM's identity. Each refusal names the rule that owns it.
func TestCDSParseRefusesWhatAClientCannotUse(t *testing.T) {
	for _, tc := range []struct {
		name string
		cds  CDS
		want error
	}{
		{"no address", CDS{Measurements: boundPin()}, ErrNoCDSAddress},
		{"address without port", CDS{Address: "cds.example.com", Measurements: boundPin()}, ErrNotHostPort},
		{"ipv6 address", CDS{Address: "[2001:db8::1]:8443", Measurements: boundPin()}, ErrNotIPv4},
		{"port zero", CDS{Address: "192.0.2.50:0", Measurements: boundPin()}, ErrPortUnserved},
		{"loopback address", CDS{Address: "127.0.0.1:8443", Measurements: boundPin()}, ErrNotRoutableIPv4},
		{"uppercase name", CDS{Address: "CDS.example.com:8443", Measurements: boundPin()}, ErrNotDNSHostname},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cds.Parse()
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %v, want %v", err, tc.want)
			}
			if !errors.Is(tc.cds.Validate(), tc.want) {
				t.Fatalf("Validate = %v, want what Parse refuses", tc.cds.Validate())
			}
		})
	}
}

// A pin that is not one VM's identity is refused where the measurements are
// read, which has no error value of its own to match.
func TestCDSParseRefusesAPinThatIsNoIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, measurements, want string
	}{
		{"malformed measurements", "{", "cds.measurements"},
		{"pin without a launch file", digestOnlyPin, "launch file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CDS{Address: "192.0.2.50:8443", Measurements: tc.measurements}.Parse()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse = %v, want %q", err, tc.want)
			}
		})
	}
}

// What a node takes out of an accepted block: the endpoint its pod ruleset
// admits, the policy its clients verify CDS with, and the launch file that pin
// binds.
func TestCDSCarriesTheEndpointPolicyAndLaunchFile(t *testing.T) {
	cds := CDS{Address: "cds.example.org:8443", Measurements: boundPin()}
	endpoint, err := cds.Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if endpoint.Host != "cds.example.org" || endpoint.Port != 8443 {
		t.Fatalf("endpoint = %s:%d", endpoint.Host, endpoint.Port)
	}
	policy, err := endpoint.Policy()
	if err != nil || !strings.Contains(string(policy), testutil.TestMeasurement) {
		t.Fatalf("Policy = %s, %v", policy, err)
	}
	if string(endpoint.LaunchFile) != testutil.CDSLaunchFile {
		t.Fatalf("LaunchFile = %q", endpoint.LaunchFile)
	}
}
