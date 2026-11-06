package cmdsutil

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// boundPin is the document `c8s cds config new` writes.
func boundPin() string {
	return testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)
}

// digestOnlyPin names the CDS image and binds no launch file.
var digestOnlyPin = fmt.Sprintf(
	`{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":%q}]}`,
	testutil.TestMeasurement,
)

// Each refusal names the rule that owns it.
func TestCDSParseRefusesWhatAClientCannotUse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		want    error
	}{
		{name: "no address", want: ErrNoCDSAddress},
		{name: "address without port", address: "cds.example.com", want: ErrNotHostPort},
		{name: "ipv6 address", address: "[2001:db8::1]:8443", want: ErrNotIPv4},
		{name: "port zero", address: "192.0.2.50:0", want: ErrPortUnserved},
		{name: "loopback address", address: "127.0.0.1:8443", want: ErrNotRoutableIPv4},
		{name: "uppercase name", address: "CDS.example.com:8443", want: ErrNotDNSHostname},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cds := CDS{Address: tc.address, Measurements: boundPin()}
			if _, err := cds.Parse(); !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %v, want %v", err, tc.want)
			}
			if err := cds.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want what Parse refuses", err)
			}
		})
	}
}

// A pin that is not one VM's identity is refused where the measurements are
// read, which has no error value of its own to match.
func TestCDSParseRefusesAPinThatIsNoIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		measurements string
		want         string
	}{
		{name: "malformed measurements", measurements: "{", want: "cds.measurements"},
		{name: "pin without a launch file", measurements: digestOnlyPin, want: "launch file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cds := CDS{Address: "192.0.2.50:8443", Measurements: tc.measurements}
			if _, err := cds.Parse(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse = %v, want %q", err, tc.want)
			}
		})
	}
}

// An accepted block carries the endpoint, the policy its clients verify CDS
// with, and the launch file its pin binds.
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
