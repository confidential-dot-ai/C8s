package cmdsutil

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
)

// boundPin is the document `c8s ta config new` writes.
func boundPin() string {
	return testutil.TAPinDocument(testutil.TestMeasurement, testutil.TALaunchFile)
}

// digestOnlyPin names the Trust Authority image and binds no launch file.
var digestOnlyPin = fmt.Sprintf(
	`{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"ta","measurement":%q}]}`,
	testutil.TestMeasurement,
)

// tdxPin binds the launch file to a TDX image pinned by MRTD and the given
// rtmr array, which on TDX covers the firmware alone unless RTMR[1] and
// RTMR[2] are in it.
func tdxPin(rtmr string) string {
	return fmt.Sprintf(
		`{"schema_version":"2","tee":"tdx","measurements":[{"name":"ta","mrtd":%q,"rtmr":%s,"launch_file":%q}]}`,
		testutil.TestMeasurement, rtmr, testutil.TALaunchFile,
	)
}

// Each refusal names the rule that owns it.
func TestTAParseRefusesWhatAClientCannotUse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		want    error
	}{
		{name: "no address", want: ErrNoTAAddress},
		{name: "address without port", address: "ta.example.com", want: ErrNotHostPort},
		{name: "ipv6 address", address: "[2001:db8::1]:8443", want: ErrNotIPv4},
		{name: "port zero", address: "192.0.2.50:0", want: ErrPortUnserved},
		{name: "loopback address", address: "127.0.0.1:8443", want: ErrNotRoutableIPv4},
		{name: "uppercase name", address: "TA.example.com:8443", want: ErrNotDNSHostname},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := TA{Address: tc.address, Measurements: boundPin()}
			if _, err := ta.Parse(); !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %v, want %v", err, tc.want)
			}
			if err := ta.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want what Parse refuses", err)
			}
		})
	}
}

// A pin that is not one VM's identity is refused where the measurements are
// read, which has no error value of its own to match.
func TestTAParseRefusesAPinThatIsNoIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		measurements string
		want         string
	}{
		{name: "malformed measurements", measurements: "{", want: "ta.measurements"},
		{name: "pin without a launch file", measurements: digestOnlyPin, want: "launch file"},
		{name: "tdx pin by mrtd alone", measurements: tdxPin(`[null,null,null,null]`), want: "leaves RTMR[1] unpinned"},
		{name: "tdx pin without rtmr2", measurements: tdxPin(fmt.Sprintf(`[null,%q,null,null]`, testutil.TestMeasurement)), want: "leaves RTMR[2] unpinned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := TA{Address: "192.0.2.50:8443", Measurements: tc.measurements}
			if _, err := ta.Parse(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse = %v, want %q", err, tc.want)
			}
		})
	}
}

// A TDX Trust Authority is one VM once MRTD, RTMR[1] and RTMR[2] are pinned together with
// its launch file.
func TestTAParseAcceptsATDXPinWithItsGuestRegisters(t *testing.T) {
	rtmr := fmt.Sprintf(`[null,%q,%q,null]`, testutil.TestMeasurement, testutil.TestMeasurement)
	ta := TA{Address: "192.0.2.50:8443", Measurements: tdxPin(rtmr)}
	if _, err := ta.Parse(); err != nil {
		t.Fatalf("Parse = %v, want the pinned TDX Trust Authority accepted", err)
	}
}

// An accepted block carries the endpoint, the policy its clients verify Trust Authority
// with, and the launch file its pin binds.
func TestTACarriesTheEndpointPolicyAndLaunchFile(t *testing.T) {
	ta := TA{Address: "ta.example.org:8443", Measurements: boundPin()}
	endpoint, err := ta.Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if endpoint.Host != "ta.example.org" || endpoint.Port != 8443 {
		t.Fatalf("endpoint = %s:%d", endpoint.Host, endpoint.Port)
	}
	policy, err := endpoint.Policy()
	if err != nil || !strings.Contains(string(policy), testutil.TestMeasurement) {
		t.Fatalf("Policy = %s, %v", policy, err)
	}
	if string(endpoint.LaunchFile) != testutil.TALaunchFile {
		t.Fatalf("LaunchFile = %q", endpoint.LaunchFile)
	}
}
