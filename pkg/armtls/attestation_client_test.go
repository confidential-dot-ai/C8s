package armtls

import "testing"

// A proxy named in the environment must not see attestation-api requests.
func TestAttestationTransportIgnoresProxy(t *testing.T) {
	if directTransport().Proxy != nil {
		t.Fatal("attestation-api transport consults a proxy")
	}
}
