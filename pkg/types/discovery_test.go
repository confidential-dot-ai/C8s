package types

import (
	"encoding/json"
	"testing"
)

// TestPublicTLSDiscoveryModeWireFormat pins public_tls.mode as a plain JSON
// string, and an unknown value surviving the decode so a consumer can name it.
func TestPublicTLSDiscoveryModeWireFormat(t *testing.T) {
	data, err := json.Marshal(PublicTLSDiscovery{Hostname: "lb.example.com", Mode: FrontDoorModeWebPKI})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), `{"hostname":"lb.example.com","mode":"webpki"}`; got != want {
		t.Fatalf("marshal = %s, want %s", got, want)
	}
	var decoded PublicTLSDiscovery
	if err := json.Unmarshal([]byte(`{"hostname":"lb.example.com","mode":"dns"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Mode != FrontDoorMode("dns") {
		t.Fatalf("mode = %q, want dns", decoded.Mode)
	}
}
