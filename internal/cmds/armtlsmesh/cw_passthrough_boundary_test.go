//go:build linux

package armtlsmesh

import (
	"reflect"
	"testing"
)

func TestParseCWPassthroughBoundaryPorts(t *testing.T) {
	got, err := parseCWPassthrough("udp:1,tcp:65535")
	if err != nil {
		t.Fatalf("boundary ports rejected: %v", err)
	}
	want := []cwPassthrough{{protocol: "udp", sourcePort: 1}, {protocol: "tcp", sourcePort: 65535}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
