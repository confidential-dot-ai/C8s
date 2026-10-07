package cds

import (
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// A register pin is what reaches past a TDX launch measurement. Image pins
// replace the flat register map at verification, so each image must carry its
// own: a document naming one register-less image pins firmware only.
func TestPinsGuestCode(t *testing.T) {
	registers := map[int][]byte{1: []byte("kernel")}
	withRegisters := remote.ImagePin{
		Name:      "node",
		Registers: registers,
	}
	for _, tc := range []struct {
		name string
		pins armtls.Pins
		want bool
	}{
		{
			name: "launch digests alone",
			pins: armtls.Pins{Measurements: [][]byte{[]byte("mrtd")}},
			want: false,
		},
		{
			name: "launch digests with a register",
			pins: armtls.Pins{
				Measurements: [][]byte{[]byte("mrtd")},
				Registers:    registers,
			},
			want: true,
		},
		{
			name: "every image carries registers",
			pins: armtls.Pins{Images: []remote.ImagePin{withRegisters}},
			want: true,
		},
		{
			name: "one image carries none",
			pins: armtls.Pins{Images: []remote.ImagePin{withRegisters, {Name: "other"}}},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pinsGuestCode(tc.pins); got != tc.want {
				t.Fatalf("pinsGuestCode = %v, want %v", got, tc.want)
			}
		})
	}
}
