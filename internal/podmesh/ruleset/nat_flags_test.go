//go:build linux

package ruleset

import (
	"encoding/binary"
	"testing"

	"github.com/google/nftables/expr"
	nfnl "github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Flags the NAT expression names itself merge into the one flags attribute
// the kernel reports with the derived range flags.
func TestNATEncodingMergesExplicitFlags(t *testing.T) {
	encoded, err := marshalNAT(&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, Persistent: true})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := nfnl.UnmarshalAttributes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var data []nfnl.Attribute
	for _, a := range outer {
		if a.Type&^unix.NLA_F_NESTED == unix.NFTA_EXPR_DATA {
			if data, err = nfnl.UnmarshalAttributes(a.Data); err != nil {
				t.Fatal(err)
			}
		}
	}
	var flags []uint32
	for _, a := range data {
		if a.Type == unix.NFTA_NAT_FLAGS {
			flags = append(flags, binary.BigEndian.Uint32(a.Data))
		}
	}
	want := uint32(unix.NF_NAT_RANGE_MAP_IPS | unix.NF_NAT_RANGE_PERSISTENT)
	if len(flags) != 1 || flags[0] != want {
		t.Fatalf("flags attributes = %#x, want one of %#x", flags, want)
	}
}
