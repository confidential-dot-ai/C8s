//go:build linux

package ruleset

import (
	"bytes"
	"testing"

	"github.com/google/nftables/expr"
	nfnl "github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// A conntrack direction is encoded in the one byte the kernel reports, for
// either direction.
func TestCtEncodingWritesOneDirectionByte(t *testing.T) {
	for _, direction := range []uint32{ctOriginal, 1} {
		encoded, err := marshalCt(&expr.Ct{Register: compareRegister, Key: expr.CtKeyDST, Direction: direction})
		if err != nil {
			t.Fatal(err)
		}
		outer, err := nfnl.UnmarshalAttributes(encoded)
		if err != nil {
			t.Fatal(err)
		}
		var got [][]byte
		for _, a := range outer {
			if a.Type&^unix.NLA_F_NESTED != unix.NFTA_EXPR_DATA {
				continue
			}
			data, err := nfnl.UnmarshalAttributes(a.Data)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range data {
				if field.Type == unix.NFTA_CT_DIRECTION {
					got = append(got, field.Data)
				}
			}
		}
		if want := []byte{byte(direction)}; len(got) != 1 || !bytes.Equal(got[0], want) {
			t.Errorf("marshalCt(direction %d) direction attributes = %x, want one of %x", direction, got, want)
		}
	}
}
