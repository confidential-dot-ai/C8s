//go:build linux

package armtlsmesh

import (
	"reflect"
	"testing"
)

func TestParseExcludeUIDs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint32
		wantErr bool
	}{
		{name: "empty", input: "", want: nil},
		{name: "single zero", input: "0", want: []uint32{0}},
		{name: "single non-root", input: "1337", want: []uint32{1337}},
		{name: "multiple", input: "0,65534", want: []uint32{0, 65534}},
		{name: "whitespace trimmed", input: " 0 , 65534 ", want: []uint32{0, 65534}},
		{name: "trailing comma skipped", input: "0,1,", want: []uint32{0, 1}},
		{name: "leading comma skipped", input: ",0,1", want: []uint32{0, 1}},
		{name: "only commas", input: ",,,", want: nil},
		{name: "only whitespace", input: "  ", want: nil},
		// Duplicates are preserved verbatim; the rule builder emits one
		// RETURN per entry and the second match is unreachable, so the
		// duplicate is benign rather than meaningful.
		{name: "duplicates kept", input: "0,0", want: []uint32{0, 0}},
		{name: "max uint32", input: "4294967295", want: []uint32{4294967295}},
		{name: "negative rejected", input: "-1", wantErr: true},
		{name: "overflow rejected", input: "4294967296", wantErr: true},
		{name: "non-numeric rejected", input: "abc", wantErr: true},
		{name: "mixed numeric and bad", input: "0,abc", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExcludeUIDs(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseExcludeUIDs(%q) = %v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExcludeUIDs(%q) unexpected error: %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseExcludeUIDs(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseJumpBlockAtHead(t *testing.T) {
	nat := jumpBlock{table: "nat", chain: "PREROUTING", jumps: []iptablesRule{
		{chain: "PREROUTING", args: []string{"-j", preroutingChainName}},
	}}
	forward := jumpBlock{table: "filter", chain: "FORWARD", jumps: []iptablesRule{
		cwJumpRule(), cwEgressJumpRule(),
	}}
	tests := []struct {
		name          string
		block         jumpBlock
		out           string
		wantAtHead    bool
		wantMisplaced int
	}{
		{
			name:  "absent on clean chain",
			block: nat,
			out:   "-P PREROUTING ACCEPT\n",
		},
		{
			name:  "at head",
			block: nat,
			out: `-P PREROUTING ACCEPT
-A PREROUTING -j ARMTLS-MESH-PREROUTING
-A PREROUTING -j KUBE-SERVICES
`,
			wantAtHead: true,
		},
		{
			name:  "demoted below kube services",
			block: nat,
			out: `-P PREROUTING ACCEPT
-A PREROUTING -j KUBE-SERVICES
-A PREROUTING -j ARMTLS-MESH-PREROUTING
`,
			wantMisplaced: 1,
		},
		{
			name:  "other chain ignored",
			block: nat,
			out: `-A OUTPUT -j ARMTLS-MESH-PREROUTING
-A PREROUTING -j KUBE-SERVICES
`,
		},
		// The two FORWARD guards cannot both be rule 1. Reading head position
		// per rule made the second one look demoted on every tick, and the
		// watchdog then unhooked a guard on every tick to "repair" it.
		{
			name:  "sibling guards in block order are at head",
			block: forward,
			out: `-P FORWARD ACCEPT
-A FORWARD -j ARMTLS-MESH-CW
-A FORWARD -j ARMTLS-MESH-CW-EGRESS
-A FORWARD -j KUBE-FORWARD
`,
			wantAtHead: true,
		},
		{
			name:  "sibling guards out of block order",
			block: forward,
			out: `-P FORWARD ACCEPT
-A FORWARD -j ARMTLS-MESH-CW-EGRESS
-A FORWARD -j ARMTLS-MESH-CW
-A FORWARD -j KUBE-FORWARD
`,
			wantMisplaced: 2,
		},
		{
			name:  "whole block demoted below kube forward",
			block: forward,
			out: `-P FORWARD ACCEPT
-A FORWARD -j KUBE-FORWARD
-A FORWARD -j ARMTLS-MESH-CW
-A FORWARD -j ARMTLS-MESH-CW-EGRESS
`,
			wantMisplaced: 2,
		},
		{
			name:  "one sibling absent",
			block: forward,
			out: `-P FORWARD ACCEPT
-A FORWARD -j ARMTLS-MESH-CW
-A FORWARD -j KUBE-FORWARD
`,
			wantMisplaced: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAtHead, gotMisplaced := parseJumpBlockAtHead(tc.out, tc.block)
			if gotAtHead != tc.wantAtHead || gotMisplaced != tc.wantMisplaced {
				t.Fatalf("parseJumpBlockAtHead = (atHead=%v, misplaced=%d), want (%v, %d)", gotAtHead, gotMisplaced, tc.wantAtHead, tc.wantMisplaced)
			}
		})
	}
}

func TestJumpBlocksFor(t *testing.T) {
	jumps := append(jumpRules(), cwJumpRule(), cwEgressJumpRule())
	jumps = append(jumps, iptablesRule{table: "nat", chain: "PREROUTING", family: iptablesFamilyIPv6, args: []string{"-j", "V6-ONLY"}})

	blocks := jumpBlocksFor(jumps, iptablesFamilyIPv4)
	if len(blocks) != 3 {
		t.Fatalf("v4 blocks = %d, want 3 (nat OUTPUT, nat PREROUTING, filter FORWARD)", len(blocks))
	}
	forward := blocks[2]
	if forward.table != "filter" || forward.chain != "FORWARD" {
		t.Fatalf("third block = %s/%s, want filter/FORWARD", forward.table, forward.chain)
	}
	if len(forward.jumps) != 2 {
		t.Fatalf("FORWARD block holds %d jumps, want both cw guards", len(forward.jumps))
	}
	if got := forward.jumps[0].args[1]; got != cwChainName {
		t.Errorf("FORWARD block head = %q, want %q", got, cwChainName)
	}

	v6 := jumpBlocksFor(jumps, iptablesFamilyIPv6)
	if len(v6[1].jumps) != 2 {
		t.Errorf("v6 nat PREROUTING block holds %d jumps, want the all-family jump plus the v6-only one", len(v6[1].jumps))
	}
}
