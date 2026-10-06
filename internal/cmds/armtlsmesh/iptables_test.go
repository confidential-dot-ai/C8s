//go:build linux

package armtlsmesh

import (
	"maps"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestBuildPodIPSetRulesDualStack(t *testing.T) {
	rules := mustBuildPodIPSetRules(t, 15001, 1337, nil, map[iptablesFamily]string{
		iptablesFamilyIPv4: "10.0.0.1",
		iptablesFamilyIPv6: "fd00::10",
	})

	if len(rules) != 4 {
		t.Fatalf("expected 4 rules (2 OUTPUT + 2 PREROUTING DNAT), got %d", len(rules))
	}

	// Rule 1: IPv4 OUTPUT REDIRECT, owner exclusion for the proxy UID.
	r1 := rules[0]
	if r1.table != "nat" || r1.chain != chainName {
		t.Errorf("rule 1: table=%q chain=%q, want nat/%s", r1.table, r1.chain, chainName)
	}
	if r1.family != iptablesFamilyIPv4 {
		t.Errorf("rule 1: family=%q, want IPv4", r1.family)
	}
	if r1.label != "output-pod-ipset-1:65535" {
		t.Errorf("rule 1: label=%q, want %q", r1.label, "output-pod-ipset-1:65535")
	}
	assertContains(t, "rule 1", r1.args, "--match-set", podIPSetName4)
	assertContains(t, "rule 1", r1.args, "--dport", "1:65535")
	assertContains(t, "rule 1", r1.args, "--uid-owner", "1337")
	assertContains(t, "rule 1", r1.args, "-j", "REDIRECT")
	assertContains(t, "rule 1", r1.args, "--to-port", "15001")

	// Rule 2: IPv4 PREROUTING DNAT to nodeIP:15001. PREROUTING has no socket
	// owner so no UID exclusion; loop prevention comes from the LOCAL-PODS
	// src match (the proxy on hostNetwork has src=nodeIP, not in the set).
	r2 := rules[1]
	if r2.chain != preroutingChainName {
		t.Errorf("rule 2: chain=%q, want %q", r2.chain, preroutingChainName)
	}
	if r2.family != iptablesFamilyIPv4 {
		t.Errorf("rule 2: family=%q, want IPv4", r2.family)
	}
	if r2.label != "prerouting-pod-ipset-1:65535" {
		t.Errorf("rule 2: label=%q, want %q", r2.label, "prerouting-pod-ipset-1:65535")
	}
	assertContains(t, "rule 2", r2.args, "--match-set", localPodIPSetName4)
	assertContains(t, "rule 2", r2.args, "--match-set", podIPSetName4)
	assertContains(t, "rule 2", r2.args, "--dport", "1:65535")
	assertContains(t, "rule 2", r2.args, "-j", "DNAT")
	assertContains(t, "rule 2", r2.args, "--to-destination", "10.0.0.1:15001")
	assertArgNotContains(t, "rule 2", r2.args, "REDIRECT")
	assertArgNotContains(t, "rule 2", r2.args, "--to-port")
	assertArgNotContains(t, "rule 2", r2.args, "--uid-owner")

	// Rule 3: IPv6 OUTPUT REDIRECT.
	r3 := rules[2]
	if r3.family != iptablesFamilyIPv6 {
		t.Errorf("rule 3: family=%q, want IPv6", r3.family)
	}
	assertContains(t, "rule 3", r3.args, "--match-set", podIPSetName6)
	assertContains(t, "rule 3", r3.args, "-j", "REDIRECT")

	// Rule 4: IPv6 PREROUTING DNAT to [nodeIP]:15001.
	r4 := rules[3]
	if r4.chain != preroutingChainName || r4.family != iptablesFamilyIPv6 {
		t.Errorf("rule 4: chain=%q family=%q, want %s/IPv6", r4.chain, r4.family, preroutingChainName)
	}
	assertContains(t, "rule 4", r4.args, "-j", "DNAT")
	assertContains(t, "rule 4", r4.args, "--to-destination", "[fd00::10]:15001")
	assertArgNotContains(t, "rule 4", r4.args, "REDIRECT")
}

// TestBuildPodIPSetRulesIPv4Only asserts that an IPv4-only node IP installs
// IPv4 OUTPUT+PREROUTING but skips the IPv6 PREROUTING rule entirely — no
// REDIRECT fallback, which would silently reintroduce the AKS bug for IPv6.
func TestBuildPodIPSetRulesIPv4Only(t *testing.T) {
	rules := mustBuildPodIPSetRules(t, 15001, 1337, nil, map[iptablesFamily]string{
		iptablesFamilyIPv4: "10.0.0.1",
	})

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (2 OUTPUT + 1 IPv4 PREROUTING), got %d", len(rules))
	}
	assertContains(t, "ipv4 prerouting", rules[1].args, "-j", "DNAT")
	assertContains(t, "ipv4 prerouting", rules[1].args, "--to-destination", "10.0.0.1:15001")
	for _, r := range rules {
		if r.chain == preroutingChainName && r.family == iptablesFamilyIPv6 {
			t.Fatalf("IPv6 PREROUTING rule must not be emitted without an IPv6 node IP; got %+v", r)
		}
	}
}

// TestBuildPodIPSetRulesIPv6Only mirrors the v4-only case for v6 single-stack.
func TestBuildPodIPSetRulesIPv6Only(t *testing.T) {
	rules := mustBuildPodIPSetRules(t, 15001, 1337, nil, map[iptablesFamily]string{
		iptablesFamilyIPv6: "fd00::10",
	})

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (2 OUTPUT + 1 IPv6 PREROUTING), got %d", len(rules))
	}
	for _, r := range rules {
		if r.chain == preroutingChainName && r.family == iptablesFamilyIPv4 {
			t.Fatalf("IPv4 PREROUTING rule must not be emitted without an IPv4 node IP; got %+v", r)
		}
	}
	var ipv6Prerouting *iptablesRule
	for i, r := range rules {
		if r.chain == preroutingChainName && r.family == iptablesFamilyIPv6 {
			ipv6Prerouting = &rules[i]
		}
	}
	if ipv6Prerouting == nil {
		t.Fatal("expected an IPv6 PREROUTING DNAT rule")
	}
	assertContains(t, "ipv6 prerouting", ipv6Prerouting.args, "-j", "DNAT")
	assertContains(t, "ipv6 prerouting", ipv6Prerouting.args, "--to-destination", "[fd00::10]:15001")
}

func TestBuildPodIPSetRulesExcludeUIDs(t *testing.T) {
	tests := []struct {
		name        string
		excludeUIDs []uint32
	}{
		{name: "single", excludeUIDs: []uint32{0}},
		{name: "multiple", excludeUIDs: []uint32{0, 65534}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := mustBuildPodIPSetRules(t, 15001, 1337, tt.excludeUIDs, map[iptablesFamily]string{
				iptablesFamilyIPv4: "10.0.0.1",
				iptablesFamilyIPv6: "fd00::10",
			})
			if want := len(tt.excludeUIDs) + 4; len(rules) != want {
				t.Fatalf("got %d rules, want %d (%d exclude + 4 ipset rules)", len(rules), want, len(tt.excludeUIDs))
			}
			for i, uid := range tt.excludeUIDs {
				r := rules[i]
				uidStr := strconv.Itoa(int(uid))
				wantLabel := "exclude-uid-" + uidStr
				if r.label != wantLabel {
					t.Errorf("exclude rule %d: label=%q, want %q", i, r.label, wantLabel)
				}
				assertContains(t, wantLabel, r.args, "--uid-owner", uidStr)
				assertContains(t, wantLabel, r.args, "-j", "RETURN")
			}
			// Ipset rules still present after the excludes.
			ipsetRules := rules[len(tt.excludeUIDs):]
			assertContains(t, "rule 1", ipsetRules[0].args, "--dport", "1:65535")
			assertContains(t, "rule 2", ipsetRules[1].args, "--dport", "1:65535")
		})
	}
}

func TestMakeDNATRulePanicsOnEmptyDestination(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("makeDNATRule with empty toDestination should panic; it did not")
		}
	}()
	_ = makeDNATRule(dnatRuleSpec{
		chain:       preroutingChainName,
		family:      iptablesFamilyIPv4,
		labelPrefix: "test",
		dportRange:  "1:65535",
	})
}

func TestJumpRules(t *testing.T) {
	jumps := jumpRules()
	if len(jumps) != 2 {
		t.Fatalf("expected 2 jump rules, got %d", len(jumps))
	}
	if jumps[0].table != "nat" {
		t.Errorf("output jump rule: table=%q, want nat", jumps[0].table)
	}
	if jumps[0].chain != "OUTPUT" {
		t.Errorf("output jump rule: chain=%q, want OUTPUT", jumps[0].chain)
	}
	assertContains(t, "output jump", jumps[0].args, "-j", chainName)

	if jumps[1].table != "nat" {
		t.Errorf("prerouting jump rule: table=%q, want nat", jumps[1].table)
	}
	if jumps[1].chain != "PREROUTING" {
		t.Errorf("prerouting jump rule: chain=%q, want PREROUTING", jumps[1].chain)
	}
	assertContains(t, "prerouting jump", jumps[1].args, "-j", preroutingChainName)
}

// TestJumpRulesArgsShape guards the assumption parseJumpBlockAtHead relies on:
// each jump's args is exactly {"-j", chain}. Any matcher (e.g. -m comment,
// conntrack) would let iptables -S renormalize tokens, defeat the literal
// string compare, and turn the watchdog into a reinsert-every-tick loop. Catch
// the regression here instead of in a noisy production race.
func TestJumpRulesArgsShape(t *testing.T) {
	jumps := append(append(jumpRules(), cwJumpRule()), cwEgressJumpRule())
	for i, jump := range jumps {
		if len(jump.args) != 2 || jump.args[0] != "-j" {
			t.Fatalf("jump %d args = %v; parseJumpBlockAtHead requires {\"-j\", <chain>}", i, jump.args)
		}
	}
}

func TestCWJumpRule(t *testing.T) {
	jump := cwJumpRule()
	if jump.table != "filter" {
		t.Errorf("cw jump: table=%q, want filter", jump.table)
	}
	if jump.chain != "FORWARD" {
		t.Errorf("cw jump: chain=%q, want FORWARD", jump.chain)
	}
	assertContains(t, "cw jump", jump.args, "-j", cwChainName)
}

func TestCWEGressJumpRule(t *testing.T) {
	jump := cwEgressJumpRule()
	if jump.table != "filter" {
		t.Errorf("cw egress jump: table=%q, want filter", jump.table)
	}
	if jump.chain != "FORWARD" {
		t.Errorf("cw egress jump: chain=%q, want FORWARD", jump.chain)
	}
	assertContains(t, "cw egress jump", jump.args, "-j", cwEgressChainName)
}

func TestBuildCWGuardRulesDefaultPassthrough(t *testing.T) {
	rules := buildCWGuardRules(defaultCWPassthrough)
	// Per family, in order: conntrack RETURN, the udp:53 exemption, the two
	// tcp:53 exemptions (one per admitted segment shape), then DROP.
	const perFamily = 5
	if len(rules) != 2*perFamily {
		t.Fatalf("expected %d rules (%d per family), got %d", 2*perFamily, perFamily, len(rules))
	}
	for i, spec := range []struct {
		family  iptablesFamily
		setName string
	}{
		{iptablesFamilyIPv4, cwPodIPSetName4},
		{iptablesFamilyIPv6, cwPodIPSetName6},
	} {
		group := rules[i*perFamily : (i+1)*perFamily]
		ret, ptUDP, ptSYNACK, ptNonSYN, drop := group[0], group[1], group[2], group[3], group[4]
		for _, r := range []iptablesRule{ret, ptUDP, ptSYNACK, ptNonSYN, drop} {
			if r.table != "filter" || r.chain != cwChainName {
				t.Errorf("%s: table=%q chain=%q, want filter/%s", spec.family, r.table, r.chain, cwChainName)
			}
			if r.family != spec.family {
				t.Errorf("rule family=%q, want %q", r.family, spec.family)
			}
			assertContains(t, "cw guard", r.args, "--match-set", spec.setName)
		}
		// The conntrack RETURN comes first so replies to cw-pod egress pass.
		assertContains(t, "cw return", ret.args, "--ctstate", "ESTABLISHED,RELATED")
		assertContains(t, "cw return", ret.args, "-j", "RETURN")
		assertArgNotContains(t, "cw return", ret.args, "-p")
		// Passthrough exemptions (udp+tcp source port 53) precede the DROP so a
		// dataplane that breaks the query's conntrack tuple still admits the
		// reply that get-cert needs. Pin them verbatim: the exemption is the
		// guard's only hole, so its exact width is the security property. The
		// TCP legs enumerate the admitted segment shapes rather than negating
		// SYN, which would also admit SYN|FIN and SYN|RST.
		wantUDP := []string{
			"-p", "udp", "--sport", "53", "--dport", cwPassthroughDportRange,
			"-m", "set", "--match-set", spec.setName, "dst",
			"-j", "RETURN",
		}
		if !reflect.DeepEqual(ptUDP.args, wantUDP) {
			t.Errorf("%s udp passthrough = %v, want %v", spec.family, ptUDP.args, wantUDP)
		}
		wantSYNACK := []string{
			"-p", "tcp", "--sport", "53", "--dport", cwPassthroughDportRange,
			"--tcp-flags", "SYN,RST,ACK,FIN", "SYN,ACK",
			"-m", "set", "--match-set", spec.setName, "dst",
			"-j", "RETURN",
		}
		if !reflect.DeepEqual(ptSYNACK.args, wantSYNACK) {
			t.Errorf("%s tcp syn-ack passthrough = %v, want %v", spec.family, ptSYNACK.args, wantSYNACK)
		}
		wantNonSYN := []string{
			"-p", "tcp", "--sport", "53", "--dport", cwPassthroughDportRange,
			"--tcp-flags", "SYN", "NONE",
			"-m", "set", "--match-set", spec.setName, "dst",
			"-j", "RETURN",
		}
		if !reflect.DeepEqual(ptNonSYN.args, wantNonSYN) {
			t.Errorf("%s tcp non-syn passthrough = %v, want %v", spec.family, ptNonSYN.args, wantNonSYN)
		}
		// --tcp-flags is a TCP-match option; on the udp rule it is a parse error
		// at install time.
		assertArgNotContains(t, "cw pt udp", ptUDP.args, "--tcp-flags")
		// The DROP stays protocol-agnostic and conntrack-agnostic.
		assertContains(t, "cw drop", drop.args, "-j", "DROP")
		assertArgNotContains(t, "cw drop", drop.args, "--ctstate")
		assertArgNotContains(t, "cw drop", drop.args, "-p")
	}
}

// An empty passthrough is the strict fail-closed posture: conntrack RETURN then
// drop-all, no exemptions.
func TestBuildCWGuardRulesEmptyPassthroughIsStrict(t *testing.T) {
	rules := buildCWGuardRules(nil)
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules (RETURN + DROP per family), got %d", len(rules))
	}
	for _, r := range rules {
		assertArgNotContains(t, "strict", r.args, "--sport")
	}
	assertContains(t, "strict return", rules[0].args, "--ctstate", "ESTABLISHED,RELATED")
	assertContains(t, "strict drop", rules[1].args, "-j", "DROP")
}

// The egress guard drops non-TCP from cw pod source IPs (the mesh carries
// TCP only), exempting established TCP replies, UDP/53 queries to any
// destination, and the ICMPv6 types IPv6 needs. Golden test asserting the
// exact rules for both families.
func TestBuildCWEgressGuardRulesGolden(t *testing.T) {
	rules := buildCWEgressGuardRules()
	specs := []struct {
		family  iptablesFamily
		setName string
	}{
		{iptablesFamilyIPv4, cwPodIPSetName4},
		{iptablesFamilyIPv6, cwPodIPSetName6},
	}
	// Per family: established RETURN, DNS RETURN, [14 ICMPv6 RETURN for v6],
	// nontcp DROP. v4 = 3, v6 = 3 + 14.
	var offset int
	for _, spec := range specs {
		icmpCount := 0
		if spec.family == iptablesFamilyIPv6 {
			icmpCount = len(essentialICMPv6Types)
		}
		perFamily := 3 + icmpCount // est, dns, icmpv6 x N, drop
		group := rules[offset : offset+perFamily]
		offset += perFamily
		est, dns, drop := group[0], group[1], group[perFamily-1]
		for _, r := range []iptablesRule{est, dns, drop} {
			if r.table != "filter" || r.chain != cwEgressChainName {
				t.Errorf("%s: table=%q chain=%q, want filter/%s", spec.family, r.table, r.chain, cwEgressChainName)
			}
			if r.family != spec.family {
				t.Errorf("rule family=%q, want %q", r.family, spec.family)
			}
			assertContains(t, "cw egress", r.args, "--match-set", spec.setName)
			if !slices.Contains(r.args, "src") {
				t.Errorf("%s: rule missing src match; args %v", spec.family, r.args)
			}
		}
		// Established RETURN must be restricted to TCP: established non-TCP
		// (the SEC-4 bypass) falls through to the non-TCP drop.
		wantEst := []string{
			"-m", "set", "--match-set", spec.setName, "src",
			"-p", "tcp",
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-j", "RETURN",
		}
		if !reflect.DeepEqual(est.args, wantEst) {
			t.Errorf("%s established return = %v, want %v", spec.family, est.args, wantEst)
		}
		// The carve-out names no destination, so it survives kube-proxy's
		// Service DNAT and holds whatever address the cluster resolver has.
		wantDNS := []string{
			"-m", "set", "--match-set", spec.setName, "src",
			"-p", "udp", "--dport", "53",
			"-j", "RETURN",
		}
		if !reflect.DeepEqual(dns.args, wantDNS) {
			t.Errorf("%s dns query = %v, want %v", spec.family, dns.args, wantDNS)
		}
		// ICMPv6 allow rules (v6 only) must cover every essential type.
		if spec.family == iptablesFamilyIPv6 {
			for ti, wantType := range essentialICMPv6Types {
				r := group[2+ti]
				want := []string{
					"-m", "set", "--match-set", spec.setName, "src",
					"-p", "ipv6-icmp", "--icmpv6-type", strconv.Itoa(wantType),
					"-j", "RETURN",
				}
				if !reflect.DeepEqual(r.args, want) {
					t.Errorf("%s icmpv6 allow %d = %v, want %v", spec.family, wantType, r.args, want)
				}
				if r.family != iptablesFamilyIPv6 {
					t.Errorf("icmpv6 allow rule family=%q, want ipv6", r.family)
				}
			}
		}
		// The drop is non-TCP (protocol negation) and protocol-agnostic.
		wantDrop := []string{
			"-m", "set", "--match-set", spec.setName, "src",
			"!", "-p", "tcp",
			"-j", "DROP",
		}
		if !reflect.DeepEqual(drop.args, wantDrop) {
			t.Errorf("%s nontcp drop = %v, want %v", spec.family, drop.args, wantDrop)
		}
	}
}

// The egress DROP must never match TCP (the mesh intercepts pod TCP in
// PREROUTING before FORWARD), so a TCP packet's protocol column never equals
// "tcp" at the point the drop is evaluated. The rule uses `! -p tcp`.
func TestBuildCWEgressGuardRulesDoesNotDropTCP(t *testing.T) {
	rules := buildCWEgressGuardRules()
	for _, r := range rules {
		if !strings.Contains(r.label, "drop") {
			continue
		}
		// The negation must be present and immediately precede -p tcp.
		found := false
		for i, a := range r.args {
			if a == "!" && i+2 < len(r.args) && r.args[i+1] == "-p" && r.args[i+2] == "tcp" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: drop rule does not carry `! -p tcp`; got %v", r.label, r.args)
		}
	}
}

// The established-return rule must carry -p tcp, so pre-existing established
// non-TCP flows are still dropped (SEC-4). A guard built without this would
// let arbitrary established UDP pass the host FORWARD guard.
func TestBuildCWEgressGuardEstablishedReturnIsTCPOnly(t *testing.T) {
	rules := buildCWEgressGuardRules()
	for _, r := range rules {
		if !strings.Contains(r.label, "established") {
			continue
		}
		assertContains(t, r.label, r.args, "-p", "tcp")
		assertContains(t, r.label, r.args, "--ctstate", "ESTABLISHED,RELATED")
		assertContains(t, r.label, r.args, "-j", "RETURN")
		if slices.Contains(r.args, "-d") {
			t.Errorf("%s: established return must not scope a destination; got %v", r.label, r.args)
		}
	}
}

// Every entry an operator can configure carries the destination-port bound,
// and every TCP entry carries a flag match.
// TestCWGuardTCPExemptionsAdmitOnlyReplyShapes checks what those flags admit.
func TestBuildCWGuardRulesExemptionsCannotOpenConnections(t *testing.T) {
	entries := []cwPassthrough{{"udp", 53}, {"tcp", 53}, {"tcp", 8443}, {"udp", 123}}
	rules := buildCWGuardRules(entries)

	var exemptions, tcpRules int
	for _, r := range rules {
		if !slices.Contains(r.args, "--sport") {
			continue
		}
		exemptions++
		assertContains(t, r.label, r.args, "--dport", cwPassthroughDportRange)
		// Key off the value following -p, not the presence of the token "tcp":
		// a rule emitting `-p 6` would otherwise skip the flag requirement and
		// pass while admitting every segment shape.
		if argValue(r.args, "-p") != "tcp" {
			assertArgNotContains(t, r.label, r.args, "--tcp-flags")
			continue
		}
		tcpRules++
		if argValue(r.args, "--tcp-flags") == "" {
			t.Errorf("%s: tcp exemption carries no --tcp-flags match", r.label)
		}
	}
	// Two families: two udp entries emit one rule each, two tcp entries emit
	// one per admitted segment shape.
	if exemptions != 12 {
		t.Fatalf("found %d exemption rules, want 12", exemptions)
	}
	if tcpRules != 8 {
		t.Fatalf("found %d tcp exemption rules, want 8", tcpRules)
	}
}

// tcpFlagBits are the bit values behind iptables' --tcp-flags names.
var tcpFlagBits = map[string]uint8{
	"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
	"ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80,
}

func tcpFlagValue(t *testing.T, spec string) uint8 {
	t.Helper()
	if spec == "NONE" {
		return 0
	}
	var bits uint8
	for name := range strings.SplitSeq(spec, ",") {
		b, ok := tcpFlagBits[name]
		if !ok {
			t.Fatalf("unknown TCP flag %q in %q", name, spec)
		}
		bits |= b
	}
	return bits
}

// The TCP exemptions are evaluated as netfilter evaluates them —
// (flags & mask) == comp.
func TestCWGuardTCPExemptionsAdmitOnlyReplyShapes(t *testing.T) {
	type leg struct{ mask, comp uint8 }
	var legs []leg
	for _, f := range cwTCPReplyFlags {
		if len(f.args) != 3 || f.args[0] != "--tcp-flags" {
			t.Fatalf("cwTCPReplyFlags entry %q is not {--tcp-flags, mask, comp}: %v", f.suffix, f.args)
		}
		legs = append(legs, leg{tcpFlagValue(t, f.args[1]), tcpFlagValue(t, f.args[2])})
	}
	admits := func(flags uint8) bool {
		for _, l := range legs {
			if flags&l.mask == l.comp {
				return true
			}
		}
		return false
	}

	for _, tc := range []struct {
		flags string
		admit bool
	}{
		// Connection initiation in every shape that carries SYN.
		{"SYN", false},
		{"SYN,FIN", false},
		{"SYN,RST", false},
		{"SYN,FIN,ACK", false},
		{"SYN,RST,ACK", false},
		{"SYN,FIN,RST,ACK", false},
		// Reply traffic.
		{"SYN,ACK", true},
		{"ACK", true},
		{"ACK,PSH", true},
		{"FIN,ACK", true},
		{"RST,ACK", true},
		{"RST", true},
		{"NONE", true},
		{"SYN,ACK,PSH", true},
		// The ECN handshake reply: the mask leaves ECE free and must keep it so.
		{"SYN,ACK,ECE", true},
	} {
		t.Run(tc.flags, func(t *testing.T) {
			if got := admits(tcpFlagValue(t, tc.flags)); got != tc.admit {
				t.Errorf("exemption admits %s = %v, want %v", tc.flags, got, tc.admit)
			}
		})
	}
}

// The counter reader attributes a RETURN row to an exemption by its protocol
// column, so every protocol-scoped rule the guard installs must be an exemption.
// A protocol-scoped rule without a source port would inflate the gauge.
func TestCWGuardProtocolScopedRulesAreExemptions(t *testing.T) {
	rules := buildCWGuardRules(defaultCWPassthrough)
	if len(rules) == 0 {
		t.Fatal("no rules to check")
	}
	for _, r := range rules {
		if slices.Contains(r.args, "-p") && !slices.Contains(r.args, "--sport") {
			t.Errorf("%s: protocol-scoped rule with no source port; the counter reader would count it as an exemption", r.label)
		}
	}
}

// The exemption window is the stock Linux ephemeral port window.
func TestCWPassthroughDportRangeBoundaries(t *testing.T) {
	if cwPassthroughDportRange != "32768:60999" {
		t.Fatalf("cwPassthroughDportRange = %q, want the stock ephemeral window 32768:60999", cwPassthroughDportRange)
	}
	loStr, hiStr, ok := strings.Cut(cwPassthroughDportRange, ":")
	if !ok {
		t.Fatalf("cwPassthroughDportRange = %q is not a lo:hi range", cwPassthroughDportRange)
	}
	lo, err := strconv.Atoi(loStr)
	if err != nil {
		t.Fatalf("range low bound %q: %v", loStr, err)
	}
	hi, err := strconv.Atoi(hiStr)
	if err != nil {
		t.Fatalf("range high bound %q: %v", hiStr, err)
	}
	for _, tc := range []struct {
		port   int
		inside bool
	}{
		{32767, false},
		{32768, true},
		{60999, true},
		{61000, false},
	} {
		if got := tc.port >= lo && tc.port <= hi; got != tc.inside {
			t.Errorf("port %d inside window = %v, want %v", tc.port, got, tc.inside)
		}
	}
}

// Every protocol the allowlist parser admits must also be attributable by the
// counter reader, under both the name and the number iptables may print.
// Widening one side alone makes the exemption counter read a permanent zero for
// the new protocol — the bypass-is-silent defect, one protocol later.
func TestCWPassthroughProtocolsBindParserAndCounter(t *testing.T) {
	for name, number := range cwPassthroughProtocols {
		if _, err := parseCWPassthrough(name + ":53"); err != nil {
			t.Errorf("parseCWPassthrough rejects %q from the protocol table: %v", name, err)
		}
		if !cwExemptionProtocolColumn[name] {
			t.Errorf("counter reader does not attribute protocol column %q", name)
		}
		if !cwExemptionProtocolColumn[number] {
			t.Errorf("counter reader does not attribute protocol column %q (%s)", number, name)
		}
	}
	// Port-less protocols, the empty name, and the wrong case and number forms
	// of an accepted name: all stay non-members however the allowlist widens.
	nonMembers := []string{"icmp", "gre", "esp", "", "TCP", "6"}
	if len(nonMembers) == 0 {
		t.Fatal("no non-members to check")
	}
	for _, proto := range nonMembers {
		if _, err := parseCWPassthrough(proto + ":53"); err == nil {
			t.Errorf("parseCWPassthrough accepted %q, which is absent from the protocol table", proto)
		}
	}
	// The rejection message enumerates the table, so widening it cannot leave
	// operators reading a stale list.
	want := strings.Join(slices.Sorted(maps.Keys(cwPassthroughProtocols)), " or ")
	_, err := parseCWPassthrough("icmp:53")
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("rejection %v does not enumerate the accepted protocols %q", err, want)
	}
}

// iptables-translate renders a rule as the nft expression it compiles to, so
// the flag mask and port window are asserted as matched rather than as
// assembled. It installs nothing, but it does resolve ipset names, so the set
// fragment is stripped. Skipped where the binary is absent.
func TestCWGuardExemptionsTranslateToExpectedNftMatches(t *testing.T) {
	wantFlags := map[string]string{
		"cw-passthrough-tcp-53-synack": "tcp flags syn,ack / fin,syn,rst,ack",
		"cw-passthrough-tcp-53-nonsyn": "tcp flags 0x0 / syn",
	}
	for _, tc := range []struct {
		bin    string
		family iptablesFamily
	}{
		{"iptables-translate", iptablesFamilyIPv4},
		{"ip6tables-translate", iptablesFamilyIPv6},
	} {
		t.Run(tc.bin, func(t *testing.T) {
			bin, err := exec.LookPath(tc.bin)
			if err != nil {
				// Setting this in a job that ships the binary turns a base
				// image that drops it into a failure instead of a silent skip.
				// No job sets it yet.
				if os.Getenv("C8S_REQUIRE_IPTABLES_TRANSLATE") != "" {
					t.Fatalf("%s not installed and C8S_REQUIRE_IPTABLES_TRANSLATE is set", tc.bin)
				}
				t.Skipf("%s not installed", tc.bin)
			}
			var checked int
			for _, r := range buildCWGuardRules(defaultCWPassthrough) {
				if r.family != tc.family || !slices.Contains(r.args, "--sport") {
					continue
				}
				checked++
				args := slices.Concat([]string{"-A", "FORWARD"}, withoutSetMatch(r.args))
				out, err := exec.Command(bin, args...).CombinedOutput()
				if err != nil {
					t.Fatalf("%s %v: %v\n%s", tc.bin, args, err, out)
				}
				got := string(out)
				if !strings.Contains(got, "dport 32768-60999") {
					t.Errorf("%s: exemption window missing from nft form: %s", r.label, got)
				}
				// `! --syn` renders as `flags != syn / ...`, which also admits
				// SYN|FIN and SYN|RST.
				if strings.Contains(got, "flags !=") {
					t.Errorf("%s: negated flag match admits SYN-bearing shapes: %s", r.label, got)
				}
				if want, ok := wantFlags[r.label]; ok && !strings.Contains(got, want) {
					t.Errorf("%s: want nft match %q, got %s", r.label, want, got)
				}
			}
			if checked != 3 {
				t.Fatalf("translated %d exemption rules, want 3 (udp:53 plus both tcp:53 legs)", checked)
			}
		})
	}
}

// withoutSetMatch drops the `-m set --match-set <name> dst` fragment: the
// *-translate binaries resolve the set and fail when it does not exist.
func withoutSetMatch(args []string) []string {
	for i := 0; i+4 < len(args); i++ {
		if args[i] == "-m" && args[i+1] == "set" && args[i+2] == "--match-set" && args[i+4] == "dst" {
			return slices.Concat(args[:i], args[i+5:])
		}
	}
	return args
}

func TestParseCWPassthrough(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    []cwPassthrough
		wantErr bool
	}{
		{name: "empty", in: "", want: nil},
		{name: "dns default", in: "udp:53,tcp:53", want: []cwPassthrough{{"udp", 53}, {"tcp", 53}}},
		{name: "whitespace", in: " udp:53 , tcp:53 ", want: []cwPassthrough{{"udp", 53}, {"tcp", 53}}},
		{name: "single", in: "tcp:8443", want: []cwPassthrough{{"tcp", 8443}}},
		{name: "bad proto", in: "icmp:53", wantErr: true},
		{name: "missing port", in: "udp", wantErr: true},
		{name: "port zero", in: "udp:0", wantErr: true},
		{name: "port too big", in: "udp:70000", wantErr: true},
		{name: "non-numeric port", in: "udp:dns", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCWPassthrough(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseCWPassthrough(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// The flag default is derived from defaultCWPassthrough via formatCWPassthrough,
// and the chart hardcodes the same string (asserted in the chart tests). Pin the
// rendered form so the two sources of truth cannot silently drift.
func TestFormatCWPassthroughDefaultMatchesChart(t *testing.T) {
	if got := formatCWPassthrough(defaultCWPassthrough); got != "udp:53,tcp:53" {
		t.Fatalf("default passthrough flag = %q, want udp:53,tcp:53 (chart default must match)", got)
	}
	// Round-trips: formatting then parsing yields the original.
	round, err := parseCWPassthrough(formatCWPassthrough(defaultCWPassthrough))
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if !reflect.DeepEqual(round, defaultCWPassthrough) {
		t.Fatalf("round-trip = %v, want %v", round, defaultCWPassthrough)
	}
}

func mustBuildPodIPSetRules(t *testing.T, outboundPort, uid int, excludeUIDs []uint32, nodeIPs map[iptablesFamily]string) []iptablesRule {
	t.Helper()
	return buildPodIPSetRules(outboundPort, uid, excludeUIDs, nodeIPs)
}

// argValue returns the token following flag, and argValueAt the token n
// positions after it. Empty when the flag is absent or has no such token.
func argValue(args []string, flag string) string {
	return argValueAt(args, flag, 1)
}

func argValueAt(args []string, flag string, n int) string {
	for i, a := range args {
		if a == flag && i+n < len(args) {
			return args[i+n]
		}
	}
	return ""
}

// assertContains checks that args contains the flag followed by the expected value.
func assertContains(t *testing.T, label string, args []string, flag, want string) {
	t.Helper()
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == want {
			return
		}
	}
	t.Errorf("%s: args %v missing %s %s", label, args, flag, want)
}

// assertArgNotContains rejects any args entry equal to value or that starts
// with `value=`. The `value=` check catches single-token flag forms
// (e.g. `--to-port=15001`) which a substring-only matcher misses. Pass the
// exact token; iptables flag values (IPs, ports, UIDs) never begin with a
// flag-like prefix in this codebase, so the check is unambiguous in
// practice. To assert a value is absent (e.g. the literal "REDIRECT"),
// pass the token form, not a fragment.
func assertArgNotContains(t *testing.T, label string, args []string, value string) {
	t.Helper()
	prefix := value + "="
	for _, a := range args {
		if a == value || (len(a) > len(prefix) && a[:len(prefix)] == prefix) {
			t.Errorf("%s: args %v unexpectedly contain %s", label, args, value)
			return
		}
	}
}

// composeIptablesSyncRules is the pure assembly of the sync cycle: the NAT
// interception rules, the always-on inbound + egress guard rules, and their
// FORWARD jumps. A rule or jump dropped from this composition changes the
// guard on every node, so assert the full set here rather than relying on a
// live kube to exercise runIptablesSync.
func TestComposeIptablesSyncRulesAssemblesFullGuard(t *testing.T) {
	nodeIPs := map[iptablesFamily]string{
		iptablesFamilyIPv4: "10.0.0.1",
		iptablesFamilyIPv6: "fd00::10",
	}
	exclude, err := parseExcludeUIDs("0")
	if err != nil {
		t.Fatalf("parseExcludeUIDs: %v", err)
	}
	cwPassthrough, err := parseCWPassthrough(formatCWPassthrough(defaultCWPassthrough))
	if err != nil {
		t.Fatalf("parseCWPassthrough: %v", err)
	}
	rules, jumps := composeIptablesSyncRules(15001, defaultProxyUID, exclude, cwPassthrough, nodeIPs)

	// The egress guard rules (both families, incl. ICMPv6 and the DNS
	// carve-out) must be present.
	var egressCount, icmpv6Count, dnsCount int
	for _, r := range rules {
		if r.chain != cwEgressChainName {
			continue
		}
		egressCount++
		switch {
		case strings.Contains(r.label, "icmpv6"):
			icmpv6Count++
		case strings.Contains(r.label, "dns"):
			dnsCount++
			// A destination scope here is the regression this removed: it
			// silently drops every cw DNS query on a cluster whose resolver
			// sits at another address.
			for _, scope := range []string{"--ctorigdst", "-d"} {
				if slices.Contains(r.args, scope) {
					t.Errorf("egress dns rule is scoped by %s: %v", scope, r.args)
				}
			}
		}
	}
	if egressCount <= 0 {
		t.Fatal("compose produced no cw egress guard rules")
	}
	if icmpv6Count != len(essentialICMPv6Types) {
		t.Errorf("compose icmpv6 allow rules = %d, want %d", icmpv6Count, len(essentialICMPv6Types))
	}
	if dnsCount != 2 { // one carve-out per family
		t.Errorf("compose dns rules = %d, want one per family", dnsCount)
	}

	// The egress FORWARD jump must sit in the jump set alongside the inbound
	// cw jump and the base-chain nat jumps.
	wantJumpChains := map[string]bool{
		chainName: true, preroutingChainName: true, cwChainName: true, cwEgressChainName: true,
	}
	gotJumps := 0
	for _, j := range jumps {
		if len(j.args) != 2 || j.args[0] != "-j" {
			t.Errorf(`jump args = %v, want {"-j", <chain>}`, j.args)
		}
		if !wantJumpChains[j.args[1]] {
			t.Errorf("unexpected jump target chain %q", j.args[1])
		}
		gotJumps++
	}
	if gotJumps != len(wantJumpChains) {
		t.Errorf("jump count = %d, want %d (nat OUTPUT/PREROUTING + cw + cw egress)", gotJumps, len(wantJumpChains))
	}
}
