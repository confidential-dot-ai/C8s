//go:build linux

package ruleset

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var update = flag.Bool("update", false, "regenerate testdata/ruleset.golden")

// testPolicy exercises every kind of permission a node's trusted policy can
// name: two resolver families and a credential role with one destination.
func testPolicy() Policy {
	return Policy{
		Resolvers: []netip.Addr{netip.MustParseAddr("10.53.0.10"), netip.MustParseAddr("fd00:53::a")},
		Capture:   CapturePorts{Outbound: 15001, Inbound: 15006, Health: 15021},
		MeshUID:   1337,
		Roles:     []Role{{UID: 1338, Destinations: []Destination{{netip.MustParseAddr("10.43.0.2"), 8443}}}},
	}
}

// The golden file pins the whole ruleset in nft's own syntax: a reviewer reads
// it to see what a member pod may and may not send, and any change to an
// expression shows up here before it reaches a pod.
func TestBuildMatchesTheGoldenRuleset(t *testing.T) {
	const golden = "testdata/ruleset.golden"
	got := renderRuleset(build(testPolicy()))
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("ruleset =\n%s\nwant\n%s", got, want)
	}
}

// A ruleset that cannot be built is never installed.
func TestInstallRefusesInvalidPolicy(t *testing.T) {
	if err := Install("/proc/self/ns/net", Policy{}); !errors.Is(err, ErrPolicy) {
		t.Fatalf("error = %v, want ErrPolicy", err)
	}
}

func renderRuleset(chains []chain) string {
	var out strings.Builder
	fmt.Fprintf(&out, "table inet %s {\n", tableName)
	for _, c := range chains {
		fmt.Fprintf(&out, "\tchain %s {\n", c.name)
		fmt.Fprintf(&out, "\t\ttype %s hook %s priority %s; policy %s;\n", c.kind, hookNames[c.hook], priorityName(c.priority), policyNames[c.policy])
		for _, r := range c.rules {
			fmt.Fprintf(&out, "\t\t%s # %s\n", nftRule(r.exprs), r.name)
		}
		fmt.Fprint(&out, "\t}\n")
	}
	fmt.Fprint(&out, "}\n")
	return out.String()
}

var (
	hookNames     = map[nftables.ChainHook]string{0: "prerouting", 1: "input", 2: "forward", 3: "output", 4: "postrouting"}
	policyNames   = map[nftables.ChainPolicy]string{nftables.ChainPolicyDrop: "drop", nftables.ChainPolicyAccept: "accept"}
	verdictNames  = map[expr.VerdictKind]string{expr.VerdictAccept: "accept", expr.VerdictDrop: "drop", expr.VerdictReturn: "return"}
	metaNames     = map[expr.MetaKey]string{expr.MetaKeySKUID: "skuid", expr.MetaKeyIIFNAME: "iifname", expr.MetaKeyL4PROTO: "meta l4proto", expr.MetaKeyNFPROTO: "meta nfproto"}
	protocolNames = map[uint8]string{unix.IPPROTO_TCP: "tcp", unix.IPPROTO_UDP: "udp", unix.IPPROTO_ICMP: "icmp", unix.IPPROTO_ICMPV6: "icmpv6"}
	familyNames   = map[uint8]string{unix.NFPROTO_IPV4: "ipv4", unix.NFPROTO_IPV6: "ipv6"}
	ctStateNames  = map[uint32]string{ctStateEstablished: "established", ctStateRelated: "related"}
	addressTypes  = map[uint32]string{unix.RTN_LOCAL: "local"}
	priorityNames = map[nftables.ChainPriority]string{*nftables.ChainPriorityFilter: "filter", *nftables.ChainPriorityNATDest: "dstnat"}
)

// priorityName is the name nft gives a base-chain priority, or its number.
func priorityName(priority nftables.ChainPriority) string {
	if name, ok := priorityNames[priority]; ok {
		return name
	}
	return strconv.Itoa(int(priority))
}

// nftRule renders one rule as nft prints it. Each load remembers how the
// comparison that follows it reads.
func nftRule(exprs []expr.Any) string {
	render := nftRender{}
	for _, e := range exprs {
		render.add(e)
	}
	return strings.Join(render.tokens, " ")
}

type nftRender struct {
	tokens  []string
	subject string
	value   func([]byte) string
	port    uint16
}

func (r *nftRender) add(e expr.Any) {
	switch typed := e.(type) {
	case *expr.Meta:
		r.expect(metaNames[typed.Key], metaValue(typed.Key))
	case *expr.Payload:
		r.expect(payloadSubject(typed))
	case *expr.Ct:
		r.expect("ct state", hexValue)
	case *expr.Bitwise:
		r.value = func([]byte) string { return ctStateNames[binary.NativeEndian.Uint32(typed.Mask)] }
	case *expr.Fib:
		r.expect("fib daddr type", func(raw []byte) string { return addressTypes[binary.NativeEndian.Uint32(raw)] })
	case *expr.Cmp:
		r.tokens = append(r.tokens, r.subject, r.value(typed.Data))
	case *expr.Immediate:
		r.port = binary.BigEndian.Uint16(typed.Data)
	case *expr.Redir:
		r.tokens = append(r.tokens, fmt.Sprintf("redirect to :%d", r.port))
	case *expr.Verdict:
		r.tokens = append(r.tokens, verdictNames[typed.Kind])
	default:
		r.tokens = append(r.tokens, fmt.Sprintf("%T", e))
	}
}

func (r *nftRender) expect(subject string, value func([]byte) string) {
	r.subject, r.value = subject, value
}

func metaValue(key expr.MetaKey) func([]byte) string {
	switch key {
	case expr.MetaKeySKUID:
		return func(raw []byte) string { return fmt.Sprint(binary.NativeEndian.Uint32(raw)) }
	case expr.MetaKeyIIFNAME:
		return func(raw []byte) string { return fmt.Sprintf("%q", strings.TrimRight(string(raw), "\x00")) }
	case expr.MetaKeyL4PROTO:
		return func(raw []byte) string { return protocolNames[raw[0]] }
	default:
		return func(raw []byte) string { return familyNames[raw[0]] }
	}
}

func payloadSubject(payload *expr.Payload) (string, func([]byte) string) {
	if payload.Base == expr.PayloadBaseNetworkHeader {
		if payload.Len == 4 {
			return "ip daddr", addressValue
		}
		return "ip6 daddr", addressValue
	}
	if payload.Offset == 0 {
		return "icmpv6 type", func(raw []byte) string { return fmt.Sprint(raw[0]) }
	}
	return "th dport", func(raw []byte) string { return fmt.Sprint(binary.BigEndian.Uint16(raw)) }
}

func addressValue(raw []byte) string {
	address, _ := netip.AddrFromSlice(raw)
	return address.String()
}

func hexValue(raw []byte) string { return fmt.Sprintf("%x", raw) }
