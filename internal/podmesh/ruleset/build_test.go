//go:build linux

package ruleset

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var update = flag.Bool("update", false, "regenerate testdata/ruleset.golden")

// testPolicy exercises every kind of permission a node's trusted policy can
// name: the resolver, a credential role with one destination, and that
// destination as an exit of the whole pod.
func testPolicy() Policy {
	return Policy{
		Resolver: netip.MustParseAddr("10.53.0.10"),
		Capture: CapturePorts{
			Outbound: 15001,
			Inbound:  15006,
			Health:   15021,
		},
		MeshUID: 1337,
		Roles: []Role{{
			UID:          1338,
			Destinations: []Destination{{netip.MustParseAddr("10.43.0.2"), 8443}},
		}},
		Exits: []Exit{{netip.MustParsePrefix("10.43.0.2/32"), 8443}},
	}
}

// serverPolicy is the same policy for a pod that serves a platform role's own
// ports: the router answers external listeners, its upstream identity reaches
// its node's CDS and the cluster itself, and a third identity of that pod
// reaches the egress port outside the cluster.
func serverPolicy() Policy {
	policy := testPolicy()
	policy.Server = ServerRole{
		Listeners: []uint16{8443, 8080},
		Egress: ServerEgress{
			UID:   1340,
			Ports: []uint16{443},
		},
		Upstream: 1341,
		Services: []Destination{{netip.MustParseAddr("10.43.0.2"), 8443}},
		ClusterRanges: []netip.Prefix{
			netip.MustParsePrefix("10.52.0.0/16"),
			netip.MustParsePrefix("10.53.0.0/16"),
		},
	}
	return policy
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

// A pod granted exits carries one accept per exit, before the capture, in
// both chains; a range is compared under its mask.
func TestBuildWithGrantedExitsMatchesTheGoldenRuleset(t *testing.T) {
	const golden = "testdata/ruleset-exits.golden"
	policy := testPolicy()
	policy.Exits = append(policy.Exits,
		Exit{netip.MustParsePrefix("203.0.113.0/24"), 443},
		Exit{netip.MustParsePrefix("2001:db8::/32"), 4317},
	)
	got := renderRuleset(build(policy))
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

// The mesh listeners belong to the mesh endpoint: a process that takes one
// over once the endpoint is gone must not be able to answer on it, so the
// ruleset drops what leaves a listener port from another socket owner before
// the reply rules can carry a handshake.
func TestFilterOutputReservesTheMeshListeners(t *testing.T) {
	policy := testPolicy()
	rules := filterOutput(policy).rules
	rendered := make([]string, 0, len(rules))
	for _, r := range rules {
		rendered = append(rendered, nftRule(r.exprs))
	}
	replies := slices.Index(rendered, "ct state established accept")
	if replies < 0 {
		t.Fatalf("filter-output admits no replies:\n%s", strings.Join(rendered, "\n"))
	}
	for _, port := range []uint16{policy.Capture.Inbound, policy.Capture.Health} {
		taken := fmt.Sprintf("meta l4proto tcp th sport %d drop", port)
		at := slices.Index(rendered, taken)
		if at < 0 {
			t.Errorf("filter-output has no %q rule:\n%s", taken, strings.Join(rendered, "\n"))
			continue
		}
		if at > replies {
			t.Errorf("%q is rule %d, after the replies rule %d", taken, at, replies)
		}
		mesh := fmt.Sprintf("skuid %d meta l4proto tcp th sport %d accept", policy.MeshUID, port)
		served := slices.Index(rendered, mesh)
		if served < 0 || served > at {
			t.Errorf("the mesh endpoint may not answer on port %d before rule %d", port, at)
		}
	}
}

// A pod serving a role's own ports carries the member ruleset and exactly the
// rules of that role: its listeners, the capture of the egress port inside the
// cluster, that port outside it for the egress identity alone, and the
// cluster itself for the upstream identity alone. The identity that answers and
// forwards holds no rule of either kind, so its traffic rides the mesh
// wherever a name resolves.
func TestServerRoleAddsOnlyItsOwnRules(t *testing.T) {
	added := addedRules(renderRuleset(build(testPolicy())), renderRuleset(build(serverPolicy())))
	want := []string{
		"meta l4proto tcp th dport 8443 return # server-listener-8443",
		"meta l4proto tcp th dport 8080 return # server-listener-8080",
		"skuid 1341 meta nfproto ipv4 ip daddr 10.43.0.2 meta l4proto tcp th dport 8443 return # server-service-10.43.0.2-8443",
		"skuid 1341 meta nfproto ipv4 ip daddr 10.52.0.0 & 255.255.0.0 meta l4proto tcp return # server-upstream-in-cluster-10.52.0.0/16",
		"skuid 1341 meta nfproto ipv4 ip daddr 10.53.0.0 & 255.255.0.0 meta l4proto tcp return # server-upstream-in-cluster-10.53.0.0/16",
		"skuid 1340 meta nfproto ipv4 ip daddr 10.52.0.0 & 255.255.0.0 meta l4proto tcp th dport 443 redirect to :15001 # server-egress-443-in-cluster-10.52.0.0/16",
		"skuid 1340 meta nfproto ipv4 ip daddr 10.53.0.0 & 255.255.0.0 meta l4proto tcp th dport 443 redirect to :15001 # server-egress-443-in-cluster-10.53.0.0/16",
		"skuid 1340 meta l4proto tcp th dport 443 return # server-egress-443",
		"meta l4proto tcp th dport 8443 accept # server-listener-8443",
		"meta l4proto tcp th dport 8080 accept # server-listener-8080",
		"skuid 1341 meta nfproto ipv4 ip daddr 10.43.0.2 meta l4proto tcp th dport 8443 accept # server-service-10.43.0.2-8443",
		"skuid 1341 meta nfproto ipv4 ip daddr 10.52.0.0 & 255.255.0.0 meta l4proto tcp accept # server-upstream-in-cluster-10.52.0.0/16",
		"skuid 1341 meta nfproto ipv4 ip daddr 10.53.0.0 & 255.255.0.0 meta l4proto tcp accept # server-upstream-in-cluster-10.53.0.0/16",
		"skuid 1340 meta nfproto ipv4 ip daddr 10.52.0.0 & 255.255.0.0 meta l4proto tcp th dport 443 drop # server-egress-443-in-cluster-10.52.0.0/16",
		"skuid 1340 meta nfproto ipv4 ip daddr 10.53.0.0 & 255.255.0.0 meta l4proto tcp th dport 443 drop # server-egress-443-in-cluster-10.53.0.0/16",
		"skuid 1340 meta l4proto tcp th dport 443 accept # server-egress-443",
	}
	if !slices.Equal(added, want) {
		t.Fatalf("the server role adds\n%s\nwant\n%s", strings.Join(added, "\n"), strings.Join(want, "\n"))
	}
	// No other identity in the pod holds them: every added rule naming a uid
	// names the routing or the egress identity, and the listener rules name
	// none, because an inbound accept cannot match a socket uid.
	for _, rule := range added {
		if strings.Contains(rule, "skuid") && !strings.Contains(rule, "skuid 1340") && !strings.Contains(rule, "skuid 1341") {
			t.Errorf("a rule of the server role binds another identity: %s", rule)
		}
	}
}

// The upstream identity fetches the signed route manifest from its own node's
// CDS, so that one destination is returned before the capture and accepted on
// the way out, and it reaches the cluster's members itself. Everything else
// it dials is captured: no other rule of either chain names its identity.
func TestServerRoutingIdentityReachesItsServiceAndTheCluster(t *testing.T) {
	policy := serverPolicy()
	service := policy.Server.Services[0]
	match := fmt.Sprintf("skuid %d meta nfproto ipv4 ip daddr %s meta l4proto tcp th dport %d",
		policy.Server.Upstream, service.Addr, service.Port)
	var inCluster []string
	for _, in := range policy.Server.ClusterRanges {
		inCluster = append(inCluster, fmt.Sprintf("skuid %d meta nfproto ipv4 ip daddr %s & 255.255.0.0 meta l4proto tcp",
			policy.Server.Upstream, in.Addr()))
	}

	capture := renderedRules(captureOutbound(policy).rules)
	uncaptured := slices.Index(capture, match+" return")
	redirect := slices.Index(capture, fmt.Sprintf("meta l4proto tcp redirect to :%d", policy.Capture.Outbound))
	if uncaptured < 0 || redirect < 0 || uncaptured > redirect {
		t.Fatalf("the service is not returned before the capture:\n%s", strings.Join(capture, "\n"))
	}
	output := renderedRules(filterOutput(policy).rules)
	if !slices.Contains(output, match+" accept") {
		t.Fatalf("the service never leaves the pod:\n%s", strings.Join(output, "\n"))
	}
	for _, member := range inCluster {
		at := slices.Index(capture, member+" return")
		if at < 0 || at > redirect {
			t.Fatalf("%q is not returned before the capture:\n%s", member, strings.Join(capture, "\n"))
		}
		if !slices.Contains(output, member+" accept") {
			t.Fatalf("%q never leaves the pod:\n%s", member, strings.Join(output, "\n"))
		}
	}
	for _, rule := range slices.Concat(capture, output) {
		if !strings.HasPrefix(rule, fmt.Sprintf("skuid %d ", policy.Server.Upstream)) {
			continue
		}
		reaches := slices.ContainsFunc(append(inCluster, match), func(allowed string) bool {
			return strings.HasPrefix(rule, allowed)
		})
		if !reaches {
			t.Errorf("the upstream identity reaches more than its service and the cluster: %s", rule)
		}
	}
}

// A server role with no upstream identity would match root on the rules that
// leave the cluster to it, so no ruleset is built from one.
func TestServerRoleWithoutARoutingIdentityIsRefused(t *testing.T) {
	policy := serverPolicy()
	policy.Server.Upstream = 0
	if err := policy.validate(); !errors.Is(err, ErrPolicy) {
		t.Fatalf("error = %v, want ErrPolicy", err)
	}
}

// renderedRules are the rules of one chain as nft prints them.
func renderedRules(rules []rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, nftRule(r.exprs))
	}
	return out
}

// addedRules are the rules the second ruleset carries and the first does not,
// in the order they are installed.
func addedRules(member, server string) []string {
	had := map[string]bool{}
	for _, line := range strings.Split(member, "\n") {
		had[strings.TrimSpace(line)] = true
	}
	var added []string
	for _, line := range strings.Split(server, "\n") {
		if trimmed := strings.TrimSpace(line); !had[trimmed] {
			added = append(added, trimmed)
		}
	}
	return added
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

// masked records the mask the comparison that follows applies: over conntrack
// it selects the state bit, over an address it is the prefix nft prints beside
// it.
func (r *nftRender) masked(mask []byte) {
	if r.subject == "ct state" {
		r.value = func([]byte) string { return ctStateNames[binary.NativeEndian.Uint32(mask)] }
		return
	}
	address := r.value
	r.value = func(raw []byte) string { return address(raw) + " & " + net.IP(mask).String() }
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
		r.masked(typed.Mask)
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
	r.subject = subject
	r.value = value
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
		if payload.Len == 1 {
			return "icmpv6 type", func(raw []byte) string { return fmt.Sprint(raw[0]) }
		}
		return "th sport", portValue
	}
	return "th dport", portValue
}

func portValue(raw []byte) string {
	return fmt.Sprint(binary.BigEndian.Uint16(raw))
}

func addressValue(raw []byte) string {
	address, _ := netip.AddrFromSlice(raw)
	return address.String()
}

func hexValue(raw []byte) string {
	return fmt.Sprintf("%x", raw)
}
