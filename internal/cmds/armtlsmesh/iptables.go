//go:build linux

package armtlsmesh

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
)

// chainName is the dedicated iptables chain for locally generated traffic.
// preroutingChainName handles forwarded pod traffic entering the host network
// namespace from pod veth interfaces. Keeping them separate avoids using the
// owner match in PREROUTING, where packets do not have a local socket owner.
const chainName = "ARMTLS-MESH"
const preroutingChainName = "ARMTLS-MESH-PREROUTING"

// cwChainName is the filter-table chain that fails closed on inbound traffic
// to confidential-workload pods (see buildCWGuardRules).
const cwChainName = "ARMTLS-MESH-CW"

// cwEgressChainName is the filter-table chain that fails closed on egress:
// non-TCP from a cw pod is dropped unless it is a directed DNS query, an
// ICMPv6 essential, or an established TCP reply (see buildCWEgressGuardRules).
// TCP egress to pod IPs is redirected in PREROUTING before FORWARD; TCP to
// non-pod destinations is out of scope here.
const cwEgressChainName = "ARMTLS-MESH-CW-EGRESS"

const (
	podIPSetName4      = "ARMTLS-MESH-PODS"
	podIPSetName6      = "ARMTLS-MESH-PODS6"
	localPodIPSetName4 = "ARMTLS-MESH-LOCAL-PODS"
	localPodIPSetName6 = "ARMTLS-MESH-LOCAL-PODS6"
	cwPodIPSetName4    = "ARMTLS-MESH-CW-PODS"
	cwPodIPSetName6    = "ARMTLS-MESH-CW-PODS6"
)

// ipSetTmpSuffix names the transient set used for the atomic swap-restore.
const ipSetTmpSuffix = "-TMP"

// managedIPSetNames is the single source of truth for the ipsets this process
// owns. reconcileLiveSetMaxElem and runIptablesCleanup derive their name lists
// (and the -TMP swap variants) from it, so adding a set is one edit here.
// These names (and the chain/jump names below) are a fixed contract with the
// uninstall host sweep (internal/helmchart/c8s/files/scripts/host-sweep.sh),
// pinned there by TestHostSweepScriptMeshNetfilterNames.
var managedIPSetNames = []string{
	podIPSetName4, podIPSetName6,
	localPodIPSetName4, localPodIPSetName6,
	cwPodIPSetName4, cwPodIPSetName6,
}

// essentialICMPv6Types are the ICMPv6 types IPv6 needs to operate (RFC 4890):
// 1-4 error/PMTU reporting, 128/129 echo, 130-132 Multicast Listener, 133-137
// NDP (RS/RA/NS/NA) and redirect. The fail-closed egress guards RETURN these
// and drop every other non-TCP from a cw pod.
var essentialICMPv6Types = []int{1, 2, 3, 4, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137}

// defaultProxyUID is the UID under which the armtls-mesh sidecar proxy runs.
// Traffic from this UID is excluded from iptables redirect to avoid loops.
// This follows the Istio/Envoy convention of UID 1337.
const defaultProxyUID = 1337

const defaultIPSetMaxElem = 262144

type iptablesRule struct {
	table  string
	chain  string
	label  string
	family iptablesFamily
	args   []string
}

type iptablesFamily string

const (
	iptablesFamilyAll  iptablesFamily = ""
	iptablesFamilyIPv4 iptablesFamily = "ipv4"
	iptablesFamilyIPv6 iptablesFamily = "ipv6"
)

// buildPodIPSetRules computes NAT rules that send pod TCP traffic through the
// mesh. OUTPUT REDIRECT covers host-originated packets to pod IPs and uses
// owner matching to skip the proxy's own UID. PREROUTING covers pod-veth
// traffic and DNATs to this node's outbound listener at nodeIPsByFamily[f]
// for each family with a same-family node IP. Some CNIs (notably Azure CNI
// on AKS) count a PREROUTING REDIRECT rule but never complete the redirected
// pod TCP connect; DNAT to the node-local listener follows the same path
// pods can reach directly. A family without a same-family node IP gets no
// PREROUTING rule at all — installing a known-broken REDIRECT fallback would
// silently revive the AKS bug for that family on dual-stack nodes where the
// operator only configured one family.
//
// INVARIANT: each value in nodeIPsByFamily is a canonical, validated IP
// literal of the matching family. Callers must verify (parseNodeIPs in
// pod_ipsets_linux.go).
func buildPodIPSetRules(outboundPort, uid int, excludeUIDs []uint32, nodeIPsByFamily map[iptablesFamily]string) []iptablesRule {
	portStr := strconv.Itoa(outboundPort)
	uidStr := strconv.Itoa(uid)
	allPortsRange := "1:65535"

	rules := buildExcludeUIDRules(chainName, excludeUIDs)

	for _, spec := range []struct {
		family       iptablesFamily
		dstSetName   string
		localSetName string
	}{
		{iptablesFamilyIPv4, podIPSetName4, localPodIPSetName4},
		{iptablesFamilyIPv6, podIPSetName6, localPodIPSetName6},
	} {
		rules = append(rules, makeRedirectRule(redirectRuleSpec{
			chain:              chainName,
			family:             spec.family,
			labelPrefix:        "output-pod-ipset",
			matchArgs:          []string{"-m", "set", "--match-set", spec.dstSetName, "dst"},
			withOwnerExclusion: true,
			uidStr:             uidStr,
			portStr:            portStr,
			dportRange:         allPortsRange,
		}))
		nodeIP, hasFamily := nodeIPsByFamily[spec.family]
		if !hasFamily {
			continue
		}
		// Defense in depth: parseNodeIPs rejects empty strings, but an empty
		// value here would produce `--to-destination :15001` which iptables
		// accepts syntactically and rejects with a generic error not
		// traceable to this caller. makeDNATRule's panic only catches a
		// fully empty toDestination, not the `:port` form.
		if nodeIP == "" {
			panic(fmt.Sprintf("armtlsmesh: buildPodIPSetRules got empty nodeIP for family %s", spec.family))
		}
		rules = append(rules, makeDNATRule(dnatRuleSpec{
			chain:       preroutingChainName,
			family:      spec.family,
			labelPrefix: "prerouting-pod-ipset",
			matchArgs: []string{
				"-m", "set", "--match-set", spec.localSetName, "src",
				"-m", "set", "--match-set", spec.dstSetName, "dst",
			},
			toDestination: net.JoinHostPort(nodeIP, portStr),
			dportRange:    allPortsRange,
		}))
	}
	return rules
}

// buildExcludeUIDRules emits RETURN rules so system UIDs (e.g. root/0) skip
// the redirect, letting kubelet, containerd, and other host daemons reach
// container registries without going through the mesh.
func buildExcludeUIDRules(chain string, excludeUIDs []uint32) []iptablesRule {
	var rules []iptablesRule
	for _, euid := range excludeUIDs {
		rules = append(rules, iptablesRule{
			table: "nat",
			chain: chain,
			label: fmt.Sprintf("exclude-uid-%d", euid),
			args: []string{
				"-p", "tcp",
				"-m", "owner", "--uid-owner", strconv.FormatUint(uint64(euid), 10),
				"-j", "RETURN",
			},
		})
	}
	return rules
}

type redirectRuleSpec struct {
	chain              string
	family             iptablesFamily
	labelPrefix        string
	matchArgs          []string
	withOwnerExclusion bool
	uidStr             string
	portStr            string
	dportRange         string
}

func makeRedirectRule(spec redirectRuleSpec) iptablesRule {
	label := spec.dportRange
	if spec.labelPrefix != "" {
		label = spec.labelPrefix + "-" + spec.dportRange
	}
	args := []string{"-p", "tcp"}
	args = append(args, spec.matchArgs...)
	if spec.withOwnerExclusion {
		args = append(args, "-m", "owner", "!", "--uid-owner", spec.uidStr)
	}
	args = append(args,
		"--dport", spec.dportRange,
		"-j", "REDIRECT", "--to-port", spec.portStr,
	)
	return iptablesRule{
		table:  "nat",
		chain:  spec.chain,
		label:  label,
		family: spec.family,
		args:   args,
	}
}

type dnatRuleSpec struct {
	chain         string
	family        iptablesFamily
	labelPrefix   string
	matchArgs     []string
	toDestination string
	dportRange    string
}

func makeDNATRule(spec dnatRuleSpec) iptablesRule {
	if spec.toDestination == "" {
		// Fail fast at build time: an empty --to-destination would install
		// successfully on some iptables backends with surprising semantics,
		// and on others surface as a generic "Bad argument" pointing at
		// rule install rather than at the caller bug that produced it.
		panic(fmt.Sprintf("armtlsmesh: makeDNATRule called with empty toDestination (chain=%s family=%s)", spec.chain, spec.family))
	}
	label := spec.dportRange
	if spec.labelPrefix != "" {
		label = spec.labelPrefix + "-" + spec.dportRange
	}
	args := []string{"-p", "tcp"}
	args = append(args, spec.matchArgs...)
	args = append(args,
		"--dport", spec.dportRange,
		"-j", "DNAT", "--to-destination", spec.toDestination,
	)
	return iptablesRule{
		table:  "nat",
		chain:  spec.chain,
		label:  label,
		family: spec.family,
		args:   args,
	}
}

// cwPassthrough is one entry in the cw guard's inbound allowlist: traffic to a
// cw pod from this protocol+source-port is RETURNed before the drop WITHOUT a
// conntrack-state match, which is what admits replies the dataplane failed to
// track as ESTABLISHED (see defaultCWPassthrough).
type cwPassthrough struct {
	protocol   string // "udp" or "tcp"
	sourcePort int
}

// cwPassthroughProtocols maps each protocol the allowlist accepts to its IANA
// number. parseCWPassthrough validates against the names; the guard's counter
// reader matches the iptables protocol column, which renders as either form.
var cwPassthroughProtocols = map[string]string{
	"tcp": "6",
	"udp": "17",
}

// cwPassthroughDportRange is the stock Linux ephemeral port window: where a
// reply lands when the pod has not moved net.ipv4.ip_local_port_range.
const cwPassthroughDportRange = "32768:60999"

// cwTCPReplyFlags are the TCP segment shapes an exemption admits: the handshake
// reply, and every segment with SYN clear.
var cwTCPReplyFlags = []struct {
	suffix string
	args   []string
}{
	{"synack", []string{"--tcp-flags", "SYN,RST,ACK,FIN", "SYN,ACK"}},
	{"nonsyn", []string{"--tcp-flags", "SYN", "NONE"}},
}

// defaultCWPassthrough is the built-in allowlist: DNS replies (udp+tcp 53).
// DNS is not mesh-redirected (the redirect is TCP-to-pod-IP only, and UDP/53
// goes to the kube-dns Service VIP), so the CoreDNS reply returns to the cw
// pod via FORWARD; on dataplanes that do not track it as ESTABLISHED there
// (e.g. GKE Dataplane V2 / Cilium) the drop eats every DNS reply and get-cert
// can never resolve. Every cluster needs DNS, so this is the default rather
// than a knob a caller has to remember to set.
var defaultCWPassthrough = []cwPassthrough{
	{protocol: "udp", sourcePort: 53},
	{protocol: "tcp", sourcePort: 53},
}

// formatCWPassthrough renders entries as the --cw-inbound-passthrough flag
// value (proto:port,proto:port). Inverse of parseCWPassthrough; used so the
// flag default is derived from defaultCWPassthrough rather than restating it.
func formatCWPassthrough(entries []cwPassthrough) string {
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = fmt.Sprintf("%s:%d", e.protocol, e.sourcePort)
	}
	return strings.Join(parts, ",")
}

// parseCWPassthrough parses the --cw-inbound-passthrough flag: a comma list of
// `proto:port` entries (e.g. "udp:53,tcp:53"). An empty string is the strict
// posture (no exemptions). protocol must be udp or tcp; port must be 1-65535.
func parseCWPassthrough(raw string) ([]cwPassthrough, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []cwPassthrough
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		proto, portStr, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("invalid cw-inbound-passthrough entry %q: want proto:port", part)
		}
		proto = strings.TrimSpace(proto)
		if _, ok := cwPassthroughProtocols[proto]; !ok {
			want := strings.Join(slices.Sorted(maps.Keys(cwPassthroughProtocols)), " or ")
			return nil, fmt.Errorf("invalid cw-inbound-passthrough protocol %q: want %s", proto, want)
		}
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid cw-inbound-passthrough port %q: want 1-65535", portStr)
		}
		out = append(out, cwPassthrough{protocol: proto, sourcePort: port})
	}
	return out, nil
}

// buildCWGuardRules computes the filter-table rules that fail closed on
// inbound traffic to confidential-workload pods: any connection that reaches
// a cw pod IP via the FORWARD hook is by definition not mesh-delivered, so
// it is dropped instead of arriving as plaintext (Service-VIP DNAT,
// excluded-source-namespace dials, cross-node direct-to-pod-IP).
//
// INVARIANT: every legitimate delivery path avoids FORWARD. Mesh delivery is
// a host-originated OUTPUT dial from the proxy UID; kubelet probes and other
// host daemons are OUTPUT; meshed pod-to-pod egress is DNAT'd to the node's
// outbound listener (INPUT) in PREROUTING before FORWARD; replies to
// cw-pod-originated egress match the conntrack RETURN below.
//
// The conntrack rule uses RETURN, not ACCEPT, so CNI or NetworkPolicy rules
// later in FORWARD still run. The final drop has no -p match: the mesh carries
// only TCP, so non-TCP inbound to a cw pod is unmeshed by definition.
//
// passthrough entries are RETURNed before the drop for dataplanes that break a
// reply's conntrack tuple (see defaultCWPassthrough), bounded to
// cwPassthroughDportRange and, for TCP, to cwTCPReplyFlags. An empty
// passthrough is the strict fail-closed posture (conntrack RETURN + drop-all).
func buildCWGuardRules(passthrough []cwPassthrough) []iptablesRule {
	var rules []iptablesRule
	for _, spec := range []struct {
		family  iptablesFamily
		setName string
	}{
		{iptablesFamilyIPv4, cwPodIPSetName4},
		{iptablesFamilyIPv6, cwPodIPSetName6},
	} {
		rules = append(rules, iptablesRule{
			table:  "filter",
			chain:  cwChainName,
			label:  "cw-established-return",
			family: spec.family,
			args: []string{
				"-m", "set", "--match-set", spec.setName, "dst",
				"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
				"-j", "RETURN",
			},
		})
		for _, pt := range passthrough {
			match := []string{
				"-p", pt.protocol,
				"--sport", strconv.Itoa(pt.sourcePort),
				"--dport", cwPassthroughDportRange,
			}
			target := []string{"-m", "set", "--match-set", spec.setName, "dst", "-j", "RETURN"}
			label := fmt.Sprintf("cw-passthrough-%s-%d", pt.protocol, pt.sourcePort)
			if pt.protocol != "tcp" {
				rules = append(rules, iptablesRule{
					table:  "filter",
					chain:  cwChainName,
					label:  label,
					family: spec.family,
					args:   slices.Concat(match, target),
				})
				continue
			}
			for _, flags := range cwTCPReplyFlags {
				rules = append(rules, iptablesRule{
					table:  "filter",
					chain:  cwChainName,
					label:  label + "-" + flags.suffix,
					family: spec.family,
					args:   slices.Concat(match, flags.args, target),
				})
			}
		}
		rules = append(rules, iptablesRule{
			table:  "filter",
			chain:  cwChainName,
			label:  "cw-inbound-drop",
			family: spec.family,
			args: []string{
				"-m", "set", "--match-set", spec.setName, "dst",
				"-j", "DROP",
			},
		})
	}
	return rules
}

// buildCWEgressGuardRules computes the filter-table rules that fail closed
// on egress from confidential-workload pods: the mesh redirects TCP only, so
// these rules drop every non-TCP from a cw pod, exempting established TCP
// replies, UDP/53 queries, and the ICMPv6 types IPv6 needs. TCP egress never
// reaches this chain: pod-destination TCP is intercepted in PREROUTING and
// non-pod TCP is out of scope here.
//
// The UDP/53 carve-out names no destination. A resolver is outside the guest's
// trust boundary whatever its address, so an answer is untrusted input that
// authenticated peers do not rely on; see docs/armtls.md, "DNS".
func buildCWEgressGuardRules() []iptablesRule {
	var rules []iptablesRule
	for _, spec := range []struct {
		family  iptablesFamily
		setName string
	}{
		{iptablesFamilyIPv4, cwPodIPSetName4},
		{iptablesFamilyIPv6, cwPodIPSetName6},
	} {
		rules = append(rules, iptablesRule{
			table:  "filter",
			chain:  cwEgressChainName,
			label:  "cw-egress-established-return",
			family: spec.family,
			args: []string{
				"-m", "set", "--match-set", spec.setName, "src",
				"-p", "tcp",
				"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
				"-j", "RETURN",
			},
		})
		rules = append(rules, iptablesRule{
			table:  "filter",
			chain:  cwEgressChainName,
			label:  "cw-egress-dns-query",
			family: spec.family,
			args: []string{
				"-m", "set", "--match-set", spec.setName, "src",
				"-p", "udp", "--dport", "53",
				"-j", "RETURN",
			},
		})
		if spec.family == iptablesFamilyIPv6 {
			for _, t := range essentialICMPv6Types {
				rules = append(rules, iptablesRule{
					table:  "filter",
					chain:  cwEgressChainName,
					label:  "cw-egress-icmpv6-allow",
					family: iptablesFamilyIPv6,
					args: []string{
						"-m", "set", "--match-set", spec.setName, "src",
						"-p", "ipv6-icmp", "--icmpv6-type", strconv.Itoa(t),
						"-j", "RETURN",
					},
				})
			}
		}
		rules = append(rules, iptablesRule{
			table:  "filter",
			chain:  cwEgressChainName,
			label:  "cw-egress-nontcp-drop",
			family: spec.family,
			args: []string{
				"-m", "set", "--match-set", spec.setName, "src",
				"!", "-p", "tcp",
				"-j", "DROP",
			},
		})
	}
	return rules
}

// cwJumpRule returns the filter FORWARD jump into the cw guard chain. It rides
// at the head of FORWARD alongside cwEgressJumpRule: KUBE-FORWARD's mark-based
// ACCEPT would otherwise admit DNAT'd Service traffic before the drop runs.
// Args must stay exactly {"-j", cwChainName} — see the parseJumpBlockAtHead
// literal-compare note.
func cwJumpRule() iptablesRule {
	return iptablesRule{
		table: "filter",
		chain: "FORWARD",
		label: "jump-forward-to-" + cwChainName,
		args:  []string{"-j", cwChainName},
	}
}

// cwEgressJumpRule returns the filter FORWARD jump into the cw egress guard
// chain. Args must stay exactly {"-j", cwEgressChainName} — see the
// parseJumpBlockAtHead literal-compare note.
func cwEgressJumpRule() iptablesRule {
	return iptablesRule{
		table: "filter",
		chain: "FORWARD",
		label: "jump-forward-to-" + cwEgressChainName,
		args:  []string{"-j", cwEgressChainName},
	}
}

// jumpRules returns the base-chain jumps into armtls-mesh managed chains.
func jumpRules() []iptablesRule {
	return []iptablesRule{
		{
			table: "nat",
			chain: "OUTPUT",
			label: "jump-output-to-" + chainName,
			args:  []string{"-j", chainName},
		},
		{
			table: "nat",
			chain: "PREROUTING",
			label: "jump-prerouting-to-" + preroutingChainName,
			args:  []string{"-j", preroutingChainName},
		},
	}
}
