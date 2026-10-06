//go:build linux

package armtlsmesh

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/coreos/go-iptables/iptables"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func parseExcludeUIDs(excludeUIDsStr string) ([]uint32, error) {
	var excludeUIDs []uint32
	for s := range strings.SplitSeq(excludeUIDsStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude-uid %q: %w", s, err)
		}
		excludeUIDs = append(excludeUIDs, uint32(v))
	}
	return excludeUIDs, nil
}

type managedChain struct {
	table string
	chain string
}

var managedChains = []managedChain{
	{"nat", chainName},
	{"nat", preroutingChainName},
	{"filter", cwChainName},
	{"filter", cwEgressChainName},
}

// iptablesV4 and iptablesV6 are the per-protocol netfilter clients used for
// every nat- and filter-table mutation. Set once at the top of
// runIptablesSync / runIptablesCleanup and treated as immutable thereafter.
var (
	iptablesV4 *iptables.IPTables
	iptablesV6 *iptables.IPTables
)

func initIptablesClients() error {
	v4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("init iptables (ipv4): %w", err)
	}
	v6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return fmt.Errorf("init iptables (ipv6): %w", err)
	}
	iptablesV4, iptablesV6 = v4, v6
	return nil
}

func iptablesClients() []*iptables.IPTables {
	return []*iptables.IPTables{iptablesV4, iptablesV6}
}

func familyForIPT(ipt *iptables.IPTables) iptablesFamily {
	if ipt.Proto() == iptables.ProtocolIPv6 {
		return iptablesFamilyIPv6
	}
	return iptablesFamilyIPv4
}

func iptablesLabel(ipt *iptables.IPTables) string {
	if ipt.Proto() == iptables.ProtocolIPv6 {
		return "ip6tables"
	}
	return "iptables"
}

func installIptablesRules(logger *slog.Logger, rules []iptablesRule, jumps []iptablesRule) error {
	// Flush handles the crash-without-preStop restart where stale rules
	// linger and Append would duplicate. Redundant when reconcileLiveSetMaxElem
	// just ran, but cheap.
	if err := flushManagedIptablesChains(logger); err != nil {
		return err
	}
	for _, ipt := range iptablesClients() {
		family := familyForIPT(ipt)
		for _, r := range rules {
			if r.family != iptablesFamilyAll && r.family != family {
				continue
			}
			if err := ipt.Append(r.table, r.chain, r.args...); err != nil {
				return fmt.Errorf("install %s rule on %s: %w", r.label, iptablesLabel(ipt), err)
			}
			logger.Info("rule installed", "bin", iptablesLabel(ipt), "chain", r.chain, "dport", r.label)
		}

		if err := ensureIptablesJumpsForBinary(logger, ipt, jumps); err != nil {
			return err
		}
	}
	return nil
}

// flushManagedIptablesChains creates (idempotent) and flushes our managed
// chains. Exported so the ipset reconciler can call it before destroying live
// sets that may still be referenced by stale rules from a previous process
// that exited abruptly.
func flushManagedIptablesChains(logger *slog.Logger) error {
	for _, ipt := range iptablesClients() {
		bin := iptablesLabel(ipt)
		for _, mc := range managedChains {
			if err := ipt.NewChain(mc.table, mc.chain); err != nil {
				logger.Debug("chain already exists (expected on restart)", "bin", bin, "chain", mc.chain)
			} else {
				logger.Info("chain created", "bin", bin, "chain", mc.chain)
			}
			if err := ipt.ClearChain(mc.table, mc.chain); err != nil {
				return fmt.Errorf("flush chain %s on %s: %w", mc.chain, bin, err)
			}
			logger.Info("chain flushed", "bin", bin, "chain", mc.chain)
		}
	}
	return nil
}

func ensureIptablesJumps(logger *slog.Logger, jumps []iptablesRule) error {
	for _, ipt := range iptablesClients() {
		if err := ensureIptablesJumpsForBinary(logger, ipt, jumps); err != nil {
			return err
		}
	}
	return nil
}

// jumpBlock is the ordered run of mesh jumps that must occupy the head of one
// base chain, ahead of kube-proxy's service DNAT and of KUBE-FORWARD's
// mark-based ACCEPT. filter FORWARD carries two of them, so head position is a
// property of the block rather than of a single rule.
type jumpBlock struct {
	table string
	chain string
	jumps []iptablesRule
}

// jumpBlocksFor groups jumps by base chain for one family, preserving
// declaration order: that order is the head order the watchdog asserts.
func jumpBlocksFor(jumps []iptablesRule, family iptablesFamily) []jumpBlock {
	var blocks []jumpBlock
	index := map[[2]string]int{}
	for _, jump := range jumps {
		if jump.family != iptablesFamilyAll && jump.family != family {
			continue
		}
		key := [2]string{jump.table, jump.chain}
		i, ok := index[key]
		if !ok {
			i = len(blocks)
			index[key] = i
			blocks = append(blocks, jumpBlock{table: jump.table, chain: jump.chain})
		}
		blocks[i].jumps = append(blocks[i].jumps, jump)
	}
	return blocks
}

// ensureIptablesJumpsForBinary keeps each base chain's jump block at the head
// of that chain. A block already in place is a cheap no-op; otherwise every
// jump in it is reinserted. Two separate counters distinguish:
//   - jumpPositionViolations: confirmed-misplaced jumps (real kube-proxy race)
//   - jumpPositionCheckErrors: transient List failures where the watchdog
//     still reinserts defensively but the position couldn't be read
//
// Keeping the violation counter clean makes
// rate(armtls_mesh_iptables_jump_position_violations_total) a usable alert
// signal for kube-proxy contention without the noise of shell-call blips.
func ensureIptablesJumpsForBinary(logger *slog.Logger, ipt *iptables.IPTables, jumps []iptablesRule) error {
	bin := iptablesLabel(ipt)
	for _, block := range jumpBlocksFor(jumps, familyForIPT(ipt)) {
		atHead, misplaced, err := isJumpBlockAtHead(ipt, block)
		if err != nil {
			logger.Debug("position check failed; will reinstall defensively", "bin", bin, "chain", block.chain, "error", err)
			jumpPositionCheckErrors.Add(1)
			publishIptablesMetrics(logger)
		}
		if atHead {
			continue
		}
		// Reverse order: each insert lands at position 1, so the block's
		// first jump is the last one inserted.
		for _, jump := range slices.Backward(block.jumps) {

			deleteAllIptablesRules(logger, ipt, jump)
			if addErr := ipt.Insert(jump.table, jump.chain, 1, jump.args...); addErr != nil {
				return fmt.Errorf("install %s jump rule on %s: %w", jump.label, bin, addErr)
			}
		}
		// Only count jumps we know were demoted; a position-check error or an
		// absent jump during clean startup would inflate the count and drown
		// the kube-proxy-race signal in noise.
		if err == nil && misplaced > 0 {
			jumpPositionViolations.Add(int64(misplaced))
			publishIptablesMetrics(logger)
		}
		logger.Warn("jump block restored at chain head", "bin", bin, "chain", block.chain, "misplaced_before_restore", misplaced, "check_error", err)
	}
	return nil
}

// isJumpBlockAtHead reports whether the block's jumps are the first appended
// rules of its base chain, in the block's order, and how many of them were
// present elsewhere in the chain. The literal compare against
// strings.Join(jump.args, " ") only round-trips while jump.args stays at {"-j",
// chainName}; adding matchers (`-m comment`, conntrack, etc.) would let the
// kernel renormalize tokens and make the compare always false, causing the
// watchdog to reinsert every tick.
func isJumpBlockAtHead(ipt *iptables.IPTables, block jumpBlock) (atHead bool, misplaced int, err error) {
	lines, err := ipt.List(block.table, block.chain)
	if err != nil {
		return false, 0, err
	}
	atHead, misplaced = parseJumpBlockAtHead(strings.Join(lines, "\n"), block)
	return atHead, misplaced, nil
}

func parseJumpBlockAtHead(out string, block jumpBlock) (atHead bool, misplaced int) {
	prefix := "-A " + block.chain + " "
	var installed []string
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		installed = append(installed, strings.TrimSpace(strings.TrimPrefix(line, prefix)))
	}
	atHead = true
	for i, jump := range block.jumps {
		want := strings.Join(jump.args, " ")
		if i < len(installed) && installed[i] == want {
			continue
		}
		atHead = false
		if slices.Contains(installed, want) {
			misplaced++
		}
	}
	return atHead, misplaced
}

// jumpPositionViolations counts confirmed kube-proxy races: the watchdog
// observed our jump demoted out of position 1 and reinserted it. Exposed as
// armtls_mesh_iptables_jump_position_violations_total.
var jumpPositionViolations atomic.Int64

// jumpPositionCheckErrors counts ticks where the position check itself failed
// (e.g. iptables.List returned an error). The watchdog still reinserts
// defensively, but the cause is environmental, not a real race. Exposed as
// armtls_mesh_iptables_jump_position_check_errors_total so operators can
// alert on the two signals independently.
var jumpPositionCheckErrors atomic.Int64

func iptablesJumpPositionViolations() int64 {
	return jumpPositionViolations.Load()
}

func iptablesJumpPositionCheckErrors() int64 {
	return jumpPositionCheckErrors.Load()
}

// cwInboundDrops and cwPassthroughReturns mirror the kernel packet counters of
// the cw guard chain's DROP rules and of its passthrough exemptions, summed
// over families from each family's last successful read. The kernel counters
// restart at zero when the chain is flushed, which is why the proxy exposes
// these as gauges rather than counters.
var (
	cwInboundDrops       atomic.Int64
	cwPassthroughReturns atomic.Int64
)

// cwGuardCounts is one family's contribution to those totals.
type cwGuardCounts struct {
	drops   uint64
	returns uint64
}

// cwGuardLastRead holds the most recent successful read per family, so a read
// failure never steps a published total down. A chain flush does, legitimately:
// both families then read zero.
var cwGuardLastRead = map[iptablesFamily]cwGuardCounts{}

func iptablesCWInboundDrops() int64 {
	return cwInboundDrops.Load()
}

func iptablesCWPassthroughReturns() int64 {
	return cwPassthroughReturns.Load()
}

// cwExemptionProtocolColumn holds every rendering of an exemption row's
// protocol column: go-iptables always lists with -n, under which the nf_tables
// backend prints IANA numbers and the legacy backend prints names.
var cwExemptionProtocolColumn = func() map[string]bool {
	m := make(map[string]bool, 2*len(cwPassthroughProtocols))
	for name, number := range cwPassthroughProtocols {
		m[name] = true
		m[number] = true
	}
	return m
}()

// refreshCWGuardCounters reads the cw guard chain's per-rule packet counters
// and republishes the cross-family totals from cwGuardLastRead.
//
// INVARIANT: the passthrough exemptions are the chain's only protocol-scoped
// rules (buildCWGuardRules), so a RETURN row carrying a protocol is an
// exemption hit and the conntrack RETURN — which has no -p — is not.
func refreshCWGuardCounters() error {
	var errs []error
	for _, ipt := range iptablesClients() {
		stats, err := ipt.StructuredStats("filter", cwChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s stats on %s: %w", cwChainName, iptablesLabel(ipt), err))
			continue
		}
		var counts cwGuardCounts
		for _, s := range stats {
			switch {
			case s.Target == "DROP":
				counts.drops += s.Packets
			case s.Target == "RETURN" && cwExemptionProtocolColumn[s.Protocol]:
				counts.returns += s.Packets
			}
		}
		cwGuardLastRead[familyForIPT(ipt)] = counts
	}
	var drops, returns uint64
	for _, c := range cwGuardLastRead {
		drops += c.drops
		returns += c.returns
	}
	cwInboundDrops.Store(int64(drops))
	cwPassthroughReturns.Store(int64(returns))
	return errors.Join(errs...)
}

func runIptablesCleanup(keepGuard bool) error {
	logger, err := certutil.NewJSONLogger("info")
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	if err := initIptablesClients(); err != nil {
		return err
	}
	// PreStop uses --keep-guard so the fail-closed guard survives a mesh
	// restart/termination while workloads are still running: it removes the
	// nat interception jumps but keeps the filter FORWARD guard jumps. A full
	// teardown (no --keep-guard) removes the nat jumps and both guard jumps
	// (cw inbound + cw egress), so -X of the egress chain is not blocked by a
	// dangling FORWARD jump.
	jumps := append(jumpRules(), cwJumpRule(), cwEgressJumpRule())
	if keepGuard {
		jumps = jumpRules()
	}
	// The cw pod ipsets are the guard's membership. Deleting an ipset while
	// a filter rule still references it fails; keeping these ipsets under
	// --keep-guard is what lets the guard keep functioning.
	guardIPSetNames := []string{cwPodIPSetName4, cwPodIPSetName6}
	chainsToDelete := managedChains
	ipsetNamesToDelete := managedIPSetNames
	if keepGuard {
		chainsToDelete = []managedChain{{"nat", chainName}, {"nat", preroutingChainName}}
		ipsetNamesToDelete = filterOut(
			managedIPSetNames,
			func(n string) bool {
				for _, g := range guardIPSetNames {
					if n == g || n == g+ipSetTmpSuffix {
						return true
					}
				}
				return false
			},
		)
	}

	for _, ipt := range iptablesClients() {
		bin := iptablesLabel(ipt)
		for _, jump := range jumps {
			deleteAllIptablesRules(logger, ipt, jump)
		}

		for _, mc := range chainsToDelete {
			if err := ipt.ClearChain(mc.table, mc.chain); err != nil {
				logger.Warn("flush chain failed (may not exist)", "bin", bin, "chain", mc.chain)
			}
			if err := ipt.DeleteChain(mc.table, mc.chain); err != nil {
				logger.Warn("delete chain failed (may not exist)", "bin", bin, "chain", mc.chain)
			} else {
				logger.Info("chain removed", "bin", bin, "chain", mc.chain)
			}
		}
	}
	cleanupPodIPSetsForNames(logger, ipsetNamesToDelete)
	return nil
}

// filterOut returns a new slice containing only the elements of in for which
// keep returns false. The helper keeps the keep-guard ipset cleanup list
// derived from the single source of truth (managedIPSetNames) without
// duplicating name literals.
func filterOut(in []string, keep func(string) bool) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !keep(s) {
			out = append(out, s)
		}
	}
	return out
}

// deleteAllIptablesRules removes every instance of rule from its chain. The
// loop exits when iptables returns "rule does not exist" (the idempotent
// happy path) or any other error (logged as stop_reason).
func deleteAllIptablesRules(logger *slog.Logger, ipt *iptables.IPTables, rule iptablesRule) {
	bin := iptablesLabel(ipt)
	deleted := 0
	var stopErr error
	for {
		err := ipt.Delete(rule.table, rule.chain, rule.args...)
		if err == nil {
			deleted++
			continue
		}
		// IsNotExist is the expected end of an idempotent delete loop and
		// must not surface as a stop_reason; treat it as a clean break.
		var iptErr *iptables.Error
		if errors.As(err, &iptErr) && iptErr.IsNotExist() {
			break
		}
		stopErr = err
		break
	}
	if deleted == 0 {
		logger.Debug("rule not found", "bin", bin, "chain", rule.chain, "target", rule.label, "stop_reason", stopErr)
		return
	}
	logger.Info("rule removed", "bin", bin, "chain", rule.chain, "target", rule.label, "count", deleted, "stop_reason", stopErr)
}
