//go:build linux

package armtlsmesh

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// fakeIptablesScript emulates iptables/ip6tables closely enough for
// go-iptables: version probing, chain creation with already-exists semantics,
// list (-S) and stats (-L) output from control files, and rule deletion with
// a bounded success budget. Every invocation is appended to calls.log.
const fakeIptablesScript = `#!/bin/sh
bin=$(basename "$0")
dir="$FAKE_NF_DIR"
printf '%s %s\n' "$bin" "$*" >> "$dir/calls.log"
mode=""
chain=""
prev=""
for a in "$@"; do
  case "$prev" in
    -S) chain="$a"; mode=list ;;
    -L) chain="$a"; mode=stats ;;
    -N) chain="$a"; mode=newchain ;;
  esac
  case "$a" in
    --version) mode=version ;;
    -D) mode=delete ;;
  esac
  prev="$a"
done
case "$mode" in
  version)
    echo "$bin v1.8.7 (legacy)"
    ;;
  list)
    f="$dir/list_${bin}_${chain}"
    if [ -f "$f" ]; then cat "$f"; else echo "-P $chain ACCEPT"; fi
    ;;
  stats)
    f="$dir/stats_${bin}_${chain}"
    if [ -f "$f" ]; then
      cat "$f"
    else
      echo "$bin: No chain/target/match by that name." >&2
      exit 1
    fi
    ;;
  newchain)
    marker="$dir/chain_${bin}_${chain}"
    if [ -f "$marker" ]; then
      echo "$bin: Chain already exists." >&2
      exit 1
    fi
    : > "$marker"
    ;;
  delete)
    budget="$dir/del_budget"
    n=0
    if [ -f "$budget" ]; then n=$(cat "$budget"); fi
    if [ "$n" -gt 0 ]; then
      echo $((n-1)) > "$budget"
    else
      echo "$bin: No chain/target/match by that name." >&2
      exit 1
    fi
    ;;
esac
exit 0
`

// fakeIpsetScript emulates ipset: list/destroy driven by control files and
// restore scripts appended to restore_scripts for inspection.
const fakeIpsetScript = `#!/bin/sh
dir="$FAKE_NF_DIR"
printf 'ipset %s\n' "$*" >> "$dir/calls.log"
case "$1" in
  list)
    name="$3"
    f="$dir/ipset_list_${name}"
    if [ -f "$f" ]; then cat "$f"; exit 0; fi
    echo "ipset v7.15: The set with the given name does not exist" >&2
    exit 1
    ;;
  destroy)
    name="$2"
    if [ -f "$dir/ipset_exists_${name}" ]; then rm -f "$dir/ipset_exists_${name}"; exit 0; fi
    if [ -f "$dir/ipset_destroy_ok" ]; then exit 0; fi
    echo "ipset v7.15: The set with the given name does not exist" >&2
    exit 1
    ;;
  restore)
    { echo "== restore =="; cat; } >> "$dir/restore_scripts"
    if [ -f "$dir/ipset_restore_fail" ]; then cat "$dir/ipset_restore_fail" >&2; exit 1; fi
    exit 0
    ;;
esac
exit 0
`

type fakeNetfilter struct {
	t   *testing.T
	dir string
}

func installFakeNetfilter(t *testing.T) *fakeNetfilter {
	t.Helper()
	binDir := t.TempDir()
	ctlDir := t.TempDir()
	for _, name := range []string{"iptables", "ip6tables"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(fakeIptablesScript), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(binDir, "ipset"), []byte(fakeIpsetScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_NF_DIR", ctlDir)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return &fakeNetfilter{t: t, dir: ctlDir}
}

func (f *fakeNetfilter) set(name, content string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// remove deletes a control file, making the fake fail the command that reads
// it — the stats path exits non-zero for a chain it has no fixture for.
func (f *fakeNetfilter) remove(name string) {
	f.t.Helper()
	if err := os.Remove(filepath.Join(f.dir, name)); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeNetfilter) read(name string) string {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		return ""
	}
	return string(raw)
}

func (f *fakeNetfilter) calls() []string {
	raw := f.read("calls.log")
	if raw == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(raw, "\n"), "\n")
}

func callsContaining(calls []string, prefix, sub string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) && strings.Contains(c, sub) {
			out = append(out, c)
		}
	}
	return out
}

// silenceIptablesMetricsFile disables the shared metrics file for the test and
// restores the previous configuration afterwards.
func silenceIptablesMetricsFile(t *testing.T) {
	t.Helper()
	prev := iptablesMetricsFile.Load()
	configureIptablesMetricsFile("")
	t.Cleanup(func() { iptablesMetricsFile.Store(prev) })
}

func mustInitFakeIptables(t *testing.T) {
	t.Helper()
	if err := initIptablesClients(); err != nil {
		t.Fatalf("initIptablesClients: %v", err)
	}
}

func TestInitIptablesClientsWithFakeBinaries(t *testing.T) {
	installFakeNetfilter(t)
	if err := initIptablesClients(); err != nil {
		t.Fatalf("initIptablesClients: %v", err)
	}
	if iptablesV4 == nil || iptablesV6 == nil {
		t.Fatal("clients not initialised")
	}
	if got := familyForIPT(iptablesV4); got != iptablesFamilyIPv4 {
		t.Errorf("familyForIPT(v4) = %q", got)
	}
	if got := familyForIPT(iptablesV6); got != iptablesFamilyIPv6 {
		t.Errorf("familyForIPT(v6) = %q", got)
	}
	if got := iptablesLabel(iptablesV4); got != "iptables" {
		t.Errorf("iptablesLabel(v4) = %q", got)
	}
	if got := iptablesLabel(iptablesV6); got != "ip6tables" {
		t.Errorf("iptablesLabel(v6) = %q", got)
	}
}

func TestInstallIptablesRulesFamilyFiltering(t *testing.T) {
	nf := installFakeNetfilter(t)
	silenceIptablesMetricsFile(t)
	mustInitFakeIptables(t)

	var logBuf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	rules := []iptablesRule{
		{table: "nat", chain: chainName, label: "both", family: iptablesFamilyAll, args: []string{"-p", "tcp", "-j", "RETURN"}},
		{table: "nat", chain: chainName, label: "v4only", family: iptablesFamilyIPv4, args: []string{"-p", "tcp", "-d", "10.9.9.9", "-j", "RETURN"}},
		{table: "nat", chain: chainName, label: "v6only", family: iptablesFamilyIPv6, args: []string{"-p", "tcp", "-d", "fd00::9", "-j", "RETURN"}},
	}
	if err := installIptablesRules(logger, rules, nil); err != nil {
		t.Fatalf("installIptablesRules: %v", err)
	}

	calls := nf.calls()
	for _, tc := range []struct {
		name string
		bin  string
		sub  string
		want int
	}{
		{"all-family on v4", "iptables ", "-A " + chainName + " -p tcp -j RETURN", 1},
		{"all-family on v6", "ip6tables ", "-A " + chainName + " -p tcp -j RETURN", 1},
		{"v4 rule on v4", "iptables ", "10.9.9.9", 1},
		{"v4 rule not on v6", "ip6tables ", "10.9.9.9", 0},
		{"v6 rule on v6", "ip6tables ", "fd00::9", 1},
		{"v6 rule not on v4", "iptables ", "fd00::9", 0},
		{"v4 flush", "iptables ", "-F " + chainName + " ", 1},
		{"v6 flush", "ip6tables ", "-F " + chainName + " ", 1},
	} {
		if got := len(callsContaining(calls, tc.bin, tc.sub)); got != tc.want {
			t.Errorf("%s: %d matching calls, want %d\ncalls:\n%s", tc.name, got, tc.want, strings.Join(calls, "\n"))
		}
	}
	if !hasMsg(decodeLogRecords(logBuf.String()), "chain created") {
		t.Error("fresh chains did not log 'chain created'")
	}
}

func TestEnsureIptablesJumps(t *testing.T) {
	jumpToMesh := iptablesRule{table: "nat", chain: "OUTPUT", label: "jump", args: []string{"-j", chainName}}

	t.Run("at head is a no-op", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		silenceIptablesMetricsFile(t)
		mustInitFakeIptables(t)
		atHead := "-P OUTPUT ACCEPT\n-A OUTPUT -j " + chainName + "\n-A OUTPUT -j KUBE-SERVICES\n"
		nf.set("list_iptables_OUTPUT", atHead)
		nf.set("list_ip6tables_OUTPUT", atHead)

		violBefore := jumpPositionViolations.Load()
		chkBefore := jumpPositionCheckErrors.Load()
		if err := ensureIptablesJumps(testLogger(), []iptablesRule{jumpToMesh}); err != nil {
			t.Fatalf("ensureIptablesJumps: %v", err)
		}
		calls := nf.calls()
		if got := len(callsContaining(calls, "", "-I OUTPUT")); got != 0 {
			t.Errorf("jump reinserted while already at head:\n%s", strings.Join(calls, "\n"))
		}
		if got := len(callsContaining(calls, "", "-D OUTPUT")); got != 0 {
			t.Errorf("jump deleted while already at head:\n%s", strings.Join(calls, "\n"))
		}
		if d := jumpPositionViolations.Load() - violBefore; d != 0 {
			t.Errorf("violations advanced by %d for an at-head jump", d)
		}
		if d := jumpPositionCheckErrors.Load() - chkBefore; d != 0 {
			t.Errorf("check errors advanced by %d for a successful position check", d)
		}
	})

	t.Run("demoted jump restored and counted", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		silenceIptablesMetricsFile(t)
		mustInitFakeIptables(t)
		demoted := "-P OUTPUT ACCEPT\n-A OUTPUT -j KUBE-SERVICES\n-A OUTPUT -j " + chainName + "\n"
		nf.set("list_iptables_OUTPUT", demoted)
		nf.set("list_ip6tables_OUTPUT", demoted)

		violBefore := jumpPositionViolations.Load()
		chkBefore := jumpPositionCheckErrors.Load()
		if err := ensureIptablesJumps(testLogger(), []iptablesRule{jumpToMesh}); err != nil {
			t.Fatalf("ensureIptablesJumps: %v", err)
		}
		calls := nf.calls()
		for _, bin := range []string{"iptables ", "ip6tables "} {
			if got := len(callsContaining(calls, bin, "-I OUTPUT 1 -j "+chainName)); got != 1 {
				t.Errorf("%sinsert count = %d, want 1\n%s", bin, got, strings.Join(calls, "\n"))
			}
		}
		if d := jumpPositionViolations.Load() - violBefore; d != 2 {
			t.Errorf("violations advanced by %d, want 2 (one per binary)", d)
		}
		if d := jumpPositionCheckErrors.Load() - chkBefore; d != 0 {
			t.Errorf("check errors advanced by %d, want 0", d)
		}
	})

	// Regression: the cw inbound and egress guards share filter FORWARD, so
	// one of them is always rule 2. Checking head position per rule made that
	// one look demoted forever, and every watchdog tick then deleted and
	// reinserted both — each repair leaving FORWARD unguarded for the length
	// of two iptables execs, which is how plaintext reached a cw pod.
	t.Run("sibling FORWARD guards at head are a no-op", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		silenceIptablesMetricsFile(t)
		mustInitFakeIptables(t)
		atHead := "-P FORWARD ACCEPT\n-A FORWARD -j " + cwChainName +
			"\n-A FORWARD -j " + cwEgressChainName + "\n-A FORWARD -j KUBE-FORWARD\n"
		nf.set("list_iptables_FORWARD", atHead)
		nf.set("list_ip6tables_FORWARD", atHead)

		violBefore := jumpPositionViolations.Load()
		if err := ensureIptablesJumps(testLogger(), []iptablesRule{cwJumpRule(), cwEgressJumpRule()}); err != nil {
			t.Fatalf("ensureIptablesJumps: %v", err)
		}
		calls := nf.calls()
		for _, op := range []string{"-I FORWARD", "-D FORWARD"} {
			if got := len(callsContaining(calls, "", op)); got != 0 {
				t.Errorf("%s issued for an in-order guard block:\n%s", op, strings.Join(calls, "\n"))
			}
		}
		if d := jumpPositionViolations.Load() - violBefore; d != 0 {
			t.Errorf("violations advanced by %d for an in-order guard block", d)
		}
	})

	t.Run("demoted FORWARD guards restored in block order", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		silenceIptablesMetricsFile(t)
		mustInitFakeIptables(t)
		demoted := "-P FORWARD ACCEPT\n-A FORWARD -j KUBE-FORWARD\n-A FORWARD -j " + cwChainName +
			"\n-A FORWARD -j " + cwEgressChainName + "\n"
		nf.set("list_iptables_FORWARD", demoted)
		nf.set("list_ip6tables_FORWARD", demoted)
		nf.set("del_budget", "4")

		violBefore := jumpPositionViolations.Load()
		if err := ensureIptablesJumps(testLogger(), []iptablesRule{cwJumpRule(), cwEgressJumpRule()}); err != nil {
			t.Fatalf("ensureIptablesJumps: %v", err)
		}
		calls := callsContaining(nf.calls(), "iptables ", "-I FORWARD 1 -j ")
		if len(calls) != 2 {
			t.Fatalf("v4 insert count = %d, want 2\n%s", len(calls), strings.Join(calls, "\n"))
		}
		// Inserts land at position 1, so the last one issued ends up first.
		if !strings.Contains(calls[0], "-j "+cwEgressChainName) || !strings.Contains(calls[1], "-j "+cwChainName) {
			t.Errorf("inserts issued in the wrong order, leaving the block reversed:\n%s", strings.Join(calls, "\n"))
		}
		if d := jumpPositionViolations.Load() - violBefore; d != 4 {
			t.Errorf("violations advanced by %d, want 4 (two demoted jumps per binary)", d)
		}
	})

	t.Run("family-scoped jump touches only its binary", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		silenceIptablesMetricsFile(t)
		mustInitFakeIptables(t)
		v6Jump := iptablesRule{table: "nat", chain: "PREROUTING", label: "jump6", family: iptablesFamilyIPv6, args: []string{"-j", preroutingChainName}}
		if err := ensureIptablesJumps(testLogger(), []iptablesRule{v6Jump}); err != nil {
			t.Fatalf("ensureIptablesJumps: %v", err)
		}
		calls := nf.calls()
		if got := len(callsContaining(calls, "ip6tables ", "-I PREROUTING 1 -j "+preroutingChainName)); got != 1 {
			t.Errorf("v6 insert count = %d, want 1\n%s", got, strings.Join(calls, "\n"))
		}
		if got := len(callsContaining(calls, "iptables ", "-I PREROUTING")); got != 0 {
			t.Errorf("v4 binary touched for a v6-only jump:\n%s", strings.Join(calls, "\n"))
		}
	})
}

// cwStatsV4 and cwStatsV6 are the chain as `iptables -L -n -v -x` prints it.
// The v4 rows use the numeric protocol column that iptables 1.8.10 (nf_tables)
// prints under -n; the v6 rows use the names the legacy backend prints. Both
// ship, so both must be attributed, for tcp as well as udp.
//
// v4: drops 5, exemption returns 4+6+2 = 12.
const cwStatsV4 = `Chain ` + cwChainName + ` (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       3      100 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0            match-set ARMTLS-MESH-CW-PODS dst ctstate RELATED,ESTABLISHED
       4      200 RETURN     17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp spt:53 dpts:32768:60999 match-set ARMTLS-MESH-CW-PODS dst
       6      250 RETURN     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:53 dpts:32768:60999 flags:0x17/0x12 match-set ARMTLS-MESH-CW-PODS dst
       2      120 RETURN     6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:53 dpts:32768:60999 flags:0x02/0x00 match-set ARMTLS-MESH-CW-PODS dst
       5      300 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0            match-set ARMTLS-MESH-CW-PODS dst
`

// v6: drops 2, exemption returns 1+8+3 = 12.
const cwStatsV6 = `Chain ` + cwChainName + ` (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       9       90 RETURN     all      *      *       ::/0                 ::/0                 match-set ARMTLS-MESH-CW-PODS6 dst ctstate RELATED,ESTABLISHED
       1       40 RETURN     udp      *      *       ::/0                 ::/0                 udp spt:53 dpts:32768:60999 match-set ARMTLS-MESH-CW-PODS6 dst
       8      420 RETURN     tcp      *      *       ::/0                 ::/0                 tcp spt:53 dpts:32768:60999 flags:0x17/0x12 match-set ARMTLS-MESH-CW-PODS6 dst
       3      160 RETURN     tcp      *      *       ::/0                 ::/0                 tcp spt:53 dpts:32768:60999 flags:0x02/0x00 match-set ARMTLS-MESH-CW-PODS6 dst
       2       80 DROP       all      *      *       ::/0                 ::/0                 match-set ARMTLS-MESH-CW-PODS6 dst
`

// resetCWGuardCounters isolates a test from counter state left by another.
func resetCWGuardCounters(t *testing.T) {
	t.Helper()
	prevDrops, prevReturns := cwInboundDrops.Load(), cwPassthroughReturns.Load()
	prevRead := maps.Clone(cwGuardLastRead)
	clear(cwGuardLastRead)
	cwInboundDrops.Store(0)
	cwPassthroughReturns.Store(0)
	t.Cleanup(func() {
		cwInboundDrops.Store(prevDrops)
		cwPassthroughReturns.Store(prevReturns)
		cwGuardLastRead = prevRead
	})
}

func TestRefreshCWGuardCounters(t *testing.T) {
	nf := installFakeNetfilter(t)
	mustInitFakeIptables(t)
	nf.set("stats_iptables_"+cwChainName, cwStatsV4)
	nf.set("stats_ip6tables_"+cwChainName, cwStatsV6)
	resetCWGuardCounters(t)

	if err := refreshCWGuardCounters(); err != nil {
		t.Fatalf("refreshCWGuardCounters: %v", err)
	}
	if got := cwInboundDrops.Load(); got != 7 {
		t.Errorf("cwInboundDrops = %d, want 7 (DROP rows only, both families)", got)
	}
	if got := cwPassthroughReturns.Load(); got != 24 {
		t.Errorf("cwPassthroughReturns = %d, want 24 (protocol-scoped RETURN rows only, both families, both renderings)", got)
	}
}

// A family that cannot be read holds its previous contribution, because a
// step-down reads as a counter reset to rate().
func TestRefreshCWGuardCountersHoldsFailingFamily(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failing string
		other   string
	}{
		{"v6 read fails", "stats_ip6tables_" + cwChainName, "stats_iptables_" + cwChainName},
		{"v4 read fails", "stats_iptables_" + cwChainName, "stats_ip6tables_" + cwChainName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nf := installFakeNetfilter(t)
			mustInitFakeIptables(t)
			nf.set("stats_iptables_"+cwChainName, cwStatsV4)
			nf.set("stats_ip6tables_"+cwChainName, cwStatsV6)
			resetCWGuardCounters(t)

			if err := refreshCWGuardCounters(); err != nil {
				t.Fatalf("seed read: %v", err)
			}
			if got := cwInboundDrops.Load(); got != 7 {
				t.Fatalf("seeded cwInboundDrops = %d, want 7", got)
			}

			// Remove one family's fixture: the fake exits non-zero for a chain
			// it has no stats for.
			nf.remove(tc.failing)
			err := refreshCWGuardCounters()
			if err == nil {
				t.Fatal("expected an error naming the failing family")
			}
			if !strings.Contains(err.Error(), binForStatsKey(tc.failing)) {
				t.Errorf("error %q does not name the failing binary %q", err, binForStatsKey(tc.failing))
			}
			if !strings.Contains(err.Error(), cwChainName) {
				t.Errorf("error %q does not name the chain", err)
			}
			// Totals unchanged: the readable family re-read its own value and
			// the failing one held the value it last reported.
			if got := cwInboundDrops.Load(); got != 7 {
				t.Errorf("cwInboundDrops = %d, want 7 held across the failure", got)
			}
			if got := cwPassthroughReturns.Load(); got != 24 {
				t.Errorf("cwPassthroughReturns = %d, want 24 held across the failure", got)
			}
			// The surviving family still tracks live movement.
			nf.set(tc.other, bumpDropRow(t, statsFor(tc.other)))
			if err := refreshCWGuardCounters(); err == nil {
				t.Fatal("expected the failing family to keep erroring")
			}
			if got := cwInboundDrops.Load(); got != 8 {
				t.Errorf("cwInboundDrops = %d, want 8 after the readable family advanced by 1", got)
			}
		})
	}
}

func TestRefreshCWGuardCountersBothFamiliesFail(t *testing.T) {
	installFakeNetfilter(t)
	mustInitFakeIptables(t)
	resetCWGuardCounters(t)

	err := refreshCWGuardCounters()
	if err == nil {
		t.Fatal("expected an error when neither family can be read")
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !strings.Contains(err.Error(), bin) {
			t.Errorf("joined error %q does not name %q", err, bin)
		}
	}
	if got := cwInboundDrops.Load(); got != 0 {
		t.Errorf("cwInboundDrops = %d, want 0 with nothing ever read", got)
	}
}

func statsFor(key string) string {
	if strings.Contains(key, "ip6tables") {
		return cwStatsV6
	}
	return cwStatsV4
}

func binForStatsKey(key string) string {
	if strings.Contains(key, "ip6tables") {
		return "ip6tables"
	}
	return "iptables"
}

// bumpDropRow adds one packet to the chain's DROP row.
func bumpDropRow(t *testing.T, stats string) string {
	t.Helper()
	lines := strings.Split(stats, "\n")
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != "DROP" {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("parse DROP packet count %q: %v", fields[0], err)
		}
		lines[i] = strings.Replace(line, fields[0], strconv.Itoa(n+1), 1)
		return strings.Join(lines, "\n")
	}
	t.Fatal("no DROP row in stats fixture")
	return ""
}

func TestDeleteAllIptablesRulesCountsRemovals(t *testing.T) {
	nf := installFakeNetfilter(t)
	mustInitFakeIptables(t)
	nf.set("del_budget", "2")

	var logBuf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rule := iptablesRule{table: "nat", chain: "OUTPUT", label: "jump", args: []string{"-j", chainName}}
	deleteAllIptablesRules(logger, iptablesV4, rule)

	records := decodeLogRecords(logBuf.String())
	removed := recordsWithMsg(records, "rule removed")
	if len(removed) != 1 {
		t.Fatalf("got %d 'rule removed' records, want 1; logs: %s", len(removed), logBuf.String())
	}
	if removed[0].Count != 2 {
		t.Errorf("removed count = %d, want 2", removed[0].Count)
	}
	if hasMsg(records, "rule not found") {
		t.Error("'rule not found' logged although two instances were deleted")
	}
}

func TestRunIptablesCleanupRemovesChainsAndSets(t *testing.T) {
	nf := installFakeNetfilter(t)
	nf.set("ipset_destroy_ok", "")

	capture := captureStdout(t)
	err := runIptablesCleanup(false)
	capture.stop()
	if err != nil {
		t.Fatalf("runIptablesCleanup: %v", err)
	}

	calls := nf.calls()
	for _, tc := range []struct {
		bin, sub string
	}{
		{"iptables ", "-t nat -X " + chainName},
		{"ip6tables ", "-t nat -X " + preroutingChainName},
		{"iptables ", "-t filter -X " + cwChainName},
		{"iptables ", "-t filter -X " + cwEgressChainName},
		{"iptables ", "-t filter -D FORWARD -j " + cwEgressChainName},
		{"ipset ", "destroy " + podIPSetName4},
		{"ipset ", "destroy " + cwPodIPSetName6 + ipSetTmpSuffix},
	} {
		if len(callsContaining(calls, tc.bin, tc.sub)) == 0 {
			t.Errorf("missing %q%q call:\n%s", tc.bin, tc.sub, strings.Join(calls, "\n"))
		}
	}

	records := decodeLogRecords(capture.String())
	if !hasMsg(records, "chain removed") {
		t.Error("successful chain delete did not log 'chain removed'")
	}
	if hasMsg(records, "delete chain failed (may not exist)") {
		t.Error("successful chain delete logged the failure branch")
	}
	if hasMsg(records, "flush chain failed (may not exist)") {
		t.Error("successful chain flush logged the failure branch")
	}
	if !hasMsg(records, "ipset removed") {
		t.Error("successful ipset destroy did not log 'ipset removed'")
	}
	if hasMsg(records, "delete ipset failed (may not exist)") {
		t.Error("successful ipset destroy logged the failure branch")
	}
}

// --keep-guard removes the NAT interception (OUTPUT/PREROUTING jumps, nat
// chains, pod ipsets) but leaves the fail-closed filter guard (cw chain,
// cw egress chain, cw jumps, cw pod ipsets) in place: unmeshed inbound and
// non-TCP egress stay dropped.
func TestRunIptablesCleanupKeepGuardLeavesFailClosed(t *testing.T) {
	nf := installFakeNetfilter(t)
	nf.set("ipset_destroy_ok", "")

	capture := captureStdout(t)
	err := runIptablesCleanup(true)
	capture.stop()
	if err != nil {
		t.Fatalf("runIptablesCleanup(true): %v", err)
	}

	calls := nf.calls()
	// Interception gone: nat OUTPUT/PREROUTING chains deleted, pod ipsets
	// destroyed.
	for _, tc := range []struct {
		bin, sub string
	}{
		{"iptables ", "-t nat -X " + chainName},
		{"iptables ", "-t nat -X " + preroutingChainName},
		{"ipset ", "destroy " + podIPSetName4},
		{"ipset ", "destroy " + localPodIPSetName4},
	} {
		if len(callsContaining(calls, tc.bin, tc.sub)) == 0 {
			t.Errorf("keep-guard: missing %q%q call:\n%s", tc.bin, tc.sub, strings.Join(calls, "\n"))
		}
	}
	// Guard kept: filter cw chain and cw egress chain NOT deleted, their
	// FORWARD jumps NOT deleted, cw pod ipsets NOT destroyed.
	for _, forbidden := range []string{
		"-t filter -X " + cwChainName,
		"-t filter -X " + cwEgressChainName,
		"-t filter -D FORWARD -j " + cwChainName,
		"-t filter -D FORWARD -j " + cwEgressChainName,
		"destroy " + cwPodIPSetName4,
		"destroy " + cwPodIPSetName6,
	} {
		for _, call := range calls {
			if strings.Contains(call, forbidden) {
				t.Errorf("keep-guard must not %q; got call %q", forbidden, call)
			}
		}
	}

	// The FORWARD guard jumps are retained: assert the cw and cw egress jump
	// rules are NOT among the delete operations (only the nat jumps are).
	for _, jump := range []iptablesRule{cwJumpRule(), cwEgressJumpRule()} {
		del := "-t filter -D FORWARD -j " + jump.args[1]
		if strings.Contains(strings.Join(calls, "\n"), del) {
			t.Errorf("keep-guard must retain the %s jump; got delete call %q", jump.label, del)
		}
	}
}

// The daemonset's cleanup sidecar runs `armtls-mesh iptables-cleanup
// [--keep-guard]`; the flag must parse and reach runIptablesCleanup.
func TestIptablesCleanupCommandKeepGuardFlag(t *testing.T) {
	nf := installFakeNetfilter(t)
	nf.set("ipset_destroy_ok", "")

	cmd := newIptablesCleanupCommand()
	f := cmd.Flags().Lookup("keep-guard")
	if f == nil || f.DefValue != "false" {
		t.Fatalf("--keep-guard flag = %+v, want registered with default false", f)
	}
	if err := cmd.Flags().Set("keep-guard", "true"); err != nil {
		t.Fatalf("set --keep-guard: %v", err)
	}
	capture := captureStdout(t)
	err := cmd.RunE(cmd, nil)
	capture.stop()
	if err != nil {
		t.Fatalf("iptables-cleanup --keep-guard: %v", err)
	}
	for _, call := range nf.calls() {
		if strings.Contains(call, "-t filter -X "+cwChainName) {
			t.Errorf("keep-guard via command deleted the guard chain: %q", call)
		}
	}
}

// A destroy failure mid-teardown (set already gone) is logged and skipped,
// not fatal.
func TestCleanupPodIPSetsForNamesWarnsOnDestroyFailure(t *testing.T) {
	installFakeNetfilter(t)
	var logBuf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	cleanupPodIPSetsForNames(logger, []string{podIPSetName4})
	if !strings.Contains(logBuf.String(), "delete ipset failed") {
		t.Errorf("destroy failure should be logged and skipped, got %q", logBuf.String())
	}
}

func TestReadIPSetMaxElemStates(t *testing.T) {
	nf := installFakeNetfilter(t)
	nf.set("ipset_list_"+podIPSetName4, `Name: `+podIPSetName4+`
Type: hash:ip
Header: family inet hashsize 1024 maxelem 4096 bucketsize 12
`)

	v, exists, err := readIPSetMaxElem(podIPSetName4)
	if err != nil || !exists || v != 4096 {
		t.Errorf("existing set: (%d, %v, %v), want (4096, true, nil)", v, exists, err)
	}

	v, exists, err = readIPSetMaxElem(podIPSetName6)
	if err != nil || exists || v != 0 {
		t.Errorf("missing set: (%d, %v, %v), want (0, false, nil)", v, exists, err)
	}
}

func TestReconcileLiveSetMaxElem(t *testing.T) {
	header := func(maxElem int) string {
		return fmt.Sprintf("Name: %s\nType: hash:ip\nHeader: family inet hashsize 1024 maxelem %d\n", podIPSetName4, maxElem)
	}

	t.Run("no live sets", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		mustInitFakeIptables(t)
		if err := reconcileLiveSetMaxElem(testLogger(), 1024); err != nil {
			t.Fatalf("reconcileLiveSetMaxElem: %v", err)
		}
		if got := callsContaining(nf.calls(), "ipset ", "destroy"); len(got) != 0 {
			t.Errorf("unexpected destroys with no live sets: %v", got)
		}
	})

	t.Run("matching maxelem untouched", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		mustInitFakeIptables(t)
		nf.set("ipset_list_"+podIPSetName4, header(1024))
		if err := reconcileLiveSetMaxElem(testLogger(), 1024); err != nil {
			t.Fatalf("reconcileLiveSetMaxElem: %v", err)
		}
		if got := callsContaining(nf.calls(), "ipset ", "destroy"); len(got) != 0 {
			t.Errorf("matching set destroyed: %v", got)
		}
	})

	t.Run("mismatched maxelem rebuilt after chain flush", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		mustInitFakeIptables(t)
		nf.set("ipset_list_"+podIPSetName4, header(512))
		nf.set("ipset_destroy_ok", "")

		var logBuf syncBuffer
		logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
		if err := reconcileLiveSetMaxElem(logger, 1024); err != nil {
			t.Fatalf("reconcileLiveSetMaxElem: %v", err)
		}
		calls := nf.calls()
		destroys := callsContaining(calls, "ipset ", "destroy "+podIPSetName4)
		if len(destroys) != 1 {
			t.Fatalf("destroy count = %d, want 1\n%s", len(destroys), strings.Join(calls, "\n"))
		}
		// The referencing chains must be flushed before the destroy.
		flushIdx, destroyIdx := -1, -1
		for i, c := range calls {
			if flushIdx == -1 && strings.HasPrefix(c, "iptables ") && strings.Contains(c, "-F "+chainName) {
				flushIdx = i
			}
			if strings.HasPrefix(c, "ipset ") && strings.Contains(c, "destroy "+podIPSetName4) {
				destroyIdx = i
			}
		}
		if flushIdx == -1 || destroyIdx == -1 || flushIdx > destroyIdx {
			t.Errorf("chain flush (idx %d) must precede set destroy (idx %d)\n%s", flushIdx, destroyIdx, strings.Join(calls, "\n"))
		}
		if !hasMsg(decodeLogRecords(logBuf.String()), "destroyed live ipset to apply new maxelem") {
			t.Error("rebuild did not log the destroy")
		}
	})
}

func TestReplaceIPSetMembersTmpHandling(t *testing.T) {
	t.Run("clean reconcile stays silent and restores", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		var logBuf syncBuffer
		logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
		if err := replaceIPSetMembers(logger, podIPSetName4, "inet", []string{"10.244.0.5"}, 100); err != nil {
			t.Fatalf("replaceIPSetMembers: %v", err)
		}
		script := nf.read("restore_scripts")
		if !strings.Contains(script, "add "+podIPSetName4+ipSetTmpSuffix+" 10.244.0.5 -exist") {
			t.Errorf("restore script missing member add:\n%s", script)
		}
		records := decodeLogRecords(logBuf.String())
		if hasMsg(records, "destroyed stale ipset TMP from prior reconcile") {
			t.Error("clean path logged a stale-TMP destroy")
		}
		if hasMsg(records, "pre-destroy of stale ipset TMP failed") {
			t.Error("expected does-not-exist pre-destroy to stay silent")
		}
	})

	t.Run("stale tmp destroy is logged", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		nf.set("ipset_exists_"+podIPSetName4+ipSetTmpSuffix, "")
		var logBuf syncBuffer
		logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
		if err := replaceIPSetMembers(logger, podIPSetName4, "inet", nil, 100); err != nil {
			t.Fatalf("replaceIPSetMembers: %v", err)
		}
		if !hasMsg(decodeLogRecords(logBuf.String()), "destroyed stale ipset TMP from prior reconcile") {
			t.Error("stale-TMP destroy not logged")
		}
	})

	t.Run("restore failure surfaces stderr", func(t *testing.T) {
		nf := installFakeNetfilter(t)
		nf.set("ipset_restore_fail", "ipset v7.15: Kernel error received: Invalid argument")
		err := replaceIPSetMembers(testLogger(), podIPSetName4, "inet", nil, 100)
		if err == nil {
			t.Fatal("expected restore failure")
		}
		if !strings.Contains(err.Error(), "stderr=") || !strings.Contains(err.Error(), "Kernel error received") {
			t.Errorf("error %v does not carry the ipset stderr diagnostic", err)
		}
	})
}

func TestBuildIPSetRestoreScriptCapacityEdges(t *testing.T) {
	if _, err := buildIPSetRestoreScript(podIPSetName4, "inet", nil, 0); err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("maxelem 0: err = %v, want positivity error", err)
	}
	if _, err := buildIPSetRestoreScript(podIPSetName4, "inet", []string{"10.0.0.1", "10.0.0.2"}, 2); err != nil {
		t.Errorf("exactly-full set rejected: %v", err)
	}
}

func TestPodIPSetMembersExceedsAtCapacity(t *testing.T) {
	two := []string{"a", "b"}
	tests := []struct {
		name string
		m    podIPSetMembers
	}{
		{"allIPv6", podIPSetMembers{allIPv6: two}},
		{"localIPv4", podIPSetMembers{localIPv4: two}},
		{"localIPv6", podIPSetMembers{localIPv6: two}},
		{"cwIPv4", podIPSetMembers{cwIPv4: two}},
		{"cwIPv6", podIPSetMembers{cwIPv6: two}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.m.exceeds(2) {
				t.Error("exceeds(2) with exactly 2 members = true, want false")
			}
			if !tc.m.exceeds(1) {
				t.Error("exceeds(1) with 2 members = false, want true")
			}
		})
	}
}

func TestParseIPSetMaxElemHeaderMalformed(t *testing.T) {
	if _, err := parseIPSetMaxElemHeader("Header: family inet hashsize 1024 maxelem\n"); err == nil || !strings.Contains(err.Error(), "header missing maxelem") {
		t.Errorf("trailing maxelem: err = %v, want missing-field error", err)
	}
	_, err := parseIPSetMaxElemHeader("Header: family inet hashsize 1024 maxelem oops\n")
	if err == nil || !strings.Contains(err.Error(), `"oops"`) {
		t.Errorf("bad value: err = %v, want the offending token quoted", err)
	}
}

func TestRunIptablesSyncRejectsZeroWatchdogPeriod(t *testing.T) {
	t.Setenv("NODE_IP", "")
	cfg := defaultTestSyncConfig()
	cfg.watchdogPeriod = 0
	err := runIptablesSync(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "watchdog-period must be positive") {
		t.Fatalf("err = %v, want watchdog-period validation error", err)
	}
}

func TestRunIptablesSyncHappyPath(t *testing.T) {
	nf := installFakeNetfilter(t)
	t.Setenv("NODE_IP", "")
	own := localIPv4(t)
	cs := k8sfake.NewSimpleClientset(testPod("w1", "default", "10.244.0.5", own, nil))
	stubKubeClientset(t, cs, nil)

	prev := iptablesMetricsFile.Load()
	t.Cleanup(func() { iptablesMetricsFile.Store(prev) })

	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")
	metricsFile := filepath.Join(dir, "metrics.json")
	cfg := defaultTestSyncConfig()
	cfg.nodeIPs = []string{own}
	// Long periods keep the ticker and watchdog dormant: the loop advances
	// only on informer events, which the test drives explicitly.
	cfg.resyncPeriod = time.Hour
	cfg.watchdogPeriod = time.Hour
	cfg.ipsetMaxElem = 1024
	cfg.readyFile = readyFile
	cfg.metricsFile = metricsFile

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- runIptablesSync(ctx, cfg) }()

	assertEventually(t, 10*time.Second, func() bool {
		_, err := os.Stat(readyFile)
		return err == nil
	}, "ready file never written")

	snap, err := readIptablesMetricsFile(metricsFile)
	if err != nil {
		t.Fatalf("read metrics file: %v", err)
	}
	if snap.UpdatedAtUnixNano <= 0 {
		t.Error("metrics snapshot missing timestamp")
	}

	script := nf.read("restore_scripts")
	if !strings.Contains(script, "add "+podIPSetName4+ipSetTmpSuffix+" 10.244.0.5 -exist") {
		t.Errorf("initial reconcile did not write the pod IP:\n%s", script)
	}
	calls := nf.calls()
	if len(callsContaining(calls, "iptables ", "-A "+chainName)) == 0 {
		t.Errorf("no OUTPUT-chain rules appended:\n%s", strings.Join(calls, "\n"))
	}
	if len(callsContaining(calls, "iptables ", "-I OUTPUT 1 -j "+chainName)) == 0 {
		t.Errorf("base-chain jump not installed:\n%s", strings.Join(calls, "\n"))
	}

	// A pod event must drive a fresh reconcile and metrics publish.
	if _, err := cs.CoreV1().Pods("default").Create(ctx, testPod("w2", "default", "10.244.0.6", own, nil), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	assertEventually(t, 10*time.Second, func() bool {
		next, err := readIptablesMetricsFile(metricsFile)
		return err == nil && next.UpdatedAtUnixNano > snap.UpdatedAtUnixNano
	}, "metrics snapshot never advanced after a pod event")

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runIptablesSync = %v, want nil on cancel", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runIptablesSync did not stop on cancel")
	}
}

func TestPublishIptablesMetricsWarnsOnlyOnWriteFailure(t *testing.T) {
	prev := iptablesMetricsFile.Load()
	t.Cleanup(func() { iptablesMetricsFile.Store(prev) })

	var okBuf syncBuffer
	configureIptablesMetricsFile(filepath.Join(t.TempDir(), "metrics.json"))
	publishIptablesMetrics(slog.New(slog.NewJSONHandler(&okBuf, nil)))
	if hasMsg(decodeLogRecords(okBuf.String()), "write iptables metrics file failed") {
		t.Errorf("successful write warned: %s", okBuf.String())
	}

	var failBuf syncBuffer
	configureIptablesMetricsFile(filepath.Join(t.TempDir(), "no-such-dir", "metrics.json"))
	publishIptablesMetrics(slog.New(slog.NewJSONHandler(&failBuf, nil)))
	if !hasMsg(decodeLogRecords(failBuf.String()), "write iptables metrics file failed") {
		t.Errorf("failed write did not warn: %s", failBuf.String())
	}
}

// cwPodStore is a pod cache holding one confidential workload, which is what
// the guard sets are computed from.
func cwPodStore(t *testing.T) cache.Store {
	t.Helper()
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := store.Add(&corev1.Pod{
		Name:      "serving",
		Namespace: "demo",
		Labels:    map[string]string{labelConfidentialWorkload: "vllm"},
		Status:    corev1.PodStatus{HostIP: "10.0.0.1", PodIP: "10.244.0.9"},
	}); err != nil {
		t.Fatalf("seed pod store: %v", err)
	}
	return store
}

// Membership is what the guard matches on, so a set left at a previous cycle's
// contents is enforcement that has stopped covering pods created since — and
// the cw sets, which the fail-closed guard keys on, used to be written last and
// abandoned whenever an earlier set failed.
func TestReconcilePodIPSetsWritesGuardSetsFirst(t *testing.T) {
	nf := installFakeNetfilter(t)
	if _, err := reconcilePodIPSets(cwPodStore(t), []string{"10.0.0.1"}, nil, 100, testLogger()); err != nil {
		t.Fatalf("reconcilePodIPSets: %v", err)
	}
	script := nf.read("restore_scripts")
	cwAt := strings.Index(script, cwPodIPSetName4)
	podAt := strings.Index(script, podIPSetName4)
	if cwAt < 0 || podAt < 0 {
		t.Fatalf("both sets must be written; script:\n%s", script)
	}
	if cwAt > podAt {
		t.Errorf("the guard's own set is written after the interception sets, so an earlier failure costs it its write:\n%s", script)
	}
}

func TestReconcilePodIPSetsAttemptsEverySetWhenOneFails(t *testing.T) {
	nf := installFakeNetfilter(t)
	nf.set("ipset_restore_fail", "ipset v7.15: Kernel error received: Invalid argument")
	before := iptablesIPSetSyncFailures()

	_, err := reconcilePodIPSets(cwPodStore(t), []string{"10.0.0.1"}, nil, 100, testLogger())
	if err == nil {
		t.Fatal("a failing ipset write must surface")
	}
	// Abandoning the remaining sets is what froze membership behind a single
	// warning; every set gets its own attempt and its own error.
	for _, label := range []string{"IPv4 cw pod ipset", "IPv6 cw pod ipset", "IPv4 pod ipset", "local IPv4 pod ipset"} {
		if !strings.Contains(err.Error(), label) {
			t.Errorf("the %s was never attempted after an earlier set failed: %v", label, err)
		}
	}
	if got := iptablesIPSetSyncFailures() - before; got != 6 {
		t.Errorf("sync failures counted %d, want one per managed set (6)", got)
	}
}

// The cleanup sidecar replaced its preStop exec hook with SIGTERM handling
// (a locked node image denies every runc exec), so --on-shutdown must
// clean up when — and only when — the root context is cancelled.
func TestIptablesCleanupOnShutdown(t *testing.T) {
	nf := installFakeNetfilter(t)
	nf.set("ipset_destroy_ok", "")

	cmd := newIptablesCleanupCommand()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd.SetContext(ctx)
	for flag, value := range map[string]string{"on-shutdown": "true", "keep-guard": "true", "settle-delay": "1ms"} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set --%s: %v", flag, err)
		}
	}

	capture := captureStdout(t)
	done := make(chan error, 1)
	go func() { done <- cmd.RunE(cmd, nil) }()

	select {
	case err := <-done:
		capture.stop()
		t.Fatalf("iptables-cleanup --on-shutdown returned before SIGTERM: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	for _, call := range nf.calls() {
		if strings.Contains(call, "-t nat -X "+chainName) {
			capture.stop()
			t.Fatalf("cleanup ran before the shutdown signal: %q", call)
		}
	}

	cancel()
	err := <-done
	capture.stop()
	if err != nil {
		t.Fatalf("iptables-cleanup --on-shutdown: %v", err)
	}
	var removed bool
	for _, call := range nf.calls() {
		if strings.Contains(call, "-t nat -X "+chainName) {
			removed = true
		}
		if strings.Contains(call, "-t filter -X "+cwChainName) {
			t.Errorf("--keep-guard deleted the guard chain on shutdown: %q", call)
		}
	}
	if !removed {
		t.Errorf("shutdown did not remove the interception chain; calls: %v", nf.calls())
	}
}

// The startup probe that gates the mesh proxy on interception being installed
// is an HTTP endpoint, not an exec probe: it must refuse until the initial
// sync has completed.
func TestReadinessEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ready, err := serveReadiness(ctx, "127.0.0.1:0", logger)
	if err != nil {
		t.Fatalf("serveReadiness: %v", err)
	}
	if ready.Load() {
		t.Error("the readiness flag starts set")
	}

	rec := httptest.NewRecorder()
	handler := readinessHandler(ready)
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz before the initial sync = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	ready.Store(true)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /readyz after the initial sync = %d, want %d", rec.Code, http.StatusOK)
	}
}

// An empty --ready-addr disables the endpoint rather than failing the sync.
func TestReadinessEndpointDisabled(t *testing.T) {
	ready, err := serveReadiness(context.Background(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || ready == nil {
		t.Fatalf("serveReadiness(\"\") = %v, %v, want a usable flag", ready, err)
	}
}
