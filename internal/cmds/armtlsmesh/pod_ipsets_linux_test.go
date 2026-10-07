//go:build linux

package armtlsmesh

import (
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestCollectPodIPSetMembersSkipsHostNetworkAndDeduplicates(t *testing.T) {
	sets := collectPodIPSetMembers([]any{
		&corev1.Pod{
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.5",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}, {IP: "fd00:0:0:0:0:0:0:5"}},
			},
		},
		&corev1.Pod{
			Status: corev1.PodStatus{
				HostIP: "10.0.0.2",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
			},
		},
		&corev1.Pod{
			Spec: corev1.PodSpec{HostNetwork: true},
			Status: corev1.PodStatus{
				PodIPs: []corev1.PodIP{{IP: "10.0.0.10"}},
			},
		},
		&corev1.Pod{
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.6",
			},
		},
		// Excluded-namespace pod: in neither the all (dst) nor local (src) sets.
		&corev1.Pod{
			Namespace: "kube-system",
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.7",
			},
		},
		&corev1.Pod{
			Status: corev1.PodStatus{
				Phase:  corev1.PodSucceeded,
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.8",
			},
		},
	}, []string{"10.0.0.1"}, parseExcludedNamespaces("kube-system"))

	if want := []string{"10.244.0.5", "10.244.0.6"}; !reflect.DeepEqual(sets.allIPv4, want) {
		t.Fatalf("IPv4 pod IPs = %#v, want %#v", sets.allIPv4, want)
	}
	if want := []string{"fd00::5"}; !reflect.DeepEqual(sets.allIPv6, want) {
		t.Fatalf("IPv6 pod IPs = %#v, want %#v", sets.allIPv6, want)
	}
	if want := []string{"10.244.0.5", "10.244.0.6"}; !reflect.DeepEqual(sets.localIPv4, want) {
		t.Fatalf("local IPv4 pod IPs = %#v, want %#v", sets.localIPv4, want)
	}
	if want := []string{"fd00::5"}; !reflect.DeepEqual(sets.localIPv6, want) {
		t.Fatalf("local IPv6 pod IPs = %#v, want %#v", sets.localIPv6, want)
	}
}

func TestCollectPodIPSetMembersCWPods(t *testing.T) {
	cwLabels := map[string]string{labelConfidentialWorkload: "vllm"}
	sets := collectPodIPSetMembers([]any{
		// Local cw pod: in the cw sets and the regular sets.
		&corev1.Pod{
			Labels: cwLabels,
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}, {IP: "fd00::5"}},
			},
		},
		// Remote cw pod: membership is cluster-wide.
		&corev1.Pod{
			Labels: cwLabels,
			Status: corev1.PodStatus{
				HostIP: "10.0.0.2",
				PodIP:  "10.244.1.9",
			},
		},
		// Unlabeled pod: regular sets only.
		&corev1.Pod{
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.6",
			},
		},
		// Empty label value: not a cw pod (managed Service selectors never
		// match an empty cw id).
		&corev1.Pod{
			Labels: map[string]string{labelConfidentialWorkload: ""},
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.7",
			},
		},
		// cw pod in an excluded namespace: out of the mesh, so in no set.
		&corev1.Pod{
			Namespace: "kube-system", Labels: cwLabels,
			Status: corev1.PodStatus{
				HostIP: "10.0.0.1",
				PodIP:  "10.244.0.99",
			},
		},
		// hostNetwork and completed cw pods: excluded like everywhere else.
		&corev1.Pod{
			Labels: cwLabels,
			Spec:   corev1.PodSpec{HostNetwork: true},
			Status: corev1.PodStatus{
				PodIP: "10.0.0.10",
			},
		},
		&corev1.Pod{
			Labels: cwLabels,
			Status: corev1.PodStatus{
				Phase: corev1.PodSucceeded,
				PodIP: "10.244.0.8",
			},
		},
	}, []string{"10.0.0.1"}, parseExcludedNamespaces("kube-system"))

	// 10.244.0.99 (cw pod in kube-system) is absent from both sets.
	if want := []string{"10.244.0.5", "10.244.1.9"}; !reflect.DeepEqual(sets.cwIPv4, want) {
		t.Fatalf("cw IPv4 pod IPs = %#v, want %#v", sets.cwIPv4, want)
	}
	if want := []string{"fd00::5"}; !reflect.DeepEqual(sets.cwIPv6, want) {
		t.Fatalf("cw IPv6 pod IPs = %#v, want %#v", sets.cwIPv6, want)
	}
	if want := []string{"10.244.0.5", "10.244.0.6", "10.244.0.7", "10.244.1.9"}; !reflect.DeepEqual(sets.allIPv4, want) {
		t.Fatalf("IPv4 pod IPs = %#v, want %#v", sets.allIPv4, want)
	}
}

func TestBuildIPSetRestoreScriptBatchesMembersWithMaxElem(t *testing.T) {
	script, err := buildIPSetRestoreScript("ARMTLS-MESH-PODS", "inet", []string{"10.244.0.5", "10.244.0.6"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"create ARMTLS-MESH-PODS hash:ip family inet maxelem 1024 -exist\n",
		"create ARMTLS-MESH-PODS-TMP hash:ip family inet maxelem 1024\n",
		"flush ARMTLS-MESH-PODS-TMP\n",
		"add ARMTLS-MESH-PODS-TMP 10.244.0.5 -exist\n",
		"add ARMTLS-MESH-PODS-TMP 10.244.0.6 -exist\n",
		"swap ARMTLS-MESH-PODS-TMP ARMTLS-MESH-PODS\n",
		"destroy ARMTLS-MESH-PODS-TMP\n",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("restore script missing %q\n%s", want, script)
		}
	}
}

func TestBuildIPSetRestoreScriptRejectsOversizedSet(t *testing.T) {
	_, err := buildIPSetRestoreScript("ARMTLS-MESH-PODS", "inet", []string{"10.244.0.5", "10.244.0.6"}, 1)
	if err == nil {
		t.Fatal("expected maxelem error")
	}
	if !strings.Contains(err.Error(), "exceeds maxelem 1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResetReadyFileRemovesStaleProbeMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "armtls-iptables-ready")
	if err := os.WriteFile(path, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := resetReadyFile(path); err != nil {
		t.Fatalf("resetReadyFile: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ready file still exists after reset: stat err=%v", err)
	}
	if err := resetReadyFile(path); err != nil {
		t.Fatalf("resetReadyFile should ignore already-removed path: %v", err)
	}
}

func TestParseNodeIPs(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		wantV4  string
		wantV6  string
		wantErr string
	}{
		{name: "single ipv4", in: []string{"10.0.0.1"}, wantV4: "10.0.0.1"},
		{name: "single ipv6", in: []string{"fd00::10"}, wantV6: "fd00::10"},
		{name: "dual stack", in: []string{"10.0.0.1", "fd00::10"}, wantV4: "10.0.0.1", wantV6: "fd00::10"},
		{name: "ipv6 non-canonical", in: []string{"fd00:0:0:0:0:0:0:10"}, wantV6: "fd00::10"},

		{name: "empty list", in: nil, wantErr: "at least one --node-ip required"},
		{name: "empty value", in: []string{""}, wantErr: "empty value"},
		{name: "whitespace value", in: []string{"   "}, wantErr: "empty value"},
		{name: "invalid literal", in: []string{"not-an-ip"}, wantErr: "not a valid IP"},
		{name: "ipv4 unspecified", in: []string{"0.0.0.0"}, wantErr: "unspecified"},
		{name: "ipv6 unspecified", in: []string{"::"}, wantErr: "unspecified"},
		{name: "ipv4 loopback", in: []string{"127.0.0.1"}, wantErr: "loopback"},
		{name: "ipv6 loopback", in: []string{"::1"}, wantErr: "loopback"},
		{name: "ipv4-mapped ipv6", in: []string{"::ffff:10.0.0.1"}, wantErr: "IPv4-in-IPv6"},
		{name: "ipv4-mapped ipv6 expanded", in: []string{"0:0:0:0:0:ffff:10.0.0.1"}, wantErr: "IPv4-in-IPv6"},
		{name: "ipv4-mapped ipv6 mixed case", in: []string{"::FFFF:10.0.0.1"}, wantErr: "IPv4-in-IPv6"},
		{name: "ipv4-mapped ipv6 all-hex", in: []string{"::ffff:a00:1"}, wantErr: "IPv4-in-IPv6"},
		{name: "ipv4-compatible ipv6 deprecated form", in: []string{"::1.2.3.4"}, wantErr: "IPv4-in-IPv6"},
		{name: "zone-scoped ipv6", in: []string{"fe80::1%eth0"}, wantErr: "zone-scoped"},
		// Ambiguity check runs AFTER ParseIP, so input that has both ':' and
		// '.' but is not a valid IP gets "not a valid IP", not the misleading
		// "IPv4-in-IPv6" error.
		{name: "ipv4 with port", in: []string{"10.0.0.1:15001"}, wantErr: "not a valid IP"},
		{name: "duplicate family", in: []string{"10.0.0.1", "10.0.0.2"}, wantErr: "multiple ipv4 addresses"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNodeIPs(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got[iptablesFamilyIPv4] != tt.wantV4 {
				t.Errorf("ipv4 = %q, want %q", got[iptablesFamilyIPv4], tt.wantV4)
			}
			if got[iptablesFamilyIPv6] != tt.wantV6 {
				t.Errorf("ipv6 = %q, want %q", got[iptablesFamilyIPv6], tt.wantV6)
			}
		})
	}
}

func TestNodeIPsAreLocal(t *testing.T) {
	mustCIDR := func(s string) *net.IPNet {
		t.Helper()
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("net.ParseCIDR(%q): %v", s, err)
		}
		return &net.IPNet{IP: ip, Mask: ipNet.Mask}
	}
	mustIP := func(s string) *net.IPAddr {
		t.Helper()
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("net.ParseIP(%q): nil", s)
		}
		return &net.IPAddr{IP: ip}
	}

	tests := []struct {
		name    string
		byFam   map[iptablesFamily]string
		addrs   []net.Addr
		wantErr string
	}{
		{
			name:  "ipv4 match via IPNet",
			byFam: map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.1"},
			addrs: []net.Addr{mustCIDR("10.0.0.1/24"), mustCIDR("127.0.0.1/8")},
		},
		{
			name:  "ipv6 match via IPNet",
			byFam: map[iptablesFamily]string{iptablesFamilyIPv6: "fd00::10"},
			addrs: []net.Addr{mustCIDR("fd00::10/64")},
		},
		{
			// Non-canonical IPv6 in the interface list still matches because
			// net.IP.String() canonicalizes the lookup-side form.
			name:  "ipv6 non-canonical IPNet matches canonical byFamily",
			byFam: map[iptablesFamily]string{iptablesFamilyIPv6: "fd00::10"},
			addrs: []net.Addr{mustCIDR("fd00:0:0:0:0:0:0:10/64")},
		},
		{
			name:  "match via IPAddr fallback",
			byFam: map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.1"},
			addrs: []net.Addr{mustIP("10.0.0.1")},
		},
		{
			name:  "dual stack match",
			byFam: map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.1", iptablesFamilyIPv6: "fd00::10"},
			addrs: []net.Addr{mustCIDR("10.0.0.1/24"), mustCIDR("fd00::10/64")},
		},
		{
			name:    "no match",
			byFam:   map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.5"},
			addrs:   []net.Addr{mustCIDR("10.0.0.1/24")},
			wantErr: "10.0.0.5 (ipv4) is not bound",
		},
		{
			name:    "partial match — ipv6 missing",
			byFam:   map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.1", iptablesFamilyIPv6: "fd00::10"},
			addrs:   []net.Addr{mustCIDR("10.0.0.1/24")},
			wantErr: "fd00::10 (ipv6) is not bound",
		},
		{
			name:    "empty addrs",
			byFam:   map[iptablesFamily]string{iptablesFamilyIPv4: "10.0.0.1"},
			addrs:   nil,
			wantErr: "is not bound",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := nodeIPsAreLocal(tt.byFam, tt.addrs)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseIPSetMaxElemHeader(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    int
		wantErr string
	}{
		{
			name: "ipset 7.x header with skbinfo and counters",
			out: `Name: ARMTLS-MESH-PODS
Type: hash:ip
Revision: 5
Header: family inet hashsize 1024 maxelem 262144 bucketsize 12 initval 0xdeadbeef
Size in memory: 408
References: 1
Number of entries: 3
`,
			want: 262144,
		},
		{
			name: "ipset 6.x minimal header",
			out: `Name: ARMTLS-MESH-PODS6
Type: hash:ip
Header: family inet6 hashsize 1024 maxelem 1024
`,
			want: 1024,
		},
		{
			name:    "no header line",
			out:     "Name: ARMTLS-MESH-PODS\nType: hash:ip\n",
			wantErr: "no header line",
		},
		{
			name:    "header missing maxelem",
			out:     "Header: family inet hashsize 1024\n",
			wantErr: "header missing maxelem",
		},
		{
			name:    "non-integer maxelem",
			out:     "Header: family inet hashsize 1024 maxelem oops\n",
			wantErr: "parse maxelem",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPSetMaxElemHeader(tt.out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("maxelem = %d; want %d", got, tt.want)
			}
		})
	}
}

// Membership is what the cw guard keys on, so a set that empties is
// enforcement that stopped. The counter is what separates that from a node
// that never had cw pods.
func TestRecordIPSetMembership_CountsShrinkNotSteadyState(t *testing.T) {
	lastPodIPSetMembers.Store(0)
	lastCWIPSetMembers.Store(0)
	cwIPSetShrinkages.Store(0)
	logger := slog.New(slog.DiscardHandler)

	// First reconcile establishes the level; there is no predecessor to shrink
	// from, so an initial zero must not read as a shrink.
	recordIPSetMembership(logger, 0, 0)
	if got := cwIPSetShrinks(); got != 0 {
		t.Fatalf("shrinks after first reconcile = %d, want 0", got)
	}

	recordIPSetMembership(logger, 5, 3)
	if got := cwIPSetMemberCount(); got != 3 {
		t.Errorf("cw members = %d, want 3", got)
	}
	if got := podIPSetMemberCount(); got != 5 {
		t.Errorf("pod members = %d, want 5", got)
	}
	if got := cwIPSetShrinks(); got != 0 {
		t.Errorf("growth counted as a shrink: %d", got)
	}

	// The case the metric exists for: the set comes back smaller, so those pods
	// are no longer guarded.
	recordIPSetMembership(logger, 5, 0)
	if got := cwIPSetShrinks(); got != 1 {
		t.Errorf("shrinks = %d, want 1", got)
	}
	if got := cwIPSetMemberCount(); got != 0 {
		t.Errorf("cw members = %d, want 0", got)
	}

	// A steady zero is not a repeated shrink — otherwise the counter climbs on
	// every reconcile of an idle node and the signal is worthless.
	recordIPSetMembership(logger, 5, 0)
	if got := cwIPSetShrinks(); got != 1 {
		t.Errorf("steady zero counted again: shrinks = %d, want 1", got)
	}
}

// The snapshot the proxy reads must carry the membership levels, or the
// gauges sit at zero while the sidecar knows better.
func TestIptablesMetricsSnapshot_CarriesIPSetMembership(t *testing.T) {
	lastPodIPSetMembers.Store(7)
	lastCWIPSetMembers.Store(2)
	cwIPSetShrinkages.Store(4)
	t.Cleanup(func() {
		lastPodIPSetMembers.Store(0)
		lastCWIPSetMembers.Store(0)
		cwIPSetShrinkages.Store(0)
	})

	snap := currentIptablesMetricsSnapshot()
	if snap.PodIPSetMembers != 7 {
		t.Errorf("PodIPSetMembers = %d, want 7", snap.PodIPSetMembers)
	}
	if snap.CWIPSetMembers != 2 {
		t.Errorf("CWIPSetMembers = %d, want 2", snap.CWIPSetMembers)
	}
	if snap.CWIPSetShrinks != 4 {
		t.Errorf("CWIPSetShrinks = %d, want 4", snap.CWIPSetShrinks)
	}
}
