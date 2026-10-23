package cdsha

import (
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"
)

func testImage(b byte) DecreeImage {
	h := func(c byte) string { return strings.Repeat(string("0123456789abcdef"[c%16]), 96) }
	return DecreeImage{MRTD: h(b), RTMR1: h(b + 1), RTMR2: h(b + 2)}
}

// A decree that names images is kept in the agreed state, for clients
// outside the group (GET /ha/pins); a later set without images drops it,
// so those clients are never told a set that is no longer in force.
func TestPinDecreeIsAgreedState(t *testing.T) {
	a, b := testImage(1), testImage(5)
	pinA, _ := a.Pin()
	pinB, _ := b.Pin()
	c := newCluster(t, 3)
	for _, n := range []string{"n0", "n1", "n2"} {
		c.start(n, pinA)
	}
	g := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
	eventually(t, 10*time.Second, "genesis", func() bool { st, ok := c.decrees.get(g); return ok && st.AppliedEpoch != nil })
	c.settled(15 * time.Second)
	for _, r := range c.live() {
		if r.node.Core().PinsDecree != nil {
			t.Fatal("a pin decree before any was applied")
		}
	}
	// Measurements that are not the images' pins are refused.
	bad := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: []string{pinA}, Images: []DecreeImage{a, b}})
	eventually(t, 10*time.Second, "mismatched decree rejected", func() bool { st, ok := c.decrees.get(bad); return ok && st.RejectedReason != "" })
	ab := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: normalizePins([]string{pinA, pinB}), Images: []DecreeImage{a, b}})
	eventually(t, 10*time.Second, "A+B applied", func() bool { st, ok := c.decrees.get(ab); return ok && st.AppliedEpoch != nil })
	for _, r := range c.live() {
		eventually(t, 3*time.Second, "pin decree on "+r.name, func() bool {
			sd := r.node.Core().PinsDecree
			return sd != nil && sd.Decree.BaseEpoch == 1 && len(sd.Decree.Images) == 2
		})
	}
	bare := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 2, Measurements: normalizePins([]string{pinA, pinB, "ee"})})
	eventually(t, 10*time.Second, "bare set applied", func() bool { st, ok := c.decrees.get(bare); return ok && st.AppliedEpoch != nil })
	for _, r := range c.live() {
		eventually(t, 3*time.Second, "pin decree dropped on "+r.name, func() bool { return r.node.Core().PinsDecree == nil })
	}
}

// A decree image's pin is exactly what a TDX replica on that image reports
// (NodeAttestor): otherwise a decree naming the running image would not
// keep its replicas pinned.
func TestDecreeImagePinIsTheReplicaMeasurement(t *testing.T) {
	img := testImage(1)
	pin, err := img.Pin()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ImagePin("tdx", img.MRTD, map[int]string{1: img.RTMR1, 2: img.RTMR2})
	if pin != want || pin != img.MRTD+":"+img.RTMR1+":"+img.RTMR2 {
		t.Fatalf("pin %q, replica reports %q", pin, want)
	}
	bad := img
	bad.RTMR1 = strings.Repeat("AB", 48)
	if _, err := bad.Pin(); err == nil {
		t.Fatal("uppercase register accepted")
	}
}

func TestVerifyPinDecree(t *testing.T) {
	k, pub := operatorKey(t)
	other, _ := operatorKey(t)
	a, b := testImage(1), testImage(5)
	pinA, _ := a.Pin()
	pinB, _ := b.Pin()
	sign := func(key *ecdsa.PrivateKey, d Decree) SignedDecree {
		d.ExpiresAt = time.Now().Add(-time.Hour) // expired: clients ignore expiry
		return signDecree(t, key, d)
	}
	good := sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA, pinB}, Images: []DecreeImage{a, b}})
	if err := VerifyPinDecree(good, testCluster, pub); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		sd   SignedDecree
		want string
	}{
		"other cluster":   {good, "cluster"},
		"other key":       {sign(other, good.Decree), "signature"},
		"no images":       {sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA}}), "no images"},
		"genesis":         {sign(k, Decree{ClusterID: testCluster, Kind: Genesis, BootstrapNode: "n0", Images: []DecreeImage{a}}), "not exactly the pins"},
		"pins not images": {sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA}, Images: []DecreeImage{b}}), "not exactly the pins"},
		"bad image":       {sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{"x"}, Images: []DecreeImage{{MRTD: "zz"}}}), "lowercase hex"},
	} {
		cluster := testCluster
		if name == "other cluster" {
			cluster = "elsewhere"
		}
		if err := VerifyPinDecree(c.sd, cluster, pub); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
