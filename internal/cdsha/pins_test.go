package cdsha

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
		if r.node.PinsDecree() != nil {
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
			sd := r.node.PinsDecree()
			return sd != nil && sd.Decree.BaseEpoch == 1 && len(sd.Decree.Images) == 2
		})
	}
	bare := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 2, Measurements: normalizePins([]string{pinA, pinB, "ee"})})
	eventually(t, 10*time.Second, "bare set applied", func() bool { st, ok := c.decrees.get(bare); return ok && st.AppliedEpoch != nil })
	for _, r := range c.live() {
		eventually(t, 3*time.Second, "pin decree dropped on "+r.name, func() bool { return r.node.PinsDecree() == nil })
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
		t.Helper()
		d.IntentID, d.ExpiresAt = "i", time.Now().Add(-time.Hour) // expired: clients ignore expiry
		sd, err := SignDecree(d, key)
		if err != nil {
			t.Fatal(err)
		}
		return sd
	}
	good := sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA, pinB}, Images: []DecreeImage{a, b}})
	if err := VerifyPinDecree(good, testCluster, pub); err != nil {
		t.Fatal(err)
	}
	for name, sd := range map[string]SignedDecree{
		"other cluster":   good,
		"other key":       sign(other, good.Decree),
		"no images":       sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA}}),
		"genesis":         sign(k, Decree{ClusterID: testCluster, Kind: Genesis, BootstrapNode: "n0", Images: []DecreeImage{a}}),
		"pins not images": sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{pinA}, Images: []DecreeImage{b}}),
		"bad image":       sign(k, Decree{ClusterID: testCluster, BaseEpoch: 4, Kind: UpdateMeasurements, Measurements: []string{"x"}, Images: []DecreeImage{{MRTD: "zz"}}}),
	} {
		cluster := testCluster
		if name == "other cluster" {
			cluster = "elsewhere"
		}
		if err := VerifyPinDecree(sd, cluster, pub); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// Every refusal branch of the decree check, one decree each.
func TestVerifyDecreeRefusals(t *testing.T) {
	k, pub := operatorKey(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	img := testImage(1)
	pin, _ := img.Pin()
	tail := Core{ClusterID: testCluster, OperatorPubKey: pub, Epoch: 3, RootCert: []byte{1}, AppliedDecrees: []string{"done"}}
	sign := func(d Decree) SignedDecree {
		t.Helper()
		if d.ClusterID == "" {
			d.ClusterID = testCluster
		}
		if d.IntentID == "" {
			d.IntentID = "i"
		}
		sd, err := SignDecree(d, k)
		if err != nil {
			t.Fatal(err)
		}
		return sd
	}
	ok := sign(Decree{BaseEpoch: 3, Kind: UpdateMeasurements, Measurements: []string{pin}, Images: []DecreeImage{img}})
	if err := verifyDecree(ok, tail); err != nil {
		t.Fatal(err)
	}
	noncanon := sign(Decree{BaseEpoch: 3, Kind: UpdateMeasurements, Measurements: []string{"a"}})
	noncanon.Decree.Measurements = []string{"b", "a"}
	cases := map[string]struct {
		sd   SignedDecree
		tail Core
	}{
		"no key":            {ok, Core{ClusterID: testCluster}},
		"not PKIX":          {ok, Core{ClusterID: testCluster, OperatorPubKey: []byte("x")}},
		"not ECDSA":         {ok, Core{ClusterID: testCluster, OperatorPubKey: rsaDER}},
		"empty intent":      {func() SignedDecree { d := ok; d.Decree.IntentID = ""; return d }(), tail},
		"already applied":   {sign(Decree{IntentID: "done", BaseEpoch: 3, Kind: RotateKey}), tail},
		"empty set":         {sign(Decree{BaseEpoch: 3, Kind: UpdateMeasurements}), tail},
		"genesis with key":  {sign(Decree{Kind: Genesis, BaseEpoch: 3, BootstrapNode: "n0"}), tail},
		"restore no hash":   {sign(Decree{Kind: Restore, BaseEpoch: 3, BootstrapNode: "n0"}), Core{ClusterID: testCluster, OperatorPubKey: pub, Epoch: 3}},
		"genesis no node":   {sign(Decree{Kind: Genesis, BaseEpoch: 3}), Core{ClusterID: testCluster, OperatorPubKey: pub, Epoch: 3}},
		"node on rotate":    {sign(Decree{Kind: RotateKey, BaseEpoch: 3, BootstrapNode: "n0"}), tail},
		"recover with set":  {sign(Decree{Kind: Recover, BaseEpoch: 3, BootstrapNode: "n0", Measurements: []string{pin}}), tail},
		"unknown kind":      {sign(Decree{Kind: "Nope", BaseEpoch: 3}), tail},
		"non-canonical":     {noncanon, tail},
		"images on recover": {sign(Decree{Kind: Recover, BaseEpoch: 3, BootstrapNode: "n0", Images: []DecreeImage{img}}), tail},
		"voters even":       {sign(Decree{Kind: SetVoters, BaseEpoch: 3, Voters: 2}), tail},
		"voters too many":   {sign(Decree{Kind: SetVoters, BaseEpoch: 3, Voters: MaxVoters + 2}), tail},
		"voters on update":  {sign(Decree{Kind: UpdateMeasurements, BaseEpoch: 3, Measurements: []string{pin}, Voters: 3}), tail},
		"set voters no n":   {sign(Decree{Kind: SetVoters, BaseEpoch: 3}), tail},
		"voters pre-key":    {sign(Decree{Kind: SetVoters, BaseEpoch: 3, Voters: 3}), Core{ClusterID: testCluster, OperatorPubKey: pub, Epoch: 3}},
		"voters with set":   {sign(Decree{Kind: SetVoters, BaseEpoch: 3, Voters: 3, Measurements: []string{pin}}), tail},
	}
	for name, c := range cases {
		if err := verifyDecree(c.sd, c.tail); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
