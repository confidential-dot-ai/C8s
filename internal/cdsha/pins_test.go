package cdsha

import (
	"crypto/ecdsa"
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
	opKey, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	ca := mustCA(t)
	key, _ := x509.MarshalPKCS8PrivateKey(ca.Key)
	apply := func(i uint64, de DecreeEntry) {
		t.Helper()
		de.AtMS = time.Now().UnixMilli()
		if res := applyAt(f, i, Entry{Kind: KindDecree, Decree: &de}).(DecreeResult); res.Err != "" {
			t.Fatalf("entry %d: %s", i, res.Err)
		}
	}
	apply(1, DecreeEntry{Decree: signDecree(t, opKey, Decree{Kind: Genesis, BootstrapNode: "n0"}), Pins: []string{pinA}, RootCert: ca.Cert.Raw, Key: key})
	if f.Core().PinsDecree != nil {
		t.Fatal("a pin decree before any was applied")
	}
	ab := signDecree(t, opKey, Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: normalizePins([]string{pinA, pinB}), Images: []DecreeImage{a, b}})
	apply(2, DecreeEntry{Decree: ab})
	if sd := f.Core().PinsDecree; sd == nil || sd.Decree.IntentID != ab.Decree.IntentID {
		t.Fatalf("pin decree %+v", sd)
	}
	apply(3, DecreeEntry{Decree: signDecree(t, opKey, Decree{Kind: UpdateMeasurements, BaseEpoch: 2, Measurements: normalizePins([]string{pinA, pinB, "ee"})})})
	if f.Core().PinsDecree != nil {
		t.Fatal("a set without images kept the pin decree")
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
