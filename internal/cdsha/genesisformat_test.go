package cdsha

import (
	"crypto/x509"
	"testing"
	"time"
)

// A new cluster starts at the base format, whatever this replica could
// read: only the leader raises it, once every member reads the new one.
func TestGenesisStartsAtTheBaseFormat(t *testing.T) {
	opKey, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	ca := mustCA(t)
	key, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	g := DecreeEntry{Policy: f.LocalPolicy(), Decree: signDecree(t, opKey, Decree{Kind: Genesis, BootstrapNode: "n0", GenesisCA: caFP(ca)}),
		AtMS: time.Now().UnixMilli(), Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: key}
	if res := applyAt(f, 1, Entry{Kind: KindDecree, Decree: &g}).(DecreeResult); res.Err != "" {
		t.Fatalf("genesis: %+v", res)
	}
	if got := f.Core().Format; got != baseFormat {
		t.Fatalf("genesis agreed format %d, want the base format %d", got, baseFormat)
	}
}
