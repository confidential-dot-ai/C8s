package cdsha

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// A cold replica applies a Genesis entry only with the mesh CA the operator
// signed into the decree. A peer that replays the cluster's real Genesis
// decree with a CA of its own gets it refused, on every replica.
func TestReplayedGenesisKeepsTheSignedCA(t *testing.T) {
	op, pub := operatorKey(t)
	genuine, own := mustCA(t), mustCA(t)
	sd := signDecree(t, op, Decree{Kind: Genesis, BootstrapNode: "n0", GenesisCA: caFP(genuine)})
	entry := func(ca *issuer.CA) Entry {
		return Entry{Kind: KindDecree, Decree: &DecreeEntry{Policy: newTestFSM(t, pub).LocalPolicy(), Decree: sd, AtMS: 1,
			Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: mustPKCS8(t, ca)}}
	}

	cold := newTestFSM(t, pub)
	res := applyAt(cold, 1, entry(own)).(DecreeResult)
	if res.Err == "" || cold.Core().Joined() {
		t.Fatalf("a replayed Genesis installed a CA the decree does not name (err %q, joined %v)", res.Err, cold.Core().Joined())
	}
	if res := applyAt(cold, 2, entry(genuine)).(DecreeResult); res.Err != "" || !cold.Core().Joined() {
		t.Fatalf("the Genesis with the signed CA: %q", res.Err)
	}
}
