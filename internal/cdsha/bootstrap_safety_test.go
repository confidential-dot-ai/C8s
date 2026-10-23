package cdsha

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// Discovery failure is not evidence that an earlier cluster is absent.
func TestGenesisDiscoveryFailureFailsClosed(t *testing.T) {
	for _, unreachable := range []bool{false, true} {
		t.Run(fmt.Sprint(unreachable), func(t *testing.T) {
			key, pub := operatorKey(t)
			ds := newMemDecrees()
			cfg := soloConfig(t, "n0", freeAddr(t), pub, ds)
			cfg.Peers = func(context.Context) ([]string, error) {
				if unreachable {
					return []string{freeAddr(t)}, nil
				}
				return nil, errors.New("discovery unavailable")
			}
			n, err := NewNode(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := n.Start(); err != nil {
				t.Fatal(err)
			}
			defer n.shutdown()
			ds.put(signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "n0"}))
			n.joinOrBootstrap(context.Background())
			if n.fsm.Core().Joined() || n.member() {
				t.Fatal("discovery error allowed Genesis bootstrap")
			}
		})
	}
}
