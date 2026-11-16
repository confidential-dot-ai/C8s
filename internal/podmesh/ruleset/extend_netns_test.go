//go:build linux

package ruleset

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// A pod granted exits after its start carries them from one transaction on:
// the exit is reached uncaptured, everything else stays as it was, and the
// live ruleset verifies against the extended policy and no longer against the
// one it was installed from.
func TestExtendAddsExitsToALiveRulesetInTheNamespace(t *testing.T) {
	podNetNS(t, func(netnsPath string) error {
		peer, err := startPeerNamespace()
		if err != nil {
			return err
		}
		defer peer.stop()
		if err := connectPeer(peer); err != nil {
			return err
		}
		base := behaviourPolicy()
		if err := Install(netnsPath, base); err != nil {
			return err
		}
		mesh, err := listenAs(meshUID, "127.0.0.1", base.Capture.Outbound)
		if err != nil {
			return err
		}
		defer mesh.Close()
		go acceptAll(mesh)

		relay := address(unapproved, 8080)
		if err := sendAs(workloadUID, "tcp", relay, firstSourcePort); err != nil {
			return err
		}
		if got, err := treatmentOf(base, "tcp", relay, firstSourcePort); err != nil || got != captured {
			t.Fatalf("before the grant the relay was %s (%v), want captured", got, err)
		}

		exits := []Exit{{netip.MustParsePrefix("10.9.0.8/29"), 8080}}
		if err := Extend(netnsPath, base, exits); err != nil {
			return err
		}
		extended := base
		extended.Exits = slices.Concat(base.Exits, exits)
		if err := Verify(netnsPath, extended); err != nil {
			t.Errorf("verify after extend = %v", err)
		}
		if err := Verify(netnsPath, base); !errors.Is(err, ErrMismatch) {
			t.Errorf("verify against the base after extend = %v, want ErrMismatch", err)
		}
		if err := Extend(netnsPath, base, exits); !errors.Is(err, ErrMismatch) {
			t.Errorf("extend from a ruleset that is no longer live = %v, want ErrMismatch", err)
		}

		for i, test := range []struct {
			name        string
			network     string
			destination string
			want        treatment
		}{
			{"the exit is reached uncaptured", "tcp", relay, admitted},
			{"another port in the range is captured", "tcp", address(unapproved, 53), captured},
			{"the exit carries no UDP", "udp", relay, denied},
		} {
			sourcePort := firstSourcePort + 1 + uint16(i)
			if err := sendAs(workloadUID, test.network, test.destination, sourcePort); err != nil {
				return err
			}
			got, err := treatmentOf(extended, test.network, test.destination, sourcePort)
			if err != nil {
				return err
			}
			if got != test.want {
				t.Errorf("%s: traffic was %s, want %s", test.name, got, test.want)
			}
		}
		return nil
	})
}

// Extend refuses an exit the ruleset cannot carry before touching the
// namespace.
func TestExtendRefusesAnInvalidExit(t *testing.T) {
	err := Extend("/nonexistent", testPolicy(), []Exit{{netip.MustParsePrefix("127.0.0.0/8"), 80}})
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("Extend = %v, want ErrPolicy", err)
	}
}
