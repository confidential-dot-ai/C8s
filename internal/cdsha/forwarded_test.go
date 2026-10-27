package cdsha

import (
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// The leader commits only client writes that other replicas forward, and
// refuses everything else before it reaches the log: an entry no replica
// can apply would stop them all, and decrees, restores, CA renewals and
// format changes are the leader's own.
func TestLeaderCommitsOnlyForwardedClientWrites(t *testing.T) {
	s := newSolo(t, nil)
	n := s.node
	pinned := Claims{Measurement: "m1"}
	put := &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte("v")}
	marshal := func(e Entry) string {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	for _, tc := range []struct{ name, raw string }{
		{"not an entry", `"x"`},
		{"not an object", `[1]`},
		{"unknown field", `{"kind":"secret","secret":{"op":"put","path":"/p","value":"dg=="},"from_the_future":1}`},
		{"unknown kind", `{"kind":"from-the-future"}`},
		{"format", marshal(Entry{Kind: KindFormat, SetFormat: Format})},
		{"decree", marshal(Entry{Kind: KindDecree, Decree: &DecreeEntry{}})},
		{"restore", marshal(Entry{Kind: KindRestore, Restore: &RestoreEntry{}})},
		{"renew_ca", marshal(Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{}})},
		{"no payload", marshal(Entry{Kind: KindSecret})},
		{"two payloads", marshal(Entry{Kind: KindSecret, Secret: put, Binding: bindingAt("sb", "A", 1)})},
		{"client kind with a decree", marshal(Entry{Kind: KindSecret, Secret: put, Decree: &DecreeEntry{}})},
		{"entry format set", marshal(Entry{Kind: KindSecret, Format: Format, Secret: put})},
	} {
		before := n.fsm.AppliedIndex()
		resp := n.handleControl(pinned, controlRequest{Op: ctlApply, Entry: json.RawMessage(tc.raw)})
		if resp.Err == "" {
			t.Errorf("%s: committed: %+v", tc.name, resp)
		}
		if stuck := n.fsm.Stuck(); stuck != "" {
			t.Fatalf("%s: the leader stopped following the log: %s", tc.name, stuck)
		}
		if got := n.fsm.AppliedIndex(); got != before {
			t.Errorf("%s: applied index moved from %d to %d", tc.name, before, got)
		}
	}
	resp := n.handleControl(pinned, controlRequest{Op: ctlApply, Entry: json.RawMessage(marshal(Entry{Kind: KindSecret, Secret: put}))})
	if resp.Err != "" || n.fsm.Stuck() != "" {
		t.Fatalf("a forwarded secret write: %+v, stuck %q", resp, n.fsm.Stuck())
	}
}
