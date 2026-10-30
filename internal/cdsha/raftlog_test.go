package cdsha

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// Raft's info lines stay out of the replica log, except the ones saying a
// snapshot replaced a replica's state.
func TestRaftLogKeepsOnlySnapshotInfo(t *testing.T) {
	var buf bytes.Buffer
	l := hclog.New(&hclog.LoggerOptions{Name: "raft", Level: hclog.Info, DisableTime: true, Output: &buf, Exclude: raftQuiet})
	l.Info("Installed remote snapshot")
	l.Info("installing snapshot on", "peer", "x")
	l.Info("entering follower state", "follower", "x")
	l.Warn("heartbeat timeout reached, starting election")
	out := buf.String()
	for _, want := range []string{"Installed remote snapshot", "installing snapshot on", "heartbeat timeout reached"} {
		if !strings.Contains(out, want) {
			t.Errorf("raft log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "entering follower state") {
		t.Errorf("raft log keeps an ordinary info line:\n%s", out)
	}
}
