package cdsha

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A replica that cannot certify reads says why: once when it stops, again
// only when the reason changes (and not more often than readOutageLogEvery),
// and once when it serves again.
func TestReadOutageLogsReasonsOnce(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var o readOutage
	count := func(s string) int { return strings.Count(buf.String(), s) }

	o.renewed(log)
	if buf.Len() != 0 {
		t.Fatalf("renewal without an outage logged: %s", buf.String())
	}
	o.failed(log, errors.New("cds-ha: no leader"))
	o.failed(log, errors.New("cds-ha: no leader"))
	o.failed(log, errors.New("cds-ha: read barrier timed out")) // changed, but within the interval
	if got := count("not serving"); got != 1 {
		t.Fatalf("%d outage lines, want 1:\n%s", got, buf.String())
	}
	if !strings.Contains(buf.String(), "no leader") {
		t.Fatalf("first reason missing:\n%s", buf.String())
	}
	o.logged = time.Now().Add(-readOutageLogEvery) // the interval has passed
	o.failed(log, errors.New("cds-ha: read barrier timed out"))
	if got := count("not serving"); got != 2 || !strings.Contains(buf.String(), "read barrier timed out") {
		t.Fatalf("changed reason not logged after the interval:\n%s", buf.String())
	}
	o.renewed(log)
	o.renewed(log)
	if got := count("certified again"); got != 1 {
		t.Fatalf("%d recovery lines, want 1:\n%s", got, buf.String())
	}
}

// Status carries the Raft term, so election churn is visible.
func TestStatusReportsTerm(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
	if st := l.node.Status(); st.Term == 0 || st.Term != l.node.r().CurrentTerm() {
		t.Fatalf("status term %d, raft term %d", st.Term, l.node.r().CurrentTerm())
	}
}
