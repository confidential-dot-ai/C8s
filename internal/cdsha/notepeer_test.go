package cdsha

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestNotePeerLogsOncePerProblem(t *testing.T) {
	var buf bytes.Buffer
	r := &Replica{log: slog.New(slog.NewTextHandler(&buf, nil))}
	for _, port := range []string{"51064", "59870", "43146"} {
		r.notePeer("10.0.0.2:9443 heartbeat", "peer not reached", errors.New("read tcp 10.0.0.1:"+port+"->10.0.0.2:9443: connection reset by peer"))
	}
	r.notePeer("10.0.0.2:9443 heartbeat", "", nil)
	r.notePeer("10.0.0.2:9443 heartbeat", "", nil)
	if n := strings.Count(buf.String(), "peer not reached"); n != 1 {
		t.Fatalf("logged %d times, want once:\n%s", n, buf.String())
	}
	if n := strings.Count(buf.String(), "peer problem cleared"); n != 1 {
		t.Fatalf("cleared logged %d times, want once", n)
	}
}
