package routes

import (
	"strings"
	"testing"

	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
)

// add-pattern and rm-pattern edit the patterns and keep the exact routes,
// and add and rm keep the patterns.
func TestPatternCommands(t *testing.T) {
	h := newHarness(t)
	h.mustRun(t, "add", "--new", "--host", "app.example", "--path", "/", "--address", "a:1", "--workload", "a")
	out := h.mustRun(t, "add-pattern", "--host-suffix", "agents.example", "--workload", "opencode", "--port", "4096")
	if !strings.Contains(out, "added pattern *.agents.example") {
		t.Fatalf("add-pattern printed %q", out)
	}
	if !strings.Contains(h.stderr.String(), "<label>.agents.example / prefix -> agent <label>, workload opencode, port 4096") {
		t.Errorf("re-sign listing %q omits the pattern", h.stderr.String())
	}
	h.mustRun(t, "add", "--host", "b.example", "--path", "/", "--address", "b:1", "--workload", "b")
	m := h.cds.stored(t)
	want := pkgroutes.Pattern{HostSuffix: "agents.example", Workload: "opencode", Port: 4096}
	if len(m.Patterns) != 1 || m.Patterns[0] != want || len(m.Hosts) != 2 {
		t.Fatalf("stored patterns %+v, hosts %d; want [%+v], 2", m.Patterns, len(m.Hosts), want)
	}
	h.mustRun(t, "add-pattern", "--host-suffix", "agents.example", "--workload", "opencode", "--port", "8080")
	if m := h.cds.stored(t); len(m.Patterns) != 1 || m.Patterns[0].Port != 8080 {
		t.Fatalf("replaced patterns = %+v", m.Patterns)
	}
	h.mustRun(t, "rm-pattern", "--host-suffix", "agents.example")
	if m := h.cds.stored(t); len(m.Patterns) != 0 || len(m.Hosts) != 2 {
		t.Fatalf("after rm-pattern: patterns %+v, hosts %d", m.Patterns, len(m.Hosts))
	}
	if _, err := h.run(t, "rm-pattern", "--host-suffix", "agents.example"); err == nil || !strings.Contains(err.Error(), "no pattern") {
		t.Fatalf("rm-pattern of a missing pattern = %v", err)
	}
}
