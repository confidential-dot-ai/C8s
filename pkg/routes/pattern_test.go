package routes

import (
	"net/http"
	"strings"
	"testing"
)

func patternManifest(patterns ...any) map[string]any {
	m := baseManifest("")
	delete(hostOf(m), "routes")
	hostOf(m)["routes"] = []any{map[string]any{"path": "/", "match": "prefix", "backend": map[string]any{
		"address": "vllm.ai.svc.cluster.local:8443", "workload": "vllm",
	}}}
	m["patterns"] = patterns
	return m
}

func agentPattern(suffix string) map[string]any {
	return map[string]any{"hostSuffix": suffix, "workload": "opencode", "port": 4096}
}

func TestParsePatterns(t *testing.T) {
	m, err := Parse(encode(t, patternManifest(agentPattern("agents.example"), agentPattern("b.agents.example"))))
	if err != nil {
		t.Fatal(err)
	}
	want := []Pattern{{"agents.example", "opencode", 4096}, {"b.agents.example", "opencode", 4096}}
	if len(m.Patterns) != 2 || m.Patterns[0] != want[0] || m.Patterns[1] != want[1] {
		t.Fatalf("Patterns = %+v, want %+v", m.Patterns, want)
	}
	noPatterns, err := Parse(readExample(t))
	if err != nil || noPatterns.Patterns != nil {
		t.Fatalf("Parse(example) = %+v, %v; want no patterns", noPatterns.Patterns, err)
	}
}

func TestParsePatternsRejects(t *testing.T) {
	long := strings.Repeat("a.", 113) + "example" // 233 octets
	tests := []struct {
		name     string
		patterns []any
		wantErr  string
	}{
		{"empty list", []any{}, "patterns: must not be empty"},
		{"duplicate suffix", []any{agentPattern("agents.example"), agentPattern("agents.example")}, "another pattern has host suffix"},
		{"upper-case suffix", []any{agentPattern("Agents.example")}, "hostSuffix"},
		{"suffix too long for a label", []any{agentPattern(long)}, "no room for an agent label"},
		{"IP suffix", []any{agentPattern("10.0.0.1")}, "hostSuffix"},
		{"bad workload", []any{map[string]any{"hostSuffix": "agents.example", "workload": "Not Valid", "port": 1}}, "not a valid allowlist workload name"},
		{"port zero", []any{map[string]any{"hostSuffix": "agents.example", "workload": "w", "port": 0}}, "port: must be an integer from 1 to 65535"},
		{"port too large", []any{map[string]any{"hostSuffix": "agents.example", "workload": "w", "port": 65536}}, "port: must be an integer"},
		{"unknown member", []any{map[string]any{"hostSuffix": "agents.example", "workload": "w", "port": 1, "path": "/"}}, `unknown member "path"`},
		{"missing port", []any{map[string]any{"hostSuffix": "agents.example", "workload": "w"}}, `missing member "port"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(encode(t, patternManifest(tt.patterns...)))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSelectPattern(t *testing.T) {
	const label = "abcdefghijklmnopqrstuvwxyz"
	m := testManifest(route("/", MatchPrefix, "root"))
	m.Patterns = []Pattern{{HostSuffix: "agents.example", Workload: "opencode", Port: 4096}}
	m.Hosts["exact.agents.example"] = Host{Routes: []Route{route("/", MatchPrefix, "pinned")}}
	table := Compile(m, testReserved)
	selectHost := func(host, target string) (Route, bool) {
		r, _ := http.NewRequest(http.MethodGet, "http://x"+target, nil)
		r.Host, r.RequestURI = host, target
		got, _, ok := table.Select(r)
		return got, ok
	}

	got, ok := selectHost(strings.ToUpper(label)+".agents.example:443", "/v1/chat?x=1")
	if b := got.Backend; !ok || b.Workload != "opencode" || b.AgentLabel != label || b.AgentPort != 4096 || b.Address != "" {
		t.Fatalf("pattern host selects %+v, %v; want workload opencode, label %s, port 4096, no address", b, ok, label)
	}
	if got, ok := selectHost("exact.agents.example", "/"); !ok || got.Backend.Workload != "pinned" {
		t.Errorf("exact host under a suffix selects %+v, %v; want the exact route", got.Backend, ok)
	}
	if got, ok := selectHost("app.example", "/"); !ok || got.Backend.Workload != "root" || got.Backend.AgentLabel != "" {
		t.Errorf("exact host selects %+v, %v; want its own route", got.Backend, ok)
	}
	for _, host := range []string{"agents.example", ".agents.example", label + ".x.agents.example", label + ".other.example"} {
		if got, ok := selectHost(host, "/"); ok {
			t.Errorf("host %q selects %+v, want none", host, got)
		}
	}
	if got, ok := selectHost(label+".agents.example", "/healthz"); ok {
		t.Errorf("reserved path selects %+v, want none", got)
	}
}
