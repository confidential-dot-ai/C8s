package steps

import (
	"os/exec"
	"strings"
	"testing"
)

func TestRefusedByEndpoint(t *testing.T) {
	for _, tc := range []struct {
		r    dialReport
		want string // empty: refused by the endpoint
	}{
		{dialReport{TLS: true, Error: "remote error: tls: bad certificate"}, ""},
		{dialReport{TLS: false, Error: "dial tcp 10.0.0.2:40080: connect: connection refused"}, "tls"},
		{dialReport{TLS: true, Status: 200, Body: "hello"}, "status"},
		{dialReport{TLS: true, Error: "EOF"}, "alert"},
	} {
		err := refusedByEndpoint(tc.r)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("refusedByEndpoint(%+v) = %v, want a refusal", tc.r, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("refusedByEndpoint(%+v) = %v, want an error naming %q", tc.r, err, tc.want)
		}
	}
}

// TestWithExitStatusAfterHeredoc runs a script ending in a heredoc, as
// holdsCopiedLeaf writes, through sh: the status line must still print.
func TestWithExitStatusAfterHeredoc(t *testing.T) {
	out, err := exec.Command("sh", "-c", withExitStatus("cat > /dev/null <<'PEM'\nbody\nPEM")).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "rc=0") {
		t.Fatalf("output %q, %v; want rc=0", out, err)
	}
}

func TestChainRefusals(t *testing.T) {
	log := strings.Join([]string{
		`time=2026-11-04T10:00:00Z level=WARN msg="peer authentication failed" dir=inbound src=10.244.0.7:51234 error="armtls: mesh peer chain to a trusted mesh CA: x509: certificate signed by unknown authority"`,
		`{"level":"WARN","msg":"peer authentication failed","dir":"inbound","src":"10.244.0.7:40001","error":"armtls: mesh peer chain to a trusted mesh CA: x509: certificate signed by unknown authority"}`,
		// The endpoint's slog JSON handler writes src, a net.Addr, as an object.
		`{"time":"2026-11-05T12:36:18.880106828Z","level":"WARN","msg":"peer authentication failed","dir":"inbound","src":{"IP":"10.244.0.7","Port":33454,"Zone":""},"error":"armtls: mesh peer chain to a trusted mesh CA: x509: certificate signed by unknown authority"}`,
		`time=2026-11-04T10:00:01Z level=WARN msg="peer authentication failed" dir=inbound src=10.244.0.7:51235 error="armtls: peer negotiated protocol \"\", want \"c8s-mesh/1\""`,
		`time=2026-11-04T10:00:02Z level=WARN msg="peer authentication failed" dir=inbound src=10.244.0.71:51236 error="armtls: mesh peer chain to a trusted mesh CA: x509: certificate signed by unknown authority"`,
	}, "\n")
	if n := chainRefusals(log, "10.244.0.7"); n != 3 {
		t.Fatalf("chainRefusals = %d, want the 3 chain refusals of 10.244.0.7", n)
	}
}

// TestPeerFlagsSurviveExemptNamespace: the certificate choice is made before
// the pod is placed in the exempt namespace, which renames it.
func TestPeerFlagsSurviveExemptNamespace(t *testing.T) {
	p := &pod{name: "charlie"}
	w := &world{pods: map[string]*pod{"charlie": p}}
	if err := w.setPeerFlags("charlie", "--foreign-ca"); err != nil {
		t.Fatal(err)
	}
	p.name = "charlie-abc123"
	if flags, ok := w.peerFlags(p); !ok || len(flags) != 1 {
		t.Fatalf("peerFlags after rename = %q, %v", flags, ok)
	}
}
