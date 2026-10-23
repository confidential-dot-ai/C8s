package allowlist

import (
	"fmt"
	"strings"
	"testing"
)

// Host exits sort after ranges, by name then port, and keep the range
// encoding of existing documents.
func TestHostEgressIsCanonical(t *testing.T) {
	al, err := ParseJSON(egressDocument(`,"egress":[{"host":"huggingface.co","port":443},{"host":"*.xethub.hf.co","port":443},{"cidr":"203.0.113.7/32","port":443},{"host":"cdn-lfs.hf.co","port":443}]`))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `"egress":[{"cidr":"203.0.113.7/32","port":443},{"host":"*.xethub.hf.co","port":443},{"host":"cdn-lfs.hf.co","port":443},{"host":"huggingface.co","port":443}]`
	if !strings.Contains(string(canonical), want) {
		t.Fatalf("canonical = %s, want it to carry %s", canonical, want)
	}
	again, err := ParseJSON(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if round, _ := again.Canonical(); string(round) != string(canonical) {
		t.Fatalf("canonical bytes changed on a round trip:\n%s\n%s", canonical, round)
	}
}

func TestHostEgressAcceptsDNSNames(t *testing.T) {
	for _, host := range []string{
		"huggingface.co", "us.aws.cdn.hf.co", "*.xethub.hf.co", "*.hf.co", "a-b.example.com",
		"xn--bcher-kva.example", "login.microsoftonline.com", strings.Repeat("a", 63) + ".com",
	} {
		if _, err := ParseJSON(egressDocument(`,"egress":[{"host":"` + host + `","port":443}]`)); err != nil {
			t.Errorf("host %s: %v", host, err)
		}
	}
}

func TestHostEgressRefusesWhatIsNotAPublicName(t *testing.T) {
	for name, exit := range map[string]string{
		"empty host":          `{"host":"","port":443}`,
		"cidr and host":       `{"cidr":"203.0.113.7/32","host":"huggingface.co","port":443}`,
		"no port":             `{"host":"huggingface.co"}`,
		"upper case":          `{"host":"HuggingFace.co","port":443}`,
		"trailing dot":        `{"host":"huggingface.co.","port":443}`,
		"one label":           `{"host":"localhost","port":443}`,
		"IPv4 literal":        `{"host":"203.0.113.7","port":443}`,
		"IPv6 literal":        `{"host":"2001:db8::1","port":443}`,
		"numeric last label":  `{"host":"10.0.0.300","port":443}`,
		"bare wildcard":       `{"host":"*","port":443}`,
		"wildcard on a TLD":   `{"host":"*.com","port":443}`,
		"inner wildcard":      `{"host":"a.*.hf.co","port":443}`,
		"partial wildcard":    `{"host":"cdn*.hf.co","port":443}`,
		"double wildcard":     `{"host":"*.*.hf.co","port":443}`,
		"underscore":          `{"host":"a_b.example.com","port":443}`,
		"unicode":             `{"host":"bücher.example","port":443}`,
		"leading hyphen":      `{"host":"-a.example.com","port":443}`,
		"empty label":         `{"host":"a..example.com","port":443}`,
		"long label":          `{"host":"` + strings.Repeat("a", 64) + `.com","port":443}`,
		"long name":           `{"host":"` + strings.Repeat("abcdefghi.", 26) + `com","port":443}`,
		"bad punycode":        `{"host":"xn--a.example","port":443}`,
		"cluster service":     `{"host":"api.default.svc","port":443}`,
		"cluster domain":      `{"host":"api.default.svc.cluster.local","port":443}`,
		"localhost subdomain": `{"host":"a.localhost","port":443}`,
		"reverse zone":        `{"host":"1.0.0.127.in-addr.arpa","port":443}`,
		"declared twice":      `{"host":"huggingface.co","port":443},{"host":"huggingface.co","port":443}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJSON(egressDocument(`,"egress":[` + exit + `]`)); err == nil {
				t.Fatalf("ParseJSON accepted egress %s", exit)
			}
		})
	}
}

// The bound counts ranges and hosts together.
func TestHostEgressCountsTowardsTheBound(t *testing.T) {
	var many []string
	for i := 0; i < MaxEgress; i++ {
		many = append(many, fmt.Sprintf(`{"host":"h%d.example.com","port":443}`, i))
	}
	if _, err := ParseJSON(egressDocument(`,"egress":[` + strings.Join(many, ",") + `]`)); err != nil {
		t.Fatal(err)
	}
	many = append(many, `{"cidr":"203.0.113.7/32","port":443}`)
	if _, err := ParseJSON(egressDocument(`,"egress":[` + strings.Join(many, ",") + `]`)); err == nil {
		t.Fatal("ParseJSON accepted more exits than the bound")
	}
}

func TestMatchEgressHost(t *testing.T) {
	for _, c := range []struct {
		declared, name string
		want           bool
	}{
		{"huggingface.co", "huggingface.co", true},
		{"huggingface.co", "HuggingFace.CO.", true},
		{"huggingface.co", "www.huggingface.co", false},
		{"huggingface.co", "huggingface.co.evil.com", false},
		{"huggingface.co", "evilhuggingface.co", false},
		{"*.xethub.hf.co", "cas-server.xethub.hf.co", true},
		{"*.xethub.hf.co", "xethub.hf.co", false},
		{"*.xethub.hf.co", "a.b.xethub.hf.co", false},
		{"*.xethub.hf.co", ".xethub.hf.co", false},
		{"*.xethub.hf.co", "a.xethub-eu.hf.co", false},
		{"*.hf.co", "cdn-lfs.hf.co", true},
		{"*.hf.co", "us.aws.cdn.hf.co", false},
	} {
		if got := MatchEgressHost(c.declared, c.name); got != c.want {
			t.Errorf("MatchEgressHost(%q, %q) = %v, want %v", c.declared, c.name, got, c.want)
		}
	}
}
