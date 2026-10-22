package allowlist

import (
	"fmt"
	"strings"
	"testing"
)

const egressDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func egressDocument(egress string) []byte {
	return []byte(fmt.Sprintf(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":%q}]%s}}}`, egressDigest, egress))
}

// Exits are part of the signed canonical form, sorted, and absent from an
// entry that declares none, so existing documents keep their digests.
func TestEgressIsCanonicalAndOmittedWhenEmpty(t *testing.T) {
	al, err := ParseJSON(egressDocument(`,"egress":[{"cidr":"2001:db8::/32","port":443},{"cidr":"203.0.113.7/32","port":8443},{"cidr":"203.0.113.0/24","port":443}]`))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `"egress":[{"cidr":"203.0.113.0/24","port":443},{"cidr":"203.0.113.7/32","port":8443},{"cidr":"2001:db8::/32","port":443}]`
	if !strings.Contains(string(canonical), want) {
		t.Fatalf("canonical = %s, want it to carry %s", canonical, want)
	}

	for _, egress := range []string{``, `,"egress":[]`} {
		al, err := ParseJSON(egressDocument(egress))
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := al.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(canonical), "egress") {
			t.Fatalf("canonical = %s, want no egress key", canonical)
		}
	}
}

// A write is refused unless every exit is one TCP port on a masked range,
// within the bound, and declared once.
func TestEgressRefusesWhatARuleCannotExpress(t *testing.T) {
	var many []string
	for i := 0; i <= MaxEgress; i++ {
		many = append(many, fmt.Sprintf(`{"cidr":"203.0.113.%d/32","port":443}`, i))
	}
	for name, egress := range map[string]string{
		"no port":        `[{"cidr":"203.0.113.0/24"}]`,
		"port zero":      `[{"cidr":"203.0.113.0/24","port":0}]`,
		"port too large": `[{"cidr":"203.0.113.0/24","port":65536}]`,
		"no cidr":        `[{"port":443}]`,
		"bare address":   `[{"cidr":"203.0.113.7","port":443}]`,
		"host bits":      `[{"cidr":"203.0.113.7/24","port":443}]`,
		"4-in-6":         `[{"cidr":"::ffff:203.0.113.7/128","port":443}]`,
		"declared twice": `[{"cidr":"203.0.113.0/24","port":443},{"cidr":"203.0.113.0/24","port":443}]`,
		"unknown member": `[{"cidr":"203.0.113.0/24","port":443,"protocol":"udp"}]`,
		"too many exits": "[" + strings.Join(many, ",") + "]",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJSON(egressDocument(`,"egress":` + egress)); err == nil {
				t.Fatalf("ParseJSON accepted egress %s", egress)
			}
			body := fmt.Sprintf(`{"containers":[{"digest":%q}],"egress":%s}`, egressDigest, egress)
			if _, err := ParseWorkloadJSON([]byte(body)); err == nil {
				t.Fatalf("ParseWorkloadJSON accepted egress %s", egress)
			}
		})
	}
}

// A node reading a served document drops exits it cannot validate rather than
// every entry with them: the entry then grants no exit.
func TestServedEgressItCannotValidateIsDropped(t *testing.T) {
	al, err := ParseServedJSON(egressDocument(`,"egress":[{"cidr":"203.0.113.7/24","port":443}]`))
	if err != nil {
		t.Fatal(err)
	}
	if got := al.Workloads["w"].Egress; got != nil {
		t.Fatalf("egress = %v, want it dropped", got)
	}
}
