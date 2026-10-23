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
	al, err := ParseJSON(egressDocument(`,"egress":[{"cidr":"2001:DB8:1:0::/48","port":443},{"cidr":"203.0.113.7/32","port":8443},{"cidr":"203.0.113.0/24","port":443}]`))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `"egress":[{"cidr":"203.0.113.0/24","port":443},{"cidr":"203.0.113.7/32","port":8443},{"cidr":"2001:db8:1::/48","port":443}]`
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
		"no port":         `[{"cidr":"203.0.113.0/24"}]`,
		"port zero":       `[{"cidr":"203.0.113.0/24","port":0}]`,
		"port too large":  `[{"cidr":"203.0.113.0/24","port":65536}]`,
		"no cidr":         `[{"port":443}]`,
		"bare address":    `[{"cidr":"203.0.113.7","port":443}]`,
		"host bits":       `[{"cidr":"203.0.113.7/24","port":443}]`,
		"4-in-6":          `[{"cidr":"::ffff:203.0.113.7/128","port":443}]`,
		"declared twice":  `[{"cidr":"203.0.113.0/24","port":443},{"cidr":"203.0.113.0/24","port":443}]`,
		"unknown member":  `[{"cidr":"203.0.113.0/24","port":443,"protocol":"udp"}]`,
		"every address":   `[{"cidr":"0.0.0.0/0","port":443}]`,
		"every IPv6":      `[{"cidr":"::/0","port":443}]`,
		"over loopback":   `[{"cidr":"96.0.0.0/3","port":443}]`,
		"loopback":        `[{"cidr":"127.0.0.1/32","port":443}]`,
		"link-local":      `[{"cidr":"169.254.169.254/32","port":80}]`,
		"multicast":       `[{"cidr":"239.0.0.0/8","port":443}]`,
		"broadcast":       `[{"cidr":"255.255.255.255/32","port":443}]`,
		"unspecified":     `[{"cidr":"0.0.0.0/32","port":443}]`,
		"IPv6 loopback":   `[{"cidr":"::1/128","port":443}]`,
		"IPv6 link-local": `[{"cidr":"fe80::/64","port":443}]`,
		"NAT64":           `[{"cidr":"64:ff9b::a00:1/128","port":443}]`,
		"broad IPv4":      `[{"cidr":"10.0.0.0/8","port":443}]`,
		"just over /16":   `[{"cidr":"10.0.0.0/15","port":443}]`,
		"all global IPv6": `[{"cidr":"2000::/3","port":443}]`,
		"just over /48":   `[{"cidr":"2001:db8::/47","port":443}]`,
		"too many exits":  "[" + strings.Join(many, ",") + "]",
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

// Single addresses are the expected exit; a range is allowed down to /16
// (IPv4) and /48 (IPv6).
func TestEgressAcceptsSingleAddressesAndNarrowRanges(t *testing.T) {
	for _, cidr := range []string{"203.0.113.7/32", "198.51.0.0/16", "2001:db8::7/128", "2001:db8:1::/48"} {
		if _, err := ParseJSON(egressDocument(`,"egress":[{"cidr":"` + cidr + `","port":443}]`)); err != nil {
			t.Fatalf("exit %s: %v", cidr, err)
		}
	}
}

// Exits need the launch pinned as a secrets grant does, or CDS never signs
// them. A node reading a served document keeps them and checks again before it
// grants anything.
func TestEgressRequiresAPinnedLaunch(t *testing.T) {
	for name, container := range map[string]string{
		"args any":    `{"digest":%q,"args":{"policy":"any"}}`,
		"command any": `{"digest":%q,"command":{"policy":"any"}}`,
		"mounts any":  `{"digest":%q,"mounts":{"policy":"any"}}`,
		"host mount":  `{"digest":%q,"mounts":{"policy":"exact","rules":[{"destination":"/etc/otel","kind":"host","source":"/etc/otel"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			entry := fmt.Sprintf(`{"containers":[`+container+`],"egress":[{"cidr":"203.0.113.7/32","port":443}]}`, egressDigest)
			doc := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":` + entry + `}}`)
			if _, err := ParseJSON(doc); err == nil || !strings.Contains(err.Error(), "declared egress needs the launch pinned") {
				t.Fatalf("ParseJSON = %v, want a pin refusal", err)
			}
			if _, err := ParseWorkloadJSON([]byte(entry)); err == nil {
				t.Fatal("ParseWorkloadJSON accepted an unpinned entry with exits")
			}
			served, err := ParseServedJSON(doc)
			if err != nil {
				t.Fatal(err)
			}
			if w := served.Workloads["w"]; len(w.Egress) != 1 || w.PinnedForEgress() == nil {
				t.Fatalf("served entry = %+v, want its exit kept and reported unpinned", w)
			}
		})
	}
}
