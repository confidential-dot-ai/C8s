package allowlist

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const egressDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func egressDocument(egress string) []byte {
	return []byte(fmt.Sprintf(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":%q,"env":{"policy":"deny"}}]%s}}}`, egressDigest, egress))
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
		"local NAT64":     `[{"cidr":"64:ff9b:1::/48","port":443}]`,
		"IPv4-compatible": `[{"cidr":"::10.0.2.15/128","port":443}]`,
		"SIIT":            `[{"cidr":"::ffff:0:a00:20f/128","port":443}]`,
		"Teredo":          `[{"cidr":"2001:0:a00:1::/64","port":443}]`,
		"hostname cidr":   `[{"cidr":"relay.example.com","port":443}]`,
		"numeric cidr":    `[{"cidr":17,"port":443}]`,
		"negative port":   `[{"cidr":"203.0.113.7/32","port":-1}]`,
		"string port":     `[{"cidr":"203.0.113.7/32","port":"443"}]`,
		"not a list":      `{"cidr":"203.0.113.7/32","port":443}`,
		"null exit":       `[null]`,
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
			body := fmt.Sprintf(`{"containers":[{"digest":%q,"env":{"policy":"deny"}}],"egress":%s}`, egressDigest, egress)
			if _, err := ParseWorkloadJSON([]byte(body)); err == nil {
				t.Fatalf("ParseWorkloadJSON accepted egress %s", egress)
			}
		})
	}
}

// A node reading a served document drops exits it cannot validate or decode
// rather than every entry with them, or the document: the entry then grants no
// exit. An exit with a member this version does not know is dropped too, since
// that member may narrow it.
func TestServedEgressItCannotValidateIsDropped(t *testing.T) {
	for name, egress := range map[string]string{
		"host bits":      `[{"cidr":"203.0.113.7/24","port":443}]`,
		"hostname cidr":  `[{"cidr":"relay.example.com","port":443}]`,
		"numeric cidr":   `[{"cidr":17,"port":443}]`,
		"port too large": `[{"cidr":"203.0.113.7/32","port":70000}]`,
		"negative port":  `[{"cidr":"203.0.113.7/32","port":-1}]`,
		"string port":    `[{"cidr":"203.0.113.7/32","port":"443"}]`,
		"not a list":     `{"cidr":"203.0.113.7/32","port":443}`,
		"unknown member": `[{"cidr":"203.0.113.7/32","port":443,"protocol":"udp"}]`,
		"one bad exit":   `[{"cidr":"198.51.100.7/32","port":443},{"cidr":"203.0.113.7/32","port":"443"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			al, err := ParseServedJSON(egressDocument(`,"egress":` + egress))
			if err != nil {
				t.Fatalf("ParseServedJSON = %v, want the document kept", err)
			}
			w, ok := al.Workloads["w"]
			if !ok {
				t.Fatal("the entry was dropped, want only its egress dropped")
			}
			if w.Egress != nil {
				t.Fatalf("egress = %v, want it dropped", w.Egress)
			}
		})
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

// Exits need the launch pinned as a secrets grant does, or Trust Authority never signs
// them. A node reading a served document keeps them and checks again before it
// grants anything.
func TestEgressRequiresAPinnedLaunch(t *testing.T) {
	for name, container := range map[string]string{
		"args any":    `{"digest":%q,"args":{"policy":"any"},"env":{"policy":"deny"}}`,
		"command any": `{"digest":%q,"command":{"policy":"any"},"env":{"policy":"deny"}}`,
		"mounts any":  `{"digest":%q,"mounts":{"policy":"any"},"env":{"policy":"deny"}}`,
		"host mount":  `{"digest":%q,"mounts":{"policy":"exact","rules":[{"destination":"/etc/otel","kind":"host","source":"/etc/otel"}]},"env":{"policy":"deny"}}`,
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

// Exits need every container's env pinned too: application TLS is an exit's
// only protection, and a variable the host sets, such as HTTPS_PROXY or
// SSL_CERT_FILE, can redirect or disable it.
func TestPinnedForEgressEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		ok   bool
	}{
		{name: "absent", env: ``},
		{name: "any", env: `,"env":{"policy":"any"}`},
		{name: "present matcher", env: `,"env":{"policy":"match","variables":{"HOSTNAME":{"present":true}}}`},
		{name: "present beside exact", env: `,"env":{"policy":"match","variables":{"HOSTNAME":{"exact":"relay"},"HTTPS_PROXY":{"present":true}}}`},
		{name: "deny", env: `,"env":{"policy":"deny"}`, ok: true},
		{name: "exact", env: `,"env":{"policy":"exact","values":{"HOSTNAME":"relay"}}`, ok: true},
		{name: "exact matchers", env: `,"env":{"policy":"match","variables":{"HOSTNAME":{"exact":"relay"}}}`, ok: true},
		{name: "empty match", env: `,"env":{"policy":"match","variables":{}}`, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinned := fmt.Sprintf(`{"digest":%q,"command":{"policy":"exact","argv":["/run"]},"env":{"policy":"deny"}}`, egressDigest)
			container := fmt.Sprintf(`{"digest":%q%s}`, egressDigest, tc.env)
			entry := `{"initContainers":[` + pinned + `],"containers":[` + container + `],"egress":[{"cidr":"203.0.113.7/32","port":443}]}`
			doc := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":` + entry + `}}`)

			_, err := ParseJSON(doc)
			if tc.ok != (err == nil) {
				t.Fatalf("ParseJSON(%s) = %v, want ok %v", tc.env, err, tc.ok)
			}
			if !tc.ok && (!errors.Is(err, errEgressUnpinnedEnv) || !strings.Contains(err.Error(), `workload "w": container `+egressDigest)) {
				t.Fatalf("ParseJSON(%s) = %v, want errEgressUnpinnedEnv naming the entry and container", tc.env, err)
			}
			if _, err := ParseWorkloadJSON([]byte(entry)); tc.ok != (err == nil) {
				t.Fatalf("ParseWorkloadJSON(%s) = %v, want ok %v", tc.env, err, tc.ok)
			}
			served, err := ParseServedJSON(doc)
			if err != nil {
				t.Fatal(err)
			}
			err = served.Workloads["w"].PinnedForEgress()
			if tc.ok && err != nil || !tc.ok && !errors.Is(err, errEgressUnpinnedEnv) {
				t.Fatalf("served PinnedForEgress(%s) = %v, want ok %v", tc.env, err, tc.ok)
			}
		})
	}
}

// Service links let the host add variables a match policy does not list, so
// an entry with exits may not use them.
func TestPinnedForEgressRefusesServiceLinks(t *testing.T) {
	w := Workload{
		Containers: []Container{{
			Digest:  mustDigest(t, egressDigest),
			Command: ArgvPolicy{Policy: PolicyExact, Argv: []string{"/run"}},
			Args:    ArgvPolicy{Policy: PolicyDeny},
			Mounts:  MountPolicy{Policy: PolicyDeny},
			Env:     EnvPolicy{Policy: PolicyMatch, Variables: map[string]EnvMatcher{}, ServiceLinks: true},
		}},
		Egress: EgressList{{CIDR: netip.MustParsePrefix("203.0.113.7/32"), Port: 443}},
	}
	if err := w.PinnedForEgress(); !errors.Is(err, errEgressUnpinnedEnv) {
		t.Fatalf("PinnedForEgress(serviceLinks) = %v, want errEgressUnpinnedEnv", err)
	}
	w.Containers[0].Env.ServiceLinks = false
	if err := w.PinnedForEgress(); err != nil {
		t.Fatalf("PinnedForEgress(no serviceLinks) = %v, want nil", err)
	}
}

// A stored entry with exits that a newer rule refuses still reads for a
// write, so the write can repair or delete it; an unknown field still fails.
func TestParseStoredJSONKeepsEntryARuleNowRefuses(t *testing.T) {
	doc := []byte(fmt.Sprintf(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":%q}],"egress":[{"cidr":"203.0.113.7/32","port":443}]}}}`, egressDigest))
	if _, err := ParseJSON(doc); !errors.Is(err, errEgressUnpinnedEnv) {
		t.Fatalf("ParseJSON = %v, want errEgressUnpinnedEnv", err)
	}
	stored, err := ParseStoredJSON(doc)
	if err != nil {
		t.Fatalf("ParseStoredJSON = %v, want nil", err)
	}
	if w := stored.Workloads["w"]; len(w.Egress) != 1 {
		t.Fatalf("ParseStoredJSON entry = %+v, want its exit kept", w)
	}
	unknown := []byte(fmt.Sprintf(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":%q,"newField":1}]}}}`, egressDigest))
	if _, err := ParseStoredJSON(unknown); err == nil {
		t.Fatal("ParseStoredJSON(unknown field) = nil, want an error")
	}
}
