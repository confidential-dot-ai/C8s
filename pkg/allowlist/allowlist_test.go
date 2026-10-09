package allowlist

import (
	"bytes"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const digestA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const digestC = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func TestParseJSON_Minimal(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"cds":{"containers":[
		{"digest":"`+digestA+`","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`)
	c := al.Workloads["cds"].Containers[0]
	if c.Digest.String() != digestA || !c.AnyArgv() {
		t.Fatalf("entry not parsed: %#v", al.Workloads)
	}
}

func TestParseJSON_RejectsUnknownSchema(t *testing.T) {
	_, err := ParseJSON([]byte(`{"schema":"other","workloads":{}}`))
	if err == nil || !strings.Contains(err.Error(), "unknown schema") {
		t.Fatalf("expected unknown schema error, got %v", err)
	}
}

func TestParseJSON_RejectsUnknownFields(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","surprise":1}`)); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

// A pre-unification digests map is an unknown field on the write path.
func TestParseJSON_RejectsLegacyDigestsField(t *testing.T) {
	doc := `{"schema":"c8s.allowlist/v1","digests":{"` + digestA + `":"cds"},"workloads":{}}`
	if _, err := ParseJSON([]byte(doc)); err == nil {
		t.Fatal("expected the legacy digests field to be rejected")
	}
}

// A grant is refused wherever a container's argv is left to the host, on both
// write paths; a served document is not rejected over it.
func TestParseJSON_SecretsRequirePinnedArgv(t *testing.T) {
	grant := `"secrets":{"policy":"allow","read":["/s"]}`
	for name, ctr := range map[string]string{
		"args any":      `{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"any"}}`,
		"command any":   `{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"deny"}}`,
		"init args any": `{"digest":"` + digestB + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}],"initContainers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"}}`,
	} {
		entry := `{"containers":[` + ctr + `],` + grant + `}`
		if _, err := ParseWorkloadJSON([]byte(entry)); err == nil || !strings.Contains(err.Error(), "exact or deny") {
			t.Errorf("%s: ParseWorkloadJSON = %v, want the grant refused", name, err)
		}
		doc := `{"schema":"c8s.allowlist/v1","workloads":{"w":` + entry + `}}`
		if _, err := ParseJSON([]byte(doc)); err == nil || !strings.Contains(err.Error(), "exact or deny") {
			t.Errorf("%s: ParseJSON = %v, want the grant refused", name, err)
		}
		if _, err := ParseServedJSON([]byte(doc)); err != nil {
			t.Errorf("%s: ParseServedJSON refused a served document: %v", name, err)
		}
	}

	pinned := `{"containers":[{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}],` + grant + `}`
	if _, err := ParseWorkloadJSON([]byte(pinned)); err != nil {
		t.Fatalf("a pinned entry with a grant was refused: %v", err)
	}
	if w, _ := ParseWorkloadJSON([]byte(`{"containers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"}}],"secrets":{"policy":"deny"}}`)); w == nil {
		t.Fatal("a deny grant releases nothing and is accepted on an unconstrained entry")
	}
}

// DigestEntryName must agree with the chart's c8s.digestWorkloadName for the
// same inputs; the chart test renders the same table.
func TestDigestEntryName(t *testing.T) {
	// Hex is canonical lowercase whatever case the digest was written in.
	d, err := types.ParseDigest("sha256:ABCDEF0000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	for image, want := range map[string]string{
		"ghcr.io/x/coredns:v1":                          "coredns-abcdef000000",
		"ghcr.io/confidential-dot-ai/cds@" + d.String(): "cds-abcdef000000",
		"registry:5000/team/app":                        "app-abcdef000000",
		"busybox":                                       "busybox-abcdef000000",
		"":                                              "image-abcdef000000",
		"ghcr.io/x/not a name!":                         "image-abcdef000000",
		"ghcr.io/x/" + strings.Repeat("y", 60):          strings.Repeat("y", 50) + "-abcdef000000",
	} {
		if got := DigestEntryName(d, image); got != want {
			t.Errorf("DigestEntryName(%q) = %q, want %q", image, got, want)
		}
		if !ValidWorkloadName(want) {
			t.Errorf("%q is not a valid entry name", want)
		}
	}
	if e := DigestEntry(d, "busybox"); len(e.Containers) != 1 || !e.Containers[0].AnyArgv() || e.Label != "busybox" || e.ArgvPinned() {
		t.Fatalf("DigestEntry = %#v, want one any/any container labelled busybox", e)
	}
}

func TestParseJSON_RejectsBadDigest(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"sha256:zz"}]}}}`)); err == nil {
		t.Fatal("expected invalid digest error")
	}
}

func TestParseJSON_AbsentPolicyDefaultsToDeny(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"`+digestA+`"}]}}}`)
	c := al.Workloads["w"].Containers[0]
	if c.Command.Policy != PolicyDeny || c.Args.Policy != PolicyDeny {
		t.Fatalf("absent policies should default to deny, got %#v", c)
	}
}

func TestParseJSON_ExactRequiresArgv(t *testing.T) {
	_, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + digestA + `","args":{"policy":"exact"}}]}}}`))
	if err == nil || !strings.Contains(err.Error(), "exact policy requires") {
		t.Fatalf("expected exact-needs-argv error, got %v", err)
	}
}

func TestParseJSON_DenyRejectsArgv(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + digestA + `","args":{"policy":"deny","argv":["x"]}}]}}}`)); err == nil {
		t.Fatal("expected deny-takes-no-argv error")
	}
}

func TestParseJSON_PathValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"relative", `"read":["etc/x"]`, false},
		{"dotdot", `"read":["/a/../b"]`, false},
		{"midglob", `"read":["/a/*/b"]`, false},
		{"subtree", `"read":["/a/**"]`, true},
		{"literal", `"read":["/secret"]`, true},
		{"write with read", `"read":["/r"],"write":["/secret"]`, true},
		{"write without read", `"write":["/secret"]`, false},
	} {
		body := `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` +
			digestA + `"}],"secrets":{"policy":"allow",` + tc.body + `}}}}`
		_, err := ParseJSON([]byte(body))
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestCanonical_OrderIndependent(t *testing.T) {
	a := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestB+`","args":{"policy":"any"}},
		{"digest":"`+digestA+`","args":{"policy":"any"}}]}}}`)
	b := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","args":{"policy":"any"}},
		{"digest":"`+digestB+`","args":{"policy":"any"}}]}}}`)
	da, _ := a.Canonical()
	db, _ := b.Canonical()
	if !bytes.Equal(da, db) {
		t.Fatal("canonical form depends on container order")
	}
}

func TestCanonical_FormattingIndependent(t *testing.T) {
	compact := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"`+digestA+`"}]}}}`)
	spaced := mustParse(t, "{\n  \"schema\": \"c8s.allowlist/v1\",\n  \"workloads\": {\"w\": {\"containers\": [{\"digest\": \""+digestA+"\"}]}}\n}")
	dc, _ := compact.Canonical()
	ds, _ := spaced.Canonical()
	if !bytes.Equal(dc, ds) {
		t.Fatal("canonical form depends on source formatting")
	}
}

func TestRoundTripCanonical(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1",
		"workloads":{"w":{"label":"img","containers":[
		{"digest":"`+digestB+`","command":{"policy":"exact","argv":["/app"]},
		 "args":{"policy":"deny"}}],"secrets":{"policy":"allow","read":["/s/**"]}}}}`)
	canon, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseJSON(canon)
	if err != nil {
		t.Fatalf("re-parse canonical: %v", err)
	}
	c2, _ := again.Canonical()
	if !bytes.Equal(canon, c2) {
		t.Fatalf("canonical form not stable across round-trip:\n%s\n%s", canon, c2)
	}
}

// Order independence alone would pass even if both parses sorted descending;
// pin the absolute ascending order.
func TestSortContainers_AscendingByDigest(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestB+`","args":{"policy":"any"}},
		{"digest":"`+digestA+`","args":{"policy":"any"}}]}}}`)
	cs := al.Workloads["w"].Containers
	if cs[0].Digest.String() != digestA || cs[1].Digest.String() != digestB {
		t.Fatalf("containers not sorted ascending by digest: %s, %s", cs[0].Digest, cs[1].Digest)
	}
}

func TestSortContainers_PolicyTieBreakAscending(t *testing.T) {
	// Same digest, distinct args policies; "any" sorts before "exact".
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","args":{"policy":"exact","argv":["x"]}},
		{"digest":"`+digestA+`","args":{"policy":"any"}}]}}}`)
	cs := al.Workloads["w"].Containers
	if cs[0].Args.Policy != PolicyAny || cs[1].Args.Policy != PolicyExact {
		t.Fatalf("policy tie-break wrong: %q, %q", cs[0].Args.Policy, cs[1].Args.Policy)
	}
}

func TestSortContainers_StableOnFullTie(t *testing.T) {
	// Image is not part of the sort key; a full tie must keep input order.
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[
		{"digest":"`+digestA+`","image":"zzz","args":{"policy":"any"}},
		{"digest":"`+digestA+`","image":"aaa","args":{"policy":"any"}}]}}}`)
	cs := al.Workloads["w"].Containers
	if cs[0].Image != "zzz" || cs[1].Image != "aaa" {
		t.Fatalf("tied containers reordered: %q, %q", cs[0].Image, cs[1].Image)
	}
}

func TestValidWorkloadName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"a", true},
		{"z", true},
		{"A", true},
		{"Z", true},
		{"0", true},
		{"9", true},
		{"a.b_c-d9", true},
		{"x.", true},
		{"x_", true},
		{"x-", true},
		{"", false},
		// Bytes adjacent to each accepted range.
		{"`", false},
		{"{", false},
		{"@", false},
		{"[", false},
		{"/", false},
		{":", false},
		// Separators are only valid after the first byte.
		{".x", false},
		{"_x", false},
		{"-x", false},
		{"a b", false},
		{"a/b", false},
	} {
		if got := ValidWorkloadName(tc.name); got != tc.ok {
			t.Errorf("ValidWorkloadName(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

func TestParseJSON_RejectsBadWorkloadName(t *testing.T) {
	body := `{"schema":"c8s.allowlist/v1","workloads":{"a/b":{"containers":[{"digest":"` + digestA + `"}]}}}`
	if _, err := ParseJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "workload name") {
		t.Fatalf("expected workload name error, got %v", err)
	}
}

func TestParseWorkloadJSON(t *testing.T) {
	w, err := ParseWorkloadJSON([]byte(`{"initContainers":[{"digest":"` + digestC + `"}],"containers":[
		{"digest":"` + digestB + `"},{"digest":"` + digestA + `"}]}`))
	if err != nil {
		t.Fatalf("ParseWorkloadJSON: %v", err)
	}
	if w == nil {
		t.Fatal("ParseWorkloadJSON returned nil workload without error")
	}
	if w.Containers[0].Digest.String() != digestA || w.Containers[1].Digest.String() != digestB {
		t.Fatalf("containers not sorted: %s, %s", w.Containers[0].Digest, w.Containers[1].Digest)
	}
	if w.InitContainers[0].Command.Policy != PolicyDeny {
		t.Fatalf("absent policy should default to deny, got %q", w.InitContainers[0].Command.Policy)
	}
}

func TestParseWorkloadJSON_Rejects(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unknown field", `{"containers":[],"surprise":1}`},
		{"init missing digest", `{"initContainers":[{"image":"x"}]}`},
		{"container missing digest", `{"containers":[{"image":"x"}]}`},
	} {
		if w, err := ParseWorkloadJSON([]byte(tc.body)); err == nil {
			t.Errorf("%s: expected error, got workload %#v", tc.name, w)
		}
	}
}

func TestWorkloadDigests(t *testing.T) {
	al := mustParse(t, `{"schema":"c8s.allowlist/v1","workloads":{"w":{
		"initContainers":[{"digest":"`+digestC+`"}],
		"containers":[{"digest":"`+digestA+`"},{"digest":"`+digestB+`"}]}}}`)
	got := al.Workloads["w"].Digests()
	want := []string{digestC, digestA, digestB}
	if len(got) != len(want) {
		t.Fatalf("Digests() returned %d digests, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("Digests()[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func mustParse(t *testing.T, s string) *Allowlist {
	t.Helper()
	al, err := ParseJSON([]byte(s))
	if err != nil {
		t.Fatalf("ParseJSON: %v\n%s", err, s)
	}
	return al
}

// The 63-byte bound arrived after entries could already be stored. A served
// document carrying one over-long legacy name must still parse — failing it
// would break every allowlist pull and every `c8s verify --allowlist` in the
// cluster over an entry nobody can reach — while the write path still refuses
// to create such a name.
func TestWorkloadNameBoundIsWritePathOnly(t *testing.T) {
	long := strings.Repeat("a", MaxWorkloadNameLen+1)
	body := `{"schema":"c8s.allowlist/v1","workloads":{
		"` + long + `":{"containers":[{"digest":"` + digestA + `"}]},
		"ok":{"containers":[{"digest":"` + digestB + `"}]}}}`

	if _, err := ParseJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "workload name") {
		t.Fatalf("ParseJSON accepted an over-long name: %v", err)
	}

	al, err := ParseServedJSON([]byte(body))
	if err != nil {
		t.Fatalf("ParseServedJSON failed the whole document over one legacy name: %v", err)
	}
	if _, ok := al.Workloads["ok"]; !ok {
		t.Fatal("the in-bound entry was lost")
	}
	// Dropped, not carried: it can never be stamped on a leaf, and leaving its
	// digests admitted would be the fail-open direction.
	if _, ok := al.Workloads[long]; ok {
		t.Fatal("the over-long entry survived a served parse")
	}
	if !ValidWorkloadName("ok") || ValidWorkloadName(long) {
		t.Fatal("ValidWorkloadName must still apply the bound")
	}
}

// The grammar itself is not relaxed on either path: the name is a URL path
// segment.
func TestParseServedJSON_StillRejectsBadWorkloadNameGrammar(t *testing.T) {
	body := `{"schema":"c8s.allowlist/v1","workloads":{"a/b":{"containers":[{"digest":"` + digestA + `"}]}}}`
	if _, err := ParseServedJSON([]byte(body)); err == nil || !strings.Contains(err.Error(), "workload name") {
		t.Fatalf("expected workload name error, got %v", err)
	}
}
