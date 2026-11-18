package allowlist

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// componentSetDoc is a set file: a document holding one set with one entry,
// the shape a release publishes.
func componentSetDoc(version, digest string) string {
	return `{"schema":"c8s.allowlist/v1","components":{"` + version + `":{"entries":{"c8s-get-cert":{"containers":[{` +
		`"digest":"` + digest + `","role":"credentials",` +
		`"command":{"policy":"exact","argv":["/app/c8s","get-cert"]},"args":{"policy":"any"},` +
		`"mounts":{"policy":"exact","rules":[{"destination":"/run/c8s","kind":"emptyDir","source":"c8s-run"}]}}]}}}}}`
}

func mustSet(t *testing.T, version, digest string) pkgallowlist.ComponentSet {
	t.Helper()
	return mustParseAllowlist(t, componentSetDoc(version, digest)).Components[version]
}

// retiring is set with a deadline, as a write that retires it leaves it.
func retiring(t *testing.T, set pkgallowlist.ComponentSet, deadline string) pkgallowlist.ComponentSet {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, deadline)
	if err != nil {
		t.Fatalf("parse deadline %q: %v", deadline, err)
	}
	set.Retire = &pkgallowlist.Retirement{Deadline: pkgallowlist.Deadline{Time: parsed}}
	return set
}

func (f *fakeTA) seedSet(version string, set pkgallowlist.ComponentSet) {
	f.mu.Lock()
	if f.al.Components == nil {
		f.al.Components = map[string]pkgallowlist.ComponentSet{}
	}
	f.al.Components[version] = set
	f.mu.Unlock()
}

func (f *fakeTA) sets() map[string]pkgallowlist.ComponentSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.al.Components
}

// componentsTA is the fake Trust Authority with a pinned operator key, and the arguments
// every components write needs to reach it.
func componentsTA(t *testing.T) (*fakeTA, []string) {
	t.Helper()
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, ta := taTestServer(t, []*ecdsa.PublicKey{pub})
	return ta, []string{"--url", srv.URL, "--insecure", "--operator-key", keyPath}
}

const futureDeadline = "2099-12-01T00:00:00Z"

func TestComponentsAddPutsTheSetIn(t *testing.T) {
	ta, args := componentsTA(t)
	file := writeFile(t, "set.json", componentSetDoc("0.43.0", digA))

	out, _, err := runCmd(append([]string{"components", "add", "--set-file", file}, args...)...)
	if err != nil {
		t.Fatalf("components add: %v", err)
	}
	set, ok := ta.sets()["0.43.0"]
	if !ok {
		t.Fatalf("set 0.43.0 not written: %+v", ta.sets())
	}
	if !set.Current() {
		t.Fatal("the added set is not current")
	}
	if want := mustSet(t, "0.43.0", digA); set.DigestString() != want.DigestString() {
		t.Fatalf("set digest %s, want the file's %s", set.DigestString(), want.DigestString())
	}
	if !strings.Contains(out, "0.43.0") || !strings.Contains(out, "current") || !strings.Contains(out, set.DigestString()) {
		t.Fatalf("add does not report the set it wrote:\n%s", out)
	}
}

func TestComponentsAddRetiresAndRemoves(t *testing.T) {
	ta, args := componentsTA(t)
	ta.seedSet("0.41.0", mustSet(t, "0.41.0", digB))
	ta.seedSet("0.42.1", mustSet(t, "0.42.1", digC))
	file := writeFile(t, "set.json", componentSetDoc("0.43.0", digA))

	out, _, err := runCmd(append([]string{
		"components", "add", "--set-file", file,
		"--retire", "0.42.1=" + futureDeadline,
		"--remove", "0.41.0",
	}, args...)...)
	if err != nil {
		t.Fatalf("components add: %v", err)
	}
	sets := ta.sets()
	if _, ok := sets["0.41.0"]; ok {
		t.Fatal("the removed set is still in the allowlist")
	}
	retired, ok := sets["0.42.1"]
	if !ok || retired.Current() {
		t.Fatalf("set 0.42.1 was not retired: %+v", retired)
	}
	if got := retired.Retire.Deadline.UTC().Format(time.RFC3339); got != futureDeadline {
		t.Fatalf("deadline %s, want %s", got, futureDeadline)
	}
	if !strings.Contains(out, "retiring until "+futureDeadline) {
		t.Fatalf("add does not report the retiring set:\n%s", out)
	}
	if retired.DigestString() != mustSet(t, "0.42.1", digC).DigestString() {
		t.Fatal("retiring a set changed the bytes it names")
	}
}

func TestComponentsAddRefusals(t *testing.T) {
	tests := []struct {
		name  string
		flags []string
		file  string
		want  string
	}{
		{
			name: "the live allowlist already holds the version",
			file: componentSetDoc("0.42.1", digA),
			want: "already holds component set 0.42.1",
		},
		{
			name:  "an unknown version is retired",
			file:  componentSetDoc("0.43.0", digA),
			flags: []string{"--retire", "0.40.0=" + futureDeadline},
			want:  "holds no component set 0.40.0",
		},
		{
			name:  "an unknown version is removed",
			file:  componentSetDoc("0.43.0", digA),
			flags: []string{"--remove", "0.40.0"},
			want:  "holds no component set 0.40.0",
		},
		{
			name:  "the deadline has passed",
			file:  componentSetDoc("0.43.0", digA),
			flags: []string{"--retire", "0.42.1=2020-01-01T00:00:00Z"},
			want:  "has passed",
		},
		{
			name:  "the deadline is not the one spelling",
			file:  componentSetDoc("0.43.0", digA),
			flags: []string{"--retire", "0.42.1=2099-12-01T00:00:00+01:00"},
			want:  "second precision",
		},
		{
			name: "the set file names a deadline",
			file: `{"schema":"c8s.allowlist/v1","components":{"0.43.0":{"retire":{"deadline":"` + futureDeadline +
				`"},"entries":{}}}}`,
			want: "names a deadline",
		},
		{
			name: "the set file holds a workload entry",
			file: `{"schema":"c8s.allowlist/v1","workloads":{"web":{"containers":[` + ctrJSON(digD, "/app") +
				`]}},"components":{"0.43.0":{"entries":{}}}}`,
			want: "workload entr",
		},
		{
			name: "the set file holds two sets",
			file: `{"schema":"c8s.allowlist/v1","components":{"0.43.0":{"entries":{}},"0.44.0":{"entries":{}}}}`,
			want: "holds 2 component sets",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ta, args := componentsTA(t)
			ta.seedSet("0.42.1", mustSet(t, "0.42.1", digC))
			before := ta.currentVersion()
			file := writeFile(t, "set.json", tc.file)

			_, _, err := runCmd(append([]string{"components", "add", "--set-file", file}, append(tc.flags, args...)...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
			if got := ta.currentVersion(); got != before {
				t.Fatalf("the refused command wrote: version %d -> %d", before, got)
			}
		})
	}
}

func TestComponentsAddRetiringEverySetBefore(t *testing.T) {
	ta, args := componentsTA(t)
	ta.seedSet("0.42.1", mustSet(t, "0.42.1", digC))
	file := writeFile(t, "set.json", componentSetDoc("0.43.0", digA))

	_, _, err := runCmd(append([]string{
		"components", "add", "--set-file", file,
		"--retire", "0.42.1=" + futureDeadline,
	}, args...)...)
	if err != nil {
		t.Fatalf("components add --retire: %v", err)
	}
	added, ok := ta.sets()["0.43.0"]
	if !ok || !added.Current() {
		t.Fatalf("the added set is missing or retiring: %+v", added)
	}
}

func TestComponentsRetireUnretireRemove(t *testing.T) {
	ta, args := componentsTA(t)
	ta.seedSet("0.42.1", mustSet(t, "0.42.1", digC))
	ta.seedSet("0.43.0", mustSet(t, "0.43.0", digA))

	if _, _, err := runCmd(append([]string{"components", "retire", "0.42.1", futureDeadline}, args...)...); err != nil {
		t.Fatalf("components retire: %v", err)
	}
	if set := ta.sets()["0.42.1"]; set.Current() {
		t.Fatal("retire left the set current")
	}
	if _, _, err := runCmd(append([]string{"components", "unretire", "0.42.1"}, args...)...); err != nil {
		t.Fatalf("components unretire: %v", err)
	}
	if set := ta.sets()["0.42.1"]; !set.Current() {
		t.Fatal("unretire left the set retiring")
	}
	if _, _, err := runCmd(append([]string{"components", "remove", "0.42.1"}, args...)...); err != nil {
		t.Fatalf("components remove: %v", err)
	}
	if _, ok := ta.sets()["0.42.1"]; ok {
		t.Fatal("remove left the set in the allowlist")
	}
}

func TestComponentsSingleSetRefusals(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "retire an unknown version", args: []string{"retire", "0.40.0", futureDeadline}, want: "holds no component set"},
		{name: "unretire an unknown version", args: []string{"unretire", "0.40.0"}, want: "holds no component set"},
		{name: "remove an unknown version", args: []string{"remove", "0.40.0"}, want: "holds no component set"},
		{name: "retire the only current set", args: []string{"retire", "0.43.0", futureDeadline}, want: "no current component set"},
		{name: "remove the only current set", args: []string{"remove", "0.43.0"}, want: "no current component set"},
		{name: "retire past a deadline", args: []string{"retire", "0.43.0", "2020-01-01T00:00:00Z"}, want: "has passed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ta, args := componentsTA(t)
			ta.seedSet("0.43.0", mustSet(t, "0.43.0", digA))
			before := ta.currentVersion()

			_, _, err := runCmd(append(append([]string{"components"}, tc.args...), args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
			if got := ta.currentVersion(); got != before {
				t.Fatalf("the refused command wrote: version %d -> %d", before, got)
			}
		})
	}
}

// A write that landed since the read does not change what the command means:
// it makes the same change to the newer allowlist, keeping that write.
func TestComponentsAddAfterARacingWrite(t *testing.T) {
	ta, args := componentsTA(t)
	ta.seedSet("0.42.1", mustSet(t, "0.42.1", digC))
	raced := raceWrites(ta, 1, func(int) string { return "racer" }, workloadOf(t, 6))
	before := ta.currentVersion()
	file := writeFile(t, "set.json", componentSetDoc("0.43.0", digA))

	if _, _, err := runCmd(append([]string{
		"components", "add", "--set-file", file, "--remove", "0.42.1",
	}, args...)...); err != nil {
		t.Fatalf("components add after a racing write: %v", err)
	}
	if raced() != 1 {
		t.Fatalf("raced %d writes, want 1", raced())
	}
	if _, ok := ta.workload("racer"); !ok {
		t.Fatal("the racing write was overwritten")
	}
	sets := ta.sets()
	if _, ok := sets["0.43.0"]; !ok {
		t.Fatalf("the set was not written onto the newer allowlist: %+v", sets)
	}
	if _, ok := sets["0.42.1"]; ok {
		t.Fatal("the removed set came back with the newer allowlist")
	}
	if got := ta.currentVersion(); got != before+2 {
		t.Fatalf("version %d -> %d, want the racing write and one add", before, got)
	}
}

func TestComponentsList(t *testing.T) {
	al := mustParseAllowlist(t, componentSetDoc("0.43.0", digA))
	al.Components["0.42.1"] = retiring(t, mustSet(t, "0.42.1", digC), futureDeadline)
	al.Components["0.41.0"] = retiring(t, mustSet(t, "0.41.0", digB), "2020-01-01T00:00:00Z")
	url, _ := servingAllowlistTA(t, al)

	out, _, err := runCmd("components", "list", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("components list: %v", err)
	}
	if !strings.Contains(out, "component sets (3)") {
		t.Fatalf("missing the summary line:\n%s", out)
	}
	for _, want := range []string{
		"0.41.0", "ended 2020-01-01T00:00:00Z",
		"0.42.1", "retiring until " + futureDeadline,
		"0.43.0", "current",
		al.Components["0.43.0"].DigestString(),
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list output misses %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "0.43.0") < strings.Index(out, "0.41.0") {
		t.Fatalf("the sets are not in version order:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "0.43.0") && !strings.Contains(line, " 1 ") {
			t.Fatalf("the row does not count the set's entries: %q", line)
		}
	}
}

// Every write rebuilds the document from what it read, so a workload write
// keeps the component sets it does not name.
func TestWorkloadWritesKeepTheComponentSets(t *testing.T) {
	ta, args := componentsTA(t)
	ta.seedSet("0.43.0", mustSet(t, "0.43.0", digA))
	want := ta.sets()["0.43.0"].DigestString()
	file := writeFile(t, "entry.json", entryMap("web"))

	if _, _, err := runCmd(append([]string{"apply", file}, args...)...); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := ta.sets()["0.43.0"]; got.DigestString() != want || !got.Current() {
		t.Fatalf("apply changed the component sets: %+v", ta.sets())
	}
	if _, _, err := runCmd(append([]string{"delete", "web"}, args...)...); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := ta.sets()["0.43.0"]; got.DigestString() != want || !got.Current() {
		t.Fatalf("delete changed the component sets: %+v", ta.sets())
	}
}

// export writes the served bytes, component sets included, so a re-upload
// writes the same document.
func TestExportCarriesTheComponentSets(t *testing.T) {
	al := mustParseAllowlist(t, componentSetDoc("0.43.0", digA))
	url, _ := servingAllowlistTA(t, al)
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	path := writeFile(t, "export.json", "")

	if _, _, err := runCmd("export", path, "--url", url, "--insecure"); err != nil {
		t.Fatalf("export: %v", err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != string(canonical) {
		t.Fatalf("export wrote\n%s\nwant\n%s", written, canonical)
	}
}

func TestDiffShowsComponentSetChanges(t *testing.T) {
	live := mustParseAllowlist(t, componentSetDoc("0.42.1", digC))
	live.Components["0.41.0"] = mustSet(t, "0.41.0", digB)
	url, _ := servingAllowlistTA(t, live)

	desired := mustParseAllowlist(t, componentSetDoc("0.43.0", digA))
	desired.Components["0.42.1"] = retiring(t, mustSet(t, "0.42.1", digC), futureDeadline)
	data, err := desired.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	file := writeFile(t, "doc.json", string(data))

	out, _, err := runCmd("diff", file, "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	for _, want := range []string{
		"component sets:",
		"+ 0.43.0",
		"- 0.41.0",
		"~ 0.42.1",
		fmt.Sprintf("deadline: current -> %s", futureDeadline),
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("diff output misses %q:\n%s", want, out)
		}
	}
}
