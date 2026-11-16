package workflows

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// shippedBinaryPackage is what `make build-c8s` builds and every
// cmd/*/Dockerfile COPYs as build/c8s.
const shippedBinaryPackage = "./cmd/c8s"

// changesFilter is one dorny/paths-filter filter under `predicate-quantifier:
// every`: a file matches when it matches every positive pattern and no negated
// one.
type changesFilter struct {
	name     string
	positive []*regexp.Regexp
	negative []*regexp.Regexp
}

func (f changesFilter) matches(path string) bool {
	for _, pattern := range f.positive {
		if !pattern.MatchString(path) {
			return false
		}
	}
	for _, pattern := range f.negative {
		if pattern.MatchString(path) {
			return false
		}
	}
	return len(f.positive) > 0
}

// Every source the component images compile is classified by some filter, so a
// change to it rebuilds at least one image instead of being retagged onto a
// manifest that predates it.
func TestDockerChangesFiltersCoverShippedSources(t *testing.T) {
	filters := dockerChangesFilters(t)
	for _, path := range shippedSources(t) {
		matched := false
		for _, filter := range filters {
			if filter.matches(path) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("%s is compiled into every component image but matches no docker.yml changes filter", path)
		}
	}
}

func dockerChangesFilters(t *testing.T) []changesFilter {
	t.Helper()
	var raw string
	for _, step := range readWorkflow(t, "docker.yml").Jobs["changes"].Steps {
		if step.ID == "filter" {
			raw = step.With["filters"]
		}
	}
	if raw == "" {
		t.Fatal("docker.yml has no paths-filter step with id `filter`")
	}
	var byName map[string][]string
	if err := yaml.Unmarshal([]byte(raw), &byName); err != nil {
		t.Fatalf("parse docker.yml filters: %v", err)
	}
	var filters []changesFilter
	for name, globs := range byName {
		filter := changesFilter{name: name}
		for _, glob := range globs {
			pattern := regexp.MustCompile("^" + globRegexp(t, strings.TrimPrefix(glob, "!")) + "$")
			if strings.HasPrefix(glob, "!") {
				filter.negative = append(filter.negative, pattern)
			} else {
				filter.positive = append(filter.positive, pattern)
			}
		}
		filters = append(filters, filter)
	}
	return filters
}

// globRegexp translates the glob features these filters use — brace sets, `**`,
// `*` — into an anchored regular expression.
func globRegexp(t *testing.T, glob string) string {
	t.Helper()
	var out strings.Builder
	for i := 0; i < len(glob); {
		rest := glob[i:]
		switch {
		case rest[0] == '{':
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				t.Fatalf("unterminated brace set in %q", glob)
			}
			var alternatives []string
			for _, alternative := range strings.Split(rest[1:end], ",") {
				alternatives = append(alternatives, globRegexp(t, alternative))
			}
			out.WriteString("(?:" + strings.Join(alternatives, "|") + ")")
			i += end + 1
		case strings.HasPrefix(rest, "**/"):
			out.WriteString("(?:[^/]+/)*")
			i += 3
		case strings.HasPrefix(rest, "**"):
			out.WriteString(".*")
			i += 2
		case rest[0] == '*':
			out.WriteString("[^/]*")
			i++
		default:
			out.WriteString(regexp.QuoteMeta(rest[:1]))
			i++
		}
	}
	return out.String()
}

// shippedSources lists the module-relative Go sources and embedded inputs that
// the shipped binary compiles.
func shippedSources(t *testing.T) []string {
	t.Helper()
	const format = `{{if and .Module .Module.Main}}` +
		`{{range .GoFiles}}{{$.Module.Dir}}	{{$.Dir}}/{{.}}
{{end}}{{range .EmbedFiles}}{{$.Module.Dir}}	{{$.Dir}}/{{.}}
{{end}}{{end}}`
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", format, shippedBinaryPackage)
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", shippedBinaryPackage, err)
	}
	var sources []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		moduleDir, file, found := strings.Cut(line, "\t")
		if !found {
			continue
		}
		path, err := filepath.Rel(moduleDir, file)
		if err != nil {
			t.Fatalf("%s is outside %s: %v", file, moduleDir, err)
		}
		sources = append(sources, filepath.ToSlash(path))
	}
	if len(sources) == 0 {
		t.Fatalf("go list -deps %s reported no sources", shippedBinaryPackage)
	}
	return sources
}
