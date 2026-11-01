package workflows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// devTag turns on the CDS replica set, which a release serves as the
// singleton instead. A shipped binary that carried the tag would run as a
// replica on a cluster nobody has rolled out yet.
const devTag = "c8s_dev"

// shippedBuilds are the recipes that build a binary a CDS VM or a node
// measures: the Makefile's binaries, the images that carry them, and the
// workflows that publish them.
var shippedBuilds = []string{
	"../../Makefile",
	"../../cmd/c8s/Dockerfile",
	"../../cmd/cds/Dockerfile",
	"../../images/cds-guest/build",
	"../../images/cds-guest/cds/mkosi.sync",
	"../../.github/workflows/docker.yml",
	"../../.github/workflows/c8s-image.yml",
	"../../.github/workflows/c8s-image-publish.yml",
}

// No release build and no build the CDS image bakes carries the c8s_dev tag.
func TestShippedBuildsCarryNoDevTag(t *testing.T) {
	for _, recipe := range shippedBuilds {
		body, err := os.ReadFile(filepath.Clean(recipe))
		if err != nil {
			t.Fatalf("read %s: %v", recipe, err)
		}
		for number, line := range strings.Split(string(body), "\n") {
			if reachesTheCompiler(line) && strings.Contains(line, devTag) {
				t.Errorf("%s:%d builds a shipped binary with %s: %s", recipe, number+1, devTag, strings.TrimSpace(line))
			}
		}
	}
}

// reachesTheCompiler reports a line of a recipe that compiles Go, or that
// sets the environment a compilation reads its flags from.
func reachesTheCompiler(line string) bool {
	return strings.Contains(line, "go build") ||
		strings.Contains(line, "go install") ||
		strings.Contains(line, "make build-") ||
		strings.Contains(line, "GOFLAGS")
}
