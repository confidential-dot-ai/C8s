package workflows

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

var (
	pushesGuestRepository  = regexp.MustCompile(`IMAGE[=:] ?\S*confidential-dot-ai/guests/([a-z0-9-]+)`)
	aliasesGuestRepository = regexp.MustCompile(`record_release_aliases "\$GUESTS/([a-z0-9-]+)"`)
)

// A release alias copies a commit tag, so it lands only on a repository the build pushed.
func TestReleaseAliasesTheGuestRepositoriesTheBuildPushes(t *testing.T) {
	pushed := guestRepositories(t, "c8s-image.yml", pushesGuestRepository)
	aliased := guestRepositories(t, "c8s-image-publish.yml", aliasesGuestRepository)
	if !slices.Equal(pushed, aliased) {
		t.Errorf("c8s-image.yml pushes guests/%v, but c8s-image-publish.yml aliases guests/%v", pushed, aliased)
	}
}

func guestRepositories(t *testing.T, workflow string, namesRepository *regexp.Regexp) []string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("../../.github/workflows", workflow))
	if err != nil {
		t.Fatal(err)
	}
	var repositories []string
	for _, match := range namesRepository.FindAllSubmatch(body, -1) {
		repositories = append(repositories, string(match[1]))
	}
	if len(repositories) == 0 {
		t.Fatalf("%s names no guest image repository", workflow)
	}
	slices.Sort(repositories)
	return repositories
}
