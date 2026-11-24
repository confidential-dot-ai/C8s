package helmchart

import (
	"slices"
	"strings"
	"testing"
)

// volumedPrefix starts the seeded volumed entry's name; the rest hashes its content.
const volumedPrefix = "c8s-volumed-"

// The worker lane's volumed DaemonSet resolves to its seeded entry, which the
// release publishes as the node service, and that entry admits no other
// launch of the same image.
func TestWorkerChartVolumedMatchesSeededEntry(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateWorker(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	var name string
	for entry := range seed.Workloads {
		if strings.HasPrefix(entry, volumedPrefix) {
			name = entry
		}
	}
	if name == "" {
		t.Fatalf("the seed holds no %s* entry", volumedPrefix)
	}
	pod := renderedDaemonSet(t, out, "c8s-volumed").Spec.Template.Spec
	reported := running(t, seed, pod)
	if got, err := match(seed, reported); err != nil || got != name {
		t.Fatalf("MatchWorkload(volumed) = %q, %v, want %q", got, err, name)
	}
	flagged := slices.Clone(reported)
	flagged[0].Argv = append(slices.Clone(flagged[0].Argv), "--max-mounts=1")
	if got, err := match(seed, flagged); err == nil {
		t.Errorf("a volumed launch carrying another flag matched %q, want no match", got)
	}
}
