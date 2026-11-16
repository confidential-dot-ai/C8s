package nriimagepolicy

import (
	"errors"
	"path/filepath"
	"testing"
)

// An ended pod identity outlives the plugin that ended it: the next plugin of
// the boot reports it from the marker beside the boot gate's, and a node
// plugin, which has no pod, records nothing.
func TestEndedPodIdentityIsRetainedAcrossAPluginRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := gatedConfig(filepath.Join(dir, "registered"))
	cfg.Pod = &podConfig{UID: "assigned"}
	p := newTestPlugin(cfg)
	p.restorePodEnded()
	if p.podEnded.Load() {
		t.Fatal("a fresh boot reports an ended identity")
	}
	p.endPodIdentity(errors.New("plugin restarted"))
	if !p.podEnded.Load() {
		t.Fatal("ending the identity did not report it")
	}
	restarted := newTestPlugin(cfg)
	restarted.restorePodEnded()
	if !restarted.podEnded.Load() {
		t.Fatal("the next plugin of the boot forgot the ended identity")
	}
	node := newTestPlugin(gatedConfig(filepath.Join(t.TempDir(), "registered")))
	node.endPodIdentity(errors.New("no pod"))
	if marker := node.podEndedMarker(); marker != "" {
		t.Fatalf("a node plugin records an ended pod identity at %s", marker)
	}
}
