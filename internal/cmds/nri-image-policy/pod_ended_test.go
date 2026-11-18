package nriimagepolicy

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
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

// A restart recomputes each pod's component sets from the containers it
// recovers, so a deadline passing afterwards still ends the whole pod. The
// pod stays ended: the set that admitted its containers is out of force, so
// admission refuses them again.
func TestARestartRecomputesComponentSetMembership(t *testing.T) {
	cdsTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := cdsTime.Add(time.Hour)
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}
	document := componentDocument(t, retiring, componentContainer(t, pushDigestA, allowlist.RoleMesh, meshArgv))
	p, killed := componentSetPlugin(t, func() time.Time { return cdsTime }, componentBase(), document)
	pod := meshPod("tenant", "inference-0", testNetNS)
	pod.Uid = "inference-0-uid"
	mesh := componentCtr(pod, "c8s-mesh", pushDigestA, meshArgv)

	p.running.add(pod, mesh)
	p.recoverExisting(t.Context(), []*api.PodSandbox{pod}, []*api.Container{mesh})
	p.recheckRunning(t.Context())
	if len(*killed) != 0 {
		t.Fatalf("killed %v while the recovered pod's set was in force", *killed)
	}

	cdsTime = deadline
	if !p.policy.rebuildEndedSets() {
		t.Fatal("the retiring set stayed in force past its deadline")
	}
	p.recheckRunning(t.Context())
	if !slices.Equal(*killed, []string{mesh.Id}) {
		t.Fatalf("killed %v, want the recovered pod on the ended set", *killed)
	}
	if err := p.StartContainer(t.Context(), pod, mesh); err == nil {
		t.Fatal("a container of an ended pod started again")
	}
}
