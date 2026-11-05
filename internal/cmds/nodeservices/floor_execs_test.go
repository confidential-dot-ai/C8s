package nodeservices

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

// The node image's execs bind to the kube-apiserver RKE2 actually launched on
// each captured server, and to no other captured container: kube-scheduler,
// kube-controller-manager and kube-proxy run the same image.
func TestPreparedFloorGrantsExecsToKubeAPIServerAlone(t *testing.T) {
	entrypoints := capturedEntrypoints(t)
	for _, captured := range capturedNodes {
		index := envOpen(preparedFloor(t, captured.role, captured.node)).BuildIndex()
		granted := 0
		for _, launch := range capturedLaunches(t, captured.capture, captured.node.Name, entrypoints) {
			execs := index.ExecsOf(launch.running)
			switch apiserver := strings.HasPrefix(launch.name, "kube-apiserver-"); {
			case apiserver && len(execs) != 2:
				t.Errorf("node %s: %s is granted %q, want the livez and readyz probes", captured.node.Name, launch.name, execs)
			case !apiserver && execs != nil:
				t.Errorf("node %s: %s is granted %q", captured.node.Name, launch.name, execs)
			case apiserver:
				granted++
			}
		}
		want := 0
		if captured.role == launchconfig.Server {
			want = 1
		}
		if granted != want {
			t.Errorf("node %s: %d kube-apiserver launches are granted execs, want %d", captured.node.Name, granted, want)
		}
	}
}
