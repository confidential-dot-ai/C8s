//go:build !linux

package nriimagepolicy

import "testing"

// assertPodBootstrap drives the configured plugin over real NRI RPCs and a
// network namespace of the pod's own, which only Linux has.
func assertPodBootstrap(t *testing.T, _ *config, _ string, _ []byte, _ string) {
	t.Helper()
	t.Skip("NRI adaptation uses Linux peer credentials and the pod gate a Linux network namespace")
}
