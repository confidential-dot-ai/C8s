//go:build c8s_dev

package cds

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// In c8s_dev builds the diagnostic routes answer while the replica is not
// serving; every serving route stays gated.
func TestDevDiagnosticsPassTheGate(t *testing.T) {
	orig := devUngated
	t.Cleanup(func() { devUngated = orig })
	devUngated = devDiagnosticPath
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gated := haGate(func() bool { return false }, ok)
	for path, want := range map[string]int{"/dev/pprof/goroutine": 200, "/dev/memstats": 200, "/allowlist": 503, "/dev/ha/secrets": 503, "/attest": 503} {
		w := httptest.NewRecorder()
		gated.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
	}
}
