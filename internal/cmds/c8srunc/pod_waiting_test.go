package c8srunc

import (
	"bytes"
	"testing"
)

func TestWaitingPodRefusesRuntimeCreateAndStart(t *testing.T) {
	for _, verb := range []string{"create", "start", "run"} {
		rec, stderr := &recorder{}, &bytes.Buffer{}
		w := podWrapper(rec, stderr)
		w.Floor.PodWaiting = true
		if code := w.Run([]string{"c8s-runc", verb, "pause"}); code != exitDenied || rec.called {
			t.Fatalf("waiting guest dispatched %s", verb)
		}
	}
}
