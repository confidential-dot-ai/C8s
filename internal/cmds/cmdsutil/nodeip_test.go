package cmdsutil

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A component restarts once the node address it dials is replaced, but not on
// a value it reads once, since the plugin's in-place write can be caught half
// done, nor when the file holds no address.
func TestWatchNodeIP(t *testing.T) {
	const want = "http://192.0.2.10:8080"
	for _, tc := range []struct {
		name    string
		reads   []string
		restart bool
	}{
		{"unchanged", []string{want, want, want}, false},
		{"one torn read", []string{want, "http://192.0.2.1:8080", want, want}, false},
		{"two different torn reads", []string{"http://192.0.2.1:8080", "http://192.0.2.11", want}, false},
		{"changed", []string{want, "http://192.0.2.11:8080", "http://192.0.2.11:8080"}, true},
		{"emptied", []string{"", "", ""}, false},
		{"emptied between changes", []string{"http://192.0.2.11:8080", "", "http://192.0.2.11:8080"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			tick := make(chan time.Time)
			reads := make(chan string, len(tc.reads)+1)
			for _, r := range append(tc.reads, want) {
				reads <- r
			}
			done := make(chan struct{})
			go func() {
				watchNodeIP(ctx, cancel, tick, want, func() (string, error) {
					if r := <-reads; r != "" {
						return r, nil
					}
					return "", errors.New("no address")
				})
				close(done)
			}()
			for range tc.reads {
				select {
				case tick <- time.Time{}:
				case <-done:
				}
			}
			if tc.restart {
				<-done
				if err := NodeIPChanged(ctx, nil); !errors.Is(err, ErrNodeIPChanged) {
					t.Fatalf("NodeIPChanged() = %v, want ErrNodeIPChanged", err)
				}
				return
			}
			// The send returns once the watcher is back waiting, so every read
			// above has been handled.
			tick <- time.Time{}
			if err := NodeIPChanged(ctx, nil); err != nil {
				t.Fatalf("NodeIPChanged() = %v after %q, want nil", err, tc.reads)
			}
		})
	}
}
