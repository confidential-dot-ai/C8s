package cmdsutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ErrNodeIPChanged is the cause WatchNodeIP cancels its context with.
var ErrNodeIPChanged = errors.New("the node address changed: restarting to dial the new attestation-api")

// nodeIPPollInterval is how often WatchNodeIP rereads NodeIPPath.
const nodeIPPollInterval = 15 * time.Second

// WatchNodeIP returns a context that is canceled with ErrNodeIPChanged once
// rawURL expands to another address than expanded. The image policy plugin
// rewrites NodeIPPath in place when the node's address changes, and a
// component dials the address it expanded at startup, so it restarts to pick
// up the new one. A file that is unreadable or holds no address keeps the
// component on the address it has: a restart could not expand one either.
// rawURL without $(NODE_IP) returns ctx unchanged. Return the component's
// final error through NodeIPChanged.
func WatchNodeIP(ctx context.Context, rawURL, expanded string) context.Context {
	if !strings.Contains(rawURL, NodeIPReference) {
		return ctx
	}
	ctx, cancel := context.WithCancelCause(ctx)
	ticker := time.NewTicker(nodeIPPollInterval)
	go func() {
		defer ticker.Stop()
		watchNodeIP(ctx, cancel, ticker.C, expanded, func() (string, error) {
			return expandNodeAddress(rawURL, NodeIPPath, os.Getenv)
		})
	}()
	return ctx
}

// watchNodeIP cancels ctx once expand returns the same value other than want
// on two consecutive ticks: a reader can catch the plugin's in-place write
// half done. An expand error is no value.
func watchNodeIP(ctx context.Context, cancel context.CancelCauseFunc, tick <-chan time.Time, want string, expand func() (string, error)) {
	var last string
	seen := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		got, err := expand()
		if err != nil || got == want {
			seen = false
			continue
		}
		if seen && got == last {
			cancel(fmt.Errorf("%w (now %s)", ErrNodeIPChanged, got))
			return
		}
		last, seen = got, true
	}
}

// NodeIPChanged returns ctx's cause when WatchNodeIP canceled it, else err, so
// the component exits non-zero and the kubelet restarts it.
func NodeIPChanged(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); errors.Is(cause, ErrNodeIPChanged) {
		return cause
	}
	return err
}
