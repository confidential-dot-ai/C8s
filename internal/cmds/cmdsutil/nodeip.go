package cmdsutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
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

// PrimaryIPv4 is the routable IPv4 address of the interface the host's own
// route table selects, which is the address a node registers and publishes.
// Kubernetes' route-aware selection picks it, so it matches the address the
// kubelet registers with.
//
// The one seam over the host's routes: a test replaces it to place the node
// on a known address.
var PrimaryIPv4 = func() (netip.Addr, error) { return routableHostAddress(utilnet.ChooseHostInterface) }

// routableHostAddress is the address choose selects, held to an address a
// peer can dial: a host whose route leads over IPv6, or over an address no
// peer can reach, has no primary IPv4 address rather than an unusable one.
func routableHostAddress(choose func() (net.IP, error)) (netip.Addr, error) {
	ip, err := choose()
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := routableIPv4(ip.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("the host's primary address %s %w", ip, err)
	}
	return addr, nil
}
