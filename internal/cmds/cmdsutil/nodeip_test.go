package cmdsutil

import (
	"context"
	"errors"
	"net"
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

// An address no peer could dial leaves the node without a primary address.
func TestPrimaryIPv4FollowsTheHostRoute(t *testing.T) {
	for _, tc := range []struct {
		name      string
		chosen    string
		chooseErr error
		want      string
		wantErr   error
	}{
		{name: "the host's route", chosen: "192.0.2.9", want: "192.0.2.9"},
		{name: "no default route", chooseErr: errors.New("no default route"), wantErr: nil},
		{name: "an IPv6 route", chosen: "2001:db8::1", wantErr: ErrNotIPv4},
		{name: "a loopback route", chosen: "127.0.0.1", wantErr: ErrNotRoutableIPv4},
		{name: "the unspecified address", chosen: "0.0.0.0", wantErr: ErrNotRoutableIPv4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := routableHostAddress(func() (net.IP, error) {
				if tc.chooseErr != nil {
					return nil, tc.chooseErr
				}
				return net.ParseIP(tc.chosen), nil
			})
			switch {
			case tc.want != "":
				if err != nil || addr.String() != tc.want {
					t.Fatalf("primary address = %v, %v, want %s", addr, err, tc.want)
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("primary address = %v, %v, want %v", addr, err, tc.wantErr)
				}
			default:
				if err == nil {
					t.Fatalf("primary address = %v, want the route failure", addr)
				}
			}
		})
	}
}
