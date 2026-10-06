//go:build linux

package armtlsmesh

import (
	"testing"
)

func TestIfaceAllowed(t *testing.T) {
	if !ifaceAllowed("cni0", []string{"lo", "cni0"}) {
		t.Error("cni0 should be allowed")
	}
	if ifaceAllowed("eth0", []string{"lo", "cni0"}) {
		t.Error("eth0 should not be allowed")
	}
}

func TestDefaultLocalRouteCheck(t *testing.T) {
	if ok, err := defaultLocalRouteCheck("10.0.0.1", nil); ok || err != nil {
		t.Errorf("empty allowlist: got (%v,%v), want (false,nil)", ok, err)
	}
	if ok, err := defaultLocalRouteCheck("not-an-ip", []string{"lo"}); ok || err != nil {
		t.Errorf("bad IP: got (%v,%v), want (false,nil)", ok, err)
	}
	// The kernel routes 127.0.0.1 via lo. Netlink route-get is read-only and
	// works unprivileged; tolerate environments where it does not.
	ok, err := defaultLocalRouteCheck("127.0.0.1", []string{"lo"})
	if err == nil && !ok {
		t.Error("route to 127.0.0.1 should use lo")
	}
	if ok2, err2 := defaultLocalRouteCheck("127.0.0.1", []string{"cni0"}); err2 == nil && ok2 {
		t.Error("route to 127.0.0.1 should not match cni0-only allowlist")
	}
}
