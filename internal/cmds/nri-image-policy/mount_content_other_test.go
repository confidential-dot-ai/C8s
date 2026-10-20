//go:build !linux

package nriimagepolicy

import "testing"

func TestNodeRootUnavailableOnUnsupportedPlatform(t *testing.T) {
	if reason, _ := nodeRootUnavailable(); reason == "" {
		t.Fatal(`nodeRootUnavailable() = "", want a reason`)
	}
}
