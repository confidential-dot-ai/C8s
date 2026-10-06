//go:build !linux

// Command armtls-mesh requires Linux; this stub keeps cross-platform
// `go build ./cmd/...` working on non-Linux dev machines (otherwise the
// package has no buildable files and the build errors). It fails closed at
// runtime — the proxy depends on iptables, netlink, and SO_ORIGINAL_DST,
// none of which exist off Linux.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "armtls-mesh requires Linux (iptables, netlink, SO_ORIGINAL_DST)")
	os.Exit(1)
}
