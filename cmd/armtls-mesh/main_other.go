//go:build !linux

// Command armtls-mesh requires Linux; this stub keeps cross-platform
// `go build ./cmd/...` working on non-Linux dev machines (otherwise the
// package has no buildable files and the build errors). It fails closed at
// runtime — the endpoint depends on SO_ORIGINAL_DST, which exists only on
// Linux.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "armtls-mesh requires Linux (SO_ORIGINAL_DST)")
	os.Exit(1)
}
