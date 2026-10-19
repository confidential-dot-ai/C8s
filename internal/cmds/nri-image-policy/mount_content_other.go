//go:build !linux

package nriimagepolicy

func nodeRootFile(string) bool            { return false }
func nodeRootUnavailable() (string, bool) { return "unsupported platform", false }
