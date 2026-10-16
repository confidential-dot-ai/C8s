//go:build !linux

package nriimagepolicy

func nodeRootFile(string) (string, bool) { return "", false }
func nodeRootUnavailable() string        { return "" }
