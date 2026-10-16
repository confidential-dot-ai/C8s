//go:build !linux

package nriimagepolicy

func nodeRootFile(string) (string, bool) { return "", false }
