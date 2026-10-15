//go:build !linux

package nriimagepolicy

func hostFileContentDigest(string) string { return "" }
