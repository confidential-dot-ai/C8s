//go:build !linux

package nriimagepolicy

func pinFSVerityFile(string, bool, []string) (string, string, error) { return "", "", nil }
func pinnedFSVerityFile(string, string) bool                         { return false }
func unpinFSVerityFile(string) error                                 { return nil }
