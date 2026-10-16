//go:build !linux

package nriimagepolicy

import "log/slog"

func pinFSVerityFile(string, bool, []string) (string, string, error) { return "", "", nil }
func pinnedFSVerityFile(string, string) bool                         { return false }
func unpinFSVerityFile(string) error                                 { return nil }
func sweepVerifiedMounts(*slog.Logger)                               {}
