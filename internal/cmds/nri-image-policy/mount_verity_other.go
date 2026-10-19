//go:build !linux

package nriimagepolicy

import "log/slog"

func pinFSVerityFile(string, []string) (string, string, error) { return "", "", errVerityFilesystem }
func pinnedFSVerityFile(string, string) bool                   { return false }
func unpinFSVerityFile(string) error                           { return nil }
func sweepVerifiedMounts(*slog.Logger)                         {}
