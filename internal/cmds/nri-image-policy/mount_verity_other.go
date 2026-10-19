//go:build !linux

package nriimagepolicy

func pinFSVerityFile(string, []string) (string, string, error) { return "", "", errVerityFilesystem }
func stagedDigest(string) string                               { return "" }
func unpinFSVerityFile(string) error                           { return nil }
func checkStagingRoot() error                                  { return errVerityFilesystem }
