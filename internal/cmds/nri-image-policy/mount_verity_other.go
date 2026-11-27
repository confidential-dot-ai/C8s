//go:build !linux

package nriimagepolicy

func containerFileDigest(uint32, string, string) (string, error) { return "", errVerityFilesystem }
