//go:build !linux

package nriimagepolicy

import "github.com/confidential-dot-ai/c8s/pkg/allowlist"

type platformStorageInspector struct{}

func newMountStorageInspector() mountStorageInspector {
	return platformStorageInspector{}
}

func (platformStorageInspector) Inspect(string) allowlist.MountStorage {
	return allowlist.MountUnknown
}

func (platformStorageInspector) NoMountsBelow(string) bool {
	return false
}
