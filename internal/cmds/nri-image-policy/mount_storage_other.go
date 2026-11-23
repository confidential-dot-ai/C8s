//go:build !linux

package nriimagepolicy

import "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"

type platformStorageInspector struct{}

func newMountStorageInspector() mountStorageInspector {
	return platformStorageInspector{}
}

func (platformStorageInspector) Inspect(string) allowlist.MountStorage {
	return allowlist.MountUnknown
}
