//go:build !linux

package nriimagepolicy

import (
	"errors"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

type platformStorageInspector struct{}

func newMountStorageInspector() mountStorageInspector {
	return platformStorageInspector{}
}

func (platformStorageInspector) Inspect(string) allowlist.MountStorage {
	return allowlist.MountUnknown
}

func crossesMount(string, string) (bool, error) {
	return false, errors.New("mount IDs are unavailable on this platform")
}
