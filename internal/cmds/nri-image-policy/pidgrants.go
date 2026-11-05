package nriimagepolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// PIDNamespaceGrantDir is node-only state; no workload may bind it.
const PIDNamespaceGrantDir = "/run/nri-image-policy-pid"

var pidNamespaceGroups sync.Mutex

// PIDNamespaceGrant binds one admitted launch to a pinned sandbox namespace.
type PIDNamespaceGrant struct {
	ContainerID string `json:"containerID"`
	SandboxID   string `json:"sandboxID"`
	PodUID      string `json:"podUID"`
	Policy      string `json:"policy"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	Path        string `json:"path"`
}

func pidNamespacePath(
	dir string,
	sandboxID string,
) (string, error) {
	if !validContainerID(sandboxID) || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("invalid PID namespace directory or sandbox ID")
	}
	return filepath.Join(dir, "namespaces", sandboxID), nil
}

// WritePIDNamespaceGrant records the selected signed namespace authorization.
// Final validation and start still enforce the complete launch.
func WritePIDNamespaceGrant(
	dir string,
	grant PIDNamespaceGrant,
) error {
	want, err := pidNamespacePath(dir, grant.SandboxID)
	if err != nil || !validContainerID(grant.ContainerID) || grant.Path != want || grant.Policy == "" || grant.PodUID == "" {
		return fmt.Errorf("invalid PID namespace grant")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := requireOwnerOnly(dir, true); err != nil {
		return err
	}
	if err := bindPIDNamespaceGroup(dir, grant); err != nil {
		return err
	}
	data, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(dir, grant.ContainerID), data, 0o600)
}

// The group survives container removal and plugin restart until sandbox removal.
func bindPIDNamespaceGroup(
	dir string,
	grant PIDNamespaceGrant,
) error {
	pidNamespaceGroups.Lock()
	defer pidNamespaceGroups.Unlock()
	groupDir := filepath.Join(dir, "groups")
	if err := os.MkdirAll(groupDir, 0o700); err != nil {
		return err
	}
	if err := requireOwnerOnly(groupDir, true); err != nil {
		return err
	}
	grant.ContainerID = ""
	data, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(groupDir, grant.SandboxID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if os.IsExist(err) {
		return checkPIDNamespaceGroup(dir, grant)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func checkPIDNamespaceGroup(
	dir string,
	grant PIDNamespaceGrant,
) error {
	group, err := ReadPIDNamespaceGrant(filepath.Join(dir, "groups"), grant.SandboxID)
	if err != nil {
		return err
	}
	grant.ContainerID = ""
	if group == nil || *group != grant {
		return fmt.Errorf("the sandbox PID namespace is bound to another group")
	}
	return nil
}

// ReadPIDNamespaceGrant returns nil when no grant exists.
func ReadPIDNamespaceGrant(
	dir string,
	containerID string,
) (*PIDNamespaceGrant, error) {
	if !validContainerID(containerID) {
		return nil, fmt.Errorf("invalid runtime container ID")
	}
	for _, path := range []string{dir, filepath.Join(dir, containerID)} {
		if err := requireOwnerOnly(path, path == dir); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, containerID))
	if err != nil {
		return nil, err
	}
	var grant PIDNamespaceGrant
	if err := json.Unmarshal(data, &grant); err != nil {
		return nil, err
	}
	return &grant, nil
}

// RemovePIDNamespaceGrant removes authorization when a container is removed.
func RemovePIDNamespaceGrant(
	dir string,
	containerID string,
) error {
	if !validContainerID(containerID) {
		return fmt.Errorf("invalid runtime container ID")
	}
	err := os.Remove(filepath.Join(dir, containerID))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// CheckPIDNamespaceGrant verifies the namespace the runtime is about to join.
func CheckPIDNamespaceGrant(
	dir string,
	containerID string,
	sandboxID string,
	podUID string,
	path string,
) error {
	grant, err := ReadPIDNamespaceGrant(dir, containerID)
	if err != nil {
		return err
	}
	want, err := pidNamespacePath(dir, sandboxID)
	if err != nil || grant == nil || path != want || grant.Path != want || grant.ContainerID != containerID || grant.SandboxID != sandboxID || grant.PodUID != podUID || grant.Policy == "" {
		return fmt.Errorf("the shared PID namespace has no matching runtime grant")
	}
	if err := checkPIDNamespaceGroup(dir, *grant); err != nil {
		return err
	}
	if err := requireOwnerOnly(filepath.Dir(want), true); err != nil {
		return err
	}
	if err := requireOwnerOnly(want, false); err != nil {
		return err
	}
	device, inode, err := PIDNamespaceIdentity(want)
	if err != nil {
		return err
	}
	if device != grant.Device || inode != grant.Inode {
		return fmt.Errorf("the granted PID namespace was replaced")
	}
	return nil
}
