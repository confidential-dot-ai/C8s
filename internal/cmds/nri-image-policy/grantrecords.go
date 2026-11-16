package nriimagepolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// grantRecords keeps one file per container admission granted something,
// named by container ID and holding those grants under jsonKey.
type grantRecords struct {
	dir     string
	jsonKey string
}

// note records what admission granted a container and removes any stale
// record when it granted nothing, so a record exists exactly while admission
// last granted that container something.
func (g *grantRecords) note(containerID string, grants [][]string) error {
	if g == nil {
		return nil
	}
	if len(grants) == 0 {
		g.remove(containerID)
		return nil
	}
	if !validContainerID(containerID) {
		return fmt.Errorf("container id %q is not a runtime container id", containerID)
	}
	data, err := json.Marshal(map[string][][]string{g.jsonKey: grants})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return err
	}
	return fileutil.WriteAtomic(g.path(containerID), data, 0o600)
}

func (g *grantRecords) remove(containerID string) {
	if g == nil || !validContainerID(containerID) {
		return
	}
	_ = os.Remove(g.path(containerID))
}

// read returns a container's grants once the record and its directory pass
// requireOwnerOnly.
func (g *grantRecords) read(containerID string) ([][]string, error) {
	if !validContainerID(containerID) {
		return nil, fmt.Errorf("container id %q is not a runtime container id", containerID)
	}
	if err := requireOwnerOnly(g.dir, true); err != nil {
		return nil, err
	}
	path := g.path(containerID)
	if err := requireOwnerOnly(path, false); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record map[string][][]string
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return record[g.jsonKey], nil
}

func (g *grantRecords) path(containerID string) string {
	return filepath.Join(g.dir, containerID)
}
