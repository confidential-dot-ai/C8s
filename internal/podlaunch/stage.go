package podlaunch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// PodMarker is written last by Stage: the pod boot's authorization verdict.
const PodMarker = "/run/confos/role-pod"

// Stage authenticates the launch document and writes only fixed boot paths.
// The marker is cleared before verification and written last: an invalid
// document or failed write cannot start the pod services. Services require the
// oneshot stage unit and must never consume these files independently of its
// successful completion.
func Stage(ctx context.Context, cfg Config) error {
	if err := clearOutputs(cfg); err != nil {
		return err
	}
	verified, err := Verify(ctx, cfg)
	if err != nil {
		return err
	}
	return stageVerified(cfg, verified)
}

func (c Config) path(absolute string) string {
	if c.RootDir == "" {
		return absolute
	}
	return filepath.Join(c.RootDir, strings.TrimPrefix(absolute, "/"))
}

func clearOutputs(cfg Config) error {
	var errs []error
	for _, path := range []string{PodMarker, Dir + "/operator-pubkey", DefaultStagedPath} {
		if err := os.Remove(cfg.path(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove stale %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

func stageVerified(cfg Config, v *Verified) error {
	encoded, err := json.MarshalIndent(&v.document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode staged config: %w", err)
	}
	outputs := []struct {
		path string
		data []byte
	}{
		{Dir + "/operator-pubkey", v.operatorPub},
		{DefaultStagedPath, append(encoded, '\n')},
	}
	for _, out := range outputs {
		path := cfg.path(out.path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("create output parent: %w", err)
		}
		if err := fileutil.WriteAtomic(path, out.data, 0o600); err != nil {
			return fmt.Errorf("stage %s: %w", out.path, err)
		}
	}
	// No fallible work follows publishing the authorization verdict.
	return fileutil.WriteAtomic(cfg.path(PodMarker), nil, 0o600)
}
