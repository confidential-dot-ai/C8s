package launchconfig

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// Tests replace only the RAM-backed open; the production path always checks
// the opened directory handle before reading or writing a credential.
var openTokenDir = cmdsutil.OpenRAMBackedDir

// initializeAgentToken creates a separate agent password before the first
// server RKE2 start. The serialized role oneshot preserves it across restarts;
// omitting this credential would let RKE2 reuse its privileged server token.
func initializeAgentToken(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create agent token directory: %w", err)
	}
	root, err := openTokenDir("agent token storage", filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	if err := validateExistingAgentToken(root, name); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate agent token: %w", err)
	}
	defer clear(secret[:])
	return fileutil.WriteAtomicRoot(root, name, []byte(hex.EncodeToString(secret[:])), 0600)
}

func validateExistingAgentToken(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 64 {
		return fmt.Errorf("existing agent token must be a private 64-byte regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open existing agent token: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return fmt.Errorf("read existing agent token: %w", err)
	}
	defer clear(data)
	secret, err := hex.DecodeString(string(data))
	defer clear(secret)
	if err != nil {
		return fmt.Errorf("existing agent token is malformed")
	}
	return nil
}
