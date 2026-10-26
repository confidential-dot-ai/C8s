package launchconfig

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

// initializeSecret creates a 32-byte hex secret in RAM-backed storage, or
// checks the one an earlier staging in this boot created. The serialized role
// oneshot preserves it across restarts, so restaging never rotates it.
func initializeSecret(path, what string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create %s directory: %w", what, err)
	}
	root, err := openTokenDir(what+" storage", filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	if _, err := readSecret(root, name, what); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate %s: %w", what, err)
	}
	defer clear(secret[:])
	return fileutil.WriteAtomicRoot(root, name, []byte(hex.EncodeToString(secret[:])), 0600)
}

// readSecret returns the decoded secret; the caller clears it.
func readSecret(root *os.Root, name, what string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 64 {
		return nil, fmt.Errorf("existing %s must be a private 64-byte regular file", what)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open existing %s: %w", what, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return nil, fmt.Errorf("read existing %s: %w", what, err)
	}
	defer clear(data)
	secret, err := hex.DecodeString(string(data))
	if err != nil || len(secret) != 32 {
		clear(secret)
		return nil, fmt.Errorf("existing %s is malformed", what)
	}
	return secret, nil
}

// LoadNodePasswordKey reads the server's node-password key from RAM-backed
// storage. The caller clears the returned key.
func LoadNodePasswordKey(path string) ([]byte, error) {
	root, err := openTokenDir("node password key storage", filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readSecret(root, filepath.Base(path), "node password key")
}

// nodePasswordContext separates node-password derivation from any other use
// of an HMAC under the same key.
const nodePasswordContext = "c8s rke2 node password v1\x00"

// NodePassword derives a node's RKE2 node password from the server-only key:
// stable for the life of the key, so a rebooted node rejoins under its name,
// and distinct per name, so one node's password opens no other node's name.
func NodePassword(key []byte, nodeName string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(nodePasswordContext))
	mac.Write([]byte(nodeName))
	return hex.EncodeToString(mac.Sum(nil))
}
