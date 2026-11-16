// Package nodeservices prepares authenticated launch inputs for the image's
// Kubernetes workloads and host bootstrap services.
package nodeservices

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

const (
	nodeIPPath = "/run/nri-image-policy/node-ip"

	// PublicDir contains only authenticated, nonsecret workload inputs. Core
	// pods mount it read-only; the token-bearing launch directory stays private.
	PublicDir = "/run/c8s-node"
)

// ClearNodeIP removes what PublishNodeAddress writes.
func ClearNodeIP(rootDir string) error {
	err := os.Remove(filepath.Join(rootDir, nodeIPPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// PublishNodeAddress publishes address as the address the node's NRI
// inventory advertises. Only an address a peer can dial is published.
func PublishNodeAddress(rootDir string, address netip.Addr) error {
	if err := cmdsutil.ValidateRoutableIPv4(address.String()); err != nil {
		return fmt.Errorf("node inventory requires a routable IPv4 address")
	}
	dst := filepath.Join(rootDir, nodeIPPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	// World-readable: non-root components read it as their attestation-api
	// address (cmdsutil.NodeIPPath).
	return fileutil.WriteAtomic(dst, []byte(address.String()+"\n"), 0644)
}
