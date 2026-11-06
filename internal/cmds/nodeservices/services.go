// Package nodeservices prepares authenticated launch inputs for the image's
// Kubernetes workloads and host bootstrap services.
package nodeservices

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

const (
	launchDir  = launchconfig.Dir + "/"
	nodeIPPath = "/run/nri-image-policy/node-ip"

	// PublicDir contains only authenticated, nonsecret workload inputs. Core
	// pods mount it read-only; the token-bearing launch directory stays private.
	PublicDir = "/run/c8s-node"
)

func validateRole(d *launchconfig.Document) error {
	if d == nil {
		return fmt.Errorf("missing staged launch configuration")
	}
	if !d.Role.Valid() {
		return fmt.Errorf("invalid staged role")
	}
	return nil
}

// PublishNodeIP selects the same address as RKE2, including an explicit
// authenticated node.ip. RootDir only rebases the fixed output for tests.
func PublishNodeIP(rootDir string, d *launchconfig.Document) error {
	if err := validateRole(d); err != nil {
		return err
	}
	address := d.Node.IP
	if address == "" {
		addr, err := cmdsutil.PrimaryIPv4()
		if err != nil {
			return fmt.Errorf("resolve node address: %w", err)
		}
		address = addr.String()
	}
	return PublishNodeAddress(rootDir, address)
}

// ClearNodeIP removes what PublishNodeAddress writes.
func ClearNodeIP(rootDir string) error {
	err := os.Remove(filepath.Join(rootDir, nodeIPPath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// PublishNodeAddress publishes address, a routable IPv4, as the address the
// node's NRI inventory advertises.
func PublishNodeAddress(rootDir, address string) error {
	if err := cmdsutil.ValidateRoutableIPv4(address); err != nil {
		return fmt.Errorf("node inventory requires a routable IPv4 address")
	}
	dst := filepath.Join(rootDir, nodeIPPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	// World-readable: non-root components read it as their attestation-api
	// address (cmdsutil.NodeIPPath).
	return fileutil.WriteAtomic(dst, []byte(address+"\n"), 0644)
}
