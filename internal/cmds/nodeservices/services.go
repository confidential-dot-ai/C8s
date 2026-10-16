// Package nodeservices prepares authenticated launch inputs for the image's
// Kubernetes workloads and host bootstrap services.
package nodeservices

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

const (
	launchDir  = launchconfig.Dir + "/"
	nodeIPPath = "/var/run/nri-image-policy/node-ip"

	// PublicDir contains only authenticated, nonsecret workload inputs. Core
	// pods mount it read-only; the token-bearing launch directory stays private.
	PublicDir = "/run/c8s-node"
)

func validateRole(d *launchconfig.Document) error {
	if d == nil {
		return fmt.Errorf("missing staged launch configuration")
	}
	if d.Role != launchconfig.Server && d.Role != launchconfig.Agent {
		return fmt.Errorf("invalid staged role")
	}
	return nil
}

// primaryIPv4 is a package var so tests can fake the host's routes.
var primaryIPv4 = launchconfig.PrimaryIPv4

// PublishNodeIP selects the same address as RKE2, including an explicit
// authenticated node.ip. RootDir only rebases the fixed output for tests.
func PublishNodeIP(rootDir string, d *launchconfig.Document) error {
	if err := validateRole(d); err != nil {
		return err
	}
	address := d.Node.IP
	if address == "" {
		var err error
		if address, err = primaryIPv4(); err != nil {
			return fmt.Errorf("resolve node address: %w", err)
		}
	}
	if err := launchconfig.ValidateIPv4(address, true); err != nil {
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
