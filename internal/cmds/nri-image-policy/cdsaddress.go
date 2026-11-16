package nriimagepolicy

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// renderedCDSAddressName is the endpoint document in the plugin's runtime
// directory (renderNodeDocument).
const renderedCDSAddressName = "cds-address"

// prepareCDSAddress writes the CDS endpoint this node's injected credential
// clients dial, before any container can be created.
func (p *plugin) prepareCDSAddress() error {
	if !p.cfg.injectsCredentialClients() {
		return nil
	}
	if p.cfg.cdsAddress == "" {
		return fmt.Errorf("nothing names the CDS this node reaches: a measured config names it in allowlist.pull.url, and an install in allowlist.pull.cds_address_file")
	}
	path, err := renderNodeDocument(renderedCDSAddressName, cmdsutil.FormatCDSAddress(p.cfg.cdsAddress))
	if err != nil {
		return err
	}
	p.cdsAddress = path
	return nil
}

// loadCDSAddress is the <host>:<port> this node's CDS serves on: the address
// file an install mounts beside this config, else the URL a measured config
// carries, which launch staging wrote from the signed document
// (internal/cmds/nodeservices). "" names no CDS.
func loadCDSAddress(c pullConfig) (string, error) {
	if c.URL != "" {
		address, err := cmdsutil.CDSURLAddress(c.URL)
		if err != nil {
			return "", fmt.Errorf("allowlist.pull.url %w", err)
		}
		return address, nil
	}
	if c.CDSAddressFile == "" {
		return "", nil
	}
	address, mounted, err := cmdsutil.ResolveCDSAddress(c.CDSAddressFile, "")
	if err != nil {
		return "", err
	}
	if !mounted {
		return "", fmt.Errorf("allowlist.pull.cds_address_file %s: no such file", c.CDSAddressFile)
	}
	return address, nil
}

// bindCredentialRole completes an install's mesh policy with the port this
// node's CDS serves on, so the pod ruleset admits that port outside the
// cluster and nothing else, and validates the policy it completed. A measured
// policy arrives bound, because a baked node's CDS is staged into it at launch
// (internal/cmds/nodeservices), and that binding stands.
//
// The mesh gate copies the policy, so this belongs to loading the config.
func bindCredentialRole(cfg *config) error {
	if _, bound := cfg.credentialRole(); bound {
		return nil
	}
	if cfg.Allowlist.Pull.CDSAddressFile == "" {
		// Nothing an install mounted names the CDS this node reaches. A node
		// that injects credential clients refuses to start without a bound
		// role; one that injects none needs no binding (prepareCDSAddress).
		return nil
	}
	_, port, err := cmdsutil.SplitCDSAddress(cfg.cdsAddress)
	if err != nil {
		return err
	}
	cfg.Mesh.Roles = append(cfg.Mesh.Roles, roleBinding{
		Name: CredentialRole,
		UID:  workloadclaims.CredentialsUID,
		Port: port,
	})
	return cfg.Mesh.validate()
}

// credentialRole is this node's binding of the credential role.
func (c *config) credentialRole() (roleBinding, bool) {
	return c.Mesh.role(CredentialRole)
}

// nodeOwnAddress is this node's own address, from the same inputs the sandbox
// tokens name it by, and it must be a literal one: a pod's ruleset admits an
// address, so a name or a route guess would not be what the pod dials.
func nodeOwnAddress(cfg *config) (netip.Addr, error) {
	host := nodeConfiguredHost(cfg)
	if host == "" {
		return netip.Addr{}, fmt.Errorf("neither workload_claims.advertise_host nor %s names this node's own address",
			filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile))
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("this node's own address %q: %w", host, err)
	}
	return address, nil
}

// nodeConfiguredHost is this node's address as its configuration carries it:
// the configured advertise host, else the file whatever launched the plugin
// writes beside the inventory socket — the chart's installer from its
// Kubernetes node status, the node image from its staged launch
// configuration. "" means neither names one.
func nodeConfiguredHost(cfg *config) string {
	if host := cfg.WorkloadClaims.AdvertiseHost; host != "" {
		return host
	}
	data, err := os.ReadFile(filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
