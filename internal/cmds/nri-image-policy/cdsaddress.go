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
	endpoint, err := credentialEndpoint(p.cfg)
	if err != nil {
		return err
	}
	path, err := renderNodeDocument(renderedCDSAddressName, cmdsutil.FormatCDSAddress(endpoint))
	if err != nil {
		return err
	}
	p.cdsAddress = path
	return nil
}

// loadCDSEndpoint reads the CDS endpoint an install mounts beside this config:
// the one the plugin pulls from and its credential clients dial. A config
// naming no file yields the zero endpoint — a measured config names the CDS by
// URL and is bound at launch staging (internal/cmds/nodeservices). A named
// file must exist and must carry a port.
func loadCDSEndpoint(c pullConfig) (netip.AddrPort, error) {
	if c.CDSAddressFile == "" {
		return netip.AddrPort{}, nil
	}
	endpoint, mounted, err := cmdsutil.ResolveCDSEndpoint(c.CDSAddressFile, "")
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !mounted {
		return netip.AddrPort{}, fmt.Errorf("allowlist.pull.cds_address_file %s: no such file", c.CDSAddressFile)
	}
	if endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("allowlist.pull.cds_address_file %s names port 0, which reaches no CDS", c.CDSAddressFile)
	}
	return endpoint, nil
}

// bindCredentialRole completes a mesh policy that names no CDS address with
// endpoint, so the pod ruleset admits exactly the address this node's
// credential clients are handed, and validates the policy it completed. A
// measured policy arrives bound, because a baked node's CDS address is staged
// at launch (internal/cmds/nodeservices), and that binding stands; the zero
// endpoint leaves such a policy alone.
//
// The mesh gate copies the policy, so this belongs to loading the config.
func bindCredentialRole(cfg *config, endpoint netip.AddrPort) error {
	if _, bound := cfg.credentialRole(); bound {
		return nil
	}
	if !endpoint.IsValid() {
		// Nothing here names the CDS this node reaches. A node that injects
		// credential clients refuses to start without one; one that injects
		// none needs no binding (prepareCDSAddress).
		return nil
	}
	cfg.Mesh.Roles = append(cfg.Mesh.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{endpoint},
	})
	return cfg.Mesh.validate()
}

// credentialEndpoint is the CDS endpoint the injected credential clients of
// this node dial: the one destination of the bound credentials role, which a
// measured policy carries and loading binds from the install's address file.
func credentialEndpoint(cfg *config) (netip.AddrPort, error) {
	role, bound := cfg.credentialRole()
	if !bound {
		return netip.AddrPort{}, fmt.Errorf("nothing binds the %s role to a CDS: a measured policy names one, and an install names it in allowlist.pull.cds_address_file", CredentialRole)
	}
	if len(role.Destinations) != 1 {
		return netip.AddrPort{}, fmt.Errorf("the %s role reaches %d destinations, not the one CDS its clients dial", CredentialRole, len(role.Destinations))
	}
	return role.Destinations[0], nil
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
