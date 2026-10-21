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

// bindCredentialRole completes a mesh policy that names no CDS address with
// the endpoint this node's credential clients dial, so the pod ruleset admits
// exactly the address they are handed, and validates the policy it
// completed. A measured policy arrives bound, because a baked node's CDS
// address is staged at launch (internal/cmds/nodeservices), and that binding
// stands.
//
// The mesh gate copies the policy, so this belongs to loading the config.
func bindCredentialRole(cfg *config) error {
	if cfg.Mesh == nil {
		return nil
	}
	if _, bound := cfg.credentialRole(); bound {
		return nil
	}
	if cfg.WorkloadClaims.CDSNodePort == 0 {
		// Nothing here names the CDS this node reaches. A node that injects
		// credential clients refuses to start without one; one that injects
		// none needs no binding (prepareCDSAddress).
		return nil
	}
	endpoint, err := credentialEndpoint(cfg)
	if err != nil {
		return err
	}
	cfg.Mesh.Roles = append(cfg.Mesh.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{endpoint},
	})
	return cfg.Mesh.validate()
}

// credentialEndpoint is the CDS endpoint the injected credential clients of
// this node dial. A measured mesh policy binds it, and the pod ruleset then
// admits that one address; an install has no measured policy, so the endpoint
// is this node's own address and the CDS node port the chart renders.
func credentialEndpoint(cfg *config) (netip.AddrPort, error) {
	if role, bound := cfg.credentialRole(); bound {
		if len(role.Destinations) != 1 {
			return netip.AddrPort{}, fmt.Errorf("the %s role reaches %d destinations, not the one CDS its clients dial", CredentialRole, len(role.Destinations))
		}
		return role.Destinations[0], nil
	}
	if cfg.WorkloadClaims.CDSNodePort == 0 {
		return netip.AddrPort{}, fmt.Errorf("no measured policy binds the %s role, so workload_claims.cds_node_port is required: an injected credential client dials CDS at this node's own address and that port", CredentialRole)
	}
	address, err := nodeOwnAddress(cfg)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(address, cfg.WorkloadClaims.CDSNodePort), nil
}

// credentialRole is this node's binding of the credential role.
func (c *config) credentialRole() (roleBinding, bool) {
	if c.Mesh == nil {
		return roleBinding{}, false
	}
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
