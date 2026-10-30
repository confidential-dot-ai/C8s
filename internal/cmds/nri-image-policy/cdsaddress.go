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
	if !p.cfg.namesCDS() {
		return fmt.Errorf("nothing names the CDS this node reaches: a measured config names it in allowlist.pull.url, and an install in allowlist.pull.cds_address_file")
	}
	path, err := renderNodeDocument(renderedCDSAddressName, cmdsutil.FormatCDSAddress(p.cfg.cdsAddress))
	if err != nil {
		return err
	}
	p.cdsAddress = path
	return nil
}

// loadCDSAddress is where this node's CDS serves, from the one source this
// config names (cdsSource): the URL a measured config carries, which launch
// staging wrote from the signed document (internal/cmds/nodeservices), or the
// address file an install mounts beside this config. The zero address names
// no CDS.
func loadCDSAddress(c pullConfig) (cmdsutil.CDSAddress, error) {
	source, err := c.cdsSource()
	if err != nil {
		return cmdsutil.CDSAddress{}, err
	}
	switch {
	case source.URL != "":
		address, err := cmdsutil.CDSURLAddress(source.URL)
		if err != nil {
			return cmdsutil.CDSAddress{}, fmt.Errorf("allowlist.pull.url %w", err)
		}
		return address, nil
	case source.AddressFile == "":
		return cmdsutil.CDSAddress{}, nil
	}
	address, mounted, err := cmdsutil.ResolveCDSAddress(source.AddressFile, "")
	if err != nil {
		return cmdsutil.CDSAddress{}, err
	}
	if !mounted {
		return cmdsutil.CDSAddress{}, fmt.Errorf("allowlist.pull.cds_address_file %s: no such file", source.AddressFile)
	}
	return address, nil
}

// bindCredentialRole completes an install's mesh policy with the port address
// serves on, so the pod ruleset admits that port outside the cluster and
// nothing else, and validates the policy it completed. A measured policy
// arrives bound, because a baked node's CDS is staged into it at launch
// (internal/cmds/nodeservices), and that binding stands. A node that names a
// CDS and injects clients into its pods must end up with one bound either
// way: without it their sockets reach no port at all.
//
// The mesh gate copies the policy, so this belongs to loading the config.
func bindCredentialRole(cfg *config, address cmdsutil.CDSAddress, installed bool) error {
	switch _, bound := cfg.credentialRole(); {
	case bound:
		return nil
	case installed:
		cfg.Mesh.Roles = append(cfg.Mesh.Roles, roleBinding{
			Name: CredentialRole,
			UID:  workloadclaims.CredentialsUID,
			Port: address.Port,
		})
		return cfg.Mesh.validate()
	case cfg.injectsCredentialClients() && cfg.namesCDS():
		return fmt.Errorf("mesh.roles binds no reserved uid to the %s role, so the clients this node injects would reach no port of %s", CredentialRole, address)
	}
	return nil
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
