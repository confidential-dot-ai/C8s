package nriimagepolicy

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// nodeDir is a plugin runtime directory with this node's own address in it,
// as the installer or the node image writes it.
func nodeDir(t *testing.T, address string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, NodeIPFile), []byte(address+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// renderInTempDir puts the documents the plugin renders where a test can read
// them, instead of its compiled directory on the node.
func renderInTempDir(t *testing.T) {
	t.Helper()
	previous := enforcerRuntimeDir
	enforcerRuntimeDir = t.TempDir()
	t.Cleanup(func() { enforcerRuntimeDir = previous })
}

// installedCDSEndpoint is an install's address file, naming the CDS this
// cluster trusts, as the installer copies it beside the plugin's config.
func installedCDSEndpoint(t *testing.T, address string) allowlistConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds-address")
	if err := os.WriteFile(path, []byte(address+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return allowlistConfig{Pull: pullConfig{CDSAddressFile: path}}
}

// measuredCDSPolicy is a baked node's mesh policy: boot preparation bound the
// credential role to the CDS address staged at launch.
func measuredCDSPolicy(destination string) *meshPolicy {
	policy := meshRoles()
	policy.Roles = append(policy.Roles, roleBinding{
		Name:         CredentialRole,
		UID:          workloadclaims.CredentialsUID,
		Destinations: []netip.AddrPort{netip.MustParseAddrPort(destination)},
	})
	return policy
}

// A measured policy names the CDS its clients dial, and the address the node
// hands them is that one: the pod ruleset admits nothing else.
func TestMeasuredPolicyDecidesTheCDSEndpoint(t *testing.T) {
	cfg := &config{
		WorkloadClaims: workloadClaimsConfig{SocketDir: nodeDir(t, "10.0.0.7")},
		Allowlist:      installedCDSEndpoint(t, "10.9.9.9:8443"),
		Mesh:           measuredCDSPolicy("10.1.2.3:30808"),
	}
	endpoint, err := loadCDSEndpoint(cfg.Allowlist.Pull)
	if err != nil {
		t.Fatalf("loadCDSEndpoint: %v", err)
	}
	if err := bindCredentialRole(cfg, endpoint); err != nil {
		t.Fatalf("bindCredentialRole: %v", err)
	}
	role, bound := cfg.credentialRole()
	if !bound || len(role.Destinations) != 1 || role.Destinations[0].String() != "10.1.2.3:30808" {
		t.Fatalf("credential role = %+v, want the measured destination alone", role)
	}
	renderInTempDir(t)
	p := &plugin{cfg: cfg}
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("prepareCDSAddress: %v", err)
	}
	if got := readAddress(t, p.cdsAddress); got != "10.1.2.3:30808" {
		t.Fatalf("handed address = %q, want the measured destination", got)
	}
}

// An install's policy names no CDS address, so the node binds the credential
// role to the endpoint its address file names, pulls from that same endpoint,
// and hands its clients nothing else.
func TestInstallBindsTheCredentialRoleToItsAddressFile(t *testing.T) {
	cfg := &config{
		WorkloadClaims: workloadClaimsConfig{SocketDir: nodeDir(t, "10.0.0.7")},
		Allowlist:      installedCDSEndpoint(t, "10.9.9.9:8443"),
		Mesh:           meshRoles(),
	}
	endpoint, err := loadCDSEndpoint(cfg.Allowlist.Pull)
	if err != nil {
		t.Fatalf("loadCDSEndpoint: %v", err)
	}
	cfg.cdsEndpoint = endpoint
	if got := cfg.pullURL(); got != "https://10.9.9.9:8443" {
		t.Fatalf("pull URL = %q, want the endpoint the file names", got)
	}
	if err := bindCredentialRole(cfg, endpoint); err != nil {
		t.Fatalf("bindCredentialRole: %v", err)
	}
	role, bound := cfg.credentialRole()
	if !bound || role.UID != workloadclaims.CredentialsUID {
		t.Fatalf("credential role = %+v, want it bound to uid %d", role, workloadclaims.CredentialsUID)
	}
	if got := role.Destinations[0].String(); got != "10.9.9.9:8443" {
		t.Fatalf("destination = %q, want the endpoint the address file names", got)
	}
	if err := cfg.Mesh.validate(); err != nil {
		t.Fatalf("the completed policy no longer validates: %v", err)
	}
	renderInTempDir(t)
	p := &plugin{cfg: cfg}
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("prepareCDSAddress: %v", err)
	}
	if got := readAddress(t, p.cdsAddress); got != "10.9.9.9:8443" {
		t.Fatalf("handed address = %q, want the bound destination", got)
	}
}

// A node that injects credential clients and knows no CDS endpoint refuses to
// start: a client with no address reaches no CDS at all.
func TestCDSEndpointIsRequiredWhereClientsAreInjected(t *testing.T) {
	renderInTempDir(t)
	cfg := &config{WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()}, Mesh: meshRoles()}
	p := &plugin{cfg: cfg}
	err := p.prepareCDSAddress()
	if err == nil {
		t.Fatal("a node with no CDS endpoint started")
	}
	if !strings.Contains(err.Error(), CredentialRole) {
		t.Fatalf("error = %v, want it to name the unbound role", err)
	}
}

// An address file the node cannot read, or one holding something that is not
// an address, is refused at load: an unresolved endpoint would leave every
// injected client dialling nothing.
func TestAddressFileMustNameAnAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
	}{
		{name: "a name, not an address", address: "cds.cluster.local:8443"},
		{name: "no port", address: "10.9.9.9"},
		{name: "port 0", address: "10.9.9.9:0"},
		{name: "empty", address: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadCDSEndpoint(installedCDSEndpoint(t, tc.address).Pull); err == nil {
				t.Fatalf("address %q accepted", tc.address)
			}
		})
	}
	absent := pullConfig{CDSAddressFile: filepath.Join(t.TempDir(), "absent")}
	if _, err := loadCDSEndpoint(absent); err == nil {
		t.Fatal("a missing address file was accepted")
	}
}

// Neither rendered document is written where the plugin bind-mounts the whole
// inventory socket directory: each reaches a pod at the one path its client
// reads.
func TestRenderedDocumentsAreOutsideTheMountedSocketDirectory(t *testing.T) {
	socketDir := nodeDir(t, "10.0.0.7")
	cfg := &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: socketDir},
		Allowlist:      installedCDSEndpoint(t, "10.9.9.9:8443"),
		Mesh:           meshRoles(),
	}
	cfg.Allowlist.Pull.CDSMeasurementsConfig = testCDSPinFile(t)
	endpoint, err := loadCDSEndpoint(cfg.Allowlist.Pull)
	if err != nil {
		t.Fatalf("loadCDSEndpoint: %v", err)
	}
	if err := bindCredentialRole(cfg, endpoint); err != nil {
		t.Fatalf("bindCredentialRole: %v", err)
	}
	renderInTempDir(t)
	p := &plugin{cfg: cfg}
	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("prepareCDSAddress: %v", err)
	}
	for _, rendered := range []string{p.cdsPins, p.cdsAddress} {
		if strings.HasPrefix(rendered, socketDir) {
			t.Fatalf("document %s sits in the mounted socket directory %s", rendered, socketDir)
		}
	}
}

// A node that injects nothing hands out no address, and its clients keep their
// own arguments.
func TestNoInjectedClientsNoAddress(t *testing.T) {
	p := &plugin{cfg: &config{}}
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("prepareCDSAddress: %v", err)
	}
	if p.cdsAddress != "" {
		t.Fatalf("address path = %q, want none", p.cdsAddress)
	}
}

// The address reaches an injected credential sidecar as a read-only mount at
// the path its client reads, and no other container.
func TestCDSAddressIsMountedIntoCredentialSidecars(t *testing.T) {
	p := &plugin{
		cfg:        &config{},
		cdsAddress: "/var/run/nri-image-policy/cds-address",
	}
	pod := &api.PodSandbox{Annotations: map[string]string{workloadclaims.AnnotationInjected: "true"}}
	mount := addressMount(t, mustCredentialMounts(t, p, pod, &api.Container{Name: workloadclaims.CertContainerName}))
	if mount.GetSource() != p.cdsAddress {
		t.Fatalf("source = %q, want the plugin's own file", mount.GetSource())
	}
	if !slices.Contains(mount.GetOptions(), "ro") {
		t.Fatalf("options = %v, want a read-only mount", mount.GetOptions())
	}
	if got := mustCredentialMounts(t, p, pod, &api.Container{Name: "app"}); got != nil {
		t.Fatalf("workload adjustment = %+v, want none", got)
	}
}

// The upstream identity reads the endpoint at the same path, and that
// endpoint alone: it polls the signed route manifest from the one CDS its
// node admits for it, and takes its pins from the measured base.
func TestCDSAddressIsMountedIntoTheRoutingRole(t *testing.T) {
	p := &plugin{
		cfg:        &config{},
		cdsAddress: "/var/run/nri-image-policy/cds-address",
	}
	pod := &api.PodSandbox{Namespace: routerNamespace}
	routing := &api.Container{Name: workloadclaims.AttestContainerName, User: &api.User{Uid: workloadclaims.UpstreamUID}}
	adjustment := mustCredentialMounts(t, p, pod, routing)
	mount := addressMount(t, adjustment)
	if mount.GetSource() != p.cdsAddress {
		t.Fatalf("source = %q, want the plugin's own file", mount.GetSource())
	}
	if !slices.Contains(mount.GetOptions(), "ro") {
		t.Fatalf("options = %v, want a read-only mount", mount.GetOptions())
	}
	if got := len(adjustment.GetMounts()); got != 1 {
		t.Fatalf("the upstream role takes %d mounts, want the endpoint alone: %+v", got, adjustment.GetMounts())
	}
	// That identity outside the router's namespace, and another identity of
	// the router's pod, take none.
	if got := mustCredentialMounts(t, p, &api.PodSandbox{Namespace: "default"}, routing); got != nil {
		t.Fatalf("a pod outside the router namespace takes %+v", got)
	}
	// The front door takes none: the measured base pins what it may mount,
	// and the manifest comes through the sidecar.
	nginx := &api.Container{Name: "nginx", User: &api.User{Uid: workloadclaims.RouterUID}}
	if got := mustCredentialMounts(t, p, pod, nginx); got != nil {
		t.Fatalf("the front door takes %+v", got)
	}
}

func addressMount(t *testing.T, adjustment *api.ContainerAdjustment) *api.Mount {
	t.Helper()
	for _, m := range adjustment.GetMounts() {
		if m.GetDestination() == workloadclaims.CDSAddressPath {
			return m
		}
	}
	t.Fatalf("no mount at %s: %+v", workloadclaims.CDSAddressPath, adjustment.GetMounts())
	return nil
}

func readAddress(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}
