package nriimagepolicy

import (
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

// installedCDSAddress is an install's address file, naming the CDS this
// cluster trusts, as the installer copies it beside the plugin's config.
func installedCDSAddress(t *testing.T, address string) allowlistConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds-address")
	if err := os.WriteFile(path, []byte(address+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return allowlistConfig{Pull: pullConfig{CDSAddressFile: path}}
}

// measuredCDSPolicy is a baked node's mesh policy: boot preparation bound the
// credential role to the port the CDS staged at launch serves on.
func measuredCDSPolicy(port uint16) *meshPolicy {
	policy := meshRoles()
	policy.Roles = append(policy.Roles, roleBinding{
		Name: CredentialRole,
		UID:  workloadclaims.CredentialsUID,
		Port: port,
	})
	return policy
}

// A measured policy names the port its credential clients reach, and loading
// leaves that binding alone: the pod ruleset admits nothing else.
func TestMeasuredPolicyDecidesTheCredentialPort(t *testing.T) {
	cfg := &config{
		WorkloadClaims: workloadClaimsConfig{SocketDir: nodeDir(t, "10.0.0.7")},
		Allowlist:      installedCDSAddress(t, "cds.example.org:8443"),
		Mesh:           measuredCDSPolicy(30808),
	}
	address, err := loadCDSAddress(cfg.Allowlist.Pull)
	if err != nil {
		t.Fatalf("loadCDSAddress: %v", err)
	}
	cfg.cdsAddress = address
	if err := bindCredentialRole(cfg); err != nil {
		t.Fatalf("bindCredentialRole: %v", err)
	}
	role, bound := cfg.credentialRole()
	if !bound || role.Port != 30808 {
		t.Fatalf("credential role = %+v, want the measured port alone", role)
	}
	renderInTempDir(t)
	p := &plugin{cfg: cfg}
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("prepareCDSAddress: %v", err)
	}
	if got := readAddress(t, p.cdsAddress); got != "cds.example.org:8443" {
		t.Fatalf("handed address = %q, want the CDS this node reaches", got)
	}
}

// An install's policy binds no credential role, so the node binds it to the
// port the address file's CDS serves on, pulls from that same CDS, and hands
// its clients its name to dial.
func TestInstallBindsTheCredentialRoleToItsAddressFile(t *testing.T) {
	cfg := &config{
		WorkloadClaims: workloadClaimsConfig{SocketDir: nodeDir(t, "10.0.0.7")},
		Allowlist:      installedCDSAddress(t, "cds.example.org:8443"),
		Mesh:           meshRoles(),
	}
	address, err := loadCDSAddress(cfg.Allowlist.Pull)
	if err != nil {
		t.Fatalf("loadCDSAddress: %v", err)
	}
	cfg.cdsAddress = address
	if got := cfg.pullURL(); got != "https://cds.example.org:8443" {
		t.Fatalf("pull URL = %q, want the endpoint the file names", got)
	}
	if err := bindCredentialRole(cfg); err != nil {
		t.Fatalf("bindCredentialRole: %v", err)
	}
	role, bound := cfg.credentialRole()
	if !bound || role.UID != workloadclaims.CredentialsUID {
		t.Fatalf("credential role = %+v, want it bound to uid %d", role, workloadclaims.CredentialsUID)
	}
	if role.Port != 8443 {
		t.Fatalf("credential role port = %d, want the port the address file's CDS serves on", role.Port)
	}
	if err := cfg.Mesh.validate(); err != nil {
		t.Fatalf("the completed policy no longer validates: %v", err)
	}
	renderInTempDir(t)
	p := &plugin{cfg: cfg}
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("prepareCDSAddress: %v", err)
	}
	if got := readAddress(t, p.cdsAddress); got != "cds.example.org:8443" {
		t.Fatalf("handed address = %q, want the CDS the address file names", got)
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
	if !strings.Contains(err.Error(), "nothing names the CDS") {
		t.Fatalf("error = %v, want it to name the missing CDS", err)
	}
}

// An address file the node cannot read, or one holding something no client
// could dial, is refused at load: an endpoint the node cannot bind a rule to
// would leave every injected client dialling nothing.
func TestAddressFileMustNameAnEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
	}{
		{name: "no port", address: "cds.cluster.local"},
		{name: "port 0", address: "10.9.9.9:0"},
		{name: "a URL", address: "https://cds.cluster.local:8443"},
		{name: "empty", address: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadCDSAddress(installedCDSAddress(t, tc.address).Pull); err == nil {
				t.Fatalf("address %q accepted", tc.address)
			}
		})
	}
	absent := pullConfig{CDSAddressFile: filepath.Join(t.TempDir(), "absent")}
	if _, err := loadCDSAddress(absent); err == nil {
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
		Allowlist:      installedCDSAddress(t, "cds.example.org:8443"),
		Mesh:           meshRoles(),
	}
	cfg.Allowlist.Pull.CDSMeasurementsConfig = testCDSPinFile(t)
	address, err := loadCDSAddress(cfg.Allowlist.Pull)
	if err != nil {
		t.Fatalf("loadCDSAddress: %v", err)
	}
	cfg.cdsAddress = address
	if err := bindCredentialRole(cfg); err != nil {
		t.Fatalf("bindCredentialRole: %v", err)
	}
	renderInTempDir(t)
	p := &plugin{cfg: cfg}
	if err := p.prepareCDSPins(nodeCDSPins(t, p)); err != nil {
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
