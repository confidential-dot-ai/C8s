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
		WorkloadClaims: workloadClaimsConfig{
			SocketDir:   nodeDir(t, "10.0.0.7"),
			CDSNodePort: 31000,
		},
		Mesh: measuredCDSPolicy("10.1.2.3:30808"),
	}
	if err := bindCredentialRole(cfg); err != nil {
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
// role to its own address and the CDS node port, and hands its clients that
// same endpoint.
func TestInstallBindsTheCredentialRoleToThisNode(t *testing.T) {
	cfg := &config{
		WorkloadClaims: workloadClaimsConfig{
			SocketDir:   nodeDir(t, "10.0.0.7"),
			CDSNodePort: 30808,
		},
		Mesh: meshRoles(),
	}
	if err := bindCredentialRole(cfg); err != nil {
		t.Fatalf("bindCredentialRole: %v", err)
	}
	role, bound := cfg.credentialRole()
	if !bound || role.UID != workloadclaims.CredentialsUID {
		t.Fatalf("credential role = %+v, want it bound to uid %d", role, workloadclaims.CredentialsUID)
	}
	if got := role.Destinations[0].String(); got != "10.0.0.7:30808" {
		t.Fatalf("destination = %q, want this node's address and CDS node port", got)
	}
	if err := cfg.Mesh.validate(); err != nil {
		t.Fatalf("the completed policy no longer validates: %v", err)
	}
	renderInTempDir(t)
	p := &plugin{cfg: cfg}
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("prepareCDSAddress: %v", err)
	}
	if got := readAddress(t, p.cdsAddress); got != "10.0.0.7:30808" {
		t.Fatalf("handed address = %q, want the bound destination", got)
	}
}

// A node that injects credential clients and knows no CDS endpoint refuses to
// start: a client with no address reaches no CDS at all.
func TestCDSEndpointIsRequiredWhereClientsAreInjected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   *config
		wants string
	}{
		{
			name:  "no node port",
			cfg:   &config{WorkloadClaims: workloadClaimsConfig{SocketDir: nodeDir(t, "10.0.0.7")}},
			wants: "cds_node_port",
		},
		{
			name: "no address for this node",
			cfg: &config{WorkloadClaims: workloadClaimsConfig{
				SocketDir:   t.TempDir(),
				CDSNodePort: 30808,
			}},
			wants: "this node's own address",
		},
		{
			name: "an address that is no address",
			cfg: &config{WorkloadClaims: workloadClaimsConfig{
				SocketDir:   nodeDir(t, "node.cluster.local"),
				CDSNodePort: 30808,
			}},
			wants: "this node's own address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			renderInTempDir(t)
			p := &plugin{cfg: tc.cfg}
			err := p.prepareCDSAddress()
			if err == nil {
				t.Fatal("a node with no CDS endpoint started")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error = %v, want it to name %q", err, tc.wants)
			}
		})
	}
}

// Neither rendered document is written where the plugin bind-mounts the whole
// inventory socket directory: each reaches a pod at the one path its client
// reads.
func TestRenderedDocumentsAreOutsideTheMountedSocketDirectory(t *testing.T) {
	socketDir := nodeDir(t, "10.0.0.7")
	cfg := &config{
		Platform: "sev-snp",
		WorkloadClaims: workloadClaimsConfig{
			SocketDir:   socketDir,
			CDSNodePort: 30808,
		},
		Allowlist: allowlistConfig{Pull: pullConfig{CDSMeasurements: []string{testDigestA}}},
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
	mount := addressMount(t, p.sidecarAdjustment(pod, &api.Container{Name: workloadclaims.CertContainerName}))
	if mount.GetSource() != p.cdsAddress {
		t.Fatalf("source = %q, want the plugin's own file", mount.GetSource())
	}
	if !slices.Contains(mount.GetOptions(), "ro") {
		t.Fatalf("options = %v, want a read-only mount", mount.GetOptions())
	}
	if got := p.sidecarAdjustment(pod, &api.Container{Name: "app"}); got != nil {
		t.Fatalf("workload adjustment = %+v, want none", got)
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
