package nriimagepolicy

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var (
	testDigestA = strings.Repeat("a1", 48)
	testDigestB = strings.Repeat("b2", 48)
)

// identityPolicyFile is a complete sev-snp policy document, as a node's
// measured config names one.
const identityPolicyFile = "../../testdata/node-identities.json"

// A node whose policy is a document hands those identities on whole, through
// the same render path its independent pins take.
func TestPrepareCDSPinsRendersTheConfiguredDocument(t *testing.T) {
	renderInTempDir(t)
	p := testPlugin(t, &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: identityPolicyFile}},
	})

	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	if want := filepath.Join(enforcerRuntimeDir, renderedCDSPinsName); p.cdsPins != want {
		t.Fatalf("pins path = %q, want %q", p.cdsPins, want)
	}
	configured, err := refvalues.Load(identityPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := refvalues.Load(p.cdsPins)
	if err != nil {
		t.Fatalf("rendered pins do not load: %v", err)
	}
	if !reflect.DeepEqual(rendered, configured) {
		t.Fatalf("rendered pins = %+v, want the configured identities %+v", rendered, configured)
	}
}

// The copy the enforcer mounts is readable by the identity that reads it and
// writable by nobody else: a baked node stages its own CDS identities where
// only root can read them (internal/cmds/launchconfig), and the injected
// clients run as the credentials UID.
func TestPrepareCDSPinsStagesACopyEveryClientCanRead(t *testing.T) {
	renderInTempDir(t)
	document, err := os.ReadFile(identityPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	rootOnly := filepath.Join(t.TempDir(), "cds.json")
	if err := os.WriteFile(rootOnly, document, 0o600); err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t, &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: rootOnly}},
	})

	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	staged, err := os.Stat(p.cdsPins)
	if err != nil {
		t.Fatal(err)
	}
	if perm := staged.Mode().Perm(); perm&0o044 == 0 || perm&0o022 != 0 {
		t.Fatalf("staged pins %s are mode %04o, which uid %d cannot read or a pod could write",
			p.cdsPins, perm, workloadclaims.CredentialsUID)
	}
}

// A configured document for another platform is refused at startup: a node
// must not hand its pods pins it cannot itself verify CDS against.
func TestPrepareCDSPinsRefusesAnotherPlatformsDocument(t *testing.T) {
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: identityPolicyFile}},
	})

	if err := p.prepareCDSPins(); err == nil {
		t.Fatal("prepareCDSPins accepted a document for another platform")
	}
}

// Independent pins become the same document, so one format reaches every
// client. It must load back through the loader the clients use.
func TestPrepareCDSPinsRendersIndependentPins(t *testing.T) {
	dir := t.TempDir()
	renderInTempDir(t)
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: dir},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurements: []string{testDigestA, testDigestB}}},
	})

	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	if want := filepath.Join(enforcerRuntimeDir, renderedCDSPinsName); p.cdsPins != want {
		t.Fatalf("pins path = %q, want %q", p.cdsPins, want)
	}
	set, err := refvalues.Load(p.cdsPins)
	if err != nil {
		t.Fatalf("rendered pins do not load: %v", err)
	}
	if len(set.Images) != 2 {
		t.Fatalf("rendered images = %d, want one per launch digest", len(set.Images))
	}
	for i, want := range []string{testDigestA, testDigestB} {
		if got := hex.EncodeToString(set.Images[i].Digest); got != want {
			t.Errorf("image %d pins %q, want the configured digest %q", i, got, want)
		}
	}
}

// SNP evidence carries no registers, so a node configured with them for SNP
// is refused rather than handed a document pinning fewer identities than it
// asked for.
func TestPrepareCDSPinsRefusesRegistersTheFamilyLacks(t *testing.T) {
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist: allowlistConfig{Pull: pullConfig{
			CDSMeasurements: []string{testDigestA},
			CDSRTMRs:        []string{"1=" + strings.Repeat("cd", 48)},
		}},
	})

	if err := p.prepareCDSPins(); err == nil {
		t.Fatal("prepareCDSPins rendered register pins for a family whose evidence carries none")
	}
}

// A node that pins nothing mounts nothing: the client then has no policy to
// read, which its own unpinned check reports.
func TestPrepareCDSPinsEmptyWithoutPins(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config
	}{
		{"no pins", &config{WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()}}},
		{"no inventory directory", &config{Allowlist: allowlistConfig{Pull: pullConfig{CDSMeasurements: []string{testDigestA}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPlugin(t, tc.cfg)
			if err := p.prepareCDSPins(); err != nil {
				t.Fatalf("prepareCDSPins: %v", err)
			}
			if p.cdsPins != "" {
				t.Fatalf("pins path = %q, want none", p.cdsPins)
			}
		})
	}
}

// Competing sources are refused before anything is written: a node must not
// hand out one policy while holding its CDS to another.
func TestConfigRefusesCompetingPolicySources(t *testing.T) {
	pull := pullConfig{
		CDSMeasurementsConfig: identityPolicyFile,
		CDSMeasurements:       []string{testDigestA},
	}

	if err := pull.checkPolicySources(); err == nil {
		t.Fatal("a document beside independent pins was accepted")
	}
	if _, err := pull.policySet("tdx"); err == nil {
		t.Fatal("the loader read a document beside independent pins")
	}
	if _, err := (pullConfig{CDSMeasurements: []string{testDigestA}}).policySet("moon"); err == nil {
		t.Fatal("independent pins were accepted without a platform to render them for")
	}
}

// The enforcer hands each injected credential client the node's policy at the
// compiled path, read-only, and nothing to any other container.
func TestSidecarAdjustmentMountsTheNodePolicy(t *testing.T) {
	dir := t.TempDir()
	renderInTempDir(t)
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: dir},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurements: []string{testDigestA}}},
	})
	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	pod := &api.PodSandbox{
		Id:          "sandbox",
		Uid:         "uid",
		Annotations: map[string]string{workloadclaims.AnnotationInjected: "true"},
	}

	for _, name := range []string{workloadclaims.CertContainerName, workloadclaims.SecretContainerName, workloadclaims.VolumeContainerName} {
		adjust := p.sidecarAdjustment(pod, &api.Container{
			Name:         name,
			PodSandboxId: "sandbox",
		})
		mount := mountTo(adjust, workloadclaims.CDSPinsPath)
		if mount == nil {
			t.Fatalf("%s has no CDS policy mount: %+v", name, adjust.GetMounts())
		}
		if mount.GetSource() != filepath.Join(enforcerRuntimeDir, renderedCDSPinsName) {
			t.Errorf("%s policy source = %q, want the node's own file", name, mount.GetSource())
		}
		if !slices.Contains(mount.GetOptions(), "ro") {
			t.Errorf("%s policy mount is writable: %v", name, mount.GetOptions())
		}
	}

	workload := &api.Container{
		Name:         "app",
		PodSandboxId: "sandbox",
	}
	if adjust := p.sidecarAdjustment(pod, workload); adjust != nil {
		t.Fatalf("workload container received node mounts: %+v", adjust.GetMounts())
	}
	uninjected := &api.PodSandbox{
		Id:  "sandbox",
		Uid: "uid",
	}
	cert := &api.Container{
		Name:         workloadclaims.CertContainerName,
		PodSandboxId: "sandbox",
	}
	if adjust := p.sidecarAdjustment(uninjected, cert); adjust != nil {
		t.Fatalf("uninjected pod received node mounts: %+v", adjust.GetMounts())
	}
}

// A node that pins nothing adds no policy mount, so a client cannot mistake an
// empty file for a policy.
func TestSidecarAdjustmentWithoutPins(t *testing.T) {
	p := testPlugin(t, &config{WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()}})
	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	pod := &api.PodSandbox{
		Id:          "sandbox",
		Uid:         "uid",
		Annotations: map[string]string{workloadclaims.AnnotationInjected: "true"},
	}

	adjust := p.sidecarAdjustment(pod, &api.Container{
		Name:         workloadclaims.CertContainerName,
		PodSandboxId: "sandbox",
	})
	if mountTo(adjust, workloadclaims.CDSPinsPath) != nil {
		t.Fatalf("unpinned node mounted a policy: %+v", adjust.GetMounts())
	}
	if mountTo(adjust, workloadclaims.SidecarSocketDir) == nil {
		t.Fatalf("inventory socket mount missing: %+v", adjust.GetMounts())
	}
}

// testPlugin builds a plugin from cfg alone: these tests exercise what the
// node hands a pod, not the runtime hooks.
func testPlugin(t *testing.T, cfg *config) *plugin {
	t.Helper()
	cfg.Policy.Mode = ModeFailClosed
	p, err := newPlugin(cfg, &fakeContainerd{}, newPolicyStore(nil), audit.NewLogger(), discardLogger())
	if err != nil {
		t.Fatalf("newPlugin: %v", err)
	}
	return p
}

func mountTo(adjust *api.ContainerAdjustment, destination string) *api.Mount {
	for _, m := range adjust.GetMounts() {
		if m.GetDestination() == destination {
			return m
		}
	}
	return nil
}
