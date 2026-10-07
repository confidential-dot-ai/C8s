package nriimagepolicy

import (
	"path/filepath"
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

// A node whose policy is a document hands that document over unchanged: on a
// baked node it is the measured file, and re-rendering it could only lose a
// pin it carries. It is loaded first, so a document no client could use fails
// here rather than in every pod.
func TestPrepareCDSPinsPrefersTheConfiguredDocument(t *testing.T) {
	p := testPlugin(t, &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: identityPolicyFile}},
	})

	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	if p.cdsPins != identityPolicyFile {
		t.Fatalf("pins path = %q, want the configured document", p.cdsPins)
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
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: dir},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurements: []string{testDigestA, testDigestB}}},
	})

	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	if want := filepath.Join(dir, renderedCDSPinsName); p.cdsPins != want {
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
		if set.Images[i].Name != want {
			t.Errorf("image %d is named %q, want its digest %q", i, set.Images[i].Name, want)
		}
	}
}

// TDX pins the registers beside each launch digest; SNP evidence carries none,
// so the same input renders without them.
func TestRenderCDSPinsPerPlatform(t *testing.T) {
	registers := []string{"1=" + strings.Repeat("cd", 48)}

	tdx, err := renderCDSPins("tdx", []string{testDigestA}, registers)
	if err != nil {
		t.Fatalf("render tdx: %v", err)
	}
	set, err := refvalues.Parse(tdx)
	if err != nil {
		t.Fatalf("parse tdx: %v", err)
	}
	if len(set.Images[0].Registers) != 1 {
		t.Fatalf("tdx image registers = %v, want the node's register pin", set.Images[0].Registers)
	}

	snp, err := renderCDSPins("sev-snp", []string{testDigestA}, registers)
	if err != nil {
		t.Fatalf("render snp: %v", err)
	}
	set, err = refvalues.Parse(snp)
	if err != nil {
		t.Fatalf("parse snp: %v", err)
	}
	if len(set.Images[0].Registers) != 0 {
		t.Fatalf("snp image carries registers %v", set.Images[0].Registers)
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

	if err := pull.validatePolicyInputs("sev-snp"); err == nil {
		t.Fatal("a document beside independent pins was accepted")
	}
	if err := (pullConfig{CDSMeasurements: []string{testDigestA}}).validatePolicyInputs("moon"); err == nil {
		t.Fatal("independent pins were accepted without a platform to render them for")
	}
}

// The enforcer hands each injected credential client the node's policy at the
// compiled path, read-only, and nothing to any other container.
func TestSidecarAdjustmentMountsTheNodePolicy(t *testing.T) {
	dir := t.TempDir()
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: dir},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurements: []string{testDigestA}}},
	})
	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	pod := &api.PodSandbox{Id: "sandbox", Uid: "uid", Annotations: map[string]string{workloadclaims.AnnotationInjected: "true"}}

	for _, name := range []string{workloadclaims.CertContainerName, workloadclaims.SecretContainerName, workloadclaims.VolumeContainerName} {
		adjust := p.sidecarAdjustment(pod, &api.Container{Name: name, PodSandboxId: "sandbox"})
		mount := mountTo(adjust, workloadclaims.CDSPinsPath)
		if mount == nil {
			t.Fatalf("%s has no CDS policy mount: %+v", name, adjust.GetMounts())
		}
		if mount.GetSource() != filepath.Join(dir, renderedCDSPinsName) {
			t.Errorf("%s policy source = %q, want the node's own file", name, mount.GetSource())
		}
		if !slices.Contains(mount.GetOptions(), "ro") {
			t.Errorf("%s policy mount is writable: %v", name, mount.GetOptions())
		}
	}

	if adjust := p.sidecarAdjustment(pod, &api.Container{Name: "app", PodSandboxId: "sandbox"}); adjust != nil {
		t.Fatalf("workload container received node mounts: %+v", adjust.GetMounts())
	}
	uninjected := &api.PodSandbox{Id: "sandbox", Uid: "uid"}
	if adjust := p.sidecarAdjustment(uninjected, &api.Container{Name: workloadclaims.CertContainerName, PodSandboxId: "sandbox"}); adjust != nil {
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
	pod := &api.PodSandbox{Id: "sandbox", Uid: "uid", Annotations: map[string]string{workloadclaims.AnnotationInjected: "true"}}

	adjust := p.sidecarAdjustment(pod, &api.Container{Name: workloadclaims.CertContainerName, PodSandboxId: "sandbox"})
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
