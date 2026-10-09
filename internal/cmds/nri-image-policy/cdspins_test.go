package nriimagepolicy

import (
	"context"
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
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
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
		adjust := mustCredentialMounts(t, p, pod, &api.Container{
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
	if adjust := mustCredentialMounts(t, p, pod, workload); adjust != nil {
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
	if adjust := mustCredentialMounts(t, p, uninjected, cert); adjust != nil {
		t.Fatalf("uninjected pod received node mounts: %+v", adjust.GetMounts())
	}
}

// The router's pod is chart-rendered, so no annotation marks it; the measured
// credentials role on its reserved identity is what the node addresses its CDS
// to.
func TestSidecarAdjustmentFollowsTheMeasuredCredentialsRole(t *testing.T) {
	dir := t.TempDir()
	renderInTempDir(t)
	base := &allowlist.Allowlist{
		Schema: allowlist.Schema,
		Workloads: map[string]allowlist.Workload{
			"c8s-allowlist-proxy": {Containers: []allowlist.Container{{
				Digest: mustDigestOrPanic(pushDigestA),
				Role:   CredentialRole,
				Command: allowlist.ArgvPolicy{
					Policy: allowlist.PolicyExact,
					Argv:   []string{"/c8s", "allowlist-proxy"},
				},
				Args: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
				Mounts: allowlist.MountPolicy{
					Policy: allowlist.PolicyExact,
					Rules: []allowlist.MountRule{{
						Destination: workloadclaims.SidecarSocketDir,
						Kind:        allowlist.MountHost,
						Source:      dir,
						ReadOnly:    true,
					}},
				},
			}}},
		},
	}
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: dir},
		Allowlist:      allowlistConfig{Base: base, Pull: pullConfig{CDSMeasurements: []string{testDigestA}}},
	})
	p.policy = newPolicyStore(base)
	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	pod := &api.PodSandbox{
		Id:        "sandbox",
		Uid:       "uid",
		Namespace: "c8s-router",
	}
	// The pod's own mount set, as the router pod renders it, beside the
	// kubelet's own /etc/hosts: a declaration that pins the mount set is
	// matched against the same classification the final check uses.
	proxy := &api.Container{
		Name:         "allowlist-proxy",
		PodSandboxId: "sandbox",
		Annotations:  map[string]string{annotationImageName: "registry/c8s@" + pushDigestA},
		Args:         []string{"/c8s", "allowlist-proxy", "--port=8801"},
		User:         &api.User{Uid: workloadclaims.CredentialsUID},
		Mounts: []*api.Mount{
			readOnlyBind(dir, workloadclaims.SidecarSocketDir),
			readOnlyBind("/var/lib/kubelet/pods/uid/etc-hosts", "/etc/hosts"),
		},
	}
	if mountTo(mustCredentialMounts(t, p, pod, proxy), workloadclaims.CDSPinsPath) == nil {
		t.Error("a credentials-role container was handed no CDS policy, so it would dial an unpinned CDS")
	}

	// An ordinary container of the same pod asks for nothing and gets
	// nothing; one taking the credentials identity that the base grants no
	// role is refused.
	app := &api.Container{
		Name:         "app",
		PodSandboxId: "sandbox",
		Annotations:  proxy.Annotations,
	}
	if adjust, err := p.credentialMounts(context.Background(), pod, app); adjust != nil || err != nil {
		t.Errorf("a container outside the credentials identity got (%+v, %v), want nothing", adjust.GetMounts(), err)
	}
	app.User = &api.User{Uid: workloadclaims.CredentialsUID}
	app.Args = []string{"/c8s", "operator"}
	if _, err := p.credentialMounts(context.Background(), pod, app); err == nil {
		t.Error("a container took the credentials identity without the role, so it would reach CDS unpinned")
	}

	// A nil User is uid 0, not the reserved identity.
	proxy.User = nil
	if adjust, err := p.credentialMounts(context.Background(), pod, proxy); adjust != nil || err != nil {
		t.Errorf("a container declaring no user got (%+v, %v), want nothing", adjust.GetMounts(), err)
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

	adjust := mustCredentialMounts(t, p, pod, &api.Container{
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

// mustCredentialMounts is the adjustment the node adds for one container, for
// the cases where it must not be a refusal.
func mustCredentialMounts(t *testing.T, p *plugin, pod *api.PodSandbox, ctr *api.Container) *api.ContainerAdjustment {
	t.Helper()
	adjustment, err := p.credentialMounts(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("container %q refused: %v", ctr.GetName(), err)
	}
	return adjustment
}

func mountTo(adjust *api.ContainerAdjustment, destination string) *api.Mount {
	for _, m := range adjust.GetMounts() {
		if m.GetDestination() == destination {
			return m
		}
	}
	return nil
}
