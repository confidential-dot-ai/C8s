package nriimagepolicy

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// A node hands its CDS pin on whole, so every injected client holds CDS to the
// same launch file the node does.
func TestPrepareCDSPinsRendersTheConfiguredDocument(t *testing.T) {
	renderInTempDir(t)
	pin := testCDSPinFile(t)
	p := testPlugin(t, &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: pin}},
	})

	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	if want := filepath.Join(enforcerRuntimeDir, renderedCDSPinsName); p.cdsPins != want {
		t.Fatalf("pins path = %q, want %q", p.cdsPins, want)
	}
	configured, err := refvalues.Load(pin)
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
	rootOnly := testCDSPinFile(t)
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

// A CDS runs on the TEE family its own document declares, which an operator
// chooses independently of the nodes it serves.
func TestPrepareCDSPinsAcceptsTheCDSVMsOwnFamily(t *testing.T) {
	renderInTempDir(t)
	p := testPlugin(t, &config{
		Platform:       "tdx",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: testCDSPinFile(t)}},
	})

	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	rendered, err := refvalues.Load(p.cdsPins)
	if err != nil {
		t.Fatalf("rendered pins do not load: %v", err)
	}
	if rendered.Family != teetypes.FamilySNP {
		t.Fatalf("rendered family = %s, want the document's own %s", rendered.Family, teetypes.FamilySNP)
	}
}

// Without an inventory directory no pod of this node is injected, so there is
// nothing to render and nothing to mount.
func TestPrepareCDSPinsEmptyWithoutInventory(t *testing.T) {
	p := testPlugin(t, &config{Allowlist: allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: testCDSPinFile(t)}}})
	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	if p.cdsPins != "" {
		t.Fatalf("pins path = %q, want none", p.cdsPins)
	}
}

// A CDS is pinned to the configuration it runs on, so a document naming only
// its image is refused before anything is written: every client this node
// injects would otherwise admit any CDS VM.
func TestPrepareCDSPinsRefusesAPinWithoutALaunchBinding(t *testing.T) {
	renderInTempDir(t)
	unbound := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + testutil.TestMeasurement + `"}]}`
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: cdsPinFile(t, unbound)}},
	})

	if err := p.prepareCDSPins(); err == nil || !strings.Contains(err.Error(), "launch file") {
		t.Fatalf("prepareCDSPins = %v, want a launch-binding refusal", err)
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
		Allowlist:      allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: testCDSPinFile(t)}},
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
		Allowlist:      allowlistConfig{Base: base, Pull: pullConfig{CDSMeasurementsConfig: testCDSPinFile(t)}},
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

// A node that injects credential clients but pins no CDS refuses before any
// container is created, and renders nothing a client could mistake for a
// policy.
func TestSidecarAdjustmentRefusedWithoutPins(t *testing.T) {
	p := testPlugin(t, &config{WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()}})
	if err := p.prepareCDSPins(); err == nil || !strings.Contains(err.Error(), "pins no image") {
		t.Fatalf("prepareCDSPins() = %v, want the unpinned-CDS refusal", err)
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
	if cfg.Mesh == nil {
		cfg.Mesh = meshRoles()
	}
	p, err := newPlugin(cfg, &fakeContainerd{}, newPolicyStore(nil), audit.NewLogger(), discardLogger())
	if err != nil {
		t.Fatalf("newPlugin: %v", err)
	}
	return p
}

// The certificate gate holds the credentials identity but is no socket
// consumer: it takes the CDS policy and no socket directory, so the mounts the
// node observes for it are the webhook's alone and its exact entry holds.
func TestCertGateTakesNoSocketDirectory(t *testing.T) {
	dir := t.TempDir()
	renderInTempDir(t)
	certs := allowlist.MountRule{Destination: workloadclaims.MemberCertDir, Kind: allowlist.MountEmptyDir, Source: "c8s-certs"}
	base := &allowlist.Allowlist{
		Schema: allowlist.Schema,
		Workloads: map[string]allowlist.Workload{
			"c8s-probe-file": {Containers: []allowlist.Container{{
				Digest:  mustDigestOrPanic(pushDigestA),
				Role:    CredentialRole,
				Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/c8s", "probe-file"}},
				Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
				Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{certs}},
			}}},
		},
	}
	p := testPlugin(t, &config{
		Platform:       "sev-snp",
		WorkloadClaims: workloadClaimsConfig{SocketDir: dir},
		Allowlist:      allowlistConfig{Base: base, Pull: pullConfig{CDSMeasurementsConfig: testCDSPinFile(t)}},
	})
	p.policy = newPolicyStore(base)
	p.mountStorage = fixedStorage(allowlist.MountMemory)
	p.inventory = newAdmissionInventory(t.TempDir())
	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("prepareCDSPins: %v", err)
	}
	pod := &api.PodSandbox{
		Id:          "sandbox",
		Uid:         "uid",
		Namespace:   "default",
		Annotations: map[string]string{workloadclaims.AnnotationInjected: "true"},
	}
	gate := &api.Container{
		Name:         workloadclaims.CertWaitContainerName,
		PodSandboxId: "sandbox",
		Annotations:  map[string]string{annotationImageName: "registry/c8s@" + pushDigestA},
		Args:         []string{"/c8s", "probe-file", "--wait", workloadclaims.MemberCertDir + "/tls.crt"},
		User:         &api.User{Uid: workloadclaims.CredentialsUID},
		Mounts: []*api.Mount{{
			Source:      kubeletRoot + "/pods/uid/volumes/" + emptyDirPlugin + "/c8s-certs",
			Destination: workloadclaims.MemberCertDir,
			Type:        "bind",
			Options:     []string{"rbind", "rw"},
		}},
	}
	adjust := mustCredentialMounts(t, p, pod, gate)
	if mountTo(adjust, workloadclaims.CDSPinsPath) == nil {
		t.Error("the certificate gate was handed no CDS policy")
	}
	if m := mountTo(adjust, workloadclaims.SidecarSocketDir); m != nil {
		t.Errorf("the certificate gate was handed the socket directory %s, which it observes as a host mount", m.GetSource())
	}
	gate.Mounts = append(gate.Mounts, adjust.GetMounts()...)
	if got := p.measuredRole(context.Background(), pod, gate); got != CredentialRole {
		t.Errorf("the gate with the node's own mounts holds the role %q, want %q", got, CredentialRole)
	}
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
