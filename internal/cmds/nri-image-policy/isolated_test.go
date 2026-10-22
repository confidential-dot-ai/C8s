package nriimagepolicy

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestIsolatedPolicyRejectsClusterSettings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*meshPolicy)
	}{
		{"exemption", func(p *meshPolicy) { p.ExemptNamespaces = []string{"kube-system"} }},
		{"resolver", func(p *meshPolicy) { p.Resolver = netip.MustParseAddr("10.53.0.10") }},
		{"capture", func(p *meshPolicy) { p.Capture.Inbound = 15006 }},
		{"credential attestation", func(p *meshPolicy) { p.CredentialAttestationPort = 8400 }},
		{"role", func(p *meshPolicy) { p.Roles = meshRoles().Roles }},
		{"ranges", func(p *meshPolicy) { p.ClusterRanges = meshRoles().ClusterRanges }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := meshPolicy{Isolated: true}
			tc.change(&p)
			if err := p.validate(); err == nil {
				t.Fatal("isolated policy accepted a cluster setting")
			}
		})
	}
}

func isolatedConfig(t *testing.T) *config {
	t.Helper()
	c := meshConfigForLoad(t)
	c.Allowlist.NodeTCB = false
	c.Allowlist.Base = anyAllowlist(map[string]string{pushDigestB: "app"})
	c.Policy.Sandbox = SandboxEnforce
	c.Policy.DenyMissingAnnotation = true
	c.Mesh = &meshPolicy{Isolated: true}
	return c
}

func TestIsolatedConfigRequiresEnforcement(t *testing.T) {
	if !meshSupported {
		t.Skip("mesh config is only supported on Linux")
	}
	for _, tc := range []struct {
		name   string
		change func(*config)
	}{
		{"valid", func(*config) {}},
		{"audit", func(c *config) { c.Policy.Mode = ModeAudit; c.Policy.FatalExisting = false }},
		{"no boot gate", func(c *config) { c.Policy.FatalExisting = false }},
		{"no existing enforcement", func(c *config) { c.Policy.EnforceExisting = false }},
		{"sandbox off", func(c *config) { c.Policy.Sandbox = SandboxOff }},
		{"missing image allowed", func(c *config) { c.Policy.DenyMissingAnnotation = false }},
		{"node tcb", func(c *config) { c.Allowlist.NodeTCB = true }},
		{"exemption", func(c *config) {
			c.Policy.ExemptNamespaces = []string{"tenant"}
			c.Policy.ExemptSnapshotPath = "/var/lib/snapshot"
		}},
		{"credential injection", func(c *config) { c.WorkloadClaims.CDSNodePort = 30808 }},
		{"base role", func(c *config) { c.Allowlist.Base = roleBase(t, pushDigestB, routerRole, []string{"/app"}) }},
		{"init role", func(c *config) {
			c.Allowlist.Base = roleBase(t, pushDigestB, meshRole, []string{"/mesh"})
			w := c.Allowlist.Base.Workloads["role-entry"]
			w.InitContainers, w.Containers = w.Containers, nil
			c.Allowlist.Base.Workloads["role-entry"] = w
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := isolatedConfig(t)
			tc.change(c)
			_, err := loadMeshConfigDocument(t, c)
			if (err != nil) != (tc.name != "valid") {
				t.Fatalf("load isolated config: %v", err)
			}
		})
	}
}

func TestIsolatedGateKeepsIdentityAndNamespaceChecks(t *testing.T) {
	for _, namespace := range []string{"tenant", "kube-system", routerNamespace} {
		t.Run(namespace, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				change func(*api.PodSandbox, *api.Container, *gatedContainer)
				wants  string
			}{
				{"workload without endpoint", func(*api.PodSandbox, *api.Container, *gatedContainer) {}, ""},
				{"root", func(_ *api.PodSandbox, c *api.Container, _ *gatedContainer) { c.User.Uid = 0 }, "nonzero uid"},
				{"role", func(_ *api.PodSandbox, _ *api.Container, l *gatedContainer) { l.role = routerRole }, "no reserved uid"},
				{"network adjustment", func(_ *api.PodSandbox, _ *api.Container, l *gatedContainer) {
					l.namespaces = []*api.LinuxNamespace{{Type: "network", Path: "/other"}}
				}, "re-points"},
				{"host network", func(p *api.PodSandbox, _ *api.Container, _ *gatedContainer) { p.Linux.Namespaces = nil }, "network namespace moved"},
				{"namespace changed", func(p *api.PodSandbox, _ *api.Container, _ *gatedContainer) { p.Namespace = "other" }, "reported namespace moved"},
				{"missing pid namespace", func(_ *api.PodSandbox, c *api.Container, _ *gatedContainer) { c.Linux.Namespaces = nil }, "declares no pid namespace"},
				{"shared pid namespace", func(_ *api.PodSandbox, c *api.Container, _ *gatedContainer) {
					c.Linux.Namespaces[0].Path = "/proc/42/ns/pid"
				}, "joins the pid namespace"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					pod := meshPod(namespace, "app", testNetNS)
					gate, _ := gateWithPod(pod)
					gate.policy = &meshPolicy{Isolated: true}
					ctr := gateCtr("app", testWorkloadUID)
					launch := gatedContainer{}
					tc.change(pod, ctr, &launch)
					if !gate.hosts(pod) {
						t.Fatal("isolated pod bypassed the gate")
					}
					_, _, err := gate.admissible(pod, ctr, launch)
					if tc.wants == "" && err != nil || tc.wants != "" && (err == nil || !strings.Contains(err.Error(), tc.wants)) {
						t.Fatalf("admission = %v, want %q", err, tc.wants)
					}
				})
			}
			pod := meshPod(namespace, "app", testNetNS)
			gate, state := gateWithPod(pod)
			gate.policy = &meshPolicy{Isolated: true}
			state.meshStarted = true
			if err := gate.verifyMember(pod.GetId()); err == nil || !strings.Contains(err.Error(), "not mesh members") {
				t.Fatalf("isolated member assertion = %v", err)
			}
		})
	}
}

func TestIsolatedInventoryDoesNotInjectCredentialClients(t *testing.T) {
	c := isolatedConfig(t)
	c.WorkloadClaims.SocketDir = "/run/nri-image-policy"
	p := newTestPlugin(c)
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("isolated inventory requires no CDS endpoint: %v", err)
	}
	if err := p.prepareCDSPins(); err != nil {
		t.Fatalf("isolated inventory requires no CDS policy: %v", err)
	}
	if c.injectsCredentialClients() || p.cdsAddress != "" {
		t.Fatal("isolated inventory enabled credential injection")
	}
}

func TestIsolatedInventoryMountsRemainHostMounts(t *testing.T) {
	c := isolatedConfig(t)
	c.WorkloadClaims.SocketDir = "/run/nri-image-policy"
	p := newTestPlugin(c)
	p.inventory = newAdmissionInventory(t.TempDir())
	p.cdsPins, p.cdsAddress = "/run/c8s-enforcer/pins", "/run/c8s-enforcer/address"
	for _, tc := range []struct {
		name, container, namespace string
		uid                        uint32
	}{
		{"cert sidecar", workloadclaims.CertContainerName, "tenant", testWorkloadUID},
		{"attest sidecar", workloadclaims.AttestContainerName, "tenant", testWorkloadUID},
		{"credential identity", "client", "tenant", workloadclaims.CredentialsUID},
		{"router client", workloadclaims.AttestContainerName, routerNamespace, workloadclaims.UpstreamUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := sandboxedPod()
			pod.Namespace = tc.namespace
			injectedPod(pod)
			ctr := makeCtrWithImage(pod.GetId(), tc.container, "registry/repo@"+pushDigestB)
			ctr.User = &api.User{Uid: tc.uid, Gid: 65532}
			adjust, _, err := p.CreateContainer(context.Background(), pod, ctr)
			if err != nil || len(adjust.GetMounts()) != 0 {
				t.Fatalf("isolated create: adjustment=%v error=%v", adjust, err)
			}
			for _, mount := range []*api.Mount{
				readOnlyBind(c.WorkloadClaims.SocketDir, workloadclaims.SidecarSocketDir),
				readOnlyBind(p.cdsPins, workloadclaims.CDSPinsPath),
				readOnlyBind(p.cdsAddress, workloadclaims.CDSAddressPath),
			} {
				ctr.Mounts = []*api.Mount{mount}
				if isInjectedNodeMount(pod, ctr, mount, p.nodeMounts()) {
					t.Fatalf("isolated pod inherited a trusted mount: %s", mount.Destination)
				}
				mounts := p.observedMounts(pod, ctr)
				if binds := hostBinds(pod, ctr, p.nodeMounts(), mounts, nil); len(binds) != 1 {
					t.Fatalf("isolated host mount was exempt: %v", binds)
				}
			}
		})
	}
}

func TestIsolatedAdjustmentRejectsUnobservedPrivileges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		adjust *api.ContainerAdjustment
		wants  string
	}{
		{"no edits", nil, ""},
		{"empty hooks", &api.ContainerAdjustment{Hooks: &api.Hooks{}}, ""},
		{"arguments", &api.ContainerAdjustment{Args: []string{"/app"}}, ""},
		{"resource sizing", &api.ContainerAdjustment{Linux: &api.LinuxContainerAdjustment{Resources: &api.LinuxResources{}}}, ""},
		{"CDI", &api.ContainerAdjustment{CDIDevices: []*api.CDIDevice{{Name: "vendor/device=test"}}}, "CDI device injection"},
		{"hook", &api.ContainerAdjustment{Hooks: &api.Hooks{Prestart: []*api.Hook{{Path: "/hook"}}}}, "OCI hook"},
		{"device", &api.ContainerAdjustment{Linux: &api.LinuxContainerAdjustment{Devices: []*api.LinuxDevice{{Path: "/dev/host"}}}}, "host device node"},
		{"device permission", &api.ContainerAdjustment{Linux: &api.LinuxContainerAdjustment{Resources: &api.LinuxResources{Devices: []*api.LinuxDeviceCgroup{{Allow: true, Access: "rwm"}}}}}, "device cgroup rule"},
		{"sysctl", &api.ContainerAdjustment{Linux: &api.LinuxContainerAdjustment{Sysctl: map[string]string{"net.ipv4.ip_forward": "1"}}}, "container sysctl"},
		{"cgroup", &api.ContainerAdjustment{Linux: &api.LinuxContainerAdjustment{CgroupsPath: "/host"}}, "cgroup move"},
		{"seccomp", &api.ContainerAdjustment{Linux: &api.LinuxContainerAdjustment{SeccompPolicy: &api.LinuxSeccomp{ListenerPath: "/run/host.sock"}}}, "seccomp replacement"},
		{"runtime identity", &api.ContainerAdjustment{Annotations: map[string]string{"io.kubernetes.cri.container-type": "sandbox"}}, "runtime annotation replacement"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireIsolatedAdjustment(tc.adjust)
			if tc.wants != "" {
				p := newTestPlugin(isolatedConfig(t))
				pod := sandboxedPod()
				ctr := sandboxedContainer()
				err = p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr, Adjust: tc.adjust})
			}
			if tc.wants == "" && err != nil || tc.wants != "" && (err == nil || !strings.Contains(err.Error(), tc.wants)) {
				t.Fatalf("adjustment = %v, want %q", err, tc.wants)
			}
		})
	}
}
