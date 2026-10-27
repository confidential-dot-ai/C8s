package nriimagepolicy

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The node image's baked boot config is the plugin's other config schema
// consumer: mkosi.sync renders image-policy.yaml.in by placeholder
// substitution, so nothing type-checks it against this package's config
// struct. Parse the rendered form here so a drift fails in `go test`, not at
// node boot.
const nodeImagePolicyTemplate = "../../../node-guest-image/c8s/image-policy.yaml.in"

// The platform images mkosi.sync substitutes, as this test's stand-ins.
const (
	meshImageRepo       = "ghcr.io/confidential-dot-ai/armtls-mesh"
	meshImageDigest     = "sha256:" + "11111111111111111111111111111111111111111111111111111111111111ab"
	operatorImageRepo   = "ghcr.io/confidential-dot-ai/c8s-operator"
	operatorImageDigest = "sha256:" + "22222222222222222222222222222222222222222222222222222222222222cd"
	routerImageRepo     = "docker.io/nginxinc/nginx-unprivileged"
	routerImageDigest   = "sha256:" + "33333333333333333333333333333333333333333333333333333333333333ef"
)

func renderNodeImagePolicy(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(nodeImagePolicyTemplate))
	if err != nil {
		t.Fatalf("read node-image policy template: %v", err)
	}
	out := string(body)
	for placeholder, value := range map[string]string{
		"@PLATFORM@":        "snp",
		"@MESH_REPO@":       meshImageRepo,
		"@MESH_DIGEST@":     meshImageDigest,
		"@OPERATOR_REPO@":   operatorImageRepo,
		"@OPERATOR_DIGEST@": operatorImageDigest,
		"@ROUTER_REPO@":     routerImageRepo,
		"@ROUTER_DIGEST@":   routerImageDigest,
	} {
		out = strings.ReplaceAll(out, placeholder, value)
	}
	if ph := regexp.MustCompile(`@[A-Z_]+@`).FindString(out); ph != "" {
		t.Fatalf("unsubstituted placeholder %s left in rendered template", ph)
	}
	return out
}

func TestNodeImageBootConfig_ParsesAndAdmitsSystemImages(t *testing.T) {
	rendered := renderNodeImagePolicy(t)
	// policy.exempt_namespaces, not mesh.exempt_namespaces: image admission
	// keys on the base allowlist alone, while the mesh policy names the
	// namespaces that host no member pods.
	if strings.Contains(rendered, "exempt_snapshot_path") {
		t.Fatal("policy.exempt_namespaces must not return: admission keys on the base allowlist alone")
	}

	cfg, err := parseConfig([]byte(rendered))
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not parse: %v", err)
	}

	// The baked config is the only place the boot gate is armed, and
	// its marker has to be boot-scoped or every restart reads as a first boot.
	if !cfg.Policy.FatalExisting {
		t.Error("the baked config must set policy.fatal_existing: a container predating the plugin means admission was not in place")
	}
	if cfg.sandboxMode() != SandboxEnforce {
		t.Errorf("policy.sandbox = %q, want enforce: host privilege is exempt only through the measured base", cfg.sandboxMode())
	}
	if cfg.Logging.Syslog != "/dev/log" {
		t.Errorf("logging.syslog = %q, want /dev/log: containerd discards a pre-installed plugin's stdout", cfg.Logging.Syslog)
	}
	if !strings.HasPrefix(cfg.Policy.BootMarkerPath, "/run/") {
		t.Errorf("policy.boot_marker_path = %q, want a path under /run (tmpfs, cleared by a reboot)", cfg.Policy.BootMarkerPath)
	}

	// The RKE2 system set: every image the node runs as a container, at the
	// digest systemfloor holds it to. An RKE2 pin bump updates these with the
	// floor. Pinning the whole set, not a boot-critical subset, makes a dropped
	// or corrupted entry fail here instead of at node boot.
	systemImages := map[string]string{
		"sha256:0d26512c90d935db3180f47a7a716e3dfac0847ec29076fb5487e535125a86a8": "docker.io/rancher/hardened-cni-plugins:v1.9.1-build20260717",
		"sha256:134ab48d00e67bed72fa43e0492adf2f0c78383e21da7ee1aeb5b7aa8ef2e7ee": "docker.io/rancher/mirrored-cilium-cilium:v1.19.6",
		"sha256:25cc340fe6fd53c101e16fc452f503e7a92c219c64a80ed5381784b522dbbf77": "nvcr.io/nvidia/k8s-device-plugin:v0.19.3@sha256:25cc340fe6fd53c101e16fc452f503e7a92c219c64a80ed5381784b522dbbf77",
		"sha256:4935e86e846d75591113f64ad4e0402718a1eda08f6900a9325d54f1df64945c": "docker.io/rancher/hardened-k8s-metrics-server:v0.9.0-build20260819",
		"sha256:4f7ffbb3399c9f8137f5d0dd3ca0eddc7909e5d0155b35f1b0449baf96d61bfa": "docker.io/rancher/hardened-etcd:v3.6.14-k3s1-build20260819",
		"sha256:8d5872d767f93393273cb1ecad81e4bc08af65311d206bc31ee8f48bc58e51c4": "docker.io/rancher/hardened-snapshot-controller:v8.6.0-build20260819",
		"sha256:95a33533d97b10502be19e4f3e60e7ce9c30f4879084709af96259a01253f044": "docker.io/rancher/rke2-cloud-provider:v1.36.4-0.20260817193921-a2fc9574e060-build20260820",
		"sha256:aadc3b1a2b8b682f5b4f7b01e182eeeac16f1177af0561b07825abab1d654b2b": "docker.io/rancher/mirrored-cilium-operator-generic:v1.19.6",
		"sha256:ba922718d919920b6b6168e3f55f8effa85032a38bf44d8cc5f4df79a2fe405d": "docker.io/rancher/klipper-helm:v0.13.3-build20260820",
		"sha256:c8e5263407ac439de1dcdde98c7623efb9e17050715a80259d8bd5e81b5a9289": "docker.io/rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821",
		"sha256:c9b9b027e4d2cf1731311f9714f4aa633d37d7b0a72c9d3e6fc7a0594350d27c": "docker.io/rancher/hardened-cluster-autoscaler:v1.10.3-build20260819",
		"sha256:e9435ef6526a98e8d01d98a85d23770859ca49028ebd282912ae5e76f92c0166": "docker.io/rancher/hardened-coredns:v1.14.7-build20260819",
	}
	// The image each base digest is listed under, for the lookups below.
	baseImages := map[string]string{}
	for _, w := range cfg.Allowlist.Base.Workloads {
		for _, c := range slices.Concat(w.InitContainers, w.Containers) {
			baseImages[c.Digest.String()] = c.Image
		}
	}
	for digest, ref := range systemImages {
		if _, ok := baseImages[digest]; !ok {
			t.Errorf("%s (%s) missing from the baked base allowlist — the node cannot boot its system components", ref, digest)
		}
	}

	// Every entry is either one of the system images or one of the role
	// entries, so an entry added to or dropped from the floor fails here. Boot
	// preparation adds the separately rendered chart component seed before
	// containerd starts.
	entries := roleEntries()
	for name, w := range cfg.Allowlist.Base.Workloads {
		if _, holdsRole := entries[name]; holdsRole {
			continue
		}
		for _, d := range w.Digests() {
			if _, system := systemImages[d.String()]; !system {
				t.Errorf("base entry %q is neither a system image nor a role entry", name)
			}
		}
	}

	// A platform role is granted from the node's own measured base, where one
	// entry per role-holding component pins the argv that component is
	// launched with. That the pins are the injector's own is held in
	// internal/webhook (TestMeasuredBaseAdmitsTheInjectedArgv); here the
	// pinned launch must resolve to exactly one role, which RoleOf reports
	// only while no second entry claims the same launch for another role.
	roles := newPolicyStore(cfg.Allowlist.Base)
	for name, want := range entries {
		entry, ok := cfg.Allowlist.Base.Workloads[name]
		if !ok {
			t.Errorf("the baked base carries no %q entry, so that component holds no role", name)
			continue
		}
		if got := roles.base.RoleOf(containerLaunch(t, entry.Containers[0])); got != want {
			t.Errorf("the base grants the %q launch the role %q, want %q", name, got, want)
		}
	}

	// Only a pinned launch holds a role: the endpoint's entrypoint without the
	// arguments it is pinned with, the other image's subcommand, and a pinned
	// launch carrying a pod-chosen credential path all hold none.
	for _, launch := range []launchEvidence{
		{meshImageDigest, []string{"/app/c8s", "armtls-mesh"}},
		{meshImageDigest, []string{"/app/c8s", "armtls-mesh", "--cert-path=/pod/tls.crt"}},
		{meshImageDigest, []string{"/c8s", "get-cert"}},
		{operatorImageDigest, []string{"/c8s", "operator"}},
		{operatorImageDigest, []string{"/c8s", "cds"}},
		{operatorImageDigest, []string{"/c8s", "probe-file", "--wait", "--timeout=3m0s", "/pod/tls.crt"}},
	} {
		if got := roles.base.RoleOf(launch.container()); got != "" {
			t.Errorf("%s running %v took the %q role, want none", launch.digest, launch.argv, got)
		}
	}
	for digest, image := range baseImages {
		if strings.Contains(image, "busybox") {
			t.Errorf("busybox %s must not return to the permissive base allowlist; it is seeded argv-pinned", digest)
		}
	}

	// The measured mesh policy is what lets a baked node host member pods.
	// The capture ports and the mesh identity are shared with the injector, so
	// a drift here would seal pods against their own endpoint.
	mesh := cfg.Mesh
	if !cfg.requiresTrustedMeshEnforcement() {
		t.Error("the baked config does not require trusted mesh enforcement; its members would rest on policy the cluster admin writes")
	}
	for _, ns := range []string{"kube-system", "c8s-system"} {
		if !slices.Contains(mesh.ExemptNamespaces, ns) {
			t.Errorf("mesh.exempt_namespaces = %v, want %s exempt: it runs the node's own components", mesh.ExemptNamespaces, ns)
		}
	}
	if got, want := mesh.Resolver.String(), "10.53.0.10"; got != want {
		t.Errorf("mesh.resolver = %s, want the baked cluster-dns %s", got, want)
	}
	wantCapture := capturePorts{
		Outbound: uint16(workloadclaims.MeshOutboundPort),
		Inbound:  uint16(workloadclaims.MeshInboundPort),
		Health:   uint16(workloadclaims.MeshHealthPort),
	}
	if mesh.Capture != wantCapture {
		t.Errorf("mesh.capture = %+v, want the ports the injected endpoint binds %+v", mesh.Capture, wantCapture)
	}
	bound, ok := mesh.role(meshRole)
	if !ok || bound.UID != workloadclaims.MeshUID {
		t.Errorf("mesh role = %+v, want the reserved uid %d", bound, workloadclaims.MeshUID)
	}

	// The acme role's egress exception excludes the cluster's own ranges, so
	// the measured policy carries them.
	wantRanges := []string{"10.52.0.0/16", "10.53.0.0/16"}
	if got := prefixStrings(mesh.ClusterRanges); !slices.Equal(got, wantRanges) {
		t.Errorf("mesh.cluster_ranges = %v, want the baked cluster-cidr and service-cidr %v", got, wantRanges)
	}

	// Every base container must still admit the launch it describes at final
	// admission: an open system image with a host mount, a pinned one or a
	// role entry with the argv and mounts it pins.
	store := newPolicyStore(cfg.Allowlist.Base)
	for name, w := range cfg.Allowlist.Base.Workloads {
		for _, c := range slices.Concat(w.InitContainers, w.Containers) {
			if !store.baseAdmits(containerLaunch(t, c), launchFinal) {
				t.Errorf("base entry %q does not admit the launch its %s container describes", name, c.Image)
			}
		}
	}

	// Every system container, in any entry, pins its command, args and mounts,
	// except those of the images named here, whose launch stays open for the
	// reasons docs/allowlist-and-capabilities.md ("Host privilege") gives.
	openSystemImages := map[string]bool{
		"docker.io/rancher/mirrored-cilium-cilium:v1.19.6":           true,
		"docker.io/rancher/mirrored-cilium-operator-generic:v1.19.6": true,
		"docker.io/rancher/klipper-helm:v0.13.3-build20260820":       true,
		"docker.io/rancher/hardened-coredns:v1.14.7-build20260819":   true,
	}
	for name, w := range cfg.Allowlist.Base.Workloads {
		for _, c := range slices.Concat(w.InitContainers, w.Containers) {
			image, system := systemImages[c.Digest.String()]
			if system && !openSystemImages[image] && !pinsArgvAndMounts(c) {
				t.Errorf("base entry %q leaves the launch of %s open", name, c.Image)
			}
		}
	}
}

// CoreDNS's mounts stay open, so what keeps its pinned binary its own is the
// plugin refusing a mount over an absolute executable.
func TestNodeImageBaseRefusesAMountOverCoreDNS(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	coredns := cfg.Allowlist.Base.Workloads["coredns"].Containers[0]
	launch := containerLaunch(t, coredns)
	launch.Mounts = []allowlist.ObservedMount{{Destination: "/etc/coredns", Volume: "config-volume", Class: allowlist.MountData, Storage: allowlist.MountEncrypted}}
	store := newPolicyStore(cfg.Allowlist.Base)
	if !store.baseAdmits(launch, launchFinal) {
		t.Fatalf("the base refuses CoreDNS as RKE2 runs it: %+v", launch)
	}
	launch.Mounts = append(launch.Mounts, allowlist.ObservedMount{Destination: "/coredns", Volume: "binary", Class: allowlist.MountData, Storage: allowlist.MountEncrypted})
	if store.baseAdmits(launch, launchFinal) {
		t.Fatal("the base admits CoreDNS with a mount over its executable")
	}
}

// pinsArgvAndMounts reports whether c leaves none of its command, args and
// mounts open.
func pinsArgvAndMounts(c allowlist.Container) bool {
	return c.Command.Policy != allowlist.PolicyAny && c.Args.Policy != allowlist.PolicyAny && c.Mounts.Policy != allowlist.PolicyAny
}

// A baked node takes its front-door mode from the launch file, so the base
// pins the one shape that chart renders: the credentials it serves, the
// sidecar's leaf and key, its measured configuration directory and its
// scratch. The enforcer resolves the role from the entry that admits the
// launch, so that shape must hold the router role on its own.
func TestNodeImageBaseGrantsTheFrontDoorShape(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not parse: %v", err)
	}
	entry, ok := cfg.Allowlist.Base.Workloads["c8s-router-nginx"]
	if !ok {
		t.Fatal("the baked base carries no front-door entry")
	}
	if len(entry.Containers) != 1 {
		t.Fatalf("the front door is pinned by %d entries, want the one shape a baked node renders", len(entry.Containers))
	}
	roles := newPolicyStore(cfg.Allowlist.Base)
	for _, container := range entry.Containers {
		launch := allowlist.RunningContainer{
			Digest: container.Digest.String(),
			Argv:   slices.Clone(container.Command.Argv),
			Mounts: entryMounts(container.Mounts),
		}
		if got := roles.base.RoleOf(launch); got != routerRole {
			t.Errorf("a front door mounting %v holds the role %q, want %q", mountDestinations(container.Mounts), got, routerRole)
		}
	}
}

// Every emptyDir rule of a role entry names the pod volume behind it, so two
// destinations of one container cannot be fed from each other's volume. The
// one exception is the injected clients' discovery mount: the webhook mounts
// the volume the pod's annotation names there, so the rule pins the
// destination and the storage alone.
func TestNodeImageBaseBindsEveryRoleVolume(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not parse: %v", err)
	}
	for name := range roleEntries() {
		entry, ok := cfg.Allowlist.Base.Workloads[name]
		if !ok {
			continue
		}
		for _, container := range entry.Containers {
			for _, rule := range container.Mounts.Rules {
				if rule.Kind != allowlist.MountEmptyDir || rule.Destination == "/run/c8s/discovery" {
					continue
				}
				if rule.Source == "" {
					t.Errorf("%s pins %s without naming its volume", name, rule.Destination)
				}
			}
		}
	}
}

// The front door's key directory may not be bound at the attestation
// sidecar's chain destination: that swap would hand the serving key to the
// pod's route authority.
func TestNodeImageBaseRefusesASwappedVolume(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not parse: %v", err)
	}
	entry, ok := cfg.Allowlist.Base.Workloads["c8s-router-upstream"]
	if !ok {
		t.Fatal("the baked base carries no attestation sidecar entry")
	}
	store := newPolicyStore(cfg.Allowlist.Base)
	for _, container := range entry.Containers {
		launch := allowlist.RunningContainer{
			Digest: container.Digest.String(),
			Argv:   append(slices.Clone(container.Command.Argv), "--front-door-mode=acme"),
			Mounts: entryMounts(container.Mounts),
		}
		if !store.baseAdmits(launch, launchFinal) {
			t.Fatalf("the entry does not admit the launch it describes: %v", mountDestinations(container.Mounts))
		}
		swapped := slices.Clone(launch.Mounts)
		for i := range swapped {
			if swapped[i].Destination == "/etc/c8s-acme-tls" {
				swapped[i].Source = podVolumeSource("acme-key")
				swapped[i].Volume = "acme-key"
			}
		}
		if slices.Equal(swapped, launch.Mounts) {
			continue
		}
		launch.Mounts = swapped
		if store.baseAdmits(launch, launchFinal) {
			t.Error("the attestation sidecar was admitted with the key volume bound at its chain destination")
		}
	}
}

// A control plane that adds a credential-role container mounting the front
// door's key directory to the router pod composes a second reader of the
// serving key. The base grants that launch no declaration that pins its
// mounts, and a role container of the router's namespace runs only under one
// (requireRoleOnlyPod).
func TestNodeImageBaseRefusesAComposedKeyReader(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not parse: %v", err)
	}
	entry, ok := cfg.Allowlist.Base.Workloads["c8s-get-cert"]
	if !ok {
		t.Fatal("the baked base carries no certificate-sidecar entry")
	}
	i := slices.IndexFunc(entry.Containers, func(c allowlist.Container) bool {
		return c.Mounts.Policy == allowlist.PolicyExact
	})
	if i < 0 {
		t.Fatal("the baked base pins no mount set for the router pod's certificate sidecar")
	}
	declared := entry.Containers[i]
	store := newPolicyStore(cfg.Allowlist.Base)
	launch := allowlist.RunningContainer{
		Digest: declared.Digest.String(),
		Argv:   append(slices.Clone(declared.Command.Argv), "--san=c8s-router.c8s-router.svc"),
		Mounts: entryMounts(declared.Mounts),
	}
	if !store.base.BindsRoleMounts(launch, CredentialRole) {
		t.Fatalf("the entry does not admit the launch it describes: %v", mountDestinations(declared.Mounts))
	}
	launch.Mounts = append(launch.Mounts, allowlist.ObservedMount{
		Destination: "/etc/c8s-acme-key",
		Source:      podVolumeSource("acme-key"),
		Volume:      "acme-key",
		Class:       allowlist.MountEmptyDir,
		Storage:     allowlist.MountMemory,
	})
	if store.base.BindsRoleMounts(launch, CredentialRole) {
		t.Error("a credential client was pinned-mount admitted while mounting the front door's serving key")
	}
}

// mountDestinations names the mount set an entry pins, for a failure message.
func mountDestinations(p allowlist.MountPolicy) []string {
	destinations := make([]string, 0, len(p.Rules))
	for _, rule := range p.Rules {
		destinations = append(destinations, rule.Destination)
	}
	return destinations
}

// roleEntries is the role each base entry grants the component it pins.
func roleEntries() map[string]string {
	return map[string]string{
		"c8s-mesh-endpoint":   meshRole,
		"c8s-get-cert":        CredentialRole,
		"c8s-probe-file":      CredentialRole,
		"c8s-get-secret":      CredentialRole,
		"c8s-get-volume":      CredentialRole,
		"c8s-allowlist-proxy": CredentialRole,
		"c8s-router-nginx":    routerRole,
		"c8s-acme":            acmeRole,
		"c8s-router-upstream": upstreamRole,
	}
}

// launchEvidence is the launch evidence the enforcer resolves a role from: the
// bytes and the argv they ran with.
type launchEvidence struct {
	digest string
	argv   []string
}

// container carries the mounts the injected containers receive, so the argv is
// the only reason a role is refused.
func (l launchEvidence) container() allowlist.RunningContainer {
	return allowlist.RunningContainer{
		Digest: l.digest,
		Argv:   l.argv,
		Mounts: []allowlist.ObservedMount{{
			Destination: "/etc/c8s/certs",
			Source:      podVolumeSource("c8s-certs"),
			Volume:      "c8s-certs",
			Class:       allowlist.MountEmptyDir,
			Storage:     allowlist.MountMemory,
		}},
	}
}

// containerLaunch is the launch a container describes: the argv it pins, the
// mounts it pins where it pins any, and the environment it matches.
func containerLaunch(t *testing.T, c allowlist.Container) allowlist.RunningContainer {
	return allowlist.RunningContainer{
		Digest: c.Digest.String(),
		Argv:   append(slices.Clone(c.Command.Argv), c.Args.Argv...),
		Mounts: entryMounts(c.Mounts),
		Env:    entryEnv(t, c.Env),
	}
}

// entryEnv is environment evidence a match policy admits: each variable at
// its pinned value, or at presentValue where it need only be set. It is nil,
// no evidence, for a policy that leaves the environment open.
func entryEnv(t *testing.T, p allowlist.EnvPolicy) *allowlist.EnvObservation {
	t.Helper()
	if p.Policy != allowlist.PolicyMatch {
		return nil
	}
	exact := p.ExactValues()
	entries := make([]string, 0, len(p.Variables))
	for name := range p.Variables {
		value, pinned := exact[name]
		if !pinned {
			value = presentValue
		}
		entries = append(entries, name+"="+value)
	}
	env, err := allowlist.ObserveEnv(entries)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// presentValue stands for the value of a variable a match policy requires
// only to be set.
const presentValue = "set"

// entryMounts is mount evidence the policy admits: the mounts it pins, a host
// mount where it leaves them open, and none where it denies them.
func entryMounts(p allowlist.MountPolicy) []allowlist.ObservedMount {
	switch p.Policy {
	case allowlist.PolicyExact:
		mounts := make([]allowlist.ObservedMount, 0, len(p.Rules))
		for _, rule := range p.Rules {
			mounts = append(mounts, ruleMount(rule))
		}
		return mounts
	case allowlist.PolicyAny:
		return []allowlist.ObservedMount{{
			Destination: "/host",
			Class:       allowlist.MountHost,
			Storage:     allowlist.MountUnknown,
		}}
	default:
		return observedNoMounts
	}
}

// observedNoMounts is evidence of a launch with no bind mounts; nil would be
// no evidence at all.
var observedNoMounts = []allowlist.ObservedMount{}

// ruleMount is the mount evidence a rule describes, as the node reports it: a
// kubelet volume's source ends in the pod volume's name, and a host mount
// carries the digest of its source path.
func ruleMount(rule allowlist.MountRule) allowlist.ObservedMount {
	if rule.Kind == allowlist.MountHost {
		digest, err := allowlist.HostSourceDigest(rule.Source)
		if err != nil {
			digest = ""
		}
		return allowlist.ObservedMount{
			Destination:      rule.Destination,
			Source:           rule.Source,
			Class:            rule.Kind,
			Storage:          allowlist.MountUnknown,
			HostSourceDigest: digest,
			ReadOnly:         rule.ReadOnly,
		}
	}
	return allowlist.ObservedMount{
		Destination: rule.Destination,
		Source:      podVolumeSource(rule.Source),
		Volume:      rule.Source,
		Class:       rule.Kind,
		Storage:     allowlist.MountMemory,
	}
}

// podVolumeSource is the host source the kubelet gives a pod volume, which is
// what binds a mount to the volume behind it.
func podVolumeSource(volume string) string {
	return "/var/lib/kubelet/pods/5a1d-pod/volumes/kubernetes.io~empty-dir/" + volume
}

// prefixStrings renders the ranges as the config writes them.
func prefixStrings(ranges []netip.Prefix) []string {
	out := make([]string, 0, len(ranges))
	for _, in := range ranges {
		out = append(out, in.String())
	}
	return out
}

// bakedAddonManifests is where RKE2 applies the node image's own addons at
// boot.
const bakedAddonManifests = "../../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests"

// podKinds are the baked manifest kinds that run a pod.
var podKinds = []string{"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job"}

// The baked addons run before any C8s install, so their pods carry no mesh
// endpoint: a pod ruleset would send their traffic to a listener that does not
// exist, and the privilege floor would refuse the root helper pods one of them
// creates. Every namespace they run a pod in keeps the node's own rules.
func TestNodeImageBootConfig_ExemptsTheBakedAddonNamespaces(t *testing.T) {
	rendered := renderNodeImagePolicy(t)
	cfg, err := parseConfig([]byte(rendered))
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not parse: %v", err)
	}
	for _, namespace := range bakedAddonNamespaces(t) {
		if !slices.Contains(cfg.Mesh.ExemptNamespaces, namespace) {
			t.Errorf("mesh.exempt_namespaces = %v, want %s exempt: the baked addon it holds runs no mesh endpoint",
				cfg.Mesh.ExemptNamespaces, namespace)
		}
	}
}

// bakedAddonNamespaces are the namespaces the baked manifests run a pod in.
func bakedAddonNamespaces(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(bakedAddonManifests)
	if err != nil {
		t.Fatalf("read the baked manifests: %v", err)
	}
	var namespaces []string
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(bakedAddonManifests, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, doc := range manifestDocs(t, entry.Name(), body) {
			if !slices.Contains(podKinds, doc.Kind) || doc.Metadata.Namespace == "" {
				continue
			}
			if !slices.Contains(namespaces, doc.Metadata.Namespace) {
				namespaces = append(namespaces, doc.Metadata.Namespace)
			}
		}
	}
	if len(namespaces) == 0 {
		t.Fatalf("no manifest under %s runs a pod in a namespace", bakedAddonManifests)
	}
	return namespaces
}

// manifestDoc is as much of a baked document as the namespaces above need.
type manifestDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
}

func manifestDocs(t *testing.T, name string, body []byte) []manifestDoc {
	t.Helper()
	var docs []manifestDoc
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	for {
		var doc manifestDoc
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return docs
		}
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		docs = append(docs, doc)
	}
}
