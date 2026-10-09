package nriimagepolicy

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The node image's baked boot config is the plugin's other config schema
// consumer: mkosi.sync renders image-policy.yaml.in by placeholder
// substitution, so nothing type-checks it against this package's config
// struct. Load the rendered form here so a drift fails in `go test`, not at
// node boot.
const nodeImagePolicyTemplate = "../../../node-guest-image/c8s/image-policy.yaml.in"

// The platform images mkosi.sync substitutes, as this test's stand-ins.
const (
	meshImageRepo       = "ghcr.io/confidential-dot-ai/armtls-mesh"
	meshImageDigest     = "sha256:" + "11111111111111111111111111111111111111111111111111111111111111ab"
	operatorImageRepo   = "ghcr.io/confidential-dot-ai/c8s-operator"
	operatorImageDigest = "sha256:" + "22222222222222222222222222222222222222222222222222222222222222cd"
	routerImageRepo     = "ghcr.io/confidential-dot-ai/c8s-router"
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

func TestNodeImageBootConfig_LoadsAndAdmitsSystemImages(t *testing.T) {
	rendered := renderNodeImagePolicy(t)
	// policy.exempt_namespaces, not mesh.exempt_namespaces: image admission
	// keys on the base allowlist alone, while the mesh policy names the
	// namespaces that host no member pods.
	if strings.Contains(rendered, "exempt_snapshot_path") {
		t.Fatal("policy.exempt_namespaces must not return: admission keys on the base allowlist alone")
	}

	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not load: %v", err)
	}

	// The baked config is the only place the boot gate is armed, and
	// its marker has to be boot-scoped or every restart reads as a first boot.
	if !cfg.Policy.FatalExisting {
		t.Error("the baked config must set policy.fatal_existing: a container predating the plugin means admission was not in place")
	}
	if !strings.HasPrefix(cfg.Policy.BootMarkerPath, "/run/") {
		t.Errorf("policy.boot_marker_path = %q, want a path under /run (tmpfs, cleared by a reboot)", cfg.Policy.BootMarkerPath)
	}

	// The full RKE2 system set: every digest systemfloor derives from the
	// pinned airgap bundles and baked manifests. A regen for an RKE2 pin bump
	// rewrites these — update the pins with it. Pinning the whole set, not a
	// boot-critical subset, makes a dropped or corrupted entry fail here
	// instead of at node boot. The local-path helper's busybox is NOT here:
	// systemfloor drops it (-exclude-ref) and the chart seeds it argv-pinned.
	systemImages := map[string]string{
		"sha256:8026310fc44d985bf7c02434ad11d5f826a1aa1567606eea121b24ba9b3b0590": "docker.io/rancher/hardened-addon-resizer:1.8.23-build20260819",
		"sha256:9ad5a45ef284f2632590750a21deedab9f38d0d9cd8cc555b776a6a68e6d973b": "docker.io/rancher/hardened-calico:v3.32.1-build20260827",
		"sha256:c9b9b027e4d2cf1731311f9714f4aa633d37d7b0a72c9d3e6fc7a0594350d27c": "docker.io/rancher/hardened-cluster-autoscaler:v1.10.3-build20260819",
		"sha256:e9435ef6526a98e8d01d98a85d23770859ca49028ebd282912ae5e76f92c0166": "docker.io/rancher/hardened-coredns:v1.14.7-build20260819",
		"sha256:54a53cb983d47579a8e7cdcd9ae38bc58ff85c28c63fd26de02ce332d5f988ee": "docker.io/rancher/hardened-dns-node-cache:1.26.8-build20260819",
		"sha256:4f7ffbb3399c9f8137f5d0dd3ca0eddc7909e5d0155b35f1b0449baf96d61bfa": "docker.io/rancher/hardened-etcd:v3.6.14-k3s1-build20260819",
		"sha256:89d695035932b7b2dc482e8837f83237d80ada7d019a877cdcb379403e32f590": "docker.io/rancher/hardened-flannel:v0.28.9-build20260819",
		"sha256:4935e86e846d75591113f64ad4e0402718a1eda08f6900a9325d54f1df64945c": "docker.io/rancher/hardened-k8s-metrics-server:v0.9.0-build20260819",
		"sha256:c8e5263407ac439de1dcdde98c7623efb9e17050715a80259d8bd5e81b5a9289": "docker.io/rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821",
		"sha256:8d5872d767f93393273cb1ecad81e4bc08af65311d206bc31ee8f48bc58e51c4": "docker.io/rancher/hardened-snapshot-controller:v8.6.0-build20260819",
		"sha256:dff360a22c8a28c2af3e78b2b4cf09a6c8edc199e27eb9f7c417bfc1ac41078e": "docker.io/rancher/hardened-traefik:v3.7.11-build20260819",
		"sha256:ba922718d919920b6b6168e3f55f8effa85032a38bf44d8cc5f4df79a2fe405d": "docker.io/rancher/klipper-helm:v0.13.3-build20260820",
		"sha256:910944bb0bd94f060a82a56ca1ea1c577d3e49b3473a093a47a985f32e92d94a": "docker.io/rancher/klipper-lb:v0.4.17",
		"sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4": "docker.io/rancher/mirrored-pause:3.10.2",
		"sha256:95a33533d97b10502be19e4f3e60e7ce9c30f4879084709af96259a01253f044": "docker.io/rancher/rke2-cloud-provider:v1.36.4-0.20260817193921-a2fc9574e060-build20260820",
		"sha256:7956a28b1ebd803f58341ba88fed4c8bc878ec13226c2e55959ba5a88c21341e": "docker.io/rancher/rke2-runtime:v1.36.4-rke2r1",
		"sha256:25cc340fe6fd53c101e16fc452f503e7a92c219c64a80ed5381784b522dbbf77": "nvcr.io/nvidia/k8s-device-plugin:v0.19.3@sha256:25cc340fe6fd53c101e16fc452f503e7a92c219c64a80ed5381784b522dbbf77",
		"sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f": "rancher/local-path-provisioner:v0.0.36@sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f",
	}
	// The base allowlist carries one any-argv entry per admitted image;
	// index it by digest for the lookups below.
	baseEntries := map[string]string{}
	for _, w := range cfg.Allowlist.Base.Workloads {
		for _, d := range w.Digests() {
			baseEntries[d.String()] = w.Label
		}
	}
	for digest, ref := range systemImages {
		if _, ok := baseEntries[digest]; !ok {
			t.Errorf("%s (%s) missing from the baked base allowlist — the node cannot boot its system components", ref, digest)
		}
	}

	// Every entry is either one of the generated system images or one of the
	// role entries, so an entry a regen adds or drops fails here. Boot
	// preparation adds the separately rendered chart component seed before
	// containerd starts.
	entries := roleEntries()
	for name, w := range cfg.Allowlist.Base.Workloads {
		if _, holdsRole := entries[name]; holdsRole {
			continue
		}
		for _, d := range w.Digests() {
			if _, generated := systemImages[d.String()]; !generated {
				t.Errorf("base entry %q is neither a generated system image nor a role entry", name)
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
		if got := roles.base.RoleOf(entryLaunch(entry)); got != want {
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
	for digest := range baseEntries {
		if strings.Contains(baseEntries[digest], "busybox") {
			t.Errorf("busybox %s must not return to the permissive base allowlist; it is seeded argv-pinned", digest)
		}
	}

	// The measured mesh policy is what lets a baked node host member pods.
	// The capture ports and the mesh identity are shared with the injector, so
	// a drift here would seal pods against their own endpoint.
	mesh := cfg.Mesh
	if mesh == nil {
		t.Fatal("the baked config carries no mesh policy, so the node hosts no member pods")
	}
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

	// Every base entry must still admit the launch it describes at final
	// admission: a system image with its host mounts, a role entry with the
	// argv and mounts it pins.
	store := newPolicyStore(cfg.Allowlist.Base)
	for name, w := range cfg.Allowlist.Base.Workloads {
		if !store.baseAdmits(entryLaunch(w), launchFinal) {
			t.Errorf("base entry %q does not admit the launch it describes", name)
		}
	}
}

// The front door is pinned by one entry per front-door shape: the cds one,
// the webpki one that adds the operator's Secret, and the acme one that adds
// the leaf its sidecar mints. The enforcer resolves a role from whichever
// entry admits the launch, so each shape must hold the router role on its own.
func TestNodeImageBaseGrantsEveryFrontDoorShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(renderNodeImagePolicy(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not load: %v", err)
	}
	entry, ok := cfg.Allowlist.Base.Workloads["c8s-router-nginx"]
	if !ok {
		t.Fatal("the baked base carries no front-door entry")
	}
	if len(entry.Containers) != 3 {
		t.Fatalf("the front door is pinned by %d entries, want one per front-door shape", len(entry.Containers))
	}
	roles := newPolicyStore(cfg.Allowlist.Base)
	for _, container := range entry.Containers {
		launch := allowlist.RunningContainer{
			Digest: container.Digest.String(),
			Argv:   append(slices.Clone(container.Command.Argv), "--cert=/etc/c8s/certs/tls.crt"),
			Mounts: entryMounts(container.Mounts),
		}
		if got := roles.base.RoleOf(launch); got != routerRole {
			t.Errorf("a front door mounting %v holds the role %q, want %q", mountDestinations(container.Mounts), got, routerRole)
		}
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
		"c8s-cds-attest":      routerRole,
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
			Class:       allowlist.MountEmptyDir,
			Storage:     allowlist.MountMemory,
		}},
	}
}

// entryLaunch is the launch an entry describes: the argv it pins, and the
// mounts it pins where it pins any.
func entryLaunch(w allowlist.Workload) allowlist.RunningContainer {
	c := w.Containers[0]
	return allowlist.RunningContainer{
		Digest: c.Digest.String(),
		Argv:   append(slices.Clone(c.Command.Argv), c.Args.Argv...),
		Mounts: entryMounts(c.Mounts),
	}
}

// entryMounts is mount evidence the policy admits: the mounts it pins, or a
// host mount where it pins none.
func entryMounts(p allowlist.MountPolicy) []allowlist.ObservedMount {
	if p.Policy != allowlist.PolicyExact {
		return []allowlist.ObservedMount{{
			Destination: "/host",
			Class:       allowlist.MountHost,
			Storage:     allowlist.MountUnknown,
		}}
	}
	mounts := make([]allowlist.ObservedMount, 0, len(p.Rules))
	for _, rule := range p.Rules {
		mounts = append(mounts, allowlist.ObservedMount{
			Destination: rule.Destination,
			Class:       rule.Kind,
			Storage:     allowlist.MountMemory,
		})
	}
	return mounts
}

// prefixStrings renders the ranges as the config writes them.
func prefixStrings(ranges []netip.Prefix) []string {
	out := make([]string, 0, len(ranges))
	for _, in := range ranges {
		out = append(out, in.String())
	}
	return out
}
