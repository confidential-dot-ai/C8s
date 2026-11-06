package nriimagepolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The worker image's floor template is the plugin's other config schema
// consumer: mkosi.sync renders image-policy.yaml.in by placeholder
// substitution, so nothing type-checks it against this package's config
// struct. Parse the rendered form here so a drift fails in `go test`, not at
// worker boot.
const workerImagePolicyTemplate = "../../../images/node-guest/worker/image-policy.yaml.in"

// The platform images mkosi.sync substitutes, as this test's stand-ins.
const (
	meshImageRepo       = "ghcr.io/confidential-dot-ai/armtls-mesh"
	meshImageDigest     = "sha256:" + "11111111111111111111111111111111111111111111111111111111111111ab"
	operatorImageRepo   = "ghcr.io/confidential-dot-ai/c8s-operator"
	operatorImageDigest = "sha256:" + "22222222222222222222222222222222222222222222222222222222222222cd"
	routerImageRepo     = "docker.io/nginxinc/nginx-unprivileged"
	routerImageDigest   = "sha256:" + "33333333333333333333333333333333333333333333333333333333333333ef"
)

// The keys the floor builder and worker staging add to the template before
// the plugin ever reads it: the worker marker (internal/cmds/worker Floor) and
// the mesh settings staging fills from the worker document
// (internal/cmds/worker/stage.go). The plugin's validation requires them.
const (
	workerMarker   = "worker: true\n"
	stagedMeshKeys = "  resolver: \"10.53.0.10\"\n  cluster_ranges: [\"10.52.0.0/16\", \"10.53.0.0/16\"]\n"
)

func renderWorkerImagePolicy(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(workerImagePolicyTemplate))
	if err != nil {
		t.Fatalf("read the worker floor template: %v", err)
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
	return workerMarker + strings.Replace(out, "mesh:\n", "mesh:\n"+stagedMeshKeys, 1)
}

// A baked node takes its front-door mode from the launch file, so the base
// pins the one shape that chart renders: the credentials it serves, the
// sidecar's leaf and key, its measured configuration directory and its
// scratch. The enforcer resolves the role from the entry that admits the
// launch, so that shape must hold the router role on its own.
func TestWorkerImageBaseGrantsTheFrontDoorShape(t *testing.T) {
	cfg, err := parseConfig([]byte(renderWorkerImagePolicy(t)))
	if err != nil {
		t.Fatalf("the rendered worker floor template does not parse: %v", err)
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
func TestWorkerImageBaseBindsEveryRoleVolume(t *testing.T) {
	cfg, err := parseConfig([]byte(renderWorkerImagePolicy(t)))
	if err != nil {
		t.Fatalf("the rendered worker floor template does not parse: %v", err)
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
func TestWorkerImageBaseRefusesASwappedVolume(t *testing.T) {
	cfg, err := parseConfig([]byte(renderWorkerImagePolicy(t)))
	if err != nil {
		t.Fatalf("the rendered worker floor template does not parse: %v", err)
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
func TestWorkerImageBaseRefusesAComposedKeyReader(t *testing.T) {
	cfg, err := parseConfig([]byte(renderWorkerImagePolicy(t)))
	if err != nil {
		t.Fatalf("the rendered worker floor template does not parse: %v", err)
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
