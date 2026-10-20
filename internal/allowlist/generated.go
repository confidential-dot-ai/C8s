package allowlist

import (
	"regexp"
	"slices"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// generatedName matches the chart's generated entry names: a component
// shape (DigestEntryName's image segment cut to 41 characters, the digest
// prefix, an 8-hex policy hash), the router entry, or the
// <image>-<12hex> name releases before per-shape names gave a component.
var generatedName = regexp.MustCompile(`^(?:(.+)-([0-9a-f]{12})-[0-9a-f]{8}|(c8s-router)-[0-9a-f]{12}|(.+)-([0-9a-f]{12}))$`)

// GeneratedKey is the part of a generated entry name one image keeps across
// configurations and releases, or "" for any other name.
func GeneratedKey(name string) string {
	m := generatedName.FindStringSubmatch(name)
	switch {
	case m == nil:
		return ""
	case m[3] != "":
		return m[3]
	case m[1] != "":
		return trimBase(m[1]) + "-" + m[2]
	default:
		return trimBase(m[4]) + "-" + m[5]
	}
}

func trimBase(base string) string {
	if len(base) > 41 {
		return base[:41]
	}
	return base
}

// componentInvocations are the executables the chart's component entries pin:
// the C8s binary (/c8s in the operator and CDS images, /app/c8s in the mesh
// and volumed images), attestation-api, and nginx through its entrypoint
// script.
var componentInvocations = [][]string{{secrets.InjectedBinary}, {"/app/c8s"}, {"/attestation-api"}, {"/docker-entrypoint.sh", "nginx"}}

// OpenComponent reports whether c pins a component executable but leaves its
// args (openArgs), its mounts (openMounts) or its environment (openEnv) to
// the pod. Each lets a pod point the component at code of its choosing:
// --kubeconfig runs an exec credential plugin, nginx's -g loads a module, a
// volume replaces what the binary reads, and LD_PRELOAD, BASH_ENV or PATH
// load the pod's own code. A shape of the sidecars the webhook injects may
// leave its args open, since they are per pod, but not its mounts or env. The invocation is
// matched against the command and any exact args after it, since an entry may
// split nginx's argv either way; a command that open args could complete into
// an invocation counts too.
func OpenComponent(c pkgallowlist.Container) (openArgs, openMounts, openEnv bool) {
	if c.Command.Policy != pkgallowlist.PolicyExact {
		return false, false, false
	}
	argv := c.Command.Argv
	invocation := argv
	if c.Args.Policy == pkgallowlist.PolicyExact {
		invocation = slices.Concat(invocation, c.Args.Argv)
	}
	anyArgs := c.Args.Policy == pkgallowlist.PolicyAny || c.Args.Policy == ""
	if !slices.ContainsFunc(componentInvocations, func(prefix []string) bool {
		if len(invocation) >= len(prefix) {
			return slices.Equal(invocation[:len(prefix)], prefix)
		}
		return anyArgs && len(argv) > 0 && slices.Equal(prefix[:len(argv)], argv)
	}) {
		return false, false, false
	}
	sidecar := len(argv) == 2 && argv[0] == secrets.InjectedBinary && slices.Contains(secrets.InjectedModes, argv[1])
	openEnv = c.Env.Policy == pkgallowlist.PolicyAny || c.Env.Policy == ""
	return c.Args.Policy == pkgallowlist.PolicyAny && !sidecar, c.Mounts.Policy == pkgallowlist.PolicyAny, openEnv
}

// overrideKey is the GeneratedKey of an operator override, an entry named
// <image>-<12 hex> as the chart's component shapes are less their policy hash,
// or "" for any other name. The chart generates no such name, so one in the
// seed replaces every generated entry for that image digest.
func overrideKey(name string) string {
	m := generatedName.FindStringSubmatch(name)
	if m == nil || m[4] == "" {
		return ""
	}
	return trimBase(m[4]) + "-" + m[5]
}

// seedKeySets returns the generated keys and the override keys of seed's
// entry names, the sets retiredBySeed takes.
func seedKeySets(seed map[string]pkgallowlist.Workload) (seedKeys, overrideKeys map[string]bool) {
	seedKeys, overrideKeys = map[string]bool{}, map[string]bool{}
	for name := range seed {
		if key := GeneratedKey(name); key != "" {
			seedKeys[key] = true
		}
		if key := overrideKey(name); key != "" {
			overrideKeys[key] = true
		}
	}
	return seedKeys, overrideKeys
}

// retiredBySeed reports whether a stored entry is one an earlier chart
// generated and seed replaces: a generated name seed lacks, for an image seed
// still generates an entry for, that admits a component with open args,
// mounts or env (the entries before each component shape was pinned), or any
// generated shape of an image the seed overrides (overrideKeys). Otherwise an
// exact stale shape is kept, since a pod of the previous release may still
// restart under it; an operator's entry under another name is never touched.
func retiredBySeed(name string, w pkgallowlist.Workload, seedKeys, overrideKeys map[string]bool) bool {
	key := GeneratedKey(name)
	if !seedKeys[key] {
		return false
	}
	if overrideKeys[key] && overrideKey(name) == "" {
		return true
	}
	return slices.ContainsFunc(slices.Concat(w.InitContainers, w.Containers), func(c pkgallowlist.Container) bool {
		args, mounts, env := OpenComponent(c)
		return args || mounts || env
	})
}
