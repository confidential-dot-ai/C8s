package worker

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const routerWorkloadPrefix = "c8s-router-"

// floorSettings are the node floor's settings a worker's floor takes as they
// are. INVARIANT: every field is omitempty, so a key the node floor leaves out
// stays out.
type floorSettings struct {
	Platform       string         `yaml:"platform,omitempty"`
	Plugin         map[string]any `yaml:"plugin,omitempty"`
	WorkloadClaims map[string]any `yaml:"workload_claims,omitempty"`
	Containerd     map[string]any `yaml:"containerd,omitempty"`
	Policy         map[string]any `yaml:"policy,omitempty"`
	Logging        map[string]any `yaml:"logging,omitempty"`
}

type floorAllowlist struct {
	NodeTCB bool                 `yaml:"node_tcb,omitempty"`
	Base    *allowlist.Allowlist `yaml:"base"`
	Pull    map[string]any       `yaml:"pull,omitempty"`
}

// workerMesh is the node floor's mesh policy as a worker's floor takes it;
// stage completes it from the worker document.
type workerMesh struct {
	Capture map[string]any `yaml:"capture,omitempty"`
	Roles   []any          `yaml:"roles,omitempty"`
}

// nodeMesh is the node floor's mesh policy: a worker's, and the keys stage
// fills from the worker document or a worker refuses.
type nodeMesh struct {
	workerMesh       `yaml:",inline"`
	ExemptNamespaces any `yaml:"exempt_namespaces"`
	Exits            any `yaml:"exits"`
	Resolver         any `yaml:"resolver"`
	ClusterRanges    any `yaml:"cluster_ranges"`
}

// nodeFloor is the node image's floor, decoded strictly: a key it does not
// name is refused rather than copied.
type nodeFloor struct {
	floorSettings `yaml:",inline"`
	Allowlist     *floorAllowlist `yaml:"allowlist"`
	Mesh          *nodeMesh       `yaml:"mesh"`
}

// workerFloor is a worker image's floor.
type workerFloor struct {
	floorSettings `yaml:",inline"`
	Allowlist     floorAllowlist `yaml:"allowlist"`
	Mesh          workerMesh     `yaml:"mesh"`
	Worker        bool           `yaml:"worker"`
}

// Floor builds a worker image's NRI floor from the node image's floor, its
// digests filled, the seed `c8s node-image render` writes, and the image's
// static pod templates by file name. See NewFloorCmd for what it keeps.
func Floor(nodeFloorData, seed []byte, templates map[string][]byte) ([]byte, error) {
	node, err := parseNodeFloor(nodeFloorData)
	if err != nil {
		return nil, err
	}
	if err := keepPlatformRoles(node.Allowlist.Base); err != nil {
		return nil, err
	}
	base := node.Allowlist.Base
	name, router, err := routerEntry(seed)
	if err != nil {
		return nil, err
	}
	if _, taken := base.Workloads[name]; taken {
		return nil, fmt.Errorf("node floor: a platform role is named %s, the router's entry", name)
	}
	base.Workloads[name] = router
	for file, data := range templates {
		pod, entry, err := staticPodEntry(data)
		if err != nil {
			return nil, fmt.Errorf("static pod template %s: %w", file, err)
		}
		if _, taken := base.Workloads[pod]; taken {
			return nil, fmt.Errorf("static pod template %s: pod %s is named as another entry", file, pod)
		}
		base.Workloads[pod] = entry
	}
	if node.Allowlist.Pull == nil {
		return nil, fmt.Errorf("node floor: no allowlist.pull: a worker pulls its served allowlist from its CDS")
	}
	// Each served allowlist extends RTMR[3] before the worker applies it.
	node.Allowlist.Pull["measure_policies"] = true
	return yaml.Marshal(workerFloor{
		floorSettings: node.floorSettings,
		Allowlist:     *node.Allowlist,
		Mesh:          node.Mesh.workerMesh,
		Worker:        true,
	})
}

// parseNodeFloor decodes data strictly and requires its allowlist base and
// mesh policy.
func parseNodeFloor(data []byte) (*nodeFloor, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var floor nodeFloor
	if err := dec.Decode(&floor); err != nil {
		return nil, fmt.Errorf("node floor: %w", err)
	}
	if floor.Allowlist == nil || floor.Allowlist.Base == nil || floor.Mesh == nil {
		return nil, errors.New("node floor: no allowlist base or mesh policy")
	}
	return &floor, nil
}

// keepPlatformRoles deletes from base every entry with a container that holds
// no platform role.
func keepPlatformRoles(base *allowlist.Allowlist) error {
	maps.DeleteFunc(base.Workloads, func(_ string, w allowlist.Workload) bool {
		containers := slices.Concat(w.InitContainers, w.Containers)
		return len(containers) == 0 || slices.ContainsFunc(containers, func(c allowlist.Container) bool {
			return c.Role == ""
		})
	})
	if len(base.Workloads) == 0 {
		return errors.New("node floor base: no platform-role entry")
	}
	return nil
}

// routerEntry is the seed's one router entry.
func routerEntry(seed []byte) (string, allowlist.Workload, error) {
	parsed, err := allowlist.ParseJSON(seed)
	if err != nil {
		return "", allowlist.Workload{}, fmt.Errorf("seed: %w", err)
	}
	var names []string
	for name := range parsed.Workloads {
		if strings.HasPrefix(name, routerWorkloadPrefix) {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		return "", allowlist.Workload{}, fmt.Errorf("seed: want one %s* entry, got %v", routerWorkloadPrefix, names)
	}
	router := parsed.Workloads[names[0]]
	if err := requireNodeInputs(names[0], router); err != nil {
		return "", allowlist.Workload{}, err
	}
	return names[0], router, requireStagedFiles(names[0], router)
}

// routerMountKinds are the mounts the router may take: none filled from
// objects the control plane writes.
var routerMountKinds = []allowlist.MountClass{allowlist.MountHost, allowlist.MountNodeRootFile, allowlist.MountEmptyDir}

// requireNodeInputs refuses a router entry that leaves its launch open or
// takes a mount outside routerMountKinds: the router's settings come from the
// worker document alone.
func requireNodeInputs(name string, router allowlist.Workload) error {
	for _, c := range slices.Concat(router.InitContainers, router.Containers) {
		if !c.LaunchPinned() {
			return fmt.Errorf("seed: router entry %s container %s does not pin its launch", name, c.Digest)
		}
		for _, rule := range c.Mounts.Rules {
			if !slices.Contains(routerMountKinds, rule.Kind) {
				return fmt.Errorf("seed: router entry %s container %s mounts %s, which the control plane fills", name, c.Digest, rule.Kind)
			}
		}
	}
	return nil
}

var publicPath = regexp.MustCompile(`/run/+c8s-node(/[^\s,=:]*)?`)

// requireStagedFiles refuses a router entry naming a file under /run/c8s-node,
// in its argv, environment or mount sources, that worker stage does not
// publish.
func requireStagedFiles(name string, router allowlist.Workload) error {
	staged, err := stagedPublicNames()
	if err != nil {
		return err
	}
	for _, c := range slices.Concat(router.InitContainers, router.Containers) {
		named := slices.Concat(c.Command.Argv, c.Args.Argv, slices.Collect(maps.Values(c.Env.ExactValues())))
		for _, rule := range c.Mounts.Rules {
			named = append(named, rule.Source)
		}
		for _, text := range named {
			for _, p := range publicPath.FindAllString(text, -1) {
				file := strings.TrimPrefix(path.Clean(p), nodeservices.PublicDir)
				if file != "" && !slices.Contains(staged, strings.TrimPrefix(file, "/")) {
					return fmt.Errorf("seed: router entry %s reads %s, which worker stage does not publish", name, p)
				}
			}
		}
	}
	return nil
}
