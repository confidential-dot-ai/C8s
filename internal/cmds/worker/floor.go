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

// floorSettings are the floor template's settings a worker's floor takes as
// they are. INVARIANT: every field is omitempty, so a key the template leaves
// out stays out.
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

// workerMesh is the mesh policy a worker's floor takes from the template;
// stage completes it from the worker document.
type workerMesh struct {
	Capture map[string]any `yaml:"capture,omitempty"`
	Roles   []any          `yaml:"roles,omitempty"`
}

// floorTemplate is the worker image's floor template, decoded strictly: a key
// it does not name is refused rather than copied.
type floorTemplate struct {
	floorSettings `yaml:",inline"`
	Allowlist     *floorAllowlist `yaml:"allowlist"`
	Mesh          *workerMesh     `yaml:"mesh"`
}

// workerFloor is a worker image's floor.
type workerFloor struct {
	floorSettings `yaml:",inline"`
	Allowlist     floorAllowlist `yaml:"allowlist"`
	Mesh          workerMesh     `yaml:"mesh"`
	Worker        bool           `yaml:"worker"`
}

// Floor builds a worker image's NRI floor from the image's floor template,
// its digests filled, the seed `c8s node-image render` writes, and the image's
// static pod templates by file name. See NewFloorCmd for what it keeps.
func Floor(templateData, seed []byte, staticPods map[string][]byte) ([]byte, error) {
	template, err := parseTemplate(templateData)
	if err != nil {
		return nil, err
	}
	if err := requirePlatformRoles(template.Allowlist.Base); err != nil {
		return nil, err
	}
	// The output takes a copy: the parsed template stays as it was read.
	allow := *template.Allowlist
	base := &allowlist.Allowlist{Schema: template.Allowlist.Base.Schema, Workloads: maps.Clone(template.Allowlist.Base.Workloads)}
	allow.Base = base
	allow.Pull = maps.Clone(template.Allowlist.Pull)
	name, router, err := routerEntry(seed)
	if err != nil {
		return nil, err
	}
	if _, taken := base.Workloads[name]; taken {
		return nil, fmt.Errorf("floor template: a platform role is named %s, the router's entry", name)
	}
	base.Workloads[name] = router
	for file, data := range staticPods {
		pod, entry, err := staticPodEntry(data)
		if err != nil {
			return nil, fmt.Errorf("static pod template %s: %w", file, err)
		}
		if _, taken := base.Workloads[pod]; taken {
			return nil, fmt.Errorf("static pod template %s: pod %s is named as another entry", file, pod)
		}
		base.Workloads[pod] = entry
	}
	if allow.Pull == nil {
		return nil, fmt.Errorf("floor template: no allowlist.pull: a worker pulls its served allowlist from its CDS")
	}
	// Each served allowlist extends RTMR[3] before the worker applies it.
	allow.Pull["measure_policies"] = true
	return yaml.Marshal(workerFloor{
		floorSettings: template.floorSettings,
		Allowlist:     allow,
		Mesh:          *template.Mesh,
		Worker:        true,
	})
}

// parseTemplate decodes data strictly and requires its allowlist base and
// mesh policy.
func parseTemplate(data []byte) (*floorTemplate, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var template floorTemplate
	if err := dec.Decode(&template); err != nil {
		return nil, fmt.Errorf("floor template: %w", err)
	}
	if template.Allowlist == nil || template.Allowlist.Base == nil || template.Mesh == nil {
		return nil, errors.New("floor template: no allowlist base or mesh policy")
	}
	if len(template.Allowlist.Base.Workloads) == 0 {
		return nil, errors.New("floor template base: no entry")
	}
	return &template, nil
}

// requirePlatformRoles refuses a base entry whose containers do not all carry
// a platform role: a worker grants roles from this measured base alone.
func requirePlatformRoles(base *allowlist.Allowlist) error {
	for _, name := range slices.Sorted(maps.Keys(base.Workloads)) {
		containers := slices.Concat(base.Workloads[name].InitContainers, base.Workloads[name].Containers)
		if len(containers) == 0 {
			return fmt.Errorf("floor template base: entry %s holds no container", name)
		}
		for _, c := range containers {
			if c.Role == "" {
				return fmt.Errorf("floor template base: entry %s container with digest %s holds no platform role", name, c.Digest)
			}
		}
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
