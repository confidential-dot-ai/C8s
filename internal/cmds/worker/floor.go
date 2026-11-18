package worker

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

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
// its digests filled, and the image's static pod templates by file name. The
// base it writes holds the static pods alone; the template's platform role
// entries are published in the release's component set
// (ComponentSetFile). See NewFloorCmd for what it keeps.
func Floor(templateData []byte, staticPods map[string][]byte) ([]byte, error) {
	template, err := parseTemplate(templateData)
	if err != nil {
		return nil, err
	}
	base := map[string]allowlist.Workload{}
	for file, data := range staticPods {
		pod, entry, err := staticPodEntry(data)
		if err != nil {
			return nil, fmt.Errorf("static pod template %s: %w", file, err)
		}
		if _, taken := base[pod]; taken {
			return nil, fmt.Errorf("static pod template %s: pod %s is named as another entry", file, pod)
		}
		base[pod] = entry
	}
	return floorWithBase(template, base)
}

// PodImageFloor builds the Pod CVM image's NRI floor from the same template,
// its digests filled. Its base holds the template's role entries: a pod CVM
// follows no cluster allowlist and renders its one pod's mesh endpoint from
// the entry its image measures (internal/cmds/nodeservices RenderPodRuntime).
// It runs no static pod.
func PodImageFloor(templateData []byte) ([]byte, error) {
	template, err := parseTemplate(templateData)
	if err != nil {
		return nil, err
	}
	roles, err := roleEntries(template)
	if err != nil {
		return nil, err
	}
	return floorWithBase(template, roles)
}

// floorWithBase is the template's settings with base as the measured base, as
// every image's floor carries them.
func floorWithBase(template *floorTemplate, base map[string]allowlist.Workload) ([]byte, error) {
	// The output takes a copy: the parsed template stays as it was read.
	allow := *template.Allowlist
	allow.Base = &allowlist.Allowlist{Schema: template.Allowlist.Base.Schema, Workloads: base}
	allow.Pull = maps.Clone(template.Allowlist.Pull)
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

// RoleEntries are the floor template's platform role entries, the launches of
// a release's own components.
func RoleEntries(templateData []byte) (map[string]allowlist.Workload, error) {
	template, err := parseTemplate(templateData)
	if err != nil {
		return nil, err
	}
	return roleEntries(template)
}

// roleEntries are the template's role entries, each container bound to a
// platform role: the template describes a release's own invocations.
func roleEntries(template *floorTemplate) (map[string]allowlist.Workload, error) {
	base := template.Allowlist.Base
	for _, name := range slices.Sorted(maps.Keys(base.Workloads)) {
		containers := slices.Concat(base.Workloads[name].InitContainers, base.Workloads[name].Containers)
		if len(containers) == 0 {
			return nil, fmt.Errorf("floor template base: entry %s holds no container", name)
		}
		for _, c := range containers {
			if c.Role == "" {
				return nil, fmt.Errorf("floor template base: entry %s container with digest %s holds no platform role", name, c.Digest)
			}
		}
	}
	return maps.Clone(base.Workloads), nil
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
