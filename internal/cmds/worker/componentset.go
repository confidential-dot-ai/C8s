package worker

import (
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const routerWorkloadPrefix = "c8s-router-"

// ComponentSetFile is the component set a release publishes, as a set file
// `c8s allowlist components add --set-file` reads: an allowlist document whose
// one set, keyed by version, holds the floor template's platform role entries
// and the router entry of the seed `c8s node-image render` writes.
func ComponentSetFile(templateData, seed []byte, version string) ([]byte, error) {
	entries, err := RoleEntries(templateData)
	if err != nil {
		return nil, err
	}
	name, router, err := routerEntry(seed)
	if err != nil {
		return nil, err
	}
	if _, taken := entries[name]; taken {
		return nil, fmt.Errorf("floor template: a platform role is named %s, the router's entry", name)
	}
	entries[name] = router
	document, err := json.Marshal(allowlist.Allowlist{
		Schema:     allowlist.Schema,
		Workloads:  map[string]allowlist.Workload{},
		Components: map[string]allowlist.ComponentSet{version: {Entries: entries}},
	})
	if err != nil {
		return nil, err
	}
	// Every check an operator's write faces runs here.
	parsed, err := allowlist.ParseJSON(document)
	if err != nil {
		return nil, err
	}
	return parsed.Canonical()
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
