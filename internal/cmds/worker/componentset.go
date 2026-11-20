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

const (
	routerWorkloadPrefix  = "c8s-router-"
	volumedWorkloadPrefix = "c8s-volumed-"
)

// ComponentSetFile is the component set a release publishes, as a set file
// `c8s allowlist components add --set-file` reads: an allowlist document whose
// one set, keyed by version, holds the floor template's platform role entries
// and, from the seed `c8s node-image render` writes, the router entry and
// volumed's, marked as the release's node service.
func ComponentSetFile(templateData, seed []byte, version string) ([]byte, error) {
	entries, err := RoleEntries(templateData)
	if err != nil {
		return nil, err
	}
	parsed, err := allowlist.ParseJSON(seed)
	if err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	for _, published := range []struct {
		prefix      string
		nodeService bool
	}{
		{prefix: routerWorkloadPrefix},
		{prefix: volumedWorkloadPrefix, nodeService: true},
	} {
		name, entry, err := seedEntry(parsed, published.prefix)
		if err != nil {
			return nil, err
		}
		if _, taken := entries[name]; taken {
			return nil, fmt.Errorf("floor template: a platform role is named %s, the seed's entry", name)
		}
		entry.NodeService = published.nodeService
		entries[name] = entry
	}
	document, err := json.Marshal(allowlist.Allowlist{
		Schema:     allowlist.Schema,
		Workloads:  map[string]allowlist.Workload{},
		Components: map[string]allowlist.ComponentSet{version: {Entries: entries}},
	})
	if err != nil {
		return nil, err
	}
	set, err := allowlist.ParseJSON(document)
	if err != nil {
		return nil, err
	}
	return set.Canonical()
}

// seedEntry is the seed's one entry named with prefix.
func seedEntry(seed *allowlist.Allowlist, prefix string) (string, allowlist.Workload, error) {
	var names []string
	for name := range seed.Workloads {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		return "", allowlist.Workload{}, fmt.Errorf("seed: want one %s* entry, got %v", prefix, names)
	}
	entry := seed.Workloads[names[0]]
	if err := requireNodeInputs(names[0], entry); err != nil {
		return "", allowlist.Workload{}, err
	}
	return names[0], entry, requireStagedFiles(names[0], entry)
}

// nodeMountKinds are the mounts a published entry may take: none filled from
// objects the control plane writes.
var nodeMountKinds = []allowlist.MountClass{allowlist.MountHost, allowlist.MountNodeRootFile, allowlist.MountEmptyDir}

// requireNodeInputs refuses an entry that leaves its launch open or takes a
// mount outside nodeMountKinds: a published component's settings come from
// the node alone.
func requireNodeInputs(name string, entry allowlist.Workload) error {
	for _, c := range slices.Concat(entry.InitContainers, entry.Containers) {
		if !c.LaunchPinned() {
			return fmt.Errorf("seed: entry %s container %s does not pin its launch", name, c.Digest)
		}
		for _, rule := range c.Mounts.Rules {
			if !slices.Contains(nodeMountKinds, rule.Kind) {
				return fmt.Errorf("seed: entry %s container %s mounts %s, which the control plane fills", name, c.Digest, rule.Kind)
			}
		}
	}
	return nil
}

var publicPath = regexp.MustCompile(`/run/+c8s-node(/[^\s,=:]*)?`)

// requireStagedFiles refuses an entry naming a file under /run/c8s-node, in
// its argv, environment or mount sources, that worker stage does not publish.
func requireStagedFiles(name string, entry allowlist.Workload) error {
	staged, err := stagedPublicNames()
	if err != nil {
		return err
	}
	for _, c := range slices.Concat(entry.InitContainers, entry.Containers) {
		named := slices.Concat(c.Command.Argv, c.Args.Argv, slices.Collect(maps.Values(c.Env.ExactValues())))
		for _, rule := range c.Mounts.Rules {
			named = append(named, rule.Source)
		}
		for _, text := range named {
			for _, p := range publicPath.FindAllString(text, -1) {
				file := strings.TrimPrefix(path.Clean(p), nodeservices.PublicDir)
				if file != "" && !slices.Contains(staged, strings.TrimPrefix(file, "/")) {
					return fmt.Errorf("seed: entry %s reads %s, which worker stage does not publish", name, p)
				}
			}
		}
	}
	return nil
}
