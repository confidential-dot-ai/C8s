package allowlist

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// podTemplate is the slice of a Deployment/StatefulSet/DaemonSet/Pod we need.
// Decoding into this rather than the k8s API types keeps the CLI free of a
// client-go dependency for what is a pure text transformation.
type podTemplate struct {
	InitContainers []templateContainer `json:"initContainers"`
	Containers     []templateContainer `json:"containers"`
}

type templateContainer struct {
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	Command []string `json:"command"`
	Args    []string `json:"args"`
}

// podSpecOf finds the pod spec in a Pod or in any workload that carries a pod
// template, so `kubectl get deploy/x -o json` and `kubectl get pod/x -o json`
// both work without the caller reaching for jq first.
func podSpecOf(data []byte) (podTemplate, error) {
	var probe struct {
		Kind string `json:"kind"`
		Spec struct {
			podTemplate
			Template struct {
				Spec podTemplate `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return podTemplate{}, fmt.Errorf("parse object: %w", err)
	}
	if len(probe.Spec.Template.Spec.Containers) > 0 {
		return probe.Spec.Template.Spec, nil
	}
	if len(probe.Spec.Containers) > 0 {
		return probe.Spec.podTemplate, nil
	}
	kind := probe.Kind
	if kind == "" {
		kind = "object"
	}
	return podTemplate{}, fmt.Errorf("%s carries no containers: expected a Pod or a workload with a pod template", kind)
}

// dropInjected removes the containers c8s's admission webhook adds and returns
// their names.
func dropInjected(cs []templateContainer) ([]templateContainer, []string) {
	out := make([]templateContainer, 0, len(cs))
	var dropped []string
	for _, c := range cs {
		if workloadclaims.IsInjectedContainerName(c.Name) {
			dropped = append(dropped, c.Name)
			continue
		}
		out = append(out, c)
	}
	return out, dropped
}

// argvPolicy renders one half of a container's argv policy.
//
// An empty argv is Deny, never Exact: Exact requires equality against a
// non-empty argv and the apply is rejected outright, and Any would be looser
// than what the container actually runs.
func argvPolicy(argv []string) allowlist.ArgvPolicy {
	if len(argv) == 0 {
		return allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny}
	}
	return allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: argv}
}

func deriveContainers(cs []templateContainer) ([]allowlist.Container, error) {
	out := make([]allowlist.Container, 0, len(cs))
	for _, c := range cs {
		_, raw, found := strings.Cut(c.Image, "@")
		if !found {
			return nil, fmt.Errorf("container %q is not pinned by digest: %s", c.Name, c.Image)
		}
		digest, err := types.ParseDigest(raw)
		if err != nil {
			return nil, fmt.Errorf("container %q: %w", c.Name, err)
		}
		out = append(out, allowlist.Container{
			Digest:  digest,
			Image:   c.Image,
			Command: argvPolicy(c.Command),
			Args:    argvPolicy(c.Args),
		})
	}
	return out, nil
}

// unknownContainerErr names a policy no derived container claimed. A dropped
// container is visibly in the input, so it is not reported as unknown.
func unknownContainerErr(kind, name string) error {
	if workloadclaims.IsInjectedContainerName(name) {
		return fmt.Errorf("%s policy names %q, a container c8s injects and derive drops", kind, name)
	}
	return fmt.Errorf("%s policy names unknown container %q", kind, name)
}

func newDeriveCmd(_ *options) *cobra.Command {
	var secrets []string
	var label string
	var envMode, envFile, mountsMode, mountsFile string
	cmd := &cobra.Command{
		Use:   "derive <name> <file|->",
		Short: "Build an entry from a live Kubernetes object",
		Long: `Emit an entry for <name> from a Pod, Deployment, StatefulSet or DaemonSet
given as JSON in <file> (or stdin with '-'). Nothing is sent; pipe the result to
'apply'.

Deriving from the live object keeps the entry from drifting away from what is
actually running, and handles two things a hand-written entry usually gets
wrong. Init containers are part of the set CDS matches, so omitting them makes
every release fail with "no workload entry matches the running containers". And
a container with a command and no args needs an args policy of "deny", because
"exact" requires a non-empty argv.

Environment policy must be supplied using --env=any|deny or --env-file, a JSON
map of container names to env policies. Exact and match policies describe the
complete OCI launch environment, including image/runtime additions. Match permits
individual variables to require an exact value or presence. Pod env/envFrom alone
cannot establish the complete environment.

Mount policy comes from --mounts=any|deny or --mounts-file, a JSON map of
container names to mount policies covering every derived init and main
container. Omitting both leaves every container at "deny", which admits platform
mounts alone. The pod spec cannot prove which sources are node-provided or how
persistent storage is protected, so exact rules go in --mounts-file.

The entry pins argv, so it expires the moment a container command changes:
re-derive and re-apply whenever the workload is edited.

Containers c8s injects are dropped and named on stderr, so an admitted pod
derives the same entry as the manifest it was admitted from.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileOrStdin(cmd, args[1])
			if err != nil {
				return err
			}
			spec, err := podSpecOf(data)
			if err != nil {
				return err
			}
			var dropped, mains []string
			spec.InitContainers, dropped = dropInjected(spec.InitContainers)
			spec.Containers, mains = dropInjected(spec.Containers)
			dropped = append(dropped, mains...)
			if len(dropped) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "dropped %s: injected by c8s\n", strings.Join(dropped, ", "))
			}
			containers, err := deriveContainers(spec.Containers)
			if err != nil {
				return err
			}
			initContainers, err := deriveContainers(spec.InitContainers)
			if err != nil {
				return err
			}
			if (envMode == "") == (envFile == "") {
				return fmt.Errorf("specify exactly one of --env=any|deny or --env-file")
			}
			if mountsMode != "" && mountsMode != allowlist.PolicyAny && mountsMode != allowlist.PolicyDeny {
				return fmt.Errorf("--mounts must be any or deny; use --mounts-file for exact rules")
			}
			if mountsMode == "" && mountsFile == "" {
				fmt.Fprintln(cmd.ErrOrStderr(),
					`mounts: no policy given; every container is "deny", which admits platform mounts alone`)
			}
			var policies map[string]allowlist.EnvPolicy
			var mountPolicies map[string]allowlist.MountPolicy
			if mountsFile != "" {
				data, err := os.ReadFile(mountsFile)
				if err != nil {
					return err
				}
				mountPolicies, err = allowlist.ParseMountPoliciesJSON(data)
				if err != nil {
					return err
				}
			}
			if envFile != "" {
				data, err := os.ReadFile(envFile)
				if err != nil {
					return err
				}
				policies, err = allowlist.ParseEnvPoliciesJSON(data)
				if err != nil {
					return err
				}
			} else if envMode != allowlist.PolicyAny && envMode != allowlist.PolicyDeny {
				return fmt.Errorf("--env must be any or deny; use --env-file for exact or match policies")
			}
			used := map[string]bool{}
			usedMounts := map[string]bool{}
			type derivedContainerGroup struct {
				templates  []templateContainer
				containers []allowlist.Container
			}
			for _, part := range []derivedContainerGroup{{spec.InitContainers, initContainers}, {spec.Containers, containers}} {
				for i, c := range part.templates {
					p := allowlist.EnvPolicy{Policy: envMode}
					if envFile != "" {
						var ok bool
						p, ok = policies[c.Name]
						if !ok {
							return fmt.Errorf("missing env policy for container %q", c.Name)
						}
						used[c.Name] = true
					}
					part.containers[i].Env = p
					switch {
					case mountsFile != "":
						mount, ok := mountPolicies[c.Name]
						if !ok {
							return fmt.Errorf("missing mount policy for container %q", c.Name)
						}
						part.containers[i].Mounts = mount
						usedMounts[c.Name] = true
					case mountsMode != "":
						part.containers[i].Mounts = allowlist.MountPolicy{Policy: mountsMode}
					}
				}
			}
			for name := range policies {
				if !used[name] {
					return unknownContainerErr("env", name)
				}
			}
			for name := range mountPolicies {
				if !usedMounts[name] {
					return unknownContainerErr("mount", name)
				}
			}
			w := allowlist.Workload{
				Label:          label,
				InitContainers: initContainers,
				Containers:     containers,
			}
			if len(secrets) > 0 {
				w.Secrets = &allowlist.SecretsPolicy{
					Policy: allowlist.PolicyAllow,
					Read:   secrets,
				}
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]allowlist.Workload{args[0]: w})
		},
	}
	cmd.Flags().StringArrayVar(&secrets, "secret-read", nil,
		"grant read on this secret path (repeatable); omit for no secrets block")
	cmd.Flags().StringVar(&envMode, "env", "", "environment policy for every container: any or deny")
	cmd.Flags().StringVar(&envFile, "env-file", "", "JSON map of container names to explicit env policies (including exact and match)")
	cmd.Flags().StringVar(&mountsMode, "mounts", "", "mount policy for every container: any or deny (default deny)")
	cmd.Flags().StringVar(&mountsFile, "mounts-file", "", "JSON map of container names to explicit mount policies")
	cmd.Flags().StringVar(&label, "label", "", "optional entry label")
	cmd.MarkFlagsMutuallyExclusive("mounts", "mounts-file")
	return cmd
}
