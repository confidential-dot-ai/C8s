package allowlist

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// podTemplate is the slice of a Deployment/StatefulSet/DaemonSet/Pod we need.
// Decoding into this rather than the k8s API types keeps the CLI free of a
// client-go dependency for what is a pure text transformation.
type podTemplate struct {
	InitContainers  []templateContainer     `json:"initContainers"`
	Containers      []templateContainer     `json:"containers"`
	SecurityContext templateSecurityContext `json:"securityContext"`
	// annotations are the pod's, from the object or its pod template.
	annotations map[string]string
}

type templateSecurityContext struct {
	RunAsUser    *int64 `json:"runAsUser"`
	RunAsNonRoot *bool  `json:"runAsNonRoot"`
}

type templateContainer struct {
	Name            string                  `json:"name"`
	Image           string                  `json:"image"`
	Command         []string                `json:"command"`
	Args            []string                `json:"args"`
	SecurityContext templateSecurityContext `json:"securityContext"`
	VolumeMounts    []struct {
		Name        string `json:"name"`
		MountPath   string `json:"mountPath"`
		SubPath     string `json:"subPath"`
		SubPathExpr string `json:"subPathExpr"`
	} `json:"volumeMounts"`
}

// emptyDirMounts are the rules for every mount c declares of an emptyDir
// volume, or one at fallback when it declares none. A subpath mount is
// observed as data, so its rule is a data rule, which must sit below
// allowlist.DataMountPrefix.
func (c templateContainer) emptyDirMounts(volume, fallback string) ([]allowlist.MountRule, error) {
	var rules []allowlist.MountRule
	for _, m := range c.VolumeMounts {
		if m.Name != volume {
			continue
		}
		kind := allowlist.MountEmptyDir
		if m.SubPath != "" || m.SubPathExpr != "" {
			if !strings.HasPrefix(m.MountPath, allowlist.DataMountPrefix) {
				return nil, fmt.Errorf("container %q mounts %s by subpath at %s: an allowlist can admit a subpath mount only below %s",
					c.Name, volume, m.MountPath, allowlist.DataMountPrefix)
			}
			kind = allowlist.MountData
		}
		rules = append(rules, allowlist.MountRule{Destination: m.MountPath, Kind: kind})
	}
	if len(rules) == 0 {
		rules = append(rules, allowlist.MountRule{Destination: fallback, Kind: allowlist.MountEmptyDir})
	}
	return rules, nil
}

func effectiveSecurityContext(pod, ctr templateSecurityContext) templateSecurityContext {
	out := pod
	if ctr.RunAsUser != nil {
		out.RunAsUser = ctr.RunAsUser
	}
	if ctr.RunAsNonRoot != nil {
		out.RunAsNonRoot = ctr.RunAsNonRoot
	}
	return out
}

func statesNonzeroUID(sc templateSecurityContext) bool {
	if sc.RunAsUser != nil {
		return *sc.RunAsUser != 0
	}
	return sc.RunAsNonRoot != nil && *sc.RunAsNonRoot
}

func rootUIDWarning(name string) string {
	return fmt.Sprintf("container %q does not state a nonzero uid, and a C8s node refuses a container that runs as uid 0: "+
		"set a nonzero runAsUser, or runAsNonRoot: true if its image's USER is a nonzero uid", name)
}

func rootUIDWarnings(spec podTemplate) []string {
	var out []string
	for _, c := range slices.Concat(spec.InitContainers, spec.Containers) {
		if !statesNonzeroUID(effectiveSecurityContext(spec.SecurityContext, c.SecurityContext)) {
			out = append(out, rootUIDWarning(c.Name))
		}
	}
	return out
}

// podSpecOf finds the pod spec in a Pod or in any workload that carries a pod
// template, so `kubectl get deploy/x -o json` and `kubectl get pod/x -o json`
// both work without the caller reaching for jq first.
func podSpecOf(data []byte) (podTemplate, error) {
	type metadata struct {
		Annotations map[string]string `json:"annotations"`
	}
	var probe struct {
		Kind     string   `json:"kind"`
		Metadata metadata `json:"metadata"`
		Spec     struct {
			podTemplate
			Template struct {
				Metadata metadata    `json:"metadata"`
				Spec     podTemplate `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return podTemplate{}, fmt.Errorf("parse object: %w", err)
	}
	if spec := probe.Spec.Template.Spec; len(spec.Containers) > 0 {
		spec.annotations = probe.Spec.Template.Metadata.Annotations
		return spec, nil
	}
	if spec := probe.Spec.podTemplate; len(spec.Containers) > 0 {
		spec.annotations = probe.Metadata.Annotations
		return spec, nil
	}
	kind := probe.Kind
	if kind == "" {
		kind = "object"
	}
	return podTemplate{}, fmt.Errorf("%s carries no containers: expected a Pod or a workload with a pod template", kind)
}

// dropInjected removes the containers C8s's admission webhook adds and returns
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

// withInjectedMounts adds the mounts the webhook adds to c to a deny or exact
// policy: the secrets volume, when the pod requests secrets. The webhook keeps
// a mount c already declares for the volume, so those destinations win. A rule
// p already gives for the same destination is kept if its kind matches and
// refused otherwise, since it would refuse the injected mount. Any is returned
// unchanged.
func withInjectedMounts(p allowlist.MountPolicy, annotations map[string]string, c templateContainer) (allowlist.MountPolicy, error) {
	if p.Policy == allowlist.PolicyAny || len(workloadclaims.SplitList(annotations[workloadclaims.AnnotationSecrets])) == 0 {
		return p, nil
	}
	rules, err := c.emptyDirMounts(workloadclaims.SecretsVolumeName, workloadclaims.SecretDir)
	if err != nil {
		return p, err
	}
	out := allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: slices.Clone(p.Rules)}
	for _, r := range rules {
		i := slices.IndexFunc(out.Rules, func(have allowlist.MountRule) bool { return have.Destination == r.Destination })
		switch {
		case i < 0:
			out.Rules = append(out.Rules, r)
		case out.Rules[i].Kind != r.Kind:
			return p, fmt.Errorf("mount policy for container %q gives %s kind %q, but c8s mounts its %s volume there as %q",
				c.Name, r.Destination, out.Rules[i].Kind, workloadclaims.SecretsVolumeName, r.Kind)
		}
	}
	return out, nil
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

// imageArgv returns an image's baked Entrypoint and Cmd.
type imageArgv func(image string) (entrypoint, cmd []string, err error)

// deriveContainers pins each container's argv as the runtime resolves it: an
// unset command runs the image's Entrypoint, and unset args run its Cmd only
// when the command is unset too.
func deriveContainers(cs []templateContainer, resolve imageArgv) ([]allowlist.Container, error) {
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
		command, args := c.Command, c.Args
		if len(command) == 0 {
			entrypoint, cmd, err := resolve(c.Image)
			if err != nil {
				return nil, fmt.Errorf("container %q sets no command, so derive needs the image's baked argv: %w", c.Name, err)
			}
			command = entrypoint
			if len(args) == 0 {
				args = cmd
			}
		}
		// The matcher pins command as a prefix of the whole argv, so an image
		// with no Entrypoint runs its args (or Cmd) as the command. Pin that
		// argv exactly; a deny command would admit only an empty argv.
		if len(command) == 0 {
			command, args = args, nil
		}
		out = append(out, allowlist.Container{
			Digest:  digest,
			Image:   c.Image,
			Command: argvPolicy(command),
			Args:    argvPolicy(args),
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

type deriveFlags struct {
	label      string
	secrets    []string
	envMode    string
	envFile    string
	mountsMode string
	mountsFile string
}

func newDeriveCmd(_ *options) *cobra.Command {
	var f deriveFlags
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
"exact" requires a non-empty argv. A container that sets no command runs its
image's Entrypoint, and its Cmd too when it sets no args; derive reads both from
the registry with crane.

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

For a pod that sets confidential.ai/c8s-secrets, derive adds the secrets
emptyDir the webhook mounts into every container to each deny or exact policy,
at /run/c8s/secrets or wherever the container already mounts the volume. Other
volumes, including c8s volumes, go in --mounts-file.

The entry pins argv, so it expires the moment a container command changes:
re-derive and re-apply whenever the workload is edited.

Containers c8s injects are dropped and named on stderr, so an admitted pod
derives the same entry as the manifest it was admitted from. A container whose
spec does not state a nonzero uid is named on stderr too: a C8s node refuses a
container that runs as uid 0.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deriveEntry(cmd, args[0], args[1], f)
		},
	}
	cmd.Flags().StringArrayVar(&f.secrets, "secret-read", nil,
		"grant read on this secret path (repeatable); omit for no secrets block")
	cmd.Flags().StringVar(&f.envMode, "env", "", "environment policy for every container: any or deny")
	cmd.Flags().StringVar(&f.envFile, "env-file", "", "JSON map of container names to explicit env policies (including exact and match)")
	cmd.Flags().StringVar(&f.mountsMode, "mounts", "", "mount policy for every container: any or deny (default deny)")
	cmd.Flags().StringVar(&f.mountsFile, "mounts-file", "", "JSON map of container names to explicit mount policies")
	cmd.Flags().StringVar(&f.label, "label", "", "optional entry label")
	cmd.MarkFlagsMutuallyExclusive("mounts", "mounts-file")
	return cmd
}

func deriveEntry(cmd *cobra.Command, name, file string, f deriveFlags) error {
	spec, err := readPodSpec(cmd, file)
	if err != nil {
		return err
	}
	spec = dropInjectedFromSpec(cmd.ErrOrStderr(), spec)
	for _, warning := range rootUIDWarnings(spec) {
		fmt.Fprintln(cmd.ErrOrStderr(), warning)
	}
	resolve := craneImageArgv(cmd)
	containers, err := derivedFrom(spec.Containers, resolve)
	if err != nil {
		return err
	}
	initContainers, err := derivedFrom(spec.InitContainers, resolve)
	if err != nil {
		return err
	}
	policies, err := f.readPolicies(cmd.ErrOrStderr(), spec.annotations)
	if err != nil {
		return err
	}
	if err := policies.applyToPod(&initContainers, &containers); err != nil {
		return err
	}
	w, err := f.workload(initContainers.entries, containers.entries)
	if err != nil {
		return err
	}
	return writeJSON(cmd.OutOrStdout(), map[string]allowlist.Workload{name: w})
}

func readPodSpec(cmd *cobra.Command, file string) (podTemplate, error) {
	data, err := readFileOrStdin(cmd, file)
	if err != nil {
		return podTemplate{}, err
	}
	return podSpecOf(data)
}

func dropInjectedFromSpec(stderr io.Writer, spec podTemplate) podTemplate {
	var droppedInit, droppedMain []string
	spec.InitContainers, droppedInit = dropInjected(spec.InitContainers)
	spec.Containers, droppedMain = dropInjected(spec.Containers)
	if dropped := slices.Concat(droppedInit, droppedMain); len(dropped) > 0 {
		fmt.Fprintf(stderr, "dropped %s: injected by c8s\n", strings.Join(dropped, ", "))
	}
	return spec
}

func craneImageArgv(cmd *cobra.Command) imageArgv {
	requireCrane := sync.OnceValue(crane.Require)
	return func(image string) (entrypoint, imageCmd []string, err error) {
		if err := requireCrane(); err != nil {
			return nil, nil, err
		}
		cfg, err := crane.Config(ctx(cmd), image)
		if err != nil {
			return nil, nil, err
		}
		return cfg.Config.Entrypoint, cfg.Config.Cmd, nil
	}
}

// derivedContainers holds the entry derived from templates[i] at entries[i].
type derivedContainers struct {
	templates []templateContainer
	entries   []allowlist.Container
}

func derivedFrom(templates []templateContainer, resolve imageArgv) (derivedContainers, error) {
	entries, err := deriveContainers(templates, resolve)
	if err != nil {
		return derivedContainers{}, err
	}
	return derivedContainers{templates: templates, entries: entries}, nil
}

type containerPolicies struct {
	envs   policySource[allowlist.EnvPolicy]
	mounts policySource[allowlist.MountPolicy]
	// annotations decide the mounts c8s injects.
	annotations map[string]string
}

// The order of readPolicies' checks decides which error a bad invocation
// reports.
func (f deriveFlags) readPolicies(
	stderr io.Writer,
	annotations map[string]string,
) (containerPolicies, error) {
	if !f.setsOneEnvSource() {
		return containerPolicies{}, fmt.Errorf("specify exactly one of --env=any|deny or --env-file")
	}
	mounts, err := f.mountPolicies(stderr, annotations)
	if err != nil {
		return containerPolicies{}, err
	}
	envs, err := f.envPolicies()
	if err != nil {
		return containerPolicies{}, err
	}
	return containerPolicies{envs: envs, mounts: mounts, annotations: annotations}, nil
}

func (f deriveFlags) setsOneEnvSource() bool {
	return (f.envMode == "") != (f.envFile == "")
}

// applyToPod fails on a file policy that no container of the pod claimed.
func (p containerPolicies) applyToPod(initContainers, containers *derivedContainers) error {
	if err := p.apply(initContainers); err != nil {
		return err
	}
	if err := p.apply(containers); err != nil {
		return err
	}
	if err := p.envs.requireAllClaimed(); err != nil {
		return err
	}
	return p.mounts.requireAllClaimed()
}

func (p containerPolicies) apply(derived *derivedContainers) error {
	for i, c := range derived.templates {
		env, err := p.envs.policyFor(c.Name)
		if err != nil {
			return err
		}
		derived.entries[i].Env = env
		mount, err := p.mounts.policyFor(c.Name)
		if err != nil {
			return err
		}
		derived.entries[i].Mounts, err = withInjectedMounts(mount, p.annotations, c)
		if err != nil {
			return err
		}
	}
	return nil
}

// With no mount flag every container keeps the zero policy, which applies as
// deny.
func (f deriveFlags) mountPolicies(
	stderr io.Writer,
	annotations map[string]string,
) (policySource[allowlist.MountPolicy], error) {
	if f.mountsMode != "" && f.mountsMode != allowlist.PolicyAny && f.mountsMode != allowlist.PolicyDeny {
		return nil, fmt.Errorf("--mounts must be any or deny; use --mounts-file for exact rules")
	}
	if f.mountsMode == "" && f.mountsFile == "" {
		fmt.Fprintln(stderr, noMountPolicyNote(annotations))
	}
	if f.mountsFile == "" {
		return samePolicy[allowlist.MountPolicy]{policy: allowlist.MountPolicy{Policy: f.mountsMode}}, nil
	}
	data, err := os.ReadFile(f.mountsFile)
	if err != nil {
		return nil, err
	}
	byName, err := allowlist.ParseMountPoliciesJSON(data)
	if err != nil {
		return nil, err
	}
	return newPolicyFile("mount", byName), nil
}

func noMountPolicyNote(annotations map[string]string) string {
	if len(workloadclaims.SplitList(annotations[workloadclaims.AnnotationSecrets])) > 0 {
		return `mounts: no policy given; every container admits platform mounts and the c8s secrets mount alone`
	}
	return `mounts: no policy given; every container is "deny", which admits platform mounts alone`
}

func (f deriveFlags) envPolicies() (policySource[allowlist.EnvPolicy], error) {
	if f.envFile == "" {
		if f.envMode != allowlist.PolicyAny && f.envMode != allowlist.PolicyDeny {
			return nil, fmt.Errorf("--env must be any or deny; use --env-file for exact or match policies")
		}
		return samePolicy[allowlist.EnvPolicy]{policy: allowlist.EnvPolicy{Policy: f.envMode}}, nil
	}
	data, err := os.ReadFile(f.envFile)
	if err != nil {
		return nil, err
	}
	byName, err := allowlist.ParseEnvPoliciesJSON(data)
	if err != nil {
		return nil, err
	}
	return newPolicyFile("env", byName), nil
}

type policySource[P any] interface {
	policyFor(container string) (P, error)
	requireAllClaimed() error
}

type samePolicy[P any] struct {
	policy P
}

func (s samePolicy[P]) policyFor(string) (P, error) {
	return s.policy, nil
}

func (samePolicy[P]) requireAllClaimed() error {
	return nil
}

type policyFile[P any] struct {
	kind    string
	byName  map[string]P
	claimed map[string]bool
}

func newPolicyFile[P any](kind string, byName map[string]P) *policyFile[P] {
	return &policyFile[P]{kind: kind, byName: byName, claimed: map[string]bool{}}
}

func (p *policyFile[P]) policyFor(container string) (P, error) {
	policy, ok := p.byName[container]
	if !ok {
		var none P
		return none, fmt.Errorf("missing %s policy for container %q", p.kind, container)
	}
	p.claimed[container] = true
	return policy, nil
}

func (p *policyFile[P]) requireAllClaimed() error {
	for name := range p.byName {
		if !p.claimed[name] {
			return unknownContainerErr(p.kind, name)
		}
	}
	return nil
}

func (f deriveFlags) workload(
	initContainers []allowlist.Container,
	containers []allowlist.Container,
) (allowlist.Workload, error) {
	w := allowlist.Workload{
		Label:          f.label,
		InitContainers: initContainers,
		Containers:     containers,
	}
	if err := w.CheckVariableEvidenceBudget(); err != nil {
		return allowlist.Workload{}, err
	}
	if len(f.secrets) > 0 {
		w.Secrets = &allowlist.SecretsPolicy{
			Policy: allowlist.PolicyAllow,
			Read:   f.secrets,
		}
	}
	return w, nil
}
