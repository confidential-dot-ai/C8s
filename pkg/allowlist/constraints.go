package allowlist

// containerConstraint is the common lifecycle for a concrete field in a
// container policy. Implementations remain private: the serialized allowlist
// is made exclusively from the concrete policy structs in allowlist.go.
type containerConstraint interface {
	normalize() (field string, err error)
	admits(RunningContainer) bool
	hostIndependent() bool
	isUnconstrained() bool
}

// constraints is the single inventory of the independently constrained parts
// of a container launch. Command and args intentionally form one constraint:
// command consumes a prefix of OCI process.args and args evaluates only the
// remainder.
func (c *Container) constraints() []containerConstraint {
	return []containerConstraint{
		processConstraint{command: &c.Command, args: &c.Args},
		mountConstraint{policy: &c.Mounts},
		newEnvConstraint(&c.Env),
	}
}

type processConstraint struct {
	command *ArgvPolicy
	args    *ArgvPolicy
}

func (p processConstraint) normalize() (string, error) {
	if err := normalizeArgv(p.command); err != nil {
		return "command", err
	}
	if err := normalizeArgv(p.args); err != nil {
		return "args", err
	}
	return "", nil
}

func (p processConstraint) admits(r RunningContainer) bool {
	rest, ok := p.command.matchCommand(r.Argv)
	return ok && p.args.matchArgs(rest)
}

func (p processConstraint) hostIndependent() bool {
	return argvHostIndependent(p.command.Policy) && argvHostIndependent(p.args.Policy)
}

func argvHostIndependent(policy string) bool {
	return policy == "" || policy == PolicyDeny || policy == PolicyExact
}

func (p processConstraint) isUnconstrained() bool {
	return p.command.Policy == PolicyAny && p.args.Policy == PolicyAny
}

type mountConstraint struct {
	policy *MountPolicy
}

func (m mountConstraint) normalize() (string, error) {
	return "mounts", normalizeMounts(m.policy)
}
func (m mountConstraint) admits(r RunningContainer) bool {
	return m.policy.admits(r.Mounts)
}

// Deny and exact retain verified platform mounts (/etc/hosts, /etc/resolv.conf,
// etc.), which the runtime adds to the OCI mount table even without workload volumes.
func (m mountConstraint) hostIndependent() bool {
	for _, rule := range m.policy.Rules {
		if behavior := rule.behavior(); behavior == nil || !behavior.hostIndependent() {
			return false
		}
	}
	return m.policy.Policy == PolicyDeny || m.policy.Policy == PolicyExact || m.policy.Policy == ""
}
func (m mountConstraint) isUnconstrained() bool {
	return m.policy.Policy == PolicyAny
}

type envConstraint struct {
	policy   *EnvPolicy
	behavior envPolicyBehavior
	err      error
}

func newEnvConstraint(policy *EnvPolicy) envConstraint {
	behavior, err := policy.behavior()
	return envConstraint{policy: policy, behavior: behavior, err: err}
}

func (e envConstraint) normalize() (string, error) {
	if e.err != nil {
		return "env", e.err
	}
	if e.behavior.isUnconstrained() {
		e.policy.Policy = PolicyAny
	}
	if e.policy.Values != nil && len(e.policy.Values) == 0 {
		e.policy.Policy = PolicyDeny
		e.policy.Values = nil
	}
	return "env", nil
}
func (e envConstraint) admits(r RunningContainer) bool {
	return e.err == nil && e.behavior.admits(r.Env)
}
func (e envConstraint) hostIndependent() bool {
	return e.err == nil && e.behavior.hostIndependent()
}
func (e envConstraint) isUnconstrained() bool {
	return e.err == nil && e.behavior.isUnconstrained()
}
