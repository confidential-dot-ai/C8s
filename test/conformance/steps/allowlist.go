package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about the served allowlist as a scenario writes it: entries
// described in Given steps, written to CDS by the operator's signed path when
// the plugin is said to have applied the served allowlist, and undone
// afterwards.
func registerAllowlist(sc *godog.ScenarioContext) {
	sc.Step(`^the allowlist has a workload entry named "([^"]*)"$`, entryNamed)
	sc.Step(`^"([^"]*)" declares image "([^"]*)"$`, entryDeclares)
	sc.Step(`^"([^"]*)" declares image "([^"]*)" as an init container$`, entryDeclaresInit)
	sc.Step(`^"([^"]*)" pins the argv of "([^"]*)" to "([^"]*)"$`, entryPinsArgv)
	sc.Step(`^"([^"]*)" admits any argv for "([^"]*)"$`, entryAdmitsAnyArgv)
	sc.Step(`^"([^"]*)" pins the command of "([^"]*)" to "([^"]*)"$`, entryPinsCommand)
	sc.Step(`^"([^"]*)" pins the args of "([^"]*)" to "([^"]*)"$`, entryPinsArgs)
	sc.Step(`^"([^"]*)" admits any command for "([^"]*)"$`, entryAdmitsAnyCommand)
	sc.Step(`^"([^"]*)" admits any args for "([^"]*)"$`, entryAdmitsAnyArgs)
	sc.Step(`^"([^"]*)" states no command or args policy for "([^"]*)"$`, entryStatesNoArgvPolicy)
	sc.Step(`^"([^"]*)" states no args policy for "([^"]*)"$`, entryStatesNoArgsPolicy)
	sc.Step(`^"([^"]*)" pins the argv of "([^"]*)" to the entrypoint of that image$`, entryPinsEntrypoint)
	sc.Step(`^"([^"]*)" pins the mounts of "([^"]*)" to one rule of kind "([^"]*)" with destination "([^"]*)"$`, entryPinsMounts)
	sc.Step(`^"([^"]*)" also pins a mount of "([^"]*)" of kind "([^"]*)" with destination "([^"]*)"$`, entryPinsAnotherMount)
	sc.Step(`^"([^"]*)" matches "([^"]*)" of "([^"]*)" exact "([^"]*)"$`, entryMatchesExact)
	sc.Step(`^"([^"]*)" matches "([^"]*)" of "([^"]*)" present$`, entryMatchesPresent)
	sc.Step(`^"([^"]*)" matches the variables the node and the image add to every container of "([^"]*)" present$`, entryMatchesRuntimeVariables)
	sc.Step(`^no workload entry declares both "([^"]*)" and "([^"]*)"$`, noEntryDeclaresBoth)
	sc.Step(`^a workload entry admits image "([^"]*)" under any argv$`, someEntryAdmitsAnyArgv)
	sc.Step(`^the entries declaring image "([^"]*)" are removed from the served allowlist$`, entriesRemoved)
	sc.Step(`^the base allowlist of node "([^"]*)" does not declare image "([^"]*)"$`, baseDoesNotDeclare)
	sc.Step(`^the base allowlist of node "([^"]*)" declares image "([^"]*)"$`, baseDeclares)
	sc.Step(`^a workload entry admitting image "([^"]*)" under any argv is added to the served allowlist$`, entryAdded)
}

// lastMutation is when this process last changed the served allowlist. It
// outlives the scenario because one scenario's restore is what the next
// scenario's applied sentence has to wait out.
var lastMutation time.Time

// writtenName is the entry's allowlist workload name at CDS: the scenario's
// name, suffixed so that two scenarios naming "web" never meet.
func (w *world) writtenName(name string) string {
	return name + "-" + w.suffix()
}

func (w *world) entry(name string) (*entry, error) {
	e, ok := w.entries[name]
	if !ok {
		return nil, fmt.Errorf("no workload entry %q has been described in this scenario", name)
	}
	return e, nil
}

// find returns the entry's declared container for image, init or main.
func (w *world) find(name, image string) (*entryContainer, error) {
	e, err := w.entry(name)
	if err != nil {
		return nil, err
	}
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return nil, err
	}
	for _, c := range e.containers() {
		if c.Image == ref {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%q declares no container running %q", name, image)
}

func entryNamed(ctx context.Context, name string) error {
	w := getWorld(ctx)
	if _, ok := w.entries[name]; ok {
		return fmt.Errorf("the scenario already describes an entry %q", name)
	}
	w.entries[name] = &entry{Label: name, InitContainers: []entryContainer{}, Containers: []entryContainer{}}
	return nil
}

// declare adds a declared container for image to the entry, init or main,
// with the document's default policies: argv denied, mounts and environment
// unconstrained, until a later step opens the argv.
func (w *world) declare(name, image string, init bool) error {
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return err
	}
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	c := entryContainer{
		Digest: digest, Image: ref,
		Command: denyArgv(), Args: denyArgv(),
		Mounts: mountsPolicy{Policy: "any"}, Env: envPolicy{Policy: "any"},
	}
	if init {
		e.InitContainers = append(e.InitContainers, c)
	} else {
		e.Containers = append(e.Containers, c)
	}
	return nil
}

func entryDeclares(ctx context.Context, name, image string) error {
	return getWorld(ctx).declare(name, image, false)
}

func entryDeclaresInit(ctx context.Context, name, image string) error {
	return getWorld(ctx).declare(name, image, true)
}

// entryPinsArgv pins the whole argv: command exact, the words given, and
// args denied, as the pod manifests here leave args empty.
// setPolicy applies set to the entry's declared container for image. Each
// policy sentence sets what it names; what it leaves alone keeps the default
// declare gave it, or the nil an earlier sentence set.
func (w *world) setPolicy(name, image string, set func(*entryContainer)) error {
	c, err := w.find(name, image)
	if err != nil {
		return err
	}
	set(c)
	return nil
}

func entryPinsArgv(ctx context.Context, name, image, line string) error {
	return getWorld(ctx).setPolicy(name, image, func(c *entryContainer) {
		c.Command, c.Args = exactArgv(strings.Fields(line)), denyArgv()
	})
}

func entryAdmitsAnyArgv(ctx context.Context, name, image string) error {
	return getWorld(ctx).setPolicy(name, image, func(c *entryContainer) { c.Command, c.Args = anyArgv(), anyArgv() })
}

func entryPinsCommand(ctx context.Context, name, image, line string) error {
	return getWorld(ctx).setPolicy(name, image, func(c *entryContainer) { c.Command = exactArgv(strings.Fields(line)) })
}

func entryPinsArgs(ctx context.Context, name, image, line string) error {
	return getWorld(ctx).setPolicy(name, image, func(c *entryContainer) { c.Args = exactArgv(strings.Fields(line)) })
}

func entryAdmitsAnyCommand(ctx context.Context, name, image string) error {
	return getWorld(ctx).setPolicy(name, image, func(c *entryContainer) { c.Command = anyArgv() })
}

func entryAdmitsAnyArgs(ctx context.Context, name, image string) error {
	return getWorld(ctx).setPolicy(name, image, func(c *entryContainer) { c.Args = anyArgv() })
}

func entryStatesNoArgvPolicy(ctx context.Context, name, image string) error {
	return getWorld(ctx).setPolicy(name, image, func(c *entryContainer) { c.Command, c.Args = nil, nil })
}

func entryStatesNoArgsPolicy(ctx context.Context, name, image string) error {
	return getWorld(ctx).setPolicy(name, image, func(c *entryContainer) { c.Args = nil })
}

// entryPinsEntrypoint pins the whole argv to what the image starts with when
// a pod spec overrides nothing, as the backend reads it from the image.
func entryPinsEntrypoint(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	c, err := w.find(name, image)
	if err != nil {
		return err
	}
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return err
	}
	out, err := w.be.call("image_entrypoint", ref)
	if err != nil {
		return err
	}
	argv := strings.Split(out, "\n")
	if out == "" {
		return fmt.Errorf("image %s (%s) has no entrypoint and no cmd", image, ref)
	}
	c.Command, c.Args = exactArgv(argv), denyArgv()
	return nil
}

func entryPinsMounts(ctx context.Context, name, image, kind, destination string) error {
	c, err := getWorld(ctx).find(name, image)
	if err != nil {
		return err
	}
	c.Mounts = mountsPolicy{Policy: "exact", Rules: []mountRule{{Destination: destination, Kind: kind}}}
	return nil
}

// matchVariable adds one variable to the container's match policy, turning
// the policy into match on first use.
func matchVariable(ctx context.Context, name, image, variable string, matcher envMatcher) error {
	c, err := getWorld(ctx).find(name, image)
	if err != nil {
		return err
	}
	if c.Env.Policy != "match" {
		c.Env = envPolicy{Policy: "match", Variables: map[string]envMatcher{}}
	}
	c.Env.Variables[variable] = matcher
	return nil
}

func entryMatchesExact(ctx context.Context, name, variable, image, value string) error {
	return matchVariable(ctx, name, image, variable, envMatcher{Exact: &value})
}

func entryMatchesPresent(ctx context.Context, name, variable, image string) error {
	return matchVariable(ctx, name, image, variable, envMatcher{Present: true})
}

// runtimeVariables is what every container launches with beside the pod
// spec's and the image's: the runtime's HOSTNAME and, with no Service in the
// pod's namespace (each scenario's is fresh), the kubelet's variables for the
// API server's Service. The chart's component entries list the same set
// (c8s.runtimeEnv in the allowlist template).
var runtimeVariables = []string{
	"HOSTNAME",
	"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT", "KUBERNETES_SERVICE_PORT_HTTPS",
	"KUBERNETES_PORT", "KUBERNETES_PORT_443_TCP", "KUBERNETES_PORT_443_TCP_ADDR",
	"KUBERNETES_PORT_443_TCP_PORT", "KUBERNETES_PORT_443_TCP_PROTO",
}

// entryMatchesRuntimeVariables marks present the variables the node adds and
// the ones the image's configuration sets, so a scenario's own variables are
// the only ones left for the match to decide on.
func entryMatchesRuntimeVariables(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return err
	}
	out, err := w.be.call("image_env", ref)
	if err != nil {
		return err
	}
	variables := append([]string(nil), runtimeVariables...)
	for _, entry := range strings.Split(strings.TrimSpace(out), "\n") {
		if entry == "" {
			continue
		}
		variable, _, ok := strings.Cut(entry, "=")
		if !ok {
			return fmt.Errorf("image %s (%s): environment entry %q is not NAME=VALUE", image, ref, entry)
		}
		variables = append(variables, variable)
	}
	for _, variable := range variables {
		if err := matchVariable(ctx, name, image, variable, envMatcher{Present: true}); err != nil {
			return err
		}
	}
	return nil
}

// entryPinsAnotherMount adds a rule to mounts already pinned.
func entryPinsAnotherMount(ctx context.Context, name, image, kind, destination string) error {
	c, err := getWorld(ctx).find(name, image)
	if err != nil {
		return err
	}
	if c.Mounts.Policy != "exact" {
		return fmt.Errorf("harness precondition: %q does not pin the mounts of %s yet", name, image)
	}
	c.Mounts.Rules = append(c.Mounts.Rules, mountRule{Destination: destination, Kind: kind})
	return nil
}

// noEntryDeclaresBoth checks that no entry, served or described, names both
// images.
func noEntryDeclaresBoth(ctx context.Context, first, second string) error {
	w := getWorld(ctx)
	a, err := w.digestOf(first)
	if err != nil {
		return err
	}
	b, err := w.digestOf(second)
	if err != nil {
		return err
	}
	s, err := w.served()
	if err != nil {
		return err
	}
	for name, e := range s.entries {
		if e.declares(a) && e.declares(b) {
			return fmt.Errorf("harness precondition: served entry %q declares both %s and %s", name, first, second)
		}
	}
	for name, e := range w.entries {
		if e.declares(a) && e.declares(b) {
			return fmt.Errorf("the described entry %q declares both %s and %s", name, first, second)
		}
	}
	return nil
}

// someEntryAdmitsAnyArgv makes the served allowlist admit image under any
// argv, writing an entry when no served entry does yet.
func someEntryAdmitsAnyArgv(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	s, err := w.served()
	if err != nil {
		return err
	}
	if s.admitsAnyArgv(digest) {
		return nil
	}
	if err := entryNamed(ctx, image); err != nil {
		return err
	}
	if err := w.declare(image, image, false); err != nil {
		return err
	}
	if err := entryAdmitsAnyArgv(ctx, image, image); err != nil {
		return err
	}
	return w.writeEntries()
}

// writeEntries writes every described entry not yet at CDS.
func (w *world) writeEntries() error {
	for name := range w.entries {
		if err := w.writeEntry(name); err != nil {
			return err
		}
	}
	return nil
}

// writeEntry writes the described entry, once, through the signed path.
func (w *world) writeEntry(name string) error {
	if w.written[w.writtenName(name)] {
		return nil
	}
	return w.rewriteEntry(name)
}

// rewriteEntry writes the described entry as it is now, whether or not it
// was written before; the served allowlist is read per request, so the
// plugin's pull is not waited for.
func (w *world) rewriteEntry(name string) error {
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	written := w.writtenName(name)
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := w.putEntry(written, body); err != nil {
		return err
	}
	w.written[written] = true
	return nil
}

// putEntry writes body under name through the backend's signed path.
func (w *world) putEntry(name string, body []byte) error {
	err := withBodyFile(body, func(path string) error {
		_, err := w.be.call("allowlist_put", name, path)
		return err
	})
	lastMutation = time.Now()
	return err
}

func (w *world) deleteEntry(name string) error {
	_, err := w.be.call("allowlist_delete", name)
	lastMutation = time.Now()
	return err
}

// entriesRemoved deletes every served entry that declares image's digest,
// keeping each for restoreAllowlist.
func entriesRemoved(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	s, err := w.served()
	if err != nil {
		return err
	}
	deleted := 0
	for name, e := range s.entries {
		if !e.declares(digest) {
			continue
		}
		if err := w.deleteEntry(name); err != nil {
			return err
		}
		if !w.written[name] {
			w.removed[name] = s.raw[name]
		}
		deleted++
	}
	if deleted == 0 {
		return fmt.Errorf("harness precondition: no served entry declares %s (%s)", image, digest)
	}
	return nil
}

// restoreAllowlist undoes the scenario's writes: its entries go, the entries
// it removed come back.
func (w *world) restoreAllowlist() error {
	var errs []error
	for name := range w.written {
		errs = append(errs, w.deleteEntry(name))
	}
	for name, body := range w.removed {
		errs = append(errs, w.putEntry(name, body))
	}
	return errors.Join(errs...)
}

// entryAdded writes an entry admitting image under any argv now, without
// waiting for the plugin: the scenario says what the plugin can reach.
func entryAdded(ctx context.Context, image string) error {
	w := getWorld(ctx)
	if err := entryNamed(ctx, image); err != nil {
		return err
	}
	if err := w.declare(image, image, false); err != nil {
		return err
	}
	if err := entryAdmitsAnyArgv(ctx, image, image); err != nil {
		return err
	}
	return w.writeEntries()
}

// baseDeclaresAnswer asks the backend whether the node's base allowlist,
// fixed for the plugin's lifetime (L1), names image's digest.
func baseDeclaresAnswer(ctx context.Context, node, image string) (answer, digest string, err error) {
	w := getWorld(ctx)
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return "", "", err
	}
	digest, err = w.digestOf(image)
	if err != nil {
		return "", "", err
	}
	answer, err = w.be.call("base_declares", k8sNode, digest)
	return answer, digest, err
}

// baseDoesNotDeclare checks a precondition; a base allowlist that names the
// image is a broken harness, not a result.
func baseDoesNotDeclare(ctx context.Context, node, image string) error {
	answer, digest, err := baseDeclaresAnswer(ctx, node, image)
	if err != nil {
		return err
	}
	if answer != "no" {
		return fmt.Errorf("harness precondition: the base allowlist of node %q declares %s (%s)", node, image, digest)
	}
	return nil
}

// baseDeclares is a precondition this environment may not meet: which images
// a base allowlist names is the installation's choice, so a miss is a skip.
func baseDeclares(ctx context.Context, node, image string) error {
	answer, _, err := baseDeclaresAnswer(ctx, node, image)
	if err != nil {
		return err
	}
	if answer != "yes" {
		return godog.ErrSkip
	}
	return nil
}

// sync writes the described entries and waits for the plugin to hold them.
func (w *world) sync() error {
	if err := w.writeEntries(); err != nil {
		return err
	}
	return w.awaitApplied()
}

// awaitApplied waits for the plugin to hold what the CDS serves now, and
// records the version it holds. It polls the version the plugin reports until
// it reaches the served one, failing when the pull loop has not followed
// within three pull intervals of the last write or delete. Where nothing can
// be observed, the wait is the clock: two pull intervals, so a pull that
// started just before the write has been followed by one that saw it. That is
// the case where the pull is blocked, where the backend cannot ask the CDS or
// the plugin, and where the served version is below the applied one: the
// plugin ignores that pull by design, so nothing says it happened.
func (w *world) awaitApplied() error {
	s, err := w.be.call("pull_interval")
	if err != nil {
		return err
	}
	interval, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("pull interval %q: %w", s, err)
	}
	observed, err := w.observeApplied(interval)
	if err != nil || observed {
		return err
	}
	time.Sleep(time.Until(lastMutation.Add(2 * interval)))
	return nil
}

// observeApplied polls the plugin's applied version until it is at or past
// the served one, records it, and says whether it saw the served version
// itself; false where either version cannot be asked for or the plugin is
// ahead of the CDS.
func (w *world) observeApplied(interval time.Duration) (bool, error) {
	if w.cdsBlocked {
		return false, nil
	}
	served, err := w.servedVersion()
	if errors.Is(err, godog.ErrSkip) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// At least one interval from now: a scenario may ask before it has
	// written anything, and a plugin that is restarting answers nothing for
	// a moment, which is "not yet", not a broken harness.
	deadline := lastMutation.Add(3 * interval)
	if floor := time.Now().Add(interval); deadline.Before(floor) {
		deadline = floor
	}
	var answer string
	var applied int
	caughtUp, err := pollEvery(interval/5, time.Until(deadline), func() (bool, error) {
		var err error
		if answer, err = w.be.call("applied_version"); err != nil {
			return false, err
		}
		applied, err = strconv.Atoi(answer)
		return err == nil && applied >= served, nil
	})
	if errors.Is(err, godog.ErrSkip) {
		w.appliedVersion = strconv.Itoa(served)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !caughtUp {
		return false, fmt.Errorf("the admission plugin still reports allowlist version %q while the CDS serves %d, %s after the write with a pull every %s", answer, served, time.Since(lastMutation).Round(time.Millisecond), interval)
	}
	w.appliedVersion = answer
	return applied == served, nil
}

// servedVersion is the version of the allowlist the CDS serves now.
func (w *world) servedVersion() (int, error) {
	s, err := w.be.call("served_version")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("served version %q: %w", s, err)
	}
	return n, nil
}
