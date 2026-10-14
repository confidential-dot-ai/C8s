package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	return name + "-" + strings.TrimPrefix(w.namespace, "conf-")
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
		Mounts: mountsPolicy{Policy: "any"}, Env: policy{Policy: "any"},
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
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	written := w.writtenName(name)
	if w.written[written] {
		return nil
	}
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

// awaitApplied waits until two pull intervals have passed since the last
// write or delete: a pull that started just before it has then been followed
// by one that saw it. The plugin exposes nothing about the version it holds,
// so this is a wait, not an observation; the served version afterwards is
// what it applied, unless the pull is blocked.
func (w *world) awaitApplied() error {
	s, err := w.be.call("pull_interval")
	if err != nil {
		return err
	}
	interval, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("pull interval %q: %w", s, err)
	}
	time.Sleep(time.Until(lastMutation.Add(2 * interval)))
	if w.cdsBlocked {
		return nil
	}
	version, err := w.be.call("served_version")
	if err != nil && !errors.Is(err, godog.ErrSkip) {
		return err
	}
	w.appliedVersion = version
	return nil
}
