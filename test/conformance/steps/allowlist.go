package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about the allowlist as a scenario writes it: entries described
// in Given steps, written to CDS by the operator's signed path when the
// enforcer is said to have synced, and undone afterwards.
func registerAllowlist(sc *godog.ScenarioContext) {
	sc.Step(`^the allowlist has a workload entry named "([^"]*)"$`, entryNamed)
	sc.Step(`^"([^"]*)" declares image "([^"]*)"$`, entryDeclares)
	sc.Step(`^"([^"]*)" declares image "([^"]*)" as an init container$`, entryDeclaresInit)
	sc.Step(`^"([^"]*)" pins the command line of "([^"]*)" to "([^"]*)"$`, entryPinsCommand)
	sc.Step(`^"([^"]*)" admits any command line for "([^"]*)"$`, entryAdmitsAnyCommand)
	sc.Step(`^no workload entry declares both "([^"]*)" and "([^"]*)"$`, noEntryDeclaresBoth)
	sc.Step(`^the digest of "([^"]*)" is on the allowlist$`, digestOnAllowlist)
	sc.Step(`^the digest of "([^"]*)" is removed from the allowlist at the CDS$`, digestRemovedAtCDS)
	sc.Step(`^the boot floor of node "([^"]*)" does not contain the digest of "([^"]*)"$`, baseLacks)
	sc.Step(`^the policy enforcer on node "([^"]*)" refreshes its allowlist$`, enforcerRefreshes)
}

// lastMutation is when this process last changed the allowlist at CDS. It
// outlives the scenario because one scenario's restore is what the next
// scenario's sync has to wait out.
var lastMutation time.Time

// writtenName is the entry's name at CDS: the scenario's name, suffixed so
// that two scenarios naming "web" never meet.
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

// declare adds image to the entry, init or main, with policies that admit
// nothing until a later step opens them: the document's defaults.
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
		Command: argvPolicy{Policy: "deny"}, Args: argvPolicy{Policy: "deny"},
		Mounts: policy{Policy: "any"}, Env: policy{Policy: "any"},
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

// entryPinsCommand pins the whole command line: the container's command is
// the words given and its args are empty, as the pod manifests here set them.
func entryPinsCommand(ctx context.Context, name, image, line string) error {
	c, err := getWorld(ctx).find(name, image)
	if err != nil {
		return err
	}
	c.Command = argvPolicy{Policy: "exact", Argv: strings.Fields(line)}
	c.Args = argvPolicy{Policy: "deny"}
	return nil
}

func entryAdmitsAnyCommand(ctx context.Context, name, image string) error {
	c, err := getWorld(ctx).find(name, image)
	if err != nil {
		return err
	}
	c.Command, c.Args = argvPolicy{Policy: "any"}, argvPolicy{Policy: "any"}
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

// digestOnAllowlist makes the served allowlist admit image under any command
// line, writing an entry when nothing admits it yet.
func digestOnAllowlist(ctx context.Context, image string) error {
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
	if err := entryAdmitsAnyCommand(ctx, image, image); err != nil {
		return err
	}
	return w.writeEntries()
}

// writeEntries writes every described entry not yet at CDS.
func (w *world) writeEntries() error {
	for name, e := range w.entries {
		written := w.writtenName(name)
		if w.wrote(written) {
			continue
		}
		body, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := w.putEntry(written, body); err != nil {
			return err
		}
		w.written = append(w.written, written)
	}
	return nil
}

// putEntry writes body under name through the backend's signed path.
func (w *world) putEntry(name string, body []byte) error {
	f, err := os.CreateTemp("", "entry-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, werr := f.Write(body)
	if err := errors.Join(werr, f.Close()); err != nil {
		return err
	}
	_, err = w.be.call("allowlist_put", name, f.Name())
	lastMutation = time.Now()
	return err
}

func (w *world) deleteEntry(name string) error {
	_, err := w.be.call("allowlist_delete", name)
	lastMutation = time.Now()
	return err
}

// digestRemovedAtCDS deletes every served entry that declares image's digest,
// keeping each for restoreAllowlist.
func digestRemovedAtCDS(ctx context.Context, image string) error {
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
		if !w.wrote(name) {
			w.removed[name] = s.raw[name]
		}
		deleted++
	}
	if deleted == 0 {
		return fmt.Errorf("harness precondition: no served entry declares %s (%s)", image, digest)
	}
	return nil
}

func (w *world) wrote(name string) bool {
	for _, n := range w.written {
		if n == name {
			return true
		}
	}
	return false
}

// restoreAllowlist undoes the scenario's writes: its entries go, the entries
// it removed come back.
func (w *world) restoreAllowlist() error {
	var errs []error
	for _, name := range w.written {
		errs = append(errs, w.deleteEntry(name))
	}
	for name, body := range w.removed {
		errs = append(errs, w.putEntry(name, body))
	}
	return errors.Join(errs...)
}

func baseLacks(ctx context.Context, node, image string) error {
	w := getWorld(ctx)
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	answer, err := w.be.call("base_declares", k8sNode, digest)
	if err != nil {
		return err
	}
	if answer != "no" {
		return fmt.Errorf("harness precondition: the base allowlist of node %q declares %s (%s)", node, image, digest)
	}
	return nil
}

// enforcerRefreshes waits until the enforcer on node holds what CDS serves now.
func enforcerRefreshes(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if _, err := w.be.call("node_name", node); err != nil {
		return err
	}
	return w.awaitApplied()
}

// sync writes the described entries and waits for the enforcer to hold them.
func (w *world) sync() error {
	if err := w.writeEntries(); err != nil {
		return err
	}
	return w.awaitApplied()
}

// awaitApplied waits until two pull intervals have passed since the last
// write or delete: a pull that started just before it has then been followed
// by one that saw it. The enforcer exposes nothing about the version it
// holds, so this is a wait, not an observation.
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
	return nil
}
