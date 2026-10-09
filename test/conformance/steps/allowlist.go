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
// in Given steps, written to CDS by the operator's signed path when a pod is
// deployed or the enforcer is said to have synced, and undone afterwards.
func registerAllowlist(sc *godog.ScenarioContext) {
	sc.Step(`^the allowlist has a workload entry named "([^"]*)"$`, entryNamed)
	sc.Step(`^"([^"]*)" declares image "([^"]*)"$`, entryDeclares)
	sc.Step(`^"([^"]*)" declares image "([^"]*)" as a main container$`, entryDeclares)
	sc.Step(`^"([^"]*)" declares image "([^"]*)" as an init container$`, entryDeclaresInit)
	sc.Step(`^"([^"]*)" pins the command line of "([^"]*)" to "([^"]*)"$`, entryPinsCommand)
	sc.Step(`^"([^"]*)" admits any command line for "([^"]*)"$`, entryAdmitsAnyCommand)
	sc.Step(`^no workload entry declares both images$`, noEntryDeclaresBoth)
	sc.Step(`^the digest of "([^"]*)" is on the allowlist$`, digestOnAllowlist)
	sc.Step(`^the digest of "([^"]*)" is removed from the allowlist at the CDS$`, digestRemovedAtCDS)
	sc.Step(`^the boot floor of node "([^"]*)" does not contain the digest of "([^"]*)"$`, baseLacks)
	sc.Step(`^the policy enforcer on node "([^"]*)" refreshes its allowlist$`, enforcerRefreshes)
}

// entry is a workload entry the scenario describes, in the served document's
// shape, written whole once the scenario acts.
type entry struct {
	Label          string           `json:"label,omitempty"`
	InitContainers []entryContainer `json:"initContainers"`
	Containers     []entryContainer `json:"containers"`
	written        bool
}

type entryContainer struct {
	Digest  string     `json:"digest"`
	Image   string     `json:"image"`
	Command argvPolicy `json:"command"`
	Args    argvPolicy `json:"args"`
	Mounts  policy     `json:"mounts"`
	Env     policy     `json:"env"`
}

type argvPolicy struct {
	Policy string   `json:"policy"`
	Argv   []string `json:"argv,omitempty"`
}

type policy struct {
	Policy string `json:"policy"`
}

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
func (w *world) find(e *entry, image string) (*entryContainer, error) {
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return nil, err
	}
	for _, list := range [][]entryContainer{e.InitContainers, e.Containers} {
		for i := range list {
			if list[i].Image == ref {
				return &list[i], nil
			}
		}
	}
	return nil, fmt.Errorf("the entry declares no container running %q", image)
}

func entryNamed(ctx context.Context, name string) error {
	w := getWorld(ctx)
	if _, ok := w.entries[name]; ok {
		return fmt.Errorf("the scenario already describes an entry %q", name)
	}
	w.entries[name] = &entry{Label: name, InitContainers: []entryContainer{}, Containers: []entryContainer{}}
	return nil
}

// declared builds a declared container for image whose policies, unless a
// later step opens them, admit nothing: the document's defaults.
func (w *world) declared(image string) (entryContainer, error) {
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return entryContainer{}, err
	}
	digest, err := w.digestOf(image)
	if err != nil {
		return entryContainer{}, err
	}
	w.named(image)
	return entryContainer{
		Digest: digest, Image: ref,
		Command: argvPolicy{Policy: "deny"}, Args: argvPolicy{Policy: "deny"},
		Mounts: policy{Policy: "any"}, Env: policy{Policy: "any"},
	}, nil
}

func entryDeclares(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	c, err := w.declared(image)
	if err != nil {
		return err
	}
	e.Containers = append(e.Containers, c)
	return nil
}

func entryDeclaresInit(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	c, err := w.declared(image)
	if err != nil {
		return err
	}
	e.InitContainers = append(e.InitContainers, c)
	return nil
}

// entryPinsCommand pins the whole command line: the container's command is
// the words given and its args are empty, as the pod manifests here set them.
func entryPinsCommand(ctx context.Context, name, image, line string) error {
	w := getWorld(ctx)
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	c, err := w.find(e, image)
	if err != nil {
		return err
	}
	c.Command = argvPolicy{Policy: "exact", Argv: strings.Fields(line)}
	c.Args = argvPolicy{Policy: "deny"}
	return nil
}

func entryAdmitsAnyCommand(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	c, err := w.find(e, image)
	if err != nil {
		return err
	}
	c.Command, c.Args = argvPolicy{Policy: "any"}, argvPolicy{Policy: "any"}
	return nil
}

// noEntryDeclaresBoth checks that no entry, served or described, names every
// image the scenario has named so far.
func noEntryDeclaresBoth(ctx context.Context) error {
	w := getWorld(ctx)
	if len(w.images) < 2 {
		return errors.New("the scenario names fewer than two images")
	}
	digests := make([]string, 0, len(w.images))
	for _, image := range w.images {
		d, err := w.digestOf(image)
		if err != nil {
			return err
		}
		digests = append(digests, d)
	}
	doc, err := w.servedAllowlist()
	if err != nil {
		return err
	}
	for name, e := range doc.Workloads {
		if declaresAll(e.declaresDigest, digests) {
			return fmt.Errorf("harness precondition: served entry %q declares all of %s", name, strings.Join(w.images, ", "))
		}
	}
	for name, e := range w.entries {
		declares := func(d string) bool {
			for _, list := range [][]entryContainer{e.InitContainers, e.Containers} {
				for _, c := range list {
					if c.Digest == d {
						return true
					}
				}
			}
			return false
		}
		if declaresAll(declares, digests) {
			return fmt.Errorf("the described entry %q declares all of %s", name, strings.Join(w.images, ", "))
		}
	}
	return nil
}

func declaresAll(declares func(string) bool, digests []string) bool {
	for _, d := range digests {
		if !declares(d) {
			return false
		}
	}
	return true
}

// digestOnAllowlist makes the served allowlist admit image under any command
// line, writing an entry when nothing admits it yet.
func digestOnAllowlist(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	doc, err := w.servedAllowlist()
	if err != nil {
		return err
	}
	if doc.floorAdmits(digest) {
		return nil
	}
	name := image
	if _, exists := w.entries[name]; exists {
		return fmt.Errorf("the scenario already describes an entry %q", name)
	}
	if err := entryNamed(ctx, name); err != nil {
		return err
	}
	if err := entryDeclares(ctx, name, image); err != nil {
		return err
	}
	if err := entryAdmitsAnyCommand(ctx, name, image); err != nil {
		return err
	}
	return w.writeEntries()
}

// writeEntries writes every described entry not yet at CDS.
func (w *world) writeEntries() error {
	for name, e := range w.entries {
		if e.written {
			continue
		}
		body, err := json.Marshal(e)
		if err != nil {
			return err
		}
		f, err := os.CreateTemp("", "entry-*.json")
		if err != nil {
			return err
		}
		_, werr := f.Write(body)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return errors.Join(werr, cerr)
		}
		written := w.writtenName(name)
		_, err = w.be.call("allowlist_put", written, f.Name())
		_ = os.Remove(f.Name())
		if err != nil {
			return err
		}
		e.written = true
		w.written = append(w.written, written)
	}
	return nil
}

// digestRemovedAtCDS deletes every served entry that declares image's digest,
// keeping each for restoreAllowlist.
func digestRemovedAtCDS(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	doc, err := w.servedAllowlist()
	if err != nil {
		return err
	}
	raw, err := w.servedEntries()
	if err != nil {
		return err
	}
	deleted := 0
	for name, e := range doc.Workloads {
		if !e.declaresDigest(digest) {
			continue
		}
		if _, err := w.be.call("allowlist_delete", name); err != nil {
			return err
		}
		if !w.wrote(name) {
			w.removed[name] = raw[name]
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
		if _, err := w.be.call("allowlist_delete", name); err != nil {
			errs = append(errs, err)
		}
	}
	for name, body := range w.removed {
		f, err := os.CreateTemp("", "entry-*.json")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := f.Write(body); err != nil {
			errs = append(errs, err)
		}
		_ = f.Close()
		if _, err := w.be.call("allowlist_put", name, f.Name()); err != nil {
			errs = append(errs, err)
		}
		_ = os.Remove(f.Name())
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

// awaitApplied waits two pull intervals: a pull that started just before the
// write has then been followed by one that saw it. The enforcer exposes
// nothing about the version it holds, so this is a wait, not an observation.
func (w *world) awaitApplied() error {
	interval, err := w.pullInterval()
	if err != nil {
		return err
	}
	time.Sleep(2 * interval)
	return nil
}

func (w *world) pullInterval() (time.Duration, error) {
	s, err := w.be.call("pull_interval")
	if err != nil {
		return 0, err
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("pull interval %q: %w", s, err)
	}
	return d, nil
}
