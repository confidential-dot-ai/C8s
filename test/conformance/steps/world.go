package steps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
)

// world is one scenario's state. Names in the feature text (images, nodes,
// pods, entries) are logical; the backend maps them to this environment.
type world struct {
	be        backend
	namespace string
	pods      map[string]*pod
	lastPod   *pod
	// entries the scenario describes, written to CDS when it says the plugin
	// has applied the served allowlist; written and removed are undone after
	// the scenario.
	entries map[string]*entry
	written map[string]bool
	removed map[string]json.RawMessage
	// appliedVersion is the served version the plugin had applied when the
	// scenario last waited for it.
	appliedVersion string
	// running maps an image to the pod a scenario started a container of.
	running map[string]*pod
	// What the scenario did to the node and the CDS, undone after it: the
	// Kubernetes nodes whose plugin it addressed, those it left stopped,
	// whether it blocked the pull and whether it restarted the CDS.
	nodes        map[string]bool
	pluginDown   map[string]bool
	cdsBlocked   bool
	cdsRestarted bool
}

type pod struct {
	name       string
	containers []*container
	deployed   bool
}

type container struct {
	ref     string // reference the manifest uses
	command []string
}

type worldKey struct{}

func getWorld(ctx context.Context) *world { return ctx.Value(worldKey{}).(*world) }

func initializeScenario(be backend) func(*godog.ScenarioContext) {
	return func(sc *godog.ScenarioContext) {
		sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
			suffix := make([]byte, 4)
			if _, err := rand.Read(suffix); err != nil {
				return ctx, err
			}
			w := &world{
				be:         be,
				namespace:  "conf-" + hex.EncodeToString(suffix),
				pods:       map[string]*pod{},
				entries:    map[string]*entry{},
				written:    map[string]bool{},
				removed:    map[string]json.RawMessage{},
				running:    map[string]*pod{},
				nodes:      map[string]bool{},
				pluginDown: map[string]bool{},
			}
			if _, err := kubectl(nil, "create", "namespace", w.namespace); err != nil {
				return ctx, err
			}
			return context.WithValue(ctx, worldKey{}, w), nil
		})
		sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
			// Before may have failed before storing the world.
			if w, ok := ctx.Value(worldKey{}).(*world); ok {
				_, _ = kubectl(nil, "delete", "namespace", w.namespace, "--ignore-not-found", "--wait=false")
				// The node first: the allowlist is restored through the CDS,
				// which the scenario may have blocked or restarted.
				return ctx, errors.Join(w.restoreNode(), w.restoreAllowlist())
			}
			return ctx, nil
		})
		registerAdmission(sc)
		registerAllowlist(sc)
		registerNode(sc)
	}
}

// describe records a pod the scenario will deploy, one container per
// reference; it becomes the last pod. A scenario that says nothing about the
// argv gets one that keeps the container alive.
func (w *world) describe(name string, refs ...string) {
	p := &pod{name: name}
	for _, ref := range refs {
		p.containers = append(p.containers, &container{ref: ref, command: []string{"sleep", "3600"}})
	}
	w.pods[name], w.lastPod = p, p
}

func (p *pod) last() *container { return p.containers[len(p.containers)-1] }

func (w *world) pod(name string) (*pod, error) {
	p, ok := w.pods[name]
	if !ok {
		return nil, fmt.Errorf("no pod %q has been described in this scenario", name)
	}
	return p, nil
}

// refs maps logical images to the references the manifests use.
func (w *world) refs(images ...string) ([]string, error) {
	refs := make([]string, 0, len(images))
	for _, image := range images {
		ref, err := w.be.call("image_ref", image)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func (w *world) digestOf(image string) (string, error) {
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return "", err
	}
	digest, err := w.be.call("image_digest", ref)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("no digest for image %q (%s)", image, ref)
	}
	return digest, nil
}

// entry is a workload entry in the served document's shape: what the steps
// read from CDS and what they write to it. It is deliberately not
// pkg/allowlist: the steps observe the cluster from outside, through the
// document CDS serves, so a change to the package cannot change what the
// suite accepts.
type entry struct {
	Label          string           `json:"label,omitempty"`
	InitContainers []entryContainer `json:"initContainers"`
	Containers     []entryContainer `json:"containers"`
}

type entryContainer struct {
	Digest  string     `json:"digest"`
	Image   string     `json:"image,omitempty"`
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

// containers lists the entry's declared containers, init then main.
func (e *entry) containers() []*entryContainer {
	out := make([]*entryContainer, 0, len(e.InitContainers)+len(e.Containers))
	for i := range e.InitContainers {
		out = append(out, &e.InitContainers[i])
	}
	for i := range e.Containers {
		out = append(out, &e.Containers[i])
	}
	return out
}

// declares reports whether the entry names digest, init or main.
func (e *entry) declares(digest string) bool {
	for _, c := range e.containers() {
		if c.Digest == digest {
			return true
		}
	}
	return false
}

// admitsAnyArgv reports whether the entry admits digest under any argv.
func (e *entry) admitsAnyArgv(digest string) bool {
	for _, c := range e.containers() {
		if c.Digest == digest && c.Command.Policy == "any" && c.Args.Policy == "any" {
			return true
		}
	}
	return false
}

// served is the document CDS serves at the moment of the call: its entries
// parsed, and raw for putting one back as it was.
type served struct {
	entries map[string]*entry
	raw     map[string]json.RawMessage
}

func (w *world) served() (served, error) {
	out, err := w.be.call("served_allowlist")
	if err != nil {
		return served{}, err
	}
	var doc struct {
		Workloads map[string]json.RawMessage `json:"workloads"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return served{}, fmt.Errorf("served allowlist is not JSON: %w", err)
	}
	s := served{raw: doc.Workloads, entries: make(map[string]*entry, len(doc.Workloads))}
	for name, raw := range doc.Workloads {
		e := &entry{}
		if err := json.Unmarshal(raw, e); err != nil {
			return served{}, fmt.Errorf("served entry %q: %w", name, err)
		}
		s.entries[name] = e
	}
	return s, nil
}

// declares reports whether any served entry names digest at all.
func (s served) declares(digest string) bool {
	for _, e := range s.entries {
		if e.declares(digest) {
			return true
		}
	}
	return false
}

// admitsAnyArgv reports whether a served entry admits digest under any argv.
func (s served) admitsAnyArgv(digest string) bool {
	for _, e := range s.entries {
		if e.admitsAnyArgv(digest) {
			return true
		}
	}
	return false
}
