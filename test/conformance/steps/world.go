package steps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	// entries the scenario describes, written to CDS when a pod is deployed;
	// written and removed are undone after the scenario.
	entries map[string]*entry
	written []string
	removed map[string]json.RawMessage
	// images the scenario has named, in order, for "both images".
	images []string
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
				be:        be,
				namespace: "conf-" + hex.EncodeToString(suffix),
				pods:      map[string]*pod{},
				entries:   map[string]*entry{},
				removed:   map[string]json.RawMessage{},
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
				return ctx, w.restoreAllowlist()
			}
			return ctx, nil
		})
		registerAdmission(sc)
		registerAllowlist(sc)
	}
}

// describe records a pod the scenario will deploy; it becomes the last pod.
func (w *world) describe(name, ref string) *pod {
	p := &pod{name: name}
	p.add(ref)
	w.pods[name], w.lastPod = p, p
	return p
}

// add appends a container running ref; a scenario that says nothing about the
// command line gets one that keeps the container alive.
func (p *pod) add(ref string) *container {
	c := &container{ref: ref, command: []string{"sleep", "3600"}}
	p.containers = append(p.containers, c)
	return c
}

func (p *pod) last() *container { return p.containers[len(p.containers)-1] }

func (w *world) pod(name string) (*pod, error) {
	p, ok := w.pods[name]
	if !ok {
		return nil, fmt.Errorf("no pod %q has been described in this scenario", name)
	}
	return p, nil
}

// allowlist is the served document, reduced to what the steps ask of it. It is
// deliberately not pkg/allowlist: the steps observe the cluster from outside,
// through the document CDS serves, so a change to the package cannot change
// what the suite accepts. floorAdmits means what AdmitsAnyArgv means there.
type allowlist struct {
	Workloads map[string]allowlistEntry `json:"workloads"`
}

type allowlistEntry struct {
	InitContainers []allowlistContainer `json:"initContainers"`
	Containers     []allowlistContainer `json:"containers"`
}

type allowlistContainer struct {
	Digest  string `json:"digest"`
	Command struct {
		Policy string `json:"policy"`
	} `json:"command"`
	Args struct {
		Policy string `json:"policy"`
	} `json:"args"`
}

// servedAllowlist parses the document the backend serves.
func (w *world) servedAllowlist() (allowlist, error) {
	var doc allowlist
	raw, err := w.be.call("served_allowlist")
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return doc, fmt.Errorf("served allowlist is not JSON: %w", err)
	}
	return doc, nil
}

// servedEntries returns the served entries, name to raw JSON, for the steps
// that remove and restore them.
func (w *world) servedEntries() (map[string]json.RawMessage, error) {
	var doc struct {
		Workloads map[string]json.RawMessage `json:"workloads"`
	}
	raw, err := w.be.call("served_allowlist")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("served allowlist is not JSON: %w", err)
	}
	return doc.Workloads, nil
}

// declaresDigest reports whether the entry names digest, init or main.
func (e allowlistEntry) declaresDigest(digest string) bool {
	for _, list := range [][]allowlistContainer{e.InitContainers, e.Containers} {
		for _, c := range list {
			if c.Digest == digest {
				return true
			}
		}
	}
	return false
}

// entries are the allowlisted containers, init or not, that name digest.
func (a allowlist) entries(digest string) []allowlistContainer {
	var out []allowlistContainer
	for _, wl := range a.Workloads {
		for _, list := range [][]allowlistContainer{wl.InitContainers, wl.Containers} {
			for _, c := range list {
				if c.Digest == digest {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// floorAdmits reports whether an entry admits digest under any command line.
func (a allowlist) floorAdmits(digest string) bool {
	for _, c := range a.entries(digest) {
		if c.Command.Policy == "any" && c.Args.Policy == "any" {
			return true
		}
	}
	return false
}

// declares reports whether any workload entry names digest at all.
func (a allowlist) declares(digest string) bool { return len(a.entries(digest)) > 0 }

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

// named records an image the scenario mentions, once.
func (w *world) named(image string) {
	for _, i := range w.images {
		if i == image {
			return
		}
	}
	w.images = append(w.images, image)
}
