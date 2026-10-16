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
	entries  map[string]*entry
	written  map[string]bool
	removed  map[string]json.RawMessage
	api      cdsAPIState
	cds      cdsState
	issuance issuanceState
	mesh     meshState
	secrets  secretsState
	router   routerState
	// undo is what the scenario changed in the cluster beyond the node and
	// the allowlist, put back last in, first out before those are restored.
	undo []func() error
	// appliedVersion is the allowlist version the plugin reported applied when
	// the scenario last waited for it, or the served one where the backend
	// cannot ask the plugin.
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
	// workloadID: the pod opts into a leaf of its own, which the webhook's
	// requester obtains and renews. leaf is the one the pod holds as last
	// read (or, for a requester the scenario drives, the one its last attest
	// request was issued); renewed and refusal are what an injected
	// requester's last attempt did.
	workloadID bool
	leaf       *leaf
	renewed    bool
	refusal    *refusal
	// How the mesh sentences shape the pod: the ports its hello APIs and
	// datagram listener use, pod_manifest options, its namespace (the
	// scenario's unless a sentence moves it), the certificate a dialer in it
	// presents, whether the dialer is in it yet, and its addresses once
	// running.
	hello     []int
	datagram  int
	listener  string // the container whose log shows the datagrams received
	opts      []string
	namespace string
	cert      *peerCert
	dialer    bool     // the mesh peer has been copied into the pod
	verifyCDS []string // how the pod's certificate container verifies the CDS, as probe flags
	addrs     []string
	// What the secrets sentences add: the secret client's NAME=path specs,
	// an init container (which "that container" addresses while initLast),
	// and the requester state of the pod.
	secrets  []string
	init     *container
	initLast bool
	secret   *secretReq
	ready    bool // seen Ready once, so every main container has been admitted
}

type container struct {
	ref     string // reference the manifest uses
	command []string
	env     []string // NAME=VALUE the pod spec sets, beside what the image and the node add
}

type worldKey struct{}

func getWorld(ctx context.Context) *world { return ctx.Value(worldKey{}).(*world) }

func initializeScenario(be backend) func(*godog.ScenarioContext) {
	return func(sc *godog.ScenarioContext) {
		sc.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
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
				issuance:   issuanceState{requesters: map[string]*requester{}},
				mesh: meshState{
					nodes:     map[string]bool{},
					counters:  map[string]int64{},
					ghosts:    map[string]*pod{},
					endpoints: map[string]string{},
				},
				secrets: secretsState{active: hasTag(sc, "area:secrets"), stored: map[string][]byte{}},
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
				// The undo list first, which brings the CDS back to its
				// installed configuration; then the node, whose plugins pull
				// from that CDS; then the allowlist, written through it.
				return ctx, errors.Join(w.runUndo(), w.restoreNode(), w.restoreAllowlist())
			}
			return ctx, nil
		})
		registerAdmission(sc)
		registerAllowlist(sc)
		registerCDSAPI(sc)
		registerCDS(sc)
		registerIssuance(sc)
		registerRequester(sc)
		registerNode(sc)
		registerMesh(sc)
		registerSecrets(sc)
		registerRouter(sc)
	}
}

// hasTag reports whether the scenario carries the tag, with or without its @.
func hasTag(sc *godog.Scenario, name string) bool {
	for _, t := range sc.Tags {
		if strings.TrimPrefix(t.Name, "@") == name {
			return true
		}
	}
	return false
}

// suffix is the random part of the scenario namespace, for names that must
// not collide with another scenario's outside it.
func (w *world) suffix() string { return strings.TrimPrefix(w.namespace, "conf-") }

// onUndo records what the After hook has to run to put the cluster back.
func (w *world) onUndo(fn func() error) { w.undo = append(w.undo, fn) }

// runUndo runs the recorded steps last in, first out, every one of them.
func (w *world) runUndo() error {
	var errs []error
	for i := len(w.undo) - 1; i >= 0; i-- {
		errs = append(errs, w.undo[i]())
	}
	w.undo = nil
	return errors.Join(errs...)
}

// describe records a pod the scenario will deploy, one container per
// reference; it becomes the last pod. A scenario that says nothing about the
// argv gets one that keeps the container alive.
func (w *world) describe(name string, refs ...string) *pod {
	p := &pod{name: name, namespace: w.namespace}
	for _, ref := range refs {
		p.containers = append(p.containers, &container{ref: ref, command: []string{"sleep", "3600"}})
	}
	w.pods[name], w.lastPod = p, p
	return p
}

// last is the container "that container" addresses: the init container
// while it is the one just described, else the last main one.
func (p *pod) last() *container {
	if p.initLast {
		return p.init
	}
	return p.containers[len(p.containers)-1]
}

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
	Secrets        *secretsGrant    `json:"secrets,omitempty"`
}

// entryContainer is a declared container. Command and Args are nil when the
// entry states no policy, which the document's defaults then decide.
type entryContainer struct {
	Digest  string       `json:"digest"`
	Image   string       `json:"image,omitempty"`
	Command *argvPolicy  `json:"command,omitempty"`
	Args    *argvPolicy  `json:"args,omitempty"`
	Mounts  mountsPolicy `json:"mounts"`
	Env     envPolicy    `json:"env"`
}

type argvPolicy struct {
	Policy string   `json:"policy"`
	Argv   []string `json:"argv,omitempty"`
}

func anyArgv() *argvPolicy                { return &argvPolicy{Policy: "any"} }
func denyArgv() *argvPolicy               { return &argvPolicy{Policy: "deny"} }
func exactArgv(argv []string) *argvPolicy { return &argvPolicy{Policy: "exact", Argv: argv} }

func (p *argvPolicy) is(policy string) bool { return p != nil && p.Policy == policy }

type envPolicy struct {
	Policy    string                `json:"policy"`
	Variables map[string]envMatcher `json:"variables,omitempty"`
}

// envMatcher is one variable of a match policy: exactly one of the two is set.
type envMatcher struct {
	Exact   *string `json:"exact,omitempty"`
	Present bool    `json:"present,omitempty"`
}

type mountsPolicy struct {
	Policy string      `json:"policy"`
	Rules  []mountRule `json:"rules,omitempty"`
}

// mountRule is the part of a rule every kind carries.
type mountRule struct {
	Destination string `json:"destination"`
	Kind        string `json:"kind"`
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

// admitsAnyArgv reports whether the entry admits digest under any argv. An
// entry pinned to an executable — the chart's own component shape — does not
// count: the scenarios launch their containers under `sleep`, which such an
// entry refuses.
func (e *entry) admitsAnyArgv(digest string) bool {
	for _, c := range e.containers() {
		if c.Digest == digest && c.Command.is("any") && c.Args.is("any") {
			return true
		}
	}
	return false
}

// served is an allowlist document as CDS serves it: its entries parsed, and
// raw for putting one back as it was.
type served struct {
	schema  string
	entries map[string]*entry
	raw     map[string]json.RawMessage
}

// served is the document CDS serves at the moment of the call.
func (w *world) served() (served, error) {
	out, err := w.be.call("served_allowlist")
	if err != nil {
		return served{}, err
	}
	return parseServed(out)
}

func parseServed(out string) (served, error) {
	var doc struct {
		Schema    string                     `json:"schema"`
		Workloads map[string]json.RawMessage `json:"workloads"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return served{}, fmt.Errorf("served allowlist is not JSON: %w", err)
	}
	s := served{schema: doc.Schema, raw: doc.Workloads, entries: make(map[string]*entry, len(doc.Workloads))}
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
