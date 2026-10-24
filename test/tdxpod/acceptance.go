package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// The connected Pod acceptance boots the pinned production image as one
// server and two Pod guests on the native TDX launcher, with Services
// allocated before any VM exists, and observes through authenticated
// read-only CLI commands only: status, attestation, the CDS mesh CA and a
// public certificate probe. It then holds for the guests' one-hour credential
// timer and proves named leaves rotate while the signed workloads stay
// healthy. Manual and native; never Cloud API or provider conformance.

const (
	soak              = 65 * time.Minute
	meshContainerName = "c8s-mesh"
)

var readCommands = map[string][]string{"cds-ca": {"cds", "ca"}, "pod-status": {"pod-status", "get"},
	"pod-attest": {"pod-attest"}, "pod-attest-observed": {"pod-attest"}, "pod-mesh": {}}

var meshDeclaration = regexp.MustCompile(`(?m)^const MeshContainerName = "([^"\n]+)"$`)

// validateSourceContract fails before provisioning if a future paired image
// changes its injected sidecar name.
func validateSourceContract(source string) error {
	text, err := os.ReadFile(filepath.Join(source, "pkg/workloadclaims/workloadclaims.go"))
	if err != nil {
		return err
	}
	var declarations []string
	for _, m := range meshDeclaration.FindAllStringSubmatch(string(text), -1) {
		declarations = append(declarations, m[1])
	}
	return require(slices.Equal(declarations, []string{meshContainerName}), "paired source mesh container name differs from the acceptance contract")
}

type containerStatus struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restartCount"`
	State        struct {
		Running *struct {
			StartedAt string `json:"startedAt"`
		} `json:"running"`
		Terminated *struct {
			ExitCode  int    `json:"exitCode"`
			StartedAt string `json:"startedAt"`
		} `json:"terminated"`
	} `json:"state"`
}

func (c containerStatus) startedAt() string {
	if c.State.Running != nil {
		return c.State.Running.StartedAt
	}
	if c.State.Terminated != nil {
		return c.State.Terminated.StartedAt
	}
	return ""
}

// podState is what the attested Pod status says about the signed workloads
// and the injected mesh endpoint.
type podState struct {
	Ready, Complete, Running bool
	Starts                   map[string]string
}

var podStateOf = podStateFrom

func podStateFrom(status json.RawMessage, uid string) (podState, error) {
	var doc struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Status struct {
			ContainerStatuses     []containerStatus `json:"containerStatuses"`
			InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal(status, &doc); err != nil {
		return podState{}, errors.New("unreadable attested Pod status")
	}
	if doc.Metadata.UID != uid {
		return podState{}, errors.New("attested Pod UID differs")
	}
	states := map[string]containerStatus{}
	for _, c := range doc.Status.ContainerStatuses {
		states[c.Name] = c
	}
	if len(states) == 0 {
		return podState{Starts: map[string]string{}}, nil
	}
	if _, app := states["app"]; !app || len(states) != 2 || states["checker"].Name != "checker" {
		return podState{}, errors.New("unexpected signed workload container")
	}
	endpoints := map[string]containerStatus{}
	for _, c := range doc.Status.InitContainerStatuses {
		endpoints[c.Name] = c
	}
	if len(endpoints) != 1 || endpoints[meshContainerName].Name != meshContainerName {
		return podState{}, errors.New("expected measured mesh endpoint is missing")
	}
	states[meshContainerName] = endpoints[meshContainerName]
	for _, c := range states {
		if c.RestartCount != 0 {
			return podState{}, errors.New("workload restarted")
		}
	}
	for _, name := range []string{"app", meshContainerName} {
		if states[name].State.Terminated != nil {
			return podState{}, errors.New("application or mesh endpoint exited")
		}
	}
	ended := states["checker"].State.Terminated
	if ended != nil && ended.ExitCode != 0 {
		return podState{}, errors.New("network acceptance checker failed")
	}
	starts, running := map[string]string{}, true
	for name, c := range states {
		starts[name] = c.startedAt()
		running = running && c.State.Running != nil && starts[name] != ""
	}
	ready := true
	for _, name := range []string{"app", meshContainerName} {
		ready = ready && states[name].Ready && states[name].State.Running != nil
	}
	return podState{Ready: ready, Complete: ended != nil, Running: running, Starts: starts}, nil
}

// leaf is the public certificate probe's view of one Pod's mesh identity.
type leaf struct {
	SandboxID string `json:"sandboxID"`
	Serial    string `json:"serial"`
	SPKI      string `json:"spki"`
	Workload  string `json:"workload"`
	Denied    bool   `json:"denied"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	raw       json.RawMessage
}

func parseLeaf(raw []byte) (*leaf, error) {
	l := &leaf{raw: raw}
	if err := json.Unmarshal(raw, l); err != nil {
		return nil, errors.New("unreadable certificate probe response")
	}
	return l, nil
}

func renewed(initial, current *leaf) (bool, error) {
	if initial.SandboxID != current.SandboxID {
		return false, errors.New("pod identity changed during renewal")
	}
	if current.Workload != "connected" || !current.Denied {
		return false, errors.New("named leaf missing or certless access succeeded")
	}
	return initial.Serial != current.Serial && initial.SPKI != current.SPKI, nil
}

// renewalEvent is a new transition after steady runtime, not an early
// replacement still served later. The guest's one-hour timer allows
// downward jitter; forty minutes is below its floor.
func renewalEvent(previous, current *leaf, elapsed time.Duration) (bool, error) {
	changed, err := renewed(previous, current)
	if err != nil || !changed || elapsed < 2400*time.Second {
		return false, err
	}
	parse := func(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
	beforePrevious, err1 := parse(previous.NotBefore)
	beforeCurrent, err2 := parse(current.NotBefore)
	afterPrevious, err3 := parse(previous.NotAfter)
	afterCurrent, err4 := parse(current.NotAfter)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return false, errors.New("unreadable leaf validity")
	}
	return beforeCurrent.Sub(beforePrevious) >= 2400*time.Second && afterCurrent.After(afterPrevious), nil
}

// readinessCycle compresses repeats and requires ready, unready, ready.
func readinessCycle(values []bool) bool {
	var transitions []bool
	for i, v := range values {
		if i == 0 || v != values[i-1] {
			transitions = append(transitions, v)
		}
	}
	if len(transitions) != 0 && !transitions[0] {
		transitions = transitions[1:]
	}
	return slices.Equal(transitions, []bool{true, false, true})
}

type forward struct {
	cmd  *exec.Cmd
	log  *os.File
	done chan struct{}
}

type acceptance struct {
	*owned
	pins               pins
	cli, probe, bundle string
	forwards           []*forward
	connections        map[string]string
	vmiUIDs            map[string]string
	identity           *identity
	runDeadline        time.Time
	// Seams: the observation primitives the offline tests replace.
	validateImage             func(raw []byte) error
	caFn                      func(path string, deadline time.Time) error
	cliReadFn                 func(side string, mode []string, deadline time.Time, exact bool) (json.RawMessage, error)
	leafFn                    func(side, mode string) (*leaf, error)
	instanceFn                func(side string, deadline time.Time) (*object, error)
	warmupRoundFn             func(deadline time.Time, traces map[string][]bool, states map[string]podState) (map[string]*leaf, map[string]json.RawMessage, error)
	connectFn                 func(side string, port int) error
	vmFn                      func(side string) map[string]any
	prepareFn, provisionFn    func() error
	observeFn                 func() error
	captureFn, stopForwardsFn func() error
}

func newAcceptance(root, run, attempt, repo string) (*acceptance, error) {
	return newAcceptanceWith(root, run, attempt, repo, "c8s-podacc", "pod-connected-acceptance", productionPins, 123*time.Minute)
}

func newAcceptanceWith(root, run, attempt, repo, prefix, label string, pinData []byte, budget time.Duration) (*acceptance, error) {
	o, err := newOwned(root, run, attempt, repo, prefix, label)
	if err != nil {
		return nil, err
	}
	p, err := loadPins(pinData)
	if err != nil {
		return nil, err
	}
	a := &acceptance{owned: o, pins: p, cli: filepath.Join(o.private, "c8s"), probe: filepath.Join(o.private, "pod-mesh-probe"),
		bundle: filepath.Join(o.private, "bundle"), connections: map[string]string{}, vmiUIDs: map[string]string{}, runDeadline: now().Add(budget)}
	a.validateImage = a.validateProductionImage
	a.caFn, a.cliReadFn, a.leafFn, a.instanceFn, a.connectFn, a.vmFn = a.ca, a.cliRead, a.leaf, a.instance, a.connect, a.vm
	a.warmupRoundFn = a.warmupRound
	a.prepareFn, a.provisionFn, a.observeFn, a.captureFn, a.stopForwardsFn = a.prepare, a.provision, a.observe, a.capture, a.stopForwards
	return a, nil
}

func (a *acceptance) deadline(d time.Duration) time.Time {
	if limit := now().Add(d); limit.Before(a.runDeadline) {
		return limit
	}
	return a.runDeadline
}

func (a *acceptance) validateProductionImage(raw []byte) error {
	if raw == nil {
		return validatePins(a.pins)
	}
	_, err := validateManifest(raw, a.pins)
	return err
}

// observationError records a failed read-only observation: only static
// labels and bounded, redacted errors reach evidence.
func (a *acceptance) observationError(phase, side string, err error) error {
	if _, ok := readCommands[phase]; !slices.Contains(sides, side) || (!ok && phase != "pod-state") {
		return errors.New("invalid observation label")
	}
	message := a.redact(err.Error())
	if runes := []rune(message); len(runes) > 4096 {
		message = string(runes[len(runes)-4096:])
	}
	event := progress(phase, side, "failed", map[string]any{"error": message})
	return write(filepath.Join(a.evidence, side+"-"+phase+"-last-error.json"), event)
}

// readOnlyCLI runs one allowed observation of the paired CLI or the public
// certificate probe and returns its stdout. Failures carry only bounded,
// redacted stderr; argv and stdout never reach the log.
func (a *acceptance) readOnlyCLI(phase, side string, options []string, deadline time.Time) ([]byte, error) {
	args, ok := readCommands[phase]
	if !ok {
		return nil, errors.New("command is not an allowed CLI observation")
	}
	if (phase == "cds-ca") != (side == "server") || !slices.Contains(sides, side) {
		return nil, errors.New("invalid CLI observation side")
	}
	allowed := map[string]bool{"--node": true, "--launch-key-pub": true, "--image-manifest": true, "--timeout": true}
	switch phase {
	case "cds-ca":
		allowed = map[string]bool{"--url": true, "--image-policy-file": true, "--out": true}
	case "pod-attest":
		allowed["--expect-digest"] = true
	case "pod-mesh":
		allowed = map[string]bool{"--address": true, "--ca": true, "--mode": true}
	}
	if len(options)%2 != 0 {
		return nil, errors.New("unexpected CLI observation option")
	}
	for i := 0; i < len(options); i += 2 {
		if !allowed[options[i]] {
			return nil, errors.New("unexpected CLI observation option")
		}
		if phase == "pod-mesh" && options[i] == "--mode" && !slices.Contains([]string{"certless", "wrong-ca", "plaintext"}, options[i+1]) {
			return nil, errors.New("unexpected mesh probe mode")
		}
	}
	executable := a.cli
	if phase == "pod-mesh" {
		executable = a.probe
	}
	argv := append(append([]string{executable}, args...), options...)
	// Reads need only public pins. Never inherit an optional operator private key.
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "C8S_OPERATOR_KEY=") {
			env = append(env, kv)
		}
	}
	progress(phase, side, "started", nil)
	maximum := 50 * time.Second
	limit := 65536
	if phase == "pod-mesh" {
		maximum, limit = 15*time.Second, 8192
	}
	timeout, err := budget(deadline, maximum)
	if err != nil {
		return nil, err
	}
	result, err := execute(argv, env, nil, timeout)
	var failure error
	switch {
	case err != nil:
		failure = errors.New("could not start read-only CLI")
	case result.timedOut:
		// A timeout's own text would carry argv; report only bounded stderr.
		failure = errors.New("read-only CLI timed out; stderr: " + tail(result.stderr, 3072))
	case result.code != 0:
		failure = fmt.Errorf("read-only CLI exit %d; stderr: %s", result.code, tail(result.stderr, 3072))
	default:
		if len(result.stdout) > limit {
			return nil, errors.New("oversized authenticated response")
		}
		progress(phase, side, "complete", nil)
		return result.stdout, nil
	}
	failure = errors.New(a.redact(failure.Error()))
	if err := a.observationError(phase, side, failure); err != nil {
		return nil, err
	}
	return nil, failure
}

// prepare validates the pinned image against the registry and the paired
// clean CLI source, allocates the Services and renders the signed bundles.
func (a *acceptance) prepare() error {
	if err := a.validateImage(nil); err != nil {
		return err
	}
	source := os.Getenv("POD_ACCEPTANCE_SOURCE")
	head, err := command([]string{"git", "-C", source, "rev-parse", "HEAD"}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(head)) != a.pins.str("source") {
		return errors.New("CLI source does not match production image")
	}
	status, err := command([]string{"git", "-C", source, "status", "--porcelain"}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(status))) != 0 {
		return errors.New("paired CLI checkout is dirty")
	}
	if err := validateSourceContract(source); err != nil {
		return err
	}
	bearer, err := bearerToken()
	if err != nil {
		return err
	}
	raw, _, err := registry("/blobs/sha256:"+a.pins.str("manifestSHA256"), bearer, "application/octet-stream")
	if err != nil {
		return err
	}
	if raw == nil {
		return errors.New("pinned manifest is missing from the registry")
	}
	if err := a.validateImage(raw); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(a.private, "manifest.json"), filepath.Join(a.evidence, "manifest.json")} {
		if err := write(path, raw); err != nil {
			return err
		}
	}
	if err := write(filepath.Join(a.evidence, "image.json"), a.pins); err != nil {
		return err
	}
	for _, resource := range []string{"services", "virtualmachines.kubevirt.io", "persistentvolumeclaims", "secrets"} {
		reply, err := kube([]string{"auth", "can-i", "create", resource}, nil, 30*time.Second)
		if err != nil || strings.TrimSpace(string(reply)) != "yes" {
			return errors.New("missing scoped create authority: " + resource)
		}
	}
	endpoints, err := a.services()
	if err != nil {
		return err
	}
	id, err := renderBundle(bundleInputs{name: a.name, cli: a.cli, manifest: filepath.Join(a.private, "manifest.json"),
		manifestSHA256: a.pins.str("manifestSHA256"), source: a.pins.str("source"), meshImage: a.pins.str("meshImage"),
		out: a.bundle, endpoints: endpoints})
	if err != nil {
		return err
	}
	a.identity = id
	return write(filepath.Join(a.evidence, "identity.json"), id)
}

// services allocates the three ClusterIP Services before any VM exists and
// returns their addresses.
func (a *acceptance) services() (map[string]endpoint, error) {
	specs := serviceSpecs(a.name)
	var items []json.RawMessage
	var objects []*object
	for _, side := range sides {
		obj, err := a.createFn("service", "-"+side, specs[side])
		if err != nil {
			return nil, err
		}
		objects = append(objects, obj)
		items = append(items, obj.raw)
	}
	for _, path := range []string{filepath.Join(a.private, "services.json"), filepath.Join(a.evidence, "services.json")} {
		if err := write(path, map[string]any{"items": items}); err != nil {
			return nil, err
		}
	}
	return allocated(objects, a.name)
}

func (a *acceptance) vm(side string) map[string]any {
	cores, memory, scratch := 2, "8Gi", ""
	if side == "server" {
		cores, memory, scratch = 4, "16Gi", a.name+"-scratch"
	}
	return vmSpec(a.name+"-"+side, a.name+"-root", a.name+"-"+side+"-opkey", cores, memory, scratch)
}

// createLaunchSecrets stages each guest's three bundle files as its launch
// Secret; the CLI-owned bundle stays private and is never copied.
func (a *acceptance) createLaunchSecrets() error {
	for _, side := range sides {
		dir := filepath.Join(a.bundle, side, "pod")
		if side == "server" {
			dir = filepath.Join(a.bundle, side, "server")
		}
		secret, err := launchSecret(dir)
		if err != nil {
			return err
		}
		if _, err := a.createFn("secret", "-"+side+"-opkey", secret); err != nil {
			return err
		}
	}
	return nil
}

func (a *acceptance) provision() error {
	progress("root-import", "all", "started", nil)
	if err := a.importRoot(a.pins.str("image"), "8", "32Gi", a.deadline, "production root import failed", "production root import timed out"); err != nil {
		return err
	}
	progress("root-import", "all", "complete", nil)
	if _, err := a.createFn("pvc", "-scratch", rootClaim()); err != nil {
		return err
	}
	if err := a.createLaunchSecrets(); err != nil {
		return err
	}
	for _, side := range sides {
		if _, err := a.createFn("vm", "-"+side, a.vmFn(side)); err != nil {
			return err
		}
	}
	progress("vm-boot", "all", "started", nil)
	deadline := a.deadline(600 * time.Second)
	for now().Before(deadline) {
		running := true
		for _, side := range sides {
			vmi, err := a.instanceFn(side, deadline)
			if err != nil {
				return err
			}
			running = running && vmi != nil && vmi.Status.Phase == "Running"
		}
		if running {
			progress("vm-boot", "all", "complete", nil)
			return nil
		}
		pause(deadline, 10*time.Second)
	}
	return errors.New("three owned TDX VMIs did not reach Running")
}

// instance returns the owned VMI of one side, nil before it exists, and
// holds its UID for the rest of the run.
func (a *acceptance) instance(side string, deadline time.Time) (*object, error) {
	vm, err := a.get("vm", "-"+side, deadline)
	if err != nil {
		return nil, err
	}
	timeout, err := budget(deadline, 30*time.Second)
	if err != nil {
		return nil, err
	}
	vmi, err := kubeObject([]string{"get", "vmi", a.name + "-" + side, "--ignore-not-found", "-o", "json"}, nil, timeout)
	if err != nil || vmi == nil {
		return nil, err
	}
	if !vmi.ownedBy("VirtualMachine", vm.Metadata.UID) {
		return nil, errors.New("VMI owner differs")
	}
	if held, ok := a.vmiUIDs[side]; !ok {
		a.vmiUIDs[side] = vmi.Metadata.UID
	} else if held != vmi.Metadata.UID {
		return nil, errors.New("VMI replaced during acceptance")
	}
	if vmi.Status.Phase == "Failed" || vmi.Status.Phase == "Succeeded" {
		return nil, errors.New("guest stopped during acceptance")
	}
	return vmi, nil
}

func key(side string, port int) string { return fmt.Sprintf("%s:%d", side, port) }

// connect records how the runner reaches one guest port: the Service
// address directly, or a port-forward through the owned VMI when the
// address is unreachable and the runner may forward.
func (a *acceptance) connect(side string, port int) error {
	if _, err := a.get("service", "-"+side, time.Time{}); err != nil {
		return err
	}
	if _, err := a.instanceFn(side, time.Time{}); err != nil {
		return err
	}
	address := a.identity.Services[side].IP
	direct := net.JoinHostPort(address, fmt.Sprint(port))
	if conn, err := dial("tcp", direct, 2*time.Second); err == nil {
		conn.Close()
		a.connections[key(side, port)] = direct
		return nil
	}
	reply, err := kube([]string{"auth", "can-i", "get", "virtualmachineinstances.subresources.kubevirt.io", "--subresource=portforward"}, nil, 30*time.Second)
	if err != nil || strings.TrimSpace(string(reply)) != "yes" {
		// Running VMIs may still be booting; the bounded warmup retries the direct route.
		a.connections[key(side, port)] = direct
		return nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	local := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	// A held VMI UID and ownership checks fence this read-only transport.
	log, err := os.OpenFile(filepath.Join(a.private, fmt.Sprintf("forward-%s-%d.log", side, port)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command("virtctl", "-n", namespace, "port-forward", "vmi/"+a.name+"-"+side, fmt.Sprintf("%d:%d", local, port), "--address", "127.0.0.1")
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		return errors.New("could not start the owned VMI port-forward")
	}
	f := &forward{cmd: cmd, log: log, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(f.done) }()
	a.forwards = append(a.forwards, f)
	deadline := now().Add(30 * time.Second)
	for now().Before(deadline) {
		select {
		case <-f.done:
			return errors.New("owned VMI port-forward exited")
		default:
		}
		local := net.JoinHostPort("127.0.0.1", fmt.Sprint(local))
		if conn, err := dial("tcp", local, time.Second); err == nil {
			conn.Close()
			if _, err := a.instanceFn(side, time.Time{}); err != nil {
				return err
			}
			a.connections[key(side, port)] = local
			return nil
		}
		pause(deadline, time.Second)
	}
	return errors.New("owned VMI port-forward did not listen")
}

func (a *acceptance) stopForwards() error {
	for _, f := range a.forwards {
		select {
		case <-f.done:
		default:
			_ = f.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-f.done:
			case <-time.After(5 * time.Second):
				_ = f.cmd.Process.Kill()
				select {
				case <-f.done:
				case <-time.After(5 * time.Second):
				}
			}
		}
		f.log.Close()
	}
	return nil
}

// cliRead is one authenticated status or attestation read of a Pod guest;
// exact attestation reads carry the expected-digest gate.
func (a *acceptance) cliRead(side string, mode []string, deadline time.Time, exact bool) (json.RawMessage, error) {
	phase := ""
	switch {
	case slices.Equal(mode, []string{"pod-status", "get"}):
		phase = "pod-status"
	case slices.Equal(mode, []string{"pod-attest"}) && exact:
		phase = "pod-attest"
	case slices.Equal(mode, []string{"pod-attest"}):
		phase = "pod-attest-observed"
	default:
		return nil, errors.New("unsupported authenticated observation")
	}
	options := []string{"--node", a.connections[key(side, 8443)], "--launch-key-pub", filepath.Join(a.bundle, side, "pod/pubkey"),
		"--image-manifest", filepath.Join(a.private, "manifest.json"), "--timeout", "45s"}
	if phase == "pod-attest" {
		if a.identity == nil || len(a.identity.ExpectedDigests) == 0 {
			return nil, errors.New("exact digest gate must be nonempty")
		}
		for _, digest := range a.identity.ExpectedDigests {
			options = append(options, "--expect-digest", digest)
		}
	}
	raw, err := a.readOnlyCLI(phase, side, options, deadline)
	if err != nil {
		return nil, err
	}
	if !json.Valid(raw) {
		return nil, errors.New("unreadable authenticated response")
	}
	return raw, nil
}

func (a *acceptance) leaf(side, mode string) (*leaf, error) {
	raw, err := a.readOnlyCLI("pod-mesh", side, []string{"--address", a.connections[key(side, 8080)],
		"--ca", filepath.Join(a.evidence, "mesh-ca.pem"), "--mode", mode}, time.Time{})
	if err != nil {
		return nil, err
	}
	return parseLeaf(raw)
}

func (a *acceptance) ca(path string, deadline time.Time) error {
	_, err := a.readOnlyCLI("cds-ca", "server", []string{"--url", "https://" + a.connections[key("server", 30808)],
		"--image-policy-file", filepath.Join(a.bundle, "server/server.json"), "--out", path}, deadline)
	return err
}

// warmupPod reads one Pod's status and attestation, keeps every observation
// as evidence, and returns its named leaf and the status it parsed once the
// exact gate, a running workload and the CDS CA all hold.
func (a *acceptance) warmupPod(side string, deadline time.Time, traces map[string][]bool, states map[string]podState, caReady bool) (*leaf, json.RawMessage, error) {
	var state *podState
	exact := false
	status, err := a.cliReadFn(side, []string{"pod-status", "get"}, deadline, true)
	if err == nil {
		err = write(filepath.Join(a.evidence, side+"-initial-status.json"), []byte(status))
	}
	if err == nil {
		var s podState
		if s, err = podStateOf(status, a.name); err == nil {
			traces[side] = append(traces[side], s.Ready)
			states[side] = s
			state = &s
		}
	}
	if err != nil {
		if err := a.observationError("pod-state", side, err); err != nil {
			return nil, nil, err
		}
	}
	report, err := a.cliReadFn(side, []string{"pod-attest"}, deadline, true)
	if err == nil {
		if err := write(filepath.Join(a.evidence, side+"-initial-attestation.json"), []byte(report)); err != nil {
			return nil, nil, err
		}
		exact = true
	} else {
		if err := a.observationError("pod-attest", side, err); err != nil {
			return nil, nil, err
		}
		observed, err := a.cliReadFn(side, []string{"pod-attest"}, deadline, false)
		if err == nil {
			err = write(filepath.Join(a.evidence, side+"-diagnostic-attestation.json"),
				map[string]any{"diagnosticOnly": true, "exactDigestGatePassed": false, "report": observed})
		}
		if err != nil {
			if err := a.observationError("pod-attest-observed", side, err); err != nil {
				return nil, nil, err
			}
		}
	}
	if caReady {
		candidate, err := a.leafFn(side, "certless")
		if err != nil {
			if err := a.observationError("pod-mesh", side, err); err != nil {
				return nil, nil, err
			}
		} else if exact && state != nil && state.Running && candidate.Workload == "connected" {
			return candidate, status, nil
		}
	}
	return nil, nil, nil
}

func (a *acceptance) warmupRound(deadline time.Time, traces map[string][]bool, states map[string]podState) (map[string]*leaf, map[string]json.RawMessage, error) {
	initial, statuses := map[string]*leaf{}, map[string]json.RawMessage{}
	caReady := true
	if err := a.caFn(filepath.Join(a.evidence, "mesh-ca.pem"), deadline); err != nil {
		caReady = false
		if err := a.observationError("cds-ca", "server", err); err != nil {
			return nil, nil, err
		}
	}
	for _, side := range []string{"a", "b"} {
		candidate, status, err := a.warmupPod(side, deadline, traces, states, caReady)
		if err != nil {
			return nil, nil, err
		}
		if candidate != nil {
			initial[side], statuses[side] = candidate, status
		}
	}
	return initial, statuses, nil
}

func rawLeaves(leaves map[string]*leaf) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for side, l := range leaves {
		out[side] = l.raw
	}
	return out
}

// observe proves both Pods obtain named leaves, holds through the guests'
// credential timer while the signed workloads stay healthy, and ends with
// negative probes and a final authenticated health read.
func (a *acceptance) observe() error {
	for _, side := range sides {
		ports := []int{8443, 8080}
		if side == "server" {
			ports = []int{30808}
		}
		for _, port := range ports {
			if err := a.connectFn(side, port); err != nil {
				return err
			}
		}
	}
	if err := write(filepath.Join(a.evidence, "transport.json"), map[string]any{"runner": a.connections,
		"guestTraffic": "the three signed ClusterIP Services; port-forwards are runner observation only"}); err != nil {
		return err
	}
	deadline := a.deadline(1200 * time.Second)
	initial, traces, states := map[string]*leaf{}, map[string][]bool{"a": {}, "b": {}}, map[string]podState{}
	var initialStatus map[string]json.RawMessage
	for now().Before(deadline) {
		progress("warmup", "all", "polling", nil)
		var err error
		if initial, initialStatus, err = a.warmupRoundFn(deadline, traces, states); err != nil {
			return err
		}
		if initial["a"] != nil && initial["b"] != nil {
			break
		}
		pause(deadline, 10*time.Second)
	}
	if initial["a"] == nil || initial["b"] == nil {
		return errors.New("both Pods did not obtain named CDS leaves")
	}
	if initial["a"].SandboxID == initial["b"].SandboxID {
		return errors.New("two guests share a mesh instance identity")
	}
	if err := write(filepath.Join(a.evidence, "initial-leaves.json"), rawLeaves(initial)); err != nil {
		return err
	}
	caBytes, err := os.ReadFile(filepath.Join(a.evidence, "mesh-ca.pem"))
	if err != nil {
		return err
	}
	start := now()
	if a.runDeadline.Sub(start) < soak+360*time.Second {
		return errors.New("insufficient budget for full renewal observation")
	}
	deadline = a.deadline(soak + 600*time.Second)
	baseline := map[string]map[string]string{"a": states["a"].Starts, "b": states["b"].Starts}
	conditions := map[string]*readinessTracker{}
	for _, side := range []string{"a", "b"} {
		conditions[side] = newReadinessTracker(a.name, baseline[side])
		if err := a.recordReadiness(conditions[side], initialStatus[side], states[side], readinessCycle(traces[side]), "readiness-baseline-"+side); err != nil {
			return err
		}
	}
	previous := map[string]*leaf{"a": initial["a"], "b": initial["b"]}
	rotations := map[string]bool{"a": false, "b": false}
	elapsed := func() time.Duration { return now().Sub(start) }
	for index := 1; now().Before(deadline); index++ {
		progress("renewal-soak", "all", "polling", map[string]any{"elapsedSeconds": math.Round(elapsed().Seconds())})
		sample := map[string]any{"elapsed": elapsed().Seconds(), "pods": map[string]any{}}
		for _, side := range []string{"a", "b"} {
			if _, err := a.instanceFn(side, deadline); err != nil {
				return err
			}
			status, err := a.cliReadFn(side, []string{"pod-status", "get"}, deadline, true)
			if err != nil {
				return err
			}
			readinessName := fmt.Sprintf("readiness-%03d-%s", index, side)
			state, err := a.parseReadinessStatus(status, readinessName)
			if err != nil {
				return err
			}
			states[side] = state
			traces[side] = append(traces[side], state.Ready)
			if err := a.recordReadiness(conditions[side], status, state, readinessCycle(traces[side]), readinessName); err != nil {
				return err
			}
			l, err := a.leafFn(side, "certless")
			if err != nil {
				return err
			}
			// A checker exit can itself refresh claims; it is not timed renewal.
			rotation, err := renewalEvent(previous[side], l, elapsed())
			if err != nil {
				return err
			}
			rotations[side] = rotations[side] || (rotation && state.Running)
			previous[side] = l
			sample["pods"].(map[string]any)[side] = map[string]json.RawMessage{"status": status, "leaf": l.raw}
		}
		if err := write(filepath.Join(a.evidence, fmt.Sprintf("sample-%03d.json", index)), sample); err != nil {
			return err
		}
		if elapsed() >= soak && rotations["a"] && rotations["b"] && states["a"].Complete && states["b"].Complete {
			break
		}
		pause(deadline, 20*time.Second)
	}
	if elapsed() < soak || !rotations["a"] || !rotations["b"] {
		return errors.New("65-minute named credential rotation was not established")
	}
	for _, side := range []string{"a", "b"} {
		if !states[side].Complete || !states[side].Ready {
			return errors.New("final attested network checker or app readiness failed")
		}
	}
	for _, side := range []string{"a", "b"} {
		// Compress repeats and require ready -> unready -> ready while the app lives.
		if !readinessCycle(traces[side]) {
			return errors.New("attested readiness did not recover or had an unexpected outage")
		}
		for _, mode := range []string{"certless", "wrong-ca", "plaintext"} {
			l, err := a.leafFn(side, mode)
			if err != nil {
				return err
			}
			if err := write(filepath.Join(a.evidence, side+"-negative-"+mode+".json"), []byte(l.raw)); err != nil {
				return err
			}
		}
		report, err := a.cliReadFn(side, []string{"pod-attest"}, deadline, true)
		if err != nil {
			return err
		}
		if err := write(filepath.Join(a.evidence, side+"-final-attestation.json"), []byte(report)); err != nil {
			return err
		}
	}
	pause(deadline, 95*time.Second)
	for _, side := range []string{"a", "b"} {
		status, err := a.cliReadFn(side, []string{"pod-status", "get"}, deadline, true)
		if err != nil {
			return err
		}
		readinessName := "readiness-final-" + side
		state, err := a.parseReadinessStatus(status, readinessName)
		if err != nil {
			return err
		}
		if err := a.recordReadiness(conditions[side], status, state, true, readinessName); err != nil {
			return err
		}
		if !state.Ready || !state.Complete || !sameStarts(state.Starts, baseline[side]) {
			return errors.New("post-negative authenticated workload health failed")
		}
		if err := write(filepath.Join(a.evidence, side+"-final-status.json"), []byte(status)); err != nil {
			return err
		}
	}
	final := filepath.Join(a.private, "final-ca.pem")
	if err := a.caFn(final, deadline); err != nil {
		return err
	}
	finalBytes, err := os.ReadFile(final)
	if err != nil || string(finalBytes) != string(caBytes) {
		return errors.New("CDS mesh CA changed during acceptance")
	}
	return write(filepath.Join(a.evidence, "result.json"), map[string]any{"schema": 1, "passed": true, "scope": "native TDX; not Cloud API acceptance",
		"elapsedAfterNamedLeaves": elapsed().Seconds(), "rotated": rotations, "readiness": traces,
		"networkReceipt": "both authenticated checker exit codes zero and applications still ready"})
}

func sameStarts(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// capture records each owned VM, its VMI and launcher Pod and bounded logs
// for failure analysis.
func (a *acceptance) capture() error {
	deadline := now().Add(90 * time.Second)
	for _, side := range sides {
		if _, intended, _ := a.entry("vm", "-"+side); !intended {
			continue
		}
		err := func() error {
			vm, err := a.get("vm", "-"+side, deadline)
			if err != nil {
				return err
			}
			if err := write(filepath.Join(a.evidence, side+"-vm.json"), vm.raw); err != nil {
				return err
			}
			timeout, err := budget(deadline, 30*time.Second)
			if err != nil {
				return err
			}
			vmi, err := kubeObject([]string{"get", "vmi", a.name + "-" + side, "--ignore-not-found", "-o", "json"}, nil, timeout)
			if err != nil || vmi == nil {
				return err
			}
			if !vmi.ownedBy("VirtualMachine", vm.Metadata.UID) {
				return errors.New("capture VMI owner differs")
			}
			if err := write(filepath.Join(a.evidence, side+"-vmi.json"), vmi.raw); err != nil {
				return err
			}
			if timeout, err = budget(deadline, 30*time.Second); err != nil {
				return err
			}
			pods, err := kubeObject([]string{"get", "pods", "-l", "kubevirt.io/domain=" + a.name + "-" + side, "-o", "json"}, nil, timeout)
			if err != nil {
				return err
			}
			if pods == nil {
				return errors.New("launcher listing returned nothing")
			}
			for _, item := range pods.Items {
				pod, err := parseObject(item)
				if err != nil {
					return err
				}
				if !pod.ownedBy("VirtualMachineInstance", vmi.Metadata.UID) {
					return errors.New("capture launcher owner differs")
				}
				if err := write(filepath.Join(a.evidence, side+"-launcher.json"), []byte(item)); err != nil {
					return err
				}
				if err := a.launcherLogs(side+"-", a.name+"-"+side, vmi.Metadata.UID, pod, deadline); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			if err := write(filepath.Join(a.evidence, side+"-capture-error.json"), map[string]string{"error": err.Error()}); err != nil {
				return err
			}
		}
	}
	return nil
}

func runAcceptance(mode string) error {
	task, err := newAcceptance(filepath.Join(os.Getenv("RUNNER_TEMP"), "pod-acceptance"),
		os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT"), os.Getenv("GITHUB_REPOSITORY"))
	if err != nil {
		return err
	}
	if mode == "cleanup" {
		progress("cleanup", "all", "started", nil)
		if err := task.cleanup(); err != nil {
			return err
		}
		progress("cleanup", "all", "complete", nil)
		return nil
	}
	entries, err := task.resources()
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("acceptance already owns resources")
	}
	err = runPhases(task, [][2]any{{"prepare", task.prepareFn}, {"provision", task.provisionFn}, {"observe", task.observeFn}}, task.recordFailure)
	if err != nil {
		return err
	}
	fmt.Fprintln(progressOut, "Native TDX connected acceptance passed; this is not Cloud API acceptance.")
	return nil
}

// recordFailure writes the first phase failure as public evidence: the Go
// error type and the redacted message, never a private path or raw output.
func (a *acceptance) recordFailure(_ string, err error) error {
	return write(filepath.Join(a.evidence, "failure.json"), map[string]string{"error": a.redact(err.Error()), "type": errorClass(err)})
}

// runPhases runs the lane's phases with progress events, records the first
// failure, and always captures evidence and stops port-forwards afterwards.
func runPhases(task *acceptance, phases [][2]any, onFailure func(phase string, err error) error) (err error) {
	defer func() {
		for _, final := range []struct {
			name   string
			action func() error
		}{{"capture", task.captureFn}, {"forward-cleanup", task.stopForwardsFn}} {
			if finalErr := final.action(); finalErr != nil {
				_ = write(filepath.Join(task.evidence, final.name+"-error.json"), map[string]string{"error": task.redact(finalErr.Error())})
			}
		}
	}()
	for _, phase := range phases {
		name, action := phase[0].(string), phase[1].(func() error)
		progress(name, "all", "started", nil)
		if err = action(); err != nil {
			_ = onFailure(name, err)
			return err
		}
		progress(name, "all", "complete", nil)
	}
	return nil
}
