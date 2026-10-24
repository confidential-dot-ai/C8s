// Command tdxpod drives the manual Pod lanes of tdx-metal-e2e on the native
// TDX launcher: a boot diagnostic of one commit's dev image, the connected
// Pod acceptance of the pinned production image, and the runtime diagnostic
// of the pinned development image.
//
//	tdxpod boot run|cleanup        # POD_DIAGNOSTIC_SOURCE names the dev image's commit
//	tdxpod acceptance run|cleanup  # POD_ACCEPTANCE_SOURCE is the paired CLI checkout
//	tdxpod runtime run|cleanup     # POD_ACCEPTANCE_SOURCE is the paired CLI checkout
//	tdxpod pins production|development  # validates the pinned image and prints source=<sha>
//
// Every cluster resource a lane creates carries run-scoped labels and a
// creation nonce recorded in a private ledger before the create request,
// reads check that ownership, and deletes are preconditioned on the recorded
// UID, so a lost response or a replaced object is never adopted or deleted.
// Command failures report only the executable's name and exit code: launch
// inputs and API errors can carry Secrets.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	namespace  = "confai-images"
	ownerRepo  = "confidential-dot-ai/c8s"
	pauseImage = "docker.io/rancher/mirrored-pause:3.10.2@sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4"
	imageRepo  = "confidential-dot-ai/node-guest-base"
)

var (
	hexCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexRTMR   = regexp.MustCompile(`^[0-9a-f]{96}$`)
	decimal   = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// Seams the offline tests replace.
var (
	execute               = runProcess
	kube                  = runKubectl
	registry              = fetchRegistry
	rename                = os.Rename
	now                   = time.Now
	sleep                 = time.Sleep
	newNonce              = nonce
	dial                  = net.DialTimeout
	progressOut io.Writer = os.Stdout
)

func require(condition bool, message string) error {
	if !condition {
		return errors.New(message)
	}
	return nil
}

// budget bounds one request to maximum and never past the phase deadline; a
// zero deadline means no phase.
func budget(deadline time.Time, maximum time.Duration) (time.Duration, error) {
	remaining := maximum
	if !deadline.IsZero() {
		remaining = deadline.Sub(now())
	}
	if remaining <= 0 {
		return 0, errors.New("phase deadline reached")
	}
	return min(maximum, remaining), nil
}

func pause(deadline time.Time, d time.Duration) {
	sleep(min(d, max(0, deadline.Sub(now()))))
}

func nonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func encode(value any) ([]byte, error) {
	data, ok := value.([]byte)
	if ok {
		return data, nil
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// write publishes data (or the indented JSON of value) atomically with mode
// 0600; a failed publication leaves the previous file and no temporary.
func write(path string, value any) error {
	data, err := encode(value)
	if err != nil {
		return err
	}
	temporary := path + "." + nonce() + ".tmp"
	defer os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return rename(temporary, path)
}

// writeNew creates path exclusively; staged inputs are never overwritten.
func writeNew(path string, value any) error {
	data, err := encode(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

// processResult is one finished (or killed) child process.
type processResult struct {
	stdout, stderr []byte
	code           int
	timedOut       bool
}

// runProcess runs argv with the given environment (nil inherits) and stdin
// bytes; a nil stdin closes the child's input.
func runProcess(argv []string, env []string, stdin []byte, timeout time.Duration) (processResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := processResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), timedOut: ctx.Err() != nil}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		result.code = exit.ExitCode()
	case result.timedOut:
		result.code = -1
	default:
		return result, fmt.Errorf("could not start %s", filepath.Base(argv[0]))
	}
	return result, nil
}

// command runs argv and returns its stdout. Failures report only the
// executable name and exit code.
func command(argv []string, data []byte, timeout time.Duration) ([]byte, error) {
	result, err := execute(argv, nil, data, timeout)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(argv[0])
	if result.timedOut {
		return nil, fmt.Errorf("command timed out: %s", name)
	}
	if result.code != 0 {
		return nil, fmt.Errorf("command failed: %s (exit %d)", name, result.code)
	}
	return result.stdout, nil
}

func runKubectl(args []string, data []byte, timeout time.Duration) ([]byte, error) {
	return command(append([]string{"kubectl", "-n", namespace}, args...), data, timeout)
}

// object is the subset of a Kubernetes object the lanes read; raw keeps the
// bytes kubectl returned for the evidence.
type object struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
		OwnerReferences []struct {
			Controller bool   `json:"controller"`
			Kind       string `json:"kind"`
			UID        string `json:"uid"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		NodeName  string            `json:"nodeName"`
		ClusterIP string            `json:"clusterIP"`
		Selector  map[string]string `json:"selector"`
		Ports     []struct {
			Port       int    `json:"port"`
			TargetPort int    `json:"targetPort"`
			Protocol   string `json:"protocol"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
	Items []json.RawMessage `json:"items"`
	raw   []byte
}

func parseObject(raw []byte) (*object, error) {
	obj := &object{raw: raw}
	if err := json.Unmarshal(raw, obj); err != nil {
		return nil, fmt.Errorf("unexpected object: %w", err)
	}
	return obj, nil
}

// kubeObject runs kubectl and parses its JSON; a blank body is a nil object.
func kubeObject(args []string, data []byte, timeout time.Duration) (*object, error) {
	body, err := kube(args, data, timeout)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	return parseObject(body)
}

func (o *object) ownedBy(kind, uid string) bool {
	for _, ref := range o.Metadata.OwnerReferences {
		if ref.Controller && ref.Kind == kind && ref.UID == uid {
			return true
		}
	}
	return false
}

func fetchRegistry(path, bearer, accept string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/"+imageRepo+path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", accept)
	client := &http.Client{Timeout: 60 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("registry %s: HTTP %d", path, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	return body, response.Header, err
}

// bearerToken obtains a pull token for the image repository, with the
// workflow token when present.
func bearerToken() (string, error) {
	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/token?service=ghcr.io&scope=repository:"+imageRepo+":pull", nil)
	if err != nil {
		return "", err
	}
	if token := os.Getenv("GH_TOKEN"); token != "" {
		req.SetBasicAuth(os.Getenv("GITHUB_ACTOR"), token)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token: HTTP %d", response.StatusCode)
	}
	var reply struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&reply); err != nil {
		return "", fmt.Errorf("registry token: %w", err)
	}
	return reply.Token, nil
}

// resource is one ledger entry; a nil UID records a create whose outcome was
// lost, which cleanup must still inspect.
type resource struct {
	Kind   string  `json:"kind"`
	Suffix string  `json:"suffix"`
	UID    *string `json:"uid"`
}

type metadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// owned is a lane's run-scoped set of cluster resources.
type owned struct {
	root, private, evidence, ledger, nonceFile string
	run, attempt, repo, name, label            string
	createFn                                   func(kind, suffix string, spec map[string]any) (*object, error)
	removeFn                                   func(kind, suffix string, deadline time.Time) error
}

func newOwned(root, run, attempt, repo, prefix, label string) (*owned, error) {
	if !decimal.MatchString(run) || !decimal.MatchString(attempt) {
		return nil, errors.New("invalid workflow identity")
	}
	if strings.ToLower(repo) != ownerRepo {
		return nil, errors.New("unexpected repository")
	}
	o := &owned{root: root, run: run, attempt: attempt, repo: repo, label: label, name: prefix + "-" + run + "-" + attempt,
		private: filepath.Join(root, "private"), evidence: filepath.Join(root, "evidence")}
	for _, dir := range []string{o.private, o.evidence} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	o.ledger = filepath.Join(o.private, "resources.json")
	o.nonceFile = filepath.Join(o.private, "creation-nonces.json")
	o.createFn, o.removeFn = o.create, o.remove
	return o, nil
}

func (o *owned) resources() ([]resource, error) {
	var entries []resource
	return entries, readJSON(o.ledger, &entries)
}

func (o *owned) entry(kind, suffix string) (resource, bool, error) {
	entries, err := o.resources()
	if err != nil {
		return resource{}, false, err
	}
	for _, e := range entries {
		if e.Kind == kind && e.Suffix == suffix {
			return e, true, nil
		}
	}
	return resource{}, false, nil
}

func (o *owned) hasVM() bool {
	entries, _ := o.resources()
	for _, e := range entries {
		if e.Kind == "vm" {
			return true
		}
	}
	return false
}

// metadata names a resource and mints its creation nonce once per kind and
// suffix; the nonce persists so the cleanup process recognises what this run
// created.
func (o *owned) metadata(kind, suffix string) (metadata, error) {
	key := kind + ":" + suffix
	nonces := map[string]string{}
	if err := readJSON(o.nonceFile, &nonces); err != nil {
		return metadata{}, err
	}
	if _, ok := nonces[key]; !ok {
		if _, intended, err := o.entry(kind, suffix); err != nil {
			return metadata{}, err
		} else if intended {
			return metadata{}, errors.New("owned resource lost creation nonce")
		}
		nonces[key] = newNonce()
		if err := write(o.nonceFile, nonces); err != nil {
			return metadata{}, err
		}
	}
	return metadata{Name: o.name + suffix, Namespace: namespace,
		Labels: map[string]string{"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": o.label,
			"ci.confidential.ai/run-id": o.run, "ci.confidential.ai/run-attempt": o.attempt},
		Annotations: map[string]string{"ci.confidential.ai/repo": o.repo, "ci.confidential.ai/creation-nonce": nonces[key]}}, nil
}

// checkOwned verifies that obj is the resource this run created; uid, when
// set, must match the recorded one.
func (o *owned) checkOwned(obj *object, kind, suffix, uid string) error {
	expected, err := o.metadata(kind, suffix)
	if err != nil {
		return err
	}
	actual := obj.Metadata
	if actual.Name != expected.Name || actual.Namespace != expected.Namespace {
		return errors.New("resource scope differs")
	}
	for k, v := range expected.Labels {
		if actual.Labels[k] != v {
			return errors.New("resource ownership differs")
		}
	}
	for k, v := range expected.Annotations {
		if actual.Annotations[k] != v {
			return errors.New("resource ownership differs")
		}
	}
	if uid != "" && actual.UID != uid {
		return errors.New("resource UID changed")
	}
	return nil
}

func (o *owned) create(kind, suffix string, spec map[string]any) (*object, error) {
	if _, intended, err := o.entry(kind, suffix); err != nil {
		return nil, err
	} else if intended {
		return nil, errors.New("duplicate resource intent")
	}
	existing, err := kubeObject([]string{"get", kind, o.name + suffix, "--ignore-not-found", "-o", "json"}, nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("refusing existing resource")
	}
	meta, err := o.metadata(kind, suffix)
	if err != nil {
		return nil, err
	}
	spec["metadata"] = meta
	entries, err := o.resources()
	if err != nil {
		return nil, err
	}
	entries = append(entries, resource{Kind: kind, Suffix: suffix})
	// Record intent before a request whose result could be lost.
	if err := write(o.ledger, entries); err != nil {
		return nil, err
	}
	body, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	obj, err := kubeObject([]string{"create", "-f", "-", "-o", "json"}, body, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, errors.New("create returned no object")
	}
	if err := o.checkOwned(obj, kind, suffix, ""); err != nil {
		return nil, err
	}
	uid := obj.Metadata.UID
	entries[len(entries)-1].UID = &uid
	return obj, write(o.ledger, entries)
}

func (o *owned) get(kind, suffix string, deadline time.Time) (*object, error) {
	e, intended, err := o.entry(kind, suffix)
	if err != nil {
		return nil, err
	}
	if !intended {
		return nil, fmt.Errorf("no owned %s%s in the ledger", kind, suffix)
	}
	timeout, err := budget(deadline, 30*time.Second)
	if err != nil {
		return nil, err
	}
	obj, err := kubeObject([]string{"get", kind, o.name + suffix, "-o", "json"}, nil, timeout)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("%s%s is missing", kind, suffix)
	}
	uid := ""
	if e.UID != nil {
		uid = *e.UID
	}
	return obj, o.checkOwned(obj, kind, suffix, uid)
}

// remove deletes one owned resource with a UID precondition and waits for it
// to disappear, within two minutes or the given deadline.
func (o *owned) remove(kind, suffix string, deadline time.Time) error {
	limit := now().Add(120 * time.Second)
	if deadline.IsZero() || limit.Before(deadline) {
		deadline = limit
	}
	e, intended, err := o.entry(kind, suffix)
	if err != nil {
		return err
	}
	if !intended {
		return fmt.Errorf("no owned %s%s in the ledger", kind, suffix)
	}
	timeout, err := budget(deadline, 30*time.Second)
	if err != nil {
		return err
	}
	obj, err := kubeObject([]string{"get", kind, o.name + suffix, "--ignore-not-found", "-o", "json"}, nil, timeout)
	if err != nil {
		return err
	}
	if obj != nil {
		uid := ""
		if e.UID != nil {
			uid = *e.UID
		}
		if err := o.checkOwned(obj, kind, suffix, uid); err != nil {
			return err
		}
		// Preconditions prevent deleting a replacement after the ownership check.
		plural := map[string]string{"vm": "virtualmachines", "pod": "pods", "pvc": "persistentvolumeclaims", "secret": "secrets", "service": "services"}[kind]
		base := "/api/v1"
		if kind == "vm" {
			base = "/apis/kubevirt.io/v1"
		}
		url := fmt.Sprintf("%s/namespaces/%s/%s/%s%s", base, namespace, plural, o.name, suffix)
		options, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "DeleteOptions",
			"preconditions": map[string]string{"uid": obj.Metadata.UID}, "propagationPolicy": "Foreground"})
		if err != nil {
			return err
		}
		if timeout, err = budget(deadline, 30*time.Second); err != nil {
			return err
		}
		if _, err := kube([]string{"delete", "--raw", url, "-f", "-"}, options, timeout); err != nil {
			return err
		}
	}
	for now().Before(deadline) {
		timeout, err := budget(deadline, 30*time.Second)
		if err != nil {
			return err
		}
		remaining, err := kubeObject([]string{"get", kind, o.name + suffix, "--ignore-not-found", "-o", "json"}, nil, timeout)
		if err != nil {
			return err
		}
		if remaining == nil {
			return nil
		}
		pause(deadline, 5*time.Second)
	}
	return errors.New("resource deletion did not complete: " + kind + suffix)
}

// cleanup removes every owned resource, all VMs first, then the shared
// disks, launch Secrets and Services, and stops after the first failing
// group so nothing a VM could still use is removed.
func (o *owned) cleanup() error {
	entries, err := o.resources()
	if err != nil {
		return err
	}
	errs, removed := []string{}, []map[string]string{}
	deadline := now().Add(540 * time.Second)
	var vms, rest []resource
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Kind == "vm" {
			vms = append(vms, entries[i])
		} else {
			rest = append(rest, entries[i])
		}
	}
	for _, group := range [][]resource{vms, rest} {
		for _, e := range group {
			if err := o.removeFn(e.Kind, e.Suffix, deadline); err != nil {
				errs = append(errs, err.Error())
				continue
			}
			removed = append(removed, map[string]string{"kind": e.Kind, "name": o.name + e.Suffix})
		}
		if len(errs) != 0 {
			break
		}
	}
	if err := write(filepath.Join(o.evidence, "cleanup.json"), map[string]any{"name": o.name, "complete": len(errs) == 0, "removed": removed, "errors": errs}); err != nil {
		return err
	}
	return require(len(errs) == 0, "cleanup incomplete; retained private ownership ledger")
}

// progress prints one JSON event; lanes report phases on stdout only.
func progress(phase, side, status string, fields map[string]any) map[string]any {
	event := map[string]any{"timestamp": now().UTC().Format(time.RFC3339Nano), "phase": phase, "side": side, "status": status}
	for k, v := range fields {
		event[k] = v
	}
	line, _ := json.Marshal(event)
	fmt.Fprintln(progressOut, string(line))
	return event
}

// printable keeps text, tabs and newlines; control sequences become '?'.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f && r != '�') {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

func tail(data []byte, n int) string {
	if len(data) > n {
		data = data[len(data)-n:]
	}
	return strings.ToValidUTF8(string(data), "�")
}

func restrictUmask() { umask(0o077) }

// redact makes an error message safe for public evidence: the private run
// directory becomes a placeholder and non-printable bytes are replaced, so
// paths and raw tool output from the private tree never leave it.
func (o *owned) redact(message string) string {
	return printable(strings.ReplaceAll(message, o.private, "<private-run-directory>"))
}
