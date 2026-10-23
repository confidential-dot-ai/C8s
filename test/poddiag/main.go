// Command poddiag boots one commit's paired rke2-tdx-dev image on the native
// TDX launcher with a Pod fixture signed by the CLI built from that commit and
// retains a bounded serial log. It is a manual, disposable boot diagnostic;
// never image or Pod acceptance.
//
//	poddiag run      # resolve the image, provision a run-owned VM, capture boot logs
//	poddiag cleanup  # remove this run's VM, launch Secret and private root import
//
// The image under diagnosis is the rke2-tdx-dev build published for the commit
// in POD_DIAGNOSTIC_SOURCE, which also supplies the CLI that signs the Pod
// fixture. The manual image workflow refuses a c8s_ref that is not that
// commit, so the image profile and the components come from the same source.
//
// Every cluster resource carries run-scoped labels and a creation nonce
// recorded in a private ledger before the create request, reads check that
// ownership, and deletes are preconditioned on the recorded UID, so a lost
// response or a replaced object is never adopted or deleted.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	repo       = "confidential-dot-ai/node-guest-base"
	pauseImage = "docker.io/rancher/mirrored-pause:3.10.2@sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4"
	namespace  = "confai-images"
	ownerRepo  = "confidential-dot-ai/c8s"
	maxBytes   = 262144
)

//go:embed pod-diagnostic.json
var fixture []byte

var (
	hexCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexRTMR   = regexp.MustCompile(`^[0-9a-f]{96}$`)
	decimal   = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// Seams the offline tests replace. kube runs kubectl in the diagnostic
// namespace; registry fetches one document under repo and returns a nil body
// and header when the tag does not exist.
var (
	kube     = runKubectl
	registry = fetchRegistry
	rename   = os.Rename
	now      = time.Now
	sleep    = time.Sleep
)

func require(condition bool, message string) error {
	if !condition {
		return errors.New(message)
	}
	return nil
}

// budget bounds one request to 30s and never past the phase deadline; a zero
// deadline means no phase.
func budget(deadline time.Time) (time.Duration, error) {
	remaining := 30 * time.Second
	if !deadline.IsZero() {
		remaining = deadline.Sub(now())
	}
	if remaining <= 0 {
		return 0, errors.New("diagnostic phase deadline reached")
	}
	return min(30*time.Second, remaining), nil
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

// write publishes data (or the indented JSON of value) atomically with mode
// 0600; a failed publication leaves the previous file and no temporary.
func write(path string, value any) error {
	data, ok := value.([]byte)
	if !ok {
		var err error
		if data, err = json.MarshalIndent(value, "", "  "); err != nil {
			return err
		}
		data = append(data, '\n')
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

func command(argv []string, data []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		tail := stderr.Bytes()
		if len(tail) > 1200 {
			tail = tail[len(tail)-1200:]
		}
		return nil, fmt.Errorf("command failed: %w: %s", err, strings.ToValidUTF8(string(tail), "?"))
	}
	return stdout.Bytes(), nil
}

func runKubectl(args []string, data []byte, timeout time.Duration) ([]byte, error) {
	return command(append([]string{"kubectl", "-n", namespace}, args...), data, timeout)
}

// object is the subset of a Kubernetes object the diagnostic reads; raw keeps
// the bytes kubectl returned for the evidence.
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
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
	Items []object `json:"items"`
	raw   []byte
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
	obj := &object{raw: body}
	if err := json.Unmarshal(body, obj); err != nil {
		return nil, fmt.Errorf("kubectl %s: %w", args[0], err)
	}
	return obj, nil
}

func (o *object) ownedBy(kind, uid string) bool {
	for _, ref := range o.Metadata.OwnerReferences {
		if ref.Controller && ref.Kind == kind && ref.UID == uid {
			return true
		}
	}
	return false
}

// pins identifies the image under diagnosis and is recorded in identity.json.
type pins struct {
	Source         string `json:"source"`
	ArtifactTag    string `json:"artifactTag"`
	Image          string `json:"image"`
	ManifestSHA256 string `json:"manifestSHA256"`
	DiskSHA256     string `json:"diskSHA256"`
	Scope          string `json:"scope,omitempty"`
}

func validateManifest(data []byte, p pins) (map[string]any, error) {
	sum := sha256.Sum256(data)
	if len(data) > 65536 || hex.EncodeToString(sum[:]) != p.ManifestSHA256 {
		return nil, errors.New("diagnostic manifest digest differs")
	}
	var manifest struct {
		Inputs struct {
			BaseImage struct {
				SHA256 string `json:"sha256"`
			} `json:"base_image"`
		} `json:"inputs"`
		TDX map[string]string `json:"tdx"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("diagnostic manifest: %w", err)
	}
	if manifest.Inputs.BaseImage.SHA256 != p.DiskSHA256 {
		return nil, errors.New("diagnostic disk digest differs")
	}
	for _, k := range []string{"mrtd", "rtmr1", "rtmr2"} {
		if !hexRTMR.MatchString(manifest.TDX[k]) {
			return nil, errors.New("incomplete TDX identity")
		}
	}
	var parsed map[string]any
	return parsed, json.Unmarshal(data, &parsed)
}

func fetchRegistry(path, bearer, accept string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/"+repo+path, nil)
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

// resolve finds the dev image published for one source commit, naming the
// missing tag and the build command otherwise.
func resolve(source, bearer string) (pins, error) {
	if !hexCommit.MatchString(source) {
		return pins{}, errors.New("POD_DIAGNOSTIC_SOURCE must be the full 40-hex commit the image was built from")
	}
	tag, cdiTag := "rke2-tdx-dev-"+source[:7], "rke2-tdx-dev-cdi-"+source[:7]
	hint := fmt.Sprintf("; build it with: gh workflow run c8s-image-manual.yml --ref <branch at %s> -f dev=true -f c8s_ref=%s", source[:7], source[:7])
	body, _, err := registry("/manifests/"+tag, bearer, "application/vnd.oci.image.manifest.v1+json")
	if err != nil {
		return pins{}, err
	}
	if body == nil {
		return pins{}, fmt.Errorf("no published diagnostic artifact ghcr.io/%s:%s%s", repo, tag, hint)
	}
	if len(body) > 65536 {
		return pins{}, errors.New("oversized artifact manifest")
	}
	var artifact struct {
		Layers []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &artifact); err != nil {
		return pins{}, fmt.Errorf("%s: %w", tag, err)
	}
	layers := map[string]string{}
	for _, layer := range artifact.Layers {
		layers[layer.Annotations["org.opencontainers.image.title"]] = layer.Digest
	}
	for _, name := range []string{"manifest.json", "disk.raw"} {
		if !hexDigest.MatchString(layers[name]) {
			return pins{}, fmt.Errorf("%s does not carry manifest.json and disk.raw layers", tag)
		}
	}
	_, headers, err := registry("/manifests/"+cdiTag, bearer, "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json")
	if err != nil {
		return pins{}, err
	}
	if headers == nil {
		return pins{}, fmt.Errorf("no published diagnostic image ghcr.io/%s:%s%s", repo, cdiTag, hint)
	}
	cdi := headers.Get("Docker-Content-Digest")
	if !hexDigest.MatchString(cdi) {
		return pins{}, fmt.Errorf("%s resolved to no content digest", cdiTag)
	}
	return pins{Source: source, ArtifactTag: tag, Image: "ghcr.io/" + repo + "@" + cdi,
		ManifestSHA256: strings.TrimPrefix(layers["manifest.json"], "sha256:"),
		DiskSHA256:     strings.TrimPrefix(layers["disk.raw"], "sha256:")}, nil
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

type diagnostic struct {
	root, private, evidence, ledger, nonceFile string
	run, attempt, repo, name                   string
	pins                                       *pins
}

func newDiagnostic(root, run, attempt, repo string) (*diagnostic, error) {
	if !decimal.MatchString(run) || !decimal.MatchString(attempt) {
		return nil, errors.New("invalid workflow identity")
	}
	if strings.ToLower(repo) != ownerRepo {
		return nil, errors.New("unexpected repository")
	}
	d := &diagnostic{root: root, run: run, attempt: attempt, repo: repo, name: "c8s-poddiag-" + run + "-" + attempt,
		private: filepath.Join(root, "private"), evidence: filepath.Join(root, "evidence")}
	for _, dir := range []string{d.private, d.evidence} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	d.ledger = filepath.Join(d.private, "resources.json")
	d.nonceFile = filepath.Join(d.private, "creation-nonces.json")
	return d, nil
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

func (d *diagnostic) resources() ([]resource, error) {
	var entries []resource
	return entries, readJSON(d.ledger, &entries)
}

// metadata names a resource and mints its creation nonce once; the nonce
// persists so the cleanup process recognises what this run created.
func (d *diagnostic) metadata(suffix string) (metadata, error) {
	nonces := map[string]string{}
	if err := readJSON(d.nonceFile, &nonces); err != nil {
		return metadata{}, err
	}
	if _, ok := nonces[suffix]; !ok {
		entries, err := d.resources()
		if err != nil {
			return metadata{}, err
		}
		for _, e := range entries {
			if e.Suffix == suffix {
				return metadata{}, errors.New("owned resource lost its creation nonce")
			}
		}
		nonces[suffix] = nonce()
		if err := write(d.nonceFile, nonces); err != nil {
			return metadata{}, err
		}
	}
	return metadata{Name: d.name + suffix, Namespace: namespace,
		Labels: map[string]string{"ci.confidential.ai/managed": "true", "ci.confidential.ai/resource": "pod-diagnostic",
			"ci.confidential.ai/run-id": d.run, "ci.confidential.ai/run-attempt": d.attempt},
		Annotations: map[string]string{"ci.confidential.ai/repo": d.repo, "ci.confidential.ai/creation-nonce": nonces[suffix]}}, nil
}

// owned checks that obj is the resource this run created; uid, when set, must
// match the recorded one.
func (d *diagnostic) owned(obj *object, suffix, uid string) error {
	expected, err := d.metadata(suffix)
	if err != nil {
		return err
	}
	actual := obj.Metadata
	if actual.Name != expected.Name || actual.Namespace != expected.Namespace {
		return errors.New("resource name or namespace differs")
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

func (d *diagnostic) entry(kind, suffix string) (resource, error) {
	entries, err := d.resources()
	if err != nil {
		return resource{}, err
	}
	for _, e := range entries {
		if e.Kind == kind && e.Suffix == suffix {
			return e, nil
		}
	}
	return resource{}, fmt.Errorf("no owned %s%s in the ledger", kind, suffix)
}

func (d *diagnostic) create(kind, suffix string, spec any) (*object, error) {
	existing, err := kubeObject([]string{"get", kind, d.name + suffix, "--ignore-not-found", "-o", "json"}, nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("refusing existing resource")
	}
	entries, err := d.resources()
	if err != nil {
		return nil, err
	}
	entries = append(entries, resource{Kind: kind, Suffix: suffix})
	// Record intent before a request whose result could be lost.
	if err := write(d.ledger, entries); err != nil {
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
	if err := d.owned(obj, suffix, ""); err != nil {
		return nil, err
	}
	uid := obj.Metadata.UID
	entries[len(entries)-1].UID = &uid
	return obj, write(d.ledger, entries)
}

func (d *diagnostic) get(kind, suffix string, deadline time.Time) (*object, error) {
	e, err := d.entry(kind, suffix)
	if err != nil {
		return nil, err
	}
	timeout, err := budget(deadline)
	if err != nil {
		return nil, err
	}
	obj, err := kubeObject([]string{"get", kind, d.name + suffix, "-o", "json"}, nil, timeout)
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
	return obj, d.owned(obj, suffix, uid)
}

func bearerToken() (string, error) {
	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/token?service=ghcr.io&scope=repository:"+repo+":pull", nil)
	if err != nil {
		return "", err
	}
	if token := os.Getenv("GH_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(os.Getenv("GITHUB_ACTOR")+":"+token)))
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

// prepare resolves the image, checks the paired CLI and signs the fixture.
func (d *diagnostic) prepare() error {
	bearer, err := bearerToken()
	if err != nil {
		return err
	}
	p, err := resolve(os.Getenv("POD_DIAGNOSTIC_SOURCE"), bearer)
	if err != nil {
		return err
	}
	d.pins = &p
	data, _, err := registry("/blobs/sha256:"+p.ManifestSHA256, bearer, "application/octet-stream")
	if err != nil {
		return err
	}
	if data == nil {
		return errors.New("the artifact's manifest.json blob is missing from the registry")
	}
	if _, err := validateManifest(data, p); err != nil {
		return err
	}
	manifest := filepath.Join(d.evidence, "manifest.json")
	if err := write(manifest, data); err != nil {
		return err
	}
	cli := filepath.Join(d.private, "c8s")
	version, err := command([]string{"go", "version", "-m", cli}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	if !bytes.Contains(version, []byte("vcs.revision="+p.Source)) || !bytes.Contains(version, []byte("vcs.modified=false")) {
		return errors.New("CLI does not match the clean diagnostic source")
	}
	var parts map[string]json.RawMessage
	if err := json.Unmarshal(fixture, &parts); err != nil {
		return fmt.Errorf("fixture: %w", err)
	}
	for _, name := range []string{"pod", "workloads"} {
		if err := write(filepath.Join(d.private, name+".json"), append(bytes.Clone(parts[name]), '\n')); err != nil {
			return err
		}
	}
	common := []string{cli, "node", "launch-config"}
	if _, err := command(append(common, "new", "--out", filepath.Join(d.private, "server"), "--cluster-id", d.name,
		"--image-manifest", manifest), nil, 30*time.Second); err != nil {
		return err
	}
	if _, err := command(append(common, "new-pod", "--out", filepath.Join(d.private, "bundle"), "--cluster-id", d.name,
		"--image-manifest", manifest, "--pod-manifest", filepath.Join(d.private, "pod.json"),
		"--workloads", filepath.Join(d.private, "workloads.json"), "--server-address", "10.255.255.1",
		"--server-public-key", filepath.Join(d.private, "server/server/pubkey")), nil, 30*time.Second); err != nil {
		return err
	}
	identity := p
	identity.Scope = "boot diagnostics only; CDS deliberately unavailable"
	if err := write(filepath.Join(d.evidence, "identity.json"), identity); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "kubectl", "-n", namespace, "auth", "can-i", "create", "services")
	out, probeErr := probe.Output()
	authority := map[string]any{"namespace": namespace, "verb": "create", "resource": "services"}
	if ctx.Err() != nil {
		authority["observation"] = "timed out"
	} else {
		authority["allowed"] = probeErr == nil && string(bytes.TrimSpace(out)) == "yes"
		authority["exitCode"] = probe.ProcessState.ExitCode()
	}
	return write(filepath.Join(d.evidence, "service-authority.json"), authority)
}

// provision imports the image into a run-owned root on the TDX node and
// starts the VM with the signed launch bundle.
func (d *diagnostic) provision() error {
	if d.pins == nil {
		return errors.New("provision needs the resolved image pins from prepare")
	}
	meta, err := d.metadata("-root")
	if err != nil {
		return err
	}
	root := map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": meta,
		"spec": map[string]any{"accessModes": []string{"ReadWriteOnce"}, "storageClassName": "local-path",
			"resources": map[string]any{"requests": map[string]string{"storage": "80Gi"}}}}
	if _, err := d.create("pvc", "-root", root); err != nil {
		return err
	}
	if meta, err = d.metadata("-binder"); err != nil {
		return err
	}
	binder := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": map[string]any{
		"restartPolicy": "Never", "activeDeadlineSeconds": 1500, "automountServiceAccountToken": false,
		"nodeSelector":    map[string]string{"kubevirt.io/tdx": "true"},
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65534, "seccompProfile": map[string]string{"type": "RuntimeDefault"}},
		"containers": []map[string]any{{"name": "pause", "image": pauseImage,
			"resources":       map[string]any{"requests": map[string]string{"cpu": "2", "memory": "8Gi"}, "limits": map[string]string{"cpu": "2", "memory": "8Gi"}},
			"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}}},
		"volumes": []map[string]any{{"name": "root", "persistentVolumeClaim": map[string]any{"claimName": d.name + "-root", "readOnly": true}}}}}
	if _, err := d.create("pod", "-binder", binder); err != nil {
		return err
	}
	deadline := now().Add(300 * time.Second)
	var pvc *object
	for scheduled := false; !scheduled; {
		if !now().Before(deadline) {
			return errors.New("TDX import binder did not schedule")
		}
		var pod *object
		if pvc, err = d.get("pvc", "-root", deadline); err != nil {
			return err
		}
		if pod, err = d.get("pod", "-binder", deadline); err != nil {
			return err
		}
		if node := pod.Spec.NodeName; node != "" && pvc.Status.Phase == "Bound" {
			if pvc.Metadata.Annotations["volume.kubernetes.io/selected-node"] != node {
				return errors.New("root selected another node")
			}
			scheduled = true
			continue
		}
		pause(deadline, 5*time.Second)
	}
	if _, err := kube([]string{"annotate", "pvc", d.name + "-root", "--resource-version=" + pvc.Metadata.ResourceVersion,
		"cdi.kubevirt.io/storage.import.source=registry", "cdi.kubevirt.io/storage.import.endpoint=docker://" + d.pins.Image,
		"cdi.kubevirt.io/storage.contentType=kubevirt", "cdi.kubevirt.io/storage.import.secretName=ghcr-pull"}, nil, 30*time.Second); err != nil {
		return err
	}
	if err := d.remove("pod", "-binder"); err != nil {
		return err
	}
	deadline = now().Add(1200 * time.Second)
	for imported := false; !imported; {
		if !now().Before(deadline) {
			return errors.New("diagnostic CDI import timed out")
		}
		if pvc, err = d.get("pvc", "-root", deadline); err != nil {
			return err
		}
		switch pvc.Metadata.Annotations["cdi.kubevirt.io/storage.pod.phase"] {
		case "Failed":
			return errors.New("diagnostic CDI import failed")
		case "Succeeded":
			imported = true
			continue
		}
		pause(deadline, 10*time.Second)
	}
	bundle := filepath.Join(d.private, "bundle/pod")
	secretData := map[string]string{}
	for _, name := range []string{"pubkey", "launch.yaml", "launch.yaml.sig"} {
		content, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil {
			return err
		}
		secretData[name] = base64.StdEncoding.EncodeToString(content)
	}
	if meta, err = d.metadata("-opkey"); err != nil {
		return err
	}
	if _, err := d.create("secret", "-opkey", map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": meta, "type": "Opaque", "data": secretData}); err != nil {
		return err
	}
	vm, err := d.vm()
	if err != nil {
		return err
	}
	_, err = d.create("vm", "", vm)
	return err
}

func (d *diagnostic) vm() (map[string]any, error) {
	meta, err := d.metadata("")
	if err != nil {
		return nil, err
	}
	return map[string]any{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "metadata": meta, "spec": map[string]any{
		"runStrategy": "Once", "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"kubevirt.io/domain": d.name}}, "spec": map[string]any{
			"nodeSelector": map[string]string{"kubevirt.io/tdx": "true"}, "terminationGracePeriodSeconds": 10,
			"domain": map[string]any{"cpu": map[string]any{"model": "host-passthrough", "cores": 2}, "memory": map[string]string{"guest": "8Gi"},
				"resources": map[string]any{"requests": map[string]string{"memory": "8Gi"}}, "firmware": map[string]any{"bootloader": map[string]any{"efi": map[string]bool{"secureBoot": false}}},
				"launchSecurity": map[string]any{"tdx": map[string]any{}}, "devices": map[string]any{"autoattachVSOCK": true, "logSerialConsole": true, "rng": map[string]any{},
					"disks":      []map[string]any{{"name": "rootdisk", "disk": map[string]any{"bus": "virtio", "readonly": true}}, {"name": "opkey", "disk": map[string]any{"bus": "virtio"}}},
					"interfaces": []map[string]any{{"name": "default", "masquerade": map[string]any{}}}}},
			"networks": []map[string]any{{"name": "default", "pod": map[string]any{}}}, "volumes": []map[string]any{
				{"name": "rootdisk", "persistentVolumeClaim": map[string]string{"claimName": d.name + "-root"}},
				{"name": "opkey", "secret": map[string]string{"secretName": d.name + "-opkey", "volumeLabel": "opkeydata"}}}}}}}, nil
}

func (d *diagnostic) evidenceFile(index int, name string) string {
	return filepath.Join(d.evidence, fmt.Sprintf("%03d-%s", index, name))
}

// capture records the VM, its VMI and launcher Pod, the first and last maxBytes
// of the serial log (a dev image forwards its journal there, so the tail holds
// the latest service output) and the launcher log, reading only objects owned
// through the VM; it reports whether the VMI reached a final phase.
func (d *diagnostic) capture(index int, deadline time.Time) (bool, error) {
	read := func(args []string) (*object, error) {
		timeout, err := budget(deadline)
		if err != nil {
			return nil, err
		}
		return kubeObject(args, nil, timeout)
	}
	readRaw := func(args []string) ([]byte, error) {
		timeout, err := budget(deadline)
		if err != nil {
			return nil, err
		}
		return kube(args, nil, timeout)
	}
	vm, err := d.get("vm", "", deadline)
	if err != nil {
		return false, err
	}
	if err := write(d.evidenceFile(index, "vm.json"), vm.raw); err != nil {
		return false, err
	}
	vmi, err := read([]string{"get", "vmi", d.name, "--ignore-not-found", "-o", "json"})
	if err != nil {
		return false, err
	}
	if vmi == nil {
		return false, nil
	}
	uid := vmi.Metadata.UID
	if !vmi.ownedBy("VirtualMachine", vm.Metadata.UID) {
		return false, errors.New("VMI owner differs")
	}
	if err := write(d.evidenceFile(index, "vmi.json"), vmi.raw); err != nil {
		return false, err
	}
	pods, err := read([]string{"get", "pods", "-l", "kubevirt.io/domain=" + d.name, "-o", "json"})
	if err != nil {
		return false, err
	}
	if pods == nil {
		return false, errors.New("launcher listing returned nothing")
	}
	var listing struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(pods.raw, &listing); err != nil {
		return false, err
	}
	for i, pod := range pods.Items {
		if !pod.ownedBy("VirtualMachineInstance", uid) {
			return false, errors.New("launcher owner differs")
		}
		if err := write(d.evidenceFile(index, "launcher.json"), []byte(listing.Items[i])); err != nil {
			return false, err
		}
		name := pod.Metadata.Name
		for kind, args := range map[string][]string{
			"serial":      {"exec", name, "-c", "compute", "--", "head", "-c", fmt.Sprint(maxBytes), "/var/run/kubevirt-private/" + uid + "/virt-serial0-log"},
			"serial-tail": {"exec", name, "-c", "compute", "--", "tail", "-c", fmt.Sprint(maxBytes), "/var/run/kubevirt-private/" + uid + "/virt-serial0-log"},
			"compute.log": {"logs", name, "-c", "compute", "--tail=500", "--limit-bytes=" + fmt.Sprint(maxBytes), "--timestamps=true"},
		} {
			if err := d.captureLog(index, kind, pod.Metadata.UID, uid, args, read, readRaw); err != nil {
				if err := write(d.evidenceFile(index, kind+"-error.json"), map[string]string{"error": err.Error()}); err != nil {
					return false, err
				}
			}
		}
	}
	return vmi.Status.Phase == "Failed" || vmi.Status.Phase == "Succeeded", nil
}

func (d *diagnostic) captureLog(index int, kind, podUID, vmiUID string, args []string,
	read func([]string) (*object, error), readRaw func([]string) ([]byte, error)) error {
	data, err := readRaw(args)
	if err != nil {
		return err
	}
	if len(data) > maxBytes {
		return errors.New("oversized diagnostic output")
	}
	pod, err := read([]string{"get", "pod", args[1], "-o", "json"})
	if err != nil {
		return err
	}
	if pod == nil || pod.Metadata.UID != podUID {
		return errors.New("launcher replaced during capture")
	}
	vmi, err := read([]string{"get", "vmi", d.name, "-o", "json"})
	if err != nil {
		return err
	}
	if vmi == nil || vmi.Metadata.UID != vmiUID {
		return errors.New("VMI replaced during capture")
	}
	return write(d.evidenceFile(index, kind), data)
}

func (d *diagnostic) observe() error {
	deadline := now().Add(600 * time.Second)
	for index := range 40 {
		final, err := d.capture(index, deadline)
		if err != nil {
			return err
		}
		if final || !now().Before(deadline) {
			break
		}
		pause(deadline, 10*time.Second)
	}
	for _, pattern := range []string{"*-serial", "*-serial-tail", "*-compute.log"} {
		matches, _ := filepath.Glob(filepath.Join(d.evidence, pattern))
		for _, path := range matches {
			if info, err := os.Stat(path); err == nil && info.Size() > 0 {
				return nil
			}
		}
	}
	return errors.New("no serial or launcher log was captured; inspect native status evidence")
}

// remove deletes one owned resource with a UID precondition and waits for it
// to disappear.
func (d *diagnostic) remove(kind, suffix string) error {
	e, err := d.entry(kind, suffix)
	if err != nil {
		return err
	}
	obj, err := kubeObject([]string{"get", kind, d.name + suffix, "--ignore-not-found", "-o", "json"}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	if obj != nil {
		uid := ""
		if e.UID != nil {
			uid = *e.UID
		}
		if err := d.owned(obj, suffix, uid); err != nil {
			return err
		}
		// Preconditions prevent deleting a replacement after the ownership check.
		plural := map[string]string{"vm": "virtualmachines", "pod": "pods", "pvc": "persistentvolumeclaims", "secret": "secrets"}[kind]
		base := "/api/v1"
		if kind == "vm" {
			base = "/apis/kubevirt.io/v1"
		}
		url := fmt.Sprintf("%s/namespaces/%s/%s/%s%s", base, namespace, plural, d.name, suffix)
		options, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "DeleteOptions",
			"preconditions": map[string]string{"uid": obj.Metadata.UID}, "propagationPolicy": "Foreground"})
		if err != nil {
			return err
		}
		if _, err := kube([]string{"delete", "--raw", url, "-f", "-"}, options, 30*time.Second); err != nil {
			return err
		}
	}
	deadline := now().Add(120 * time.Second)
	for now().Before(deadline) {
		timeout, err := budget(deadline)
		if err != nil {
			return err
		}
		remaining, err := kubeObject([]string{"get", kind, d.name + suffix, "--ignore-not-found", "-o", "json"}, nil, timeout)
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

// cleanup removes owned resources newest first and keeps the disks and Secret
// if the VM could still be using them.
func (d *diagnostic) cleanup() error {
	entries, err := d.resources()
	if err != nil {
		return err
	}
	errs := []string{}
	for i := len(entries) - 1; i >= 0; i-- {
		if err := d.remove(entries[i].Kind, entries[i].Suffix); err != nil {
			errs = append(errs, err.Error())
			if entries[i].Kind == "vm" {
				break
			}
		}
	}
	if err := write(filepath.Join(d.evidence, "cleanup.json"), map[string]any{"name": d.name, "complete": len(errs) == 0, "errors": errs}); err != nil {
		return err
	}
	return require(len(errs) == 0, "cleanup incomplete; retained ownership ledger")
}

func run() error {
	if len(os.Args) != 2 || (os.Args[1] != "run" && os.Args[1] != "cleanup") {
		return errors.New("expected run or cleanup")
	}
	restrictUmask()
	d, err := newDiagnostic(filepath.Join(os.Getenv("RUNNER_TEMP"), "pod-diagnostic"),
		os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT"), os.Getenv("GITHUB_REPOSITORY"))
	if err != nil {
		return err
	}
	if os.Args[1] == "cleanup" {
		return d.cleanup()
	}
	entries, err := d.resources()
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("diagnostic run already owns resources")
	}
	err = d.prepare()
	if err == nil {
		err = d.provision()
	}
	if err == nil {
		err = d.observe()
	}
	if err != nil {
		_ = write(filepath.Join(d.evidence, "failure.json"), map[string]string{"error": err.Error(), "type": fmt.Sprintf("%T", err)})
		if entries, _ := d.resources(); hasVM(entries) {
			if _, captureErr := d.capture(999, now().Add(60*time.Second)); captureErr != nil {
				_ = write(filepath.Join(d.evidence, "failure-capture.json"), map[string]string{"error": captureErr.Error()})
			}
		}
		return err
	}
	fmt.Println("Boot evidence captured; this diagnostic does not establish image or Pod connectivity acceptance.")
	return nil
}

func hasVM(entries []resource) bool {
	for _, e := range entries {
		if e.Kind == "vm" {
			return true
		}
	}
	return false
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "poddiag:", err)
		os.Exit(1)
	}
}
