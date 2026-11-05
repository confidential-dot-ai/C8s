// Command fixtures builds the offline test workload for the Pod runtime lane
// and validates its immutable runtime inputs and receipts.
//
// It is built by run.sh at the start of a lane and serves the lane's small
// tools: a bounded command runner, the provenance receipt, the OCI fixture
// image and the three result receipts.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const usage = "usage: fixtures prepare SOURCE STAGE ARCH | image STAGE ARCH | receipt INPUTS RESULT | recovery-receipt INPUTS RESULT | kubelet-receipt INPUTS RESULT | bounded SECONDS COMMAND... | json-string FILE KEY | binaries STAGE OUTPUT"

func main() {
	args := os.Args[1:]
	var err error
	switch {
	case len(args) == 4 && args[0] == "prepare":
		err = prepare(args[1], args[2], args[3])
	case len(args) == 3 && args[0] == "image":
		err = image(args[1], args[2])
	case len(args) == 3 && args[0] == "receipt":
		err = receipt(args[1], args[2])
	case len(args) == 3 && args[0] == "recovery-receipt":
		err = recoveryReceipt(args[1], args[2])
	case len(args) == 3 && args[0] == "kubelet-receipt":
		err = kubeletReceipt(args[1], args[2])
	case len(args) >= 3 && args[0] == "bounded":
		os.Exit(bounded(args[1], args[2:]))
	case len(args) == 3 && args[0] == "json-string":
		err = jsonString(args[1], args[2])
	case len(args) == 3 && args[0] == "binaries":
		err = binaries(args[1], args[2])
	default:
		err = errors.New(usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// pins is test/integration/pod-runtime/runtime-pins.json.
type pins struct {
	RKE2Version                   string            `json:"rke2Version"`
	GuestAirgapBundlesAMD64       map[string]string `json:"guestAirgapBundlesAMD64"`
	RegistryIndex                 string            `json:"registryIndex"`
	HistoricalRuntimeAirgapDigest string            `json:"historicalRuntimeAirgapDigest"`
	Platforms                     map[string]string `json:"platforms"`
	CNI                           cniPins           `json:"cni"`
}

type cniPins struct {
	Version           string            `json:"version"`
	RegistryIndex     string            `json:"registryIndex"`
	AirgapFloorDigest string            `json:"airgapFloorDigest"`
	Platforms         map[string]string `json:"platforms"`
}

var sha256Pin = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// validateRuntimeInputs refuses source or pin drift and returns the
// digest-pinned kind runner image the cluster library names.
func validateRuntimeInputs(source string, p pins, architecture string) (string, error) {
	sync, err := os.ReadFile(filepath.Join(source, "images/node-guest/c8s/mkosi.sync"))
	if err != nil {
		return "", err
	}
	if !equal(submatches(`(?m)^RKE2_VERSION="([^"]+)"$`, sync), []string{p.RKE2Version}) {
		return "", errors.New("runtime pin must be updated with the guest RKE2 version")
	}
	if _, ok := p.Platforms[architecture]; !ok {
		return "", errors.New("runtime integration supports native Linux amd64 and arm64")
	}
	// The guest extracts runtime binaries from these pinned amd64 bundles.
	// rke2-runtime is unpacked, so it is not an executable floor entry.
	for _, bundle := range []string{"core", "cilium"} {
		checksums := submatches(`(?m)^RKE2_IMAGES_`+strings.ToUpper(bundle)+`_SHA256="([a-f0-9]{64})"$`, sync)
		if !equal(checksums, []string{p.GuestAirgapBundlesAMD64[bundle]}) {
			return "", errors.New("runtime pins must be reviewed with the guest " + bundle + " bundle")
		}
	}
	policy, err := os.ReadFile(filepath.Join(source, "images/node-guest/c8s/image-policy.yaml.in"))
	if err != nil {
		return "", err
	}
	expectedCNI := "docker.io/rancher/hardened-cni-plugins:" + p.CNI.Version
	// Match the one current Cilium init rule, not a label or an arbitrary digest.
	entries := regexp.MustCompile(`(?m)^      cilium:\n        initContainers:\n          - digest: "(sha256:[a-f0-9]{64})"\n            image: "(docker\.io/rancher/hardened-cni-plugins:[^"]+)"$`).FindAllSubmatch(policy, -1)
	images := submatches(`(?m)^\s*image: "(docker\.io/rancher/hardened-cni-plugins:[^"]+)"$`, policy)
	if len(entries) != 1 || string(entries[0][1]) != p.CNI.AirgapFloorDigest || string(entries[0][2]) != expectedCNI || !equal(images, []string{expectedCNI}) {
		return "", errors.New("CNI registry pin must be reviewed with the measured Cilium init rule")
	}
	kindLib, err := os.ReadFile(filepath.Join(source, "test/integration/cluster/lib.sh"))
	if err != nil {
		return "", err
	}
	runner := submatches(`NODE_IMAGE="\$\{C8S_IT_NODE_IMAGE:-([^}]+)\}"`, kindLib)
	if len(runner) != 1 || !regexp.MustCompile(`^kindest/node:[A-Za-z0-9.-]+@sha256:[a-f0-9]{64}$`).MatchString(runner[0]) {
		return "", errors.New("expected the existing digest-pinned kind runner image")
	}
	digests := []string{p.RegistryIndex, p.HistoricalRuntimeAirgapDigest, p.CNI.RegistryIndex, p.CNI.AirgapFloorDigest}
	for _, m := range []map[string]string{p.Platforms, p.CNI.Platforms} {
		for _, d := range m {
			digests = append(digests, d)
		}
	}
	for _, d := range digests {
		if !sha256Pin.MatchString(d) {
			return "", errors.New("runtime inputs require sha256 pins")
		}
	}
	return runner[0], nil
}

func submatches(pattern string, data []byte) []string {
	var out []string
	for _, m := range regexp.MustCompile(pattern).FindAllSubmatch(data, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

func equal(a, b []string) bool { return reflect.DeepEqual(a, b) }

// gitOutput runs git in dir; tests replace it.
var gitOutput = func(dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// inputs is the lane's provenance receipt, inputs.json.
type inputs struct {
	RunID                         string            `json:"runId"`
	SourceRevision                string            `json:"sourceRevision"`
	SourceDiffSHA256              string            `json:"sourceDiffSHA256"`
	KubeletTestSHA256             string            `json:"kubeletTestSHA256"`
	RecoveryTestSHA256            string            `json:"recoveryTestSHA256"`
	RKE2Version                   string            `json:"rke2Version"`
	RuntimeImage                  string            `json:"runtimeImage"`
	CNIImage                      string            `json:"cniImage"`
	CNIRegistryIndex              string            `json:"cniRegistryIndex"`
	CNIAirgapFloorDigest          string            `json:"cniAirgapFloorDigest"`
	RuntimeRegistryIndex          string            `json:"runtimeRegistryIndex"`
	RuntimePlatformDigest         string            `json:"runtimePlatformDigest"`
	HistoricalRuntimeAirgapDigest string            `json:"historicalRuntimeAirgapDigest"`
	GuestAirgapBundlesAMD64       map[string]string `json:"guestAirgapBundlesAMD64"`
	RunnerImage                   string            `json:"runnerImage"`
	Architecture                  string            `json:"architecture"`
	Scope                         string            `json:"scope"`
	RuntimeProvenance             string            `json:"runtimeProvenance"`
}

func prepare(source, stage, architecture string) error {
	var p pins
	raw, err := os.ReadFile(filepath.Join(source, "test/integration/pod-runtime/runtime-pins.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	runner, err := validateRuntimeInputs(source, p, architecture)
	if err != nil {
		return err
	}
	revision, err := gitOutput(source, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	diff, err := gitOutput(source, "diff", "HEAD", "--binary")
	if err != nil {
		return err
	}
	kubeletTest, err := fileSHA256(filepath.Join(source, "internal/cmds/nri-image-policy/pod_runtime_kubelet_integration_linux_test.go"))
	if err != nil {
		return err
	}
	recoveryTest, err := fileSHA256(filepath.Join(source, "internal/cmds/nri-image-policy/pod_runtime_recovery_integration_linux_test.go"))
	if err != nil {
		return err
	}
	runID, err := newRunID()
	if err != nil {
		return err
	}
	in := inputs{
		RunID:                         runID,
		SourceRevision:                strings.TrimSpace(string(revision)),
		SourceDiffSHA256:              hexSHA256(diff),
		KubeletTestSHA256:             kubeletTest,
		RecoveryTestSHA256:            recoveryTest,
		RKE2Version:                   p.RKE2Version,
		RuntimeImage:                  "docker.io/rancher/rke2-runtime@" + p.Platforms[architecture],
		CNIImage:                      "docker.io/rancher/hardened-cni-plugins@" + p.CNI.Platforms[architecture],
		CNIRegistryIndex:              p.CNI.RegistryIndex,
		CNIAirgapFloorDigest:          p.CNI.AirgapFloorDigest,
		RuntimeRegistryIndex:          p.RegistryIndex,
		RuntimePlatformDigest:         p.Platforms[architecture],
		HistoricalRuntimeAirgapDigest: p.HistoricalRuntimeAirgapDigest,
		GuestAirgapBundlesAMD64:       p.GuestAirgapBundlesAMD64,
		RunnerImage:                   runner,
		Architecture:                  architecture,
		Scope:                         "native snapshotter; simulated measurement register and credential broker",
		RuntimeProvenance:             "digest-pinned registry release runtime; runtime/CNI guest airgap byte equivalence unverified",
	}
	if err := writeJSON(filepath.Join(stage, "inputs.json"), in); err != nil {
		return err
	}
	identities, err := os.ReadFile(filepath.Join(source, "internal/testdata/node-identities.json"))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stage, "pins.json"), identities, 0o600)
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int               `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// image writes the two single-layer fixture images as an OCI layout tar.
func image(stage, architecture string) error {
	blobs := map[string][]byte{}
	blob := func(data []byte, media string) descriptor {
		digest := hexSHA256(data)
		blobs["blobs/sha256/"+digest] = data
		return descriptor{MediaType: media, Digest: "sha256:" + digest, Size: len(data)}
	}
	obj := func(value any, media string) (descriptor, error) {
		data, err := json.Marshal(value)
		if err != nil {
			return descriptor{}, err
		}
		return blob(data, media), nil
	}
	marker, err := os.ReadFile(filepath.Join(stage, "marker-workload"))
	if err != nil {
		return err
	}
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	for _, name := range []string{"pause", "marker-workload"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(marker)), Mode: 0o755, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(marker); err != nil {
			return err
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "tmp", Mode: 0o1777, Typeflag: tar.TypeDir}); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	layerDesc := blob(layer.Bytes(), "application/vnd.oci.image.layer.v1.tar")
	var descriptors []descriptor
	for _, name := range []string{"pod-start", "pod-recovery-mesh"} {
		config, err := obj(map[string]any{
			"architecture": architecture,
			"os":           "linux",
			"config":       map[string]any{"Entrypoint": []string{"/pause"}, "Env": []string{}, "Labels": map[string]string{"fixture": name}},
			"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{layerDesc.Digest}},
		}, "application/vnd.oci.image.config.v1+json")
		if err != nil {
			return err
		}
		manifest, err := obj(map[string]any{
			"schemaVersion": 2,
			"mediaType":     "application/vnd.oci.image.manifest.v1+json",
			"config":        config,
			"layers":        []descriptor{layerDesc},
		}, "application/vnd.oci.image.manifest.v1+json")
		if err != nil {
			return err
		}
		tag := "example.invalid/" + name + ":fixture"
		manifest.Annotations = map[string]string{"org.opencontainers.image.ref.name": tag}
		descriptors = append(descriptors, manifest)
		output := "fixture.json"
		if name != "pod-start" {
			output = "mesh-fixture.json"
		}
		fixture := map[string]string{"tag": tag, "pin": manifest.Digest, "reference": "example.invalid/" + name + "@" + manifest.Digest}
		if err := writeJSON(filepath.Join(stage, output), fixture); err != nil {
			return err
		}
	}
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": descriptors})
	if err != nil {
		return err
	}
	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index}
	for name, data := range blobs {
		files[name] = data
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	out, err := os.Create(filepath.Join(stage, "fixtures.tar"))
	if err != nil {
		return err
	}
	tw = tar.NewWriter(out)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(files[name])), Mode: 0o644, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(files[name]); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return out.Close()
}

// loadPair decodes a receipt against the inputs it must belong to.
func loadPair(inputsPath, resultPath, what string) (map[string]any, error) {
	var in, result map[string]any
	if err := readJSON(inputsPath, &in); err != nil {
		return nil, err
	}
	if err := readJSON(resultPath, &result); err != nil {
		return nil, err
	}
	if result["runId"] != in["runId"] {
		return nil, errors.New(what + " result is not from this invocation")
	}
	return result, nil
}

func receipt(inputsPath, resultPath string) error {
	var in map[string]any
	if err := readJSON(inputsPath, &in); err != nil {
		return err
	}
	result, err := loadPair(inputsPath, resultPath, "runtime")
	if err != nil {
		return err
	}
	if result["architecture"] != in["architecture"] {
		return errors.New("runtime result architecture does not match its inputs")
	}
	if result["sandbox-started-without-workload-permission"] != true {
		return errors.New("missing sandbox start assertion")
	}
	modes := []string{"absent", "deny", "failed-extend", "late", "socket-lost", "disconnect", "replayed", "admit"}
	cases, _ := result["cases"].(map[string]any)
	if !sameSet(keys(cases), modes) {
		return errors.New("runtime receipt must contain all eight required cases")
	}
	containerIDs := map[string]bool{}
	for mode, raw := range cases {
		c, _ := raw.(map[string]any)
		containerID, ok := c["containerId"].(string)
		if !ok || containerID == "" || containerIDs[containerID] {
			return errors.New("each runtime case requires a distinct container identity")
		}
		containerIDs[containerID] = true
		if executed, ok := c["markerExecuted"].(bool); !ok || executed != (mode == "admit") {
			return errors.New("runtime marker assertion failed: " + mode)
		}
		if mode != "admit" && !truthy(c["refusal"]) {
			return errors.New("missing runtime refusal: " + mode)
		}
		if mode != "absent" {
			request, _ := c["nriRequest"].(map[string]any)
			pid, pidOK := positiveInt(request["pid"])
			if request["containerId"] != containerID || !truthy(request["sandboxId"]) || request["sandboxId"] != result["sandboxId"] || !pidOK {
				return errors.New("invalid created NRI process identity: " + mode)
			}
			consumed := c["consumedByWrapper"]
			if mode == "admit" {
				taskPID, _ := positiveInt(c["taskPid"])
				if !reflect.DeepEqual(consumed, []any{c["nriRequest"]}) || taskPID != pid {
					return errors.New("wrapper did not consume the exact created task once")
				}
			} else if truthy(consumed) {
				return errors.New("wrapper consumed a refused runtime permission: " + mode)
			}
		}
	}
	fmt.Println("PASS: fresh runtime receipt validates all eight cases and exact task identity")
	return nil
}

var credentialInstanceID = regexp.MustCompile(`^pcvm-[a-f0-9]{64}$`)

func recoveryReceipt(inputsPath, resultPath string) error {
	result, err := loadPair(inputsPath, resultPath, "recovery")
	if err != nil {
		return err
	}
	for _, key := range []string{"fullClaimsPreserved", "taskPreserved", "oldGrantRefused", "cgroupIdentityChecked", "sandboxCleanup"} {
		if result[key] != true {
			return errors.New("missing production recovery assertion: " + key)
		}
	}
	for _, key := range []string{"pluginProcessIds", "containerdProcessIds"} {
		if !twoDistinctPIDs(result[key]) {
			return errors.New("recovery did not replace the real processes: " + key)
		}
	}
	ids := map[string]bool{}
	for _, key := range []string{"meshContainerId", "appContainerId", "removedContainerId", "postRecoveryContainerId"} {
		id, ok := result[key].(string)
		if !ok || id == "" {
			return errors.New("recovery requires four distinct actual runtime container identities")
		}
		ids[id] = true
	}
	if len(ids) != 4 {
		return errors.New("recovery requires four distinct actual runtime container identities")
	}
	observations, _ := positiveInt(result["historicalObservations"])
	digests, _ := result["measuredDigests"].([]any)
	if observations != 3 || len(digests) != 2 {
		return errors.New("recovery did not preserve distinct removed same-image history")
	}
	if !reflect.DeepEqual(result["negative"], map[string]any{"missing-history": true, "tampered-history": true, "pending-transition": true}) {
		return errors.New("recovery must refuse each invalid retained-history state")
	}
	if id, _ := result["credentialInstanceId"].(string); !credentialInstanceID.MatchString(id) {
		return errors.New("missing stable recovery credential identity")
	}
	if policy, _ := result["assignedPolicySHA256"].(string); !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(policy) {
		return errors.New("missing unchanged assigned-policy identity")
	}
	if _, ok := positiveInt(result["taskPid"]); !ok || !truthy(result["sandboxId"]) {
		return errors.New("missing retained actual task identity")
	}
	fmt.Println("PASS: fresh production recovery receipt validates actual process restart, full history and fail-closed state")
	return nil
}

func kubeletReceipt(inputsPath, resultPath string) error {
	result, err := loadPair(inputsPath, resultPath, "kubelet recovery")
	if err != nil {
		return err
	}
	for _, key := range []string{"assignmentPreserved", "fullClaimsPreserved", "tasksPreserved", "kubeletReportedRunning", "sandboxCleanup"} {
		if result[key] != true {
			return errors.New("missing actual kubelet recovery assertion: " + key)
		}
	}
	for _, key := range []string{"kubeletProcessIds", "pluginProcessIds", "containerdProcessIds"} {
		if !twoDistinctPIDs(result[key]) {
			return errors.New("kubelet recovery did not replace the actual service process: " + key)
		}
	}
	if id, _ := result["credentialInstanceId"].(string); !credentialInstanceID.MatchString(id) || !truthy(result["runtimePodUID"]) {
		return errors.New("kubelet recovery lost credential or runtime Pod identity")
	}
	for _, key := range []string{"appPID", "meshPID"} {
		if _, ok := positiveInt(result[key]); !ok {
			return errors.New("kubelet recovery is missing its retained task PID")
		}
	}
	app, mesh := result["appContainerId"], result["meshContainerId"]
	if !truthy(app) || !truthy(mesh) || app == mesh {
		return errors.New("kubelet recovery is missing distinct task identities")
	}
	fmt.Println("PASS: fresh kubelet receipt validates actual static Pod service restart and retained tasks")
	return nil
}

// bounded runs a command under a deadline, as the lane's bounded helper.
func bounded(seconds string, command []string) int {
	limit, err := strconv.Atoi(seconds)
	if err != nil {
		fmt.Fprintln(os.Stderr, usage)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(limit)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "command exceeded its bounded deadline: "+command[0])
		return 1
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// jsonString prints one string field of a JSON object.
func jsonString(path, key string) error {
	var m map[string]any
	if err := readJSON(path, &m); err != nil {
		return err
	}
	value, ok := m[key].(string)
	if !ok {
		return errors.New("missing string field: " + key)
	}
	fmt.Println(value)
	return nil
}

// binaries records the digest and size of every runtime binary the lane
// copies into its container.
func binaries(stage, output string) error {
	var files []string
	for _, dir := range []string{"runtime", "cni"} {
		entries, err := os.ReadDir(filepath.Join(stage, dir))
		if err != nil {
			return err
		}
		for _, e := range entries {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	files = append(files, "c8s-runc", "nri-runtime.test")
	records := map[string]map[string]any{}
	for _, name := range files {
		path := filepath.Join(stage, name)
		digest, err := fileSHA256(path)
		if err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		records[name] = map[string]any{"sha256": digest, "size": info.Size()}
	}
	return writeJSON(output, records)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// newRunID is a random version 4 UUID.
func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// positiveInt accepts a JSON integer above zero, not a float or a bool.
func positiveInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil || i <= 0 {
		return 0, false
	}
	return i, true
}

func twoDistinctPIDs(v any) bool {
	list, ok := v.([]any)
	if !ok || len(list) != 2 {
		return false
	}
	a, okA := positiveInt(list[0])
	b, okB := positiveInt(list[1])
	return okA && okB && a != b
}

// truthy mirrors a JSON value's truth: absent, null, false, zero, "" and
// empty containers are false.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		return x.String() != "0"
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		if !set[s] {
			return false
		}
	}
	return len(set) == len(b)
}
