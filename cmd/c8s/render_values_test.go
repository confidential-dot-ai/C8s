//go:build !c8s_node

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestValueArgsToTreeNestsDottedKeys(t *testing.T) {
	got, err := valueArgsToTree([]string{
		"--set-string", "attestationApi.image.repository=ghcr.io/x/attestation-api",
		"--set-string", "attestationApi.image.digest=sha256:abc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{
		"attestationApi": map[string]any{
			"image": map[string]any{
				"repository": "ghcr.io/x/attestation-api",
				"digest":     "sha256:abc",
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestValueArgsToTreeBuildsListFromIndexedKeys(t *testing.T) {
	got, err := valueArgsToTree([]string{
		"--set-string", "cds.measurements[0]=aa",
		"--set-string", "cds.measurements[1]=bb",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{
		"cds": map[string]any{"measurements": []any{"aa", "bb"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v (indexed keys must nest as a list, not a scalar key)", got, want)
	}
}

// A '[' that is not a clean trailing key[n] is outside the grammar and must
// error at runtime, not silently become a literal map key — so a mis-emitting
// builder fails loudly rather than writing a bogus key.
func TestValueArgsToTreeRejectsMalformedIndex(t *testing.T) {
	for _, kv := range []string{
		"a.b[x].c=x",  // non-numeric mid-path
		"a.b[=x",      // unterminated
		"a.b[x]=x",    // non-numeric
		"a.b[0][1]=x", // nested index
	} {
		if _, err := valueArgsToTree([]string{"--set-string", kv}); err == nil {
			t.Errorf("valueArgsToTree(%q) = nil error, want a grammar error", kv)
		}
	}
}

// An inner key[n] builds a list of maps, as an allowlist entry's containers do.
func TestValueArgsToTreeNestsListsOfMaps(t *testing.T) {
	got, err := valueArgsToTree([]string{
		"--set-string", "w.containers[1].digest=b",
		"--set-string", "w.containers[0].digest=a",
		"--set-string", "w.containers[0].mounts.rules[0].kind=emptyDir",
	})
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	want := map[string]any{"w": map[string]any{"containers": []any{
		map[string]any{"digest": "a", "mounts": map[string]any{"rules": []any{map[string]any{"kind": "emptyDir"}}}},
		map[string]any{"digest": "b"},
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("valueArgsToTree() = %#v, want %#v", got, want)
	}
	if _, err := valueArgsToTree([]string{"--set-string", "a.b=x", "--set-string", "a.b[0].c=y"}); err == nil {
		t.Error("valueArgsToTree() indexed a scalar, want a conflict error")
	}
}

func TestValueArgsToTreeCoercesSetTypes(t *testing.T) {
	// --set typing mirrors helm strvals: null/bool/int are coerced, the rest
	// stay strings. --set-string never coerces.
	got, err := valueArgsToTree([]string{
		"--set", "cds.node.selector=null",
		"--set", "attestationApi.teeDevices.sevGuest=true",
		"--set", "attestationApi.teeDevices.tpm=false",
		"--set", "webhook.getCert.runAsUser=65532",
		"--set-string", "attestationApi.cvmMode=aks",
		"--set-string", "image.tag=main",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cds := got["cds"].(map[string]any)["node"].(map[string]any)
	if cds["selector"] != nil {
		t.Errorf("selector: got %#v, want nil (real null)", cds["selector"])
	}
	tee := got["attestationApi"].(map[string]any)["teeDevices"].(map[string]any)
	if tee["sevGuest"] != true {
		t.Errorf("sevGuest: got %#v, want bool true", tee["sevGuest"])
	}
	if tee["tpm"] != false {
		t.Errorf("tpm: got %#v, want bool false", tee["tpm"])
	}
	if got["webhook"].(map[string]any)["getCert"].(map[string]any)["runAsUser"] != int64(65532) {
		t.Errorf("runAsUser: want int64 65532")
	}
	// --set-string keeps "aks"/"main" as strings (cvmMode and tag are never
	// coerced even though they look plain).
	if got["attestationApi"].(map[string]any)["cvmMode"] != "aks" {
		t.Errorf("cvmMode: want string \"aks\"")
	}
	if got["image"].(map[string]any)["tag"] != "main" {
		t.Errorf("tag: want string \"main\"")
	}
}

func TestValueArgsToTreeRejectsScalarMapConflict(t *testing.T) {
	// A scalar at a.b then a map at a.b.c is a builder bug, not a silent merge.
	_, err := valueArgsToTree([]string{
		"--set-string", "a.b=scalar",
		"--set-string", "a.b.c=nested",
	})
	if err == nil {
		t.Fatal("expected a conflict error, got nil")
	}
}

// Descending into a key previously cleared with `=null` must create the map,
// not mis-report the nil as a "scalar conflict". A real scalar still conflicts
// (covered above). Terminal writes keep helm's last-wins semantics — this only
// fixes the intermediate-nil descend. (Latent today: no builder emits such a
// pair, but the nil-as-scalar error would be a sharp edge if one ever did.)
func TestValueArgsToTreeDescendsThroughNull(t *testing.T) {
	got, err := valueArgsToTree([]string{
		"--set", "a=null",
		"--set-string", "a.b=v",
	})
	if err != nil {
		t.Fatalf("descend through null should not error, got: %v", err)
	}
	want := map[string]any{"a": map[string]any{"b": "v"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestValueArgsToTreeRejectsMalformedArg(t *testing.T) {
	if _, err := valueArgsToTree([]string{"--set", "noequalshere"}); err == nil {
		t.Fatal("expected error for value arg without '='")
	}
	if _, err := valueArgsToTree([]string{"--set"}); err == nil {
		t.Fatal("expected error for dangling flag with no key=value")
	}
}

// TestValueArgsToTreeSetFileReadsContent pins helm's --set-file semantics: the
// token's value names a file and the tree gets that file's content verbatim.
// Regression test for the operator-keys ConfigMap that shipped a filesystem
// path as its content instead of the PEM bundle.
func TestValueArgsToTreeSetFileReadsContent(t *testing.T) {
	pemText := "-----BEGIN PUBLIC KEY-----\nMFkwfakefakefake\n-----END PUBLIC KEY-----\n"
	path := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(path, []byte(pemText), 0o600); err != nil {
		t.Fatalf("write temp key file: %v", err)
	}

	got, err := valueArgsToTree([]string{"--set-file", "cds.operatorKeys=" + path})
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	if v := got["cds"].(map[string]any)["operatorKeys"]; v != pemText {
		t.Errorf("operatorKeys: got %#v, want the file's content (not the path)", v)
	}

	if _, err := valueArgsToTree([]string{"--set-file", "cds.operatorKeys=" + filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Fatal("expected error for --set-file naming a missing file")
	}
}

func TestValueArgsToTreeRejectsUnknownFlag(t *testing.T) {
	if _, err := valueArgsToTree([]string{"--set-json", `a={"b":1}`}); err == nil {
		t.Fatal("expected error for a value flag the parser does not implement")
	}
}

// setCvmModeForTest pins the required --cvm-mode global for a buildValueArgs
// test and restores the prior value, so a mode leaked from another test cannot
// change the emitted args.
func setCvmModeForTest(t *testing.T, mode string) {
	t.Helper()
	prev, prevPlat := installCvmMode, installHardwarePlatform
	installCvmMode = mode
	// --hardware-platform has no default anymore; state it like a caller must.
	installHardwarePlatform = "sev-snp"
	t.Cleanup(func() { installCvmMode, installHardwarePlatform = prev, prevPlat })
}

// buildValueArgs must assume nothing the operator did not pass — like install,
// an unset --distro (distro == "") emits no distro keys, leaving the chart
// default to stand; a set --distro configures the NRI installer.
func TestBuildValueArgsOmitsDistroWhenUnset(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "bare-metal", "")
	setCvmModeForTest(t, "bare-metal")

	// Isolate the distro logic from the crane digest path (which needs the
	// binary on PATH); this test is about what the builder assumes, not digests.
	prev := installResolveDigests
	installResolveDigests = false
	defer func() { installResolveDigests = prev }()

	args, err := buildValueArgs(context.Background(), cmd, "", nil, "main", "", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if slices.ContainsFunc(args, func(a string) bool {
		return a == "nriImagePolicy.distro=" ||
			a == "nriImagePolicy.distro=k8s"
	}) {
		t.Fatalf("unset distro should emit no distro keys, got %v", args)
	}

	args, err = buildValueArgs(context.Background(), cmd, "", nil, "main", "rke2", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Contains(args, "nriImagePolicy.distro=rke2") {
		t.Fatalf("set distro should plumb the NRI component key, got %v", args)
	}
}

// On the no-digest path a numeric or zero-padded image tag (a date or build-id
// tag) must survive as a string: buildValueArgs emits .tag via --set-string, so
// coerce never int-coerces it (0640 -> 640 would pin the wrong image).
func TestBuildValueArgsKeepsNumericImageTagAString(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "bare-metal", "")
	setCvmModeForTest(t, "bare-metal")
	prev := installResolveDigests
	installResolveDigests = false // tag is the sole image ref only when digests are off
	defer func() { installResolveDigests = prev }()

	args, err := buildValueArgs(context.Background(), cmd, "",
		[]c8sComponent{{valuePrefix: "cds.image", repository: "ghcr.io/x/cds"}},
		"0640", "", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tree, err := valueArgsToTree(args)
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	if got := tree["cds"].(map[string]any)["image"].(map[string]any)["tag"]; got != "0640" {
		t.Errorf("tag: got %#v, want string \"0640\" (must not int-coerce to 640)", got)
	}
}

// When digests are resolved, the bundle must pin by digest only: emitting .tag
// too is redundant. The injected resolver mirrors appendResolvedDigestArgs
// (repository + digest + deriveComponents), so the test also confirms allowlist
// derivation survives to the tree and keeps crane off PATH.
func TestBuildValueArgsOmitsTagWhenDigestsResolved(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "bare-metal", "")
	setCvmModeForTest(t, "bare-metal")

	prevFlag := installResolveDigests
	defer func() { installResolveDigests = prevFlag }()
	installResolveDigests = true
	stubResolver := func(_ context.Context, _ string, args []string, _ string, comps []c8sComponent) ([]string, error) {
		for _, c := range comps {
			args = append(args, "--set-string", c.valuePrefix+".repository="+c.repository,
				"--set-string", c.valuePrefix+".digest=sha256:abc")
		}
		return append(args, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"), nil
	}

	got, err := buildValueArgs(context.Background(), cmd, "",
		[]c8sComponent{{valuePrefix: "cds.image", repository: "ghcr.io/x/cds"}},
		"main", "", stubResolver)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tree, err := valueArgsToTree(got)
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	img := tree["cds"].(map[string]any)["image"].(map[string]any)
	if _, hasTag := img["tag"]; hasTag {
		t.Errorf("digest path must not emit a tag, got image=%#v", img)
	}
	if img["digest"] != "sha256:abc" {
		t.Errorf("digest: got %#v, want sha256:abc", img["digest"])
	}
	if got := tree["nriImagePolicy"].(map[string]any)["bootstrapAllowlist"].(map[string]any)["deriveComponents"]; got != true {
		t.Errorf("deriveComponents: got %#v, want bool true", got)
	}
}

// writeComputedValues turns the --set pairs into a real values.yaml file that
// helm can read back — install passes it as -f instead of inline --set flags.
func TestWriteComputedValuesProducesReadableFile(t *testing.T) {
	path, err := writeComputedValues([]string{
		"--set-string", "image.repository=ghcr.io/x/c8s-operator",
		"--set", "attestationApi.teeDevices.tpm=true",
		"--set", "cds.node.selector=null",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read computed values: %v", err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("computed values is not valid yaml: %v\n%s", err, data)
	}
	if got["image"].(map[string]any)["repository"] != "ghcr.io/x/c8s-operator" {
		t.Errorf("repository not in computed values: %#v", got["image"])
	}
	if got["attestationApi"].(map[string]any)["teeDevices"].(map[string]any)["tpm"] != true {
		t.Errorf("tpm should be bool true: %#v", got["attestationApi"])
	}
	// null clears the key (real YAML null, not the string "null").
	cds := got["cds"].(map[string]any)["node"].(map[string]any)
	if v, ok := cds["selector"]; !ok || v != nil {
		t.Errorf("selector should be present and null, got %#v (present=%v)", v, ok)
	}
}

// coerceSafeValueArg is the value-arg grammar valueArgsToTree / coerce actually
// handle: a single `dotted.path=value` token whose path segments are
// [A-Za-z0-9.], optionally with a single trailing list index (`foo.bar[0]`).
// Still excluded: escaped dots (`a\.b`), comma-joined multi-values (`a=1,b=2`),
// nested indices. valueArgsToTree's doc opts out of the rest of helm's --set
// grammar on the promise that buildValueArgs never emits those shapes.
var coerceSafeValueArg = regexp.MustCompile(`^[A-Za-z0-9.]+(\[[0-9]+\])?=[^,]*$`)

// TestBuildValueArgsStaysWithinParserGrammar is the lockstep guard between the
// emitter (buildValueArgs / buildDigestArgs) and the parser (valueArgsToTree /
// coerce). The parser handles only a subset of helm's --set grammar; this
// drives the real builders with every value-producing toggle set and asserts
// each emitted token stays inside that subset and round-trips cleanly. Without
// it, a helper that emits e.g. `foo[0]=x`, an escaped dot, or a bare
// non-value flag would silently break BOTH install and render-values (the
// shared path hides the divergence) with every existing test still green.
func TestBuildValueArgsStaysWithinParserGrammar(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "bare-metal", "")
	cmd.Flags().Int64("webhook-cert-fs-group", 0, "")
	cmd.Flags().Duration("webhook-get-cert-renew-interval", 0, "")
	cmd.Flags().Int64("webhook-get-cert-run-as-user", 0, "")
	cmd.Flags().Int64("webhook-get-cert-run-as-group", 0, "")
	cmd.Flags().Bool("webhook-get-cert-run-as-non-root", false, "")
	for _, name := range []string{
		flagCvmMode, "webhook-cert-fs-group",
		"webhook-get-cert-renew-interval", "webhook-get-cert-run-as-user",
		"webhook-get-cert-run-as-group", "webhook-get-cert-run-as-non-root",
	} {
		if err := cmd.Flags().Set(name, cmd.Flags().Lookup(name).DefValue); err != nil {
			t.Fatalf("mark %q changed: %v", name, err)
		}
	}

	prev := struct {
		crds, singleNode, resolveDigests          bool
		secret, cvm, plat, upstream, operatorKeys string
		workloadRefs, measurements                []string
	}{installCRDs, installSingleNode, installResolveDigests, installImagePullSecret, installCvmMode, installHardwarePlatform, installUpstream, installOperatorKeys, slices.Clone(installWorkloadRefs), slices.Clone(installMeasurements)}
	defer func() {
		installCRDs, installSingleNode, installResolveDigests = prev.crds, prev.singleNode, prev.resolveDigests
		installImagePullSecret, installCvmMode = prev.secret, prev.cvm
		installHardwarePlatform = prev.plat
		installUpstream = prev.upstream
		installOperatorKeys = prev.operatorKeys
		installWorkloadRefs = prev.workloadRefs
		installMeasurements = prev.measurements
	}()
	// Drive every value-producing toggle. --install-crds=false exercises the
	// non-default CRD path; --resolve-digests=false keeps crane off PATH (the
	// digest-arg shape is covered separately via buildDigestArgs below).
	// --measurements exercises the indexed key[i]= form in a second pass below.
	installCRDs, installSingleNode, installResolveDigests = false, true, false
	installImagePullSecret, installCvmMode = "regcred", "bare-metal"
	installHardwarePlatform = "sev-snp"
	installOperatorKeys = writeTestOperatorKeys(t)

	args, err := buildValueArgs(context.Background(), cmd, "", nil, "main", "rke2", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("buildValueArgs: %v", err)
	}
	// Add the digest helper's repository/digest tokens (stubbed resolver, no crane).
	args, err = buildDigestArgs(args, "main",
		[]c8sComponent{{valuePrefix: "cds.image", repository: "ghcr.io/x/cds"}},
		func(string) (string, error) { return "sha256:abc", nil },
		func(string) (bool, error) { return true, nil })
	if err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}

	for i := 0; i < len(args); i += 2 {
		if flag := args[i]; flag != "--set" && flag != "--set-string" && flag != "--set-file" {
			t.Fatalf("arg %d: expected --set/--set-string/--set-file, got %q (slice: %v)", i, flag, args)
		}
		if i+1 >= len(args) {
			t.Fatalf("dangling %s with no key=value", args[i])
		}
		if kv := args[i+1]; !coerceSafeValueArg.MatchString(kv) {
			t.Errorf("value arg %q is outside the grammar valueArgsToTree handles "+
				"(list index, escaped dot, comma multi-value, or a bare non-value flag); "+
				"update coerce/valueArgsToTree or keep the builders within the subset", kv)
		}
	}

	// The whole point of the grammar guard is that these args round-trip
	// through the parser cleanly, so prove it — including that the --set-file
	// pair lands as the key file's CONTENT, not its path (the operator-keys
	// ConfigMap regression).
	tree, err := valueArgsToTree(args)
	if err != nil {
		t.Fatalf("builder output failed to parse: %v", err)
	}
	keys, _ := tree["cds"].(map[string]any)["operatorKeys"].(string)
	if keys == installOperatorKeys || !strings.Contains(keys, "BEGIN PUBLIC KEY") {
		t.Fatalf("cds.operatorKeys = %q, want the PEM content of %s", keys, installOperatorKeys)
	}

	// Second pass: bare-metal mode with --measurements exercises the indexed key[i]=
	// form. Its args must also stay within the
	// grammar and round-trip to a list.
	installCvmMode = "bare-metal"
	installMeasurements = []string{strings.Repeat("ab", 48)}
	mArgs, err := appendCvmModeInstallArgs(nil, installCvmMode, installHardwarePlatform)
	if err != nil {
		t.Fatalf("appendCvmModeInstallArgs (bare-metal + measurements): %v", err)
	}
	for i := 0; i < len(mArgs); i += 2 {
		if kv := mArgs[i+1]; !coerceSafeValueArg.MatchString(kv) {
			t.Errorf("measurement arg %q is outside the grammar", kv)
		}
	}
	if _, err := valueArgsToTree(mArgs); err != nil {
		t.Fatalf("measurement args failed to parse: %v", err)
	}
}

// render-values refuses --upstream and --workload-ref: values carry neither
// the route manifest nor the workload patch.
func TestRenderValuesRefusesRoutingFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--upstream", "infer"},
		{"--workload-ref", "infer=vllm/deployment/x:8000"},
	} {
		err := runC8s(t, append([]string{"render-values", "--cvm-mode=bare-metal"}, args...)...)
		if err == nil || !strings.Contains(err.Error(), "c8s routes add") {
			t.Errorf("render-values %v = %v, want the refusal naming c8s routes add", args, err)
		}
	}
}

// writeTestOperatorKeys writes a real EC public-key PEM to a temp file (the
// builder validates it parses) and returns its path.
func writeTestOperatorKeys(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	path := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

func TestCoerceTypedVsString(t *testing.T) {
	tests := []struct {
		raw   string
		typed bool
		want  any
	}{
		{"null", true, nil},
		{"true", true, true},
		{"false", true, false},
		{"42", true, int64(42)},
		{"main", true, "main"},  // non-numeric/non-bool stays string
		{"null", false, "null"}, // --set-string never coerces
		{"true", false, "true"}, // --set-string never coerces
		{"sha256:abc", false, "sha256:abc"},
	}
	for _, tt := range tests {
		if got := coerce(tt.raw, tt.typed); got != tt.want {
			t.Errorf("coerce(%q, typed=%v) = %#v, want %#v", tt.raw, tt.typed, got, tt.want)
		}
	}
}
