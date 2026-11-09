// Tests for the chart's argv-pinned seed entries (c8s.argvPinnedEntries):
// platform images that carry a shell — the nri-image-policy installer image —
// must be admitted by the served allowlist only under their exact expected
// argv, never by digest alone. The boot config's base is digest-only
// admission, so it must not carry any of them either.
package helmchart

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// componentsFile is c8s-lib's component table and image pins.
var componentsFile = filepath.Join(chartsDir, "lib", "files", "components.yaml")

// chartImageDigest reads the digest file pins for one third-party image, so a
// bump by pin-watch or through .github/scripts/chart-image-pins.sh set needs
// no edit here.
func chartImageDigest(t *testing.T, file string, path ...string) string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var values map[string]any
	if err := sigsyaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var node any = values
	for _, key := range path {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s has no %s", file, strings.Join(path, "."))
		}
		node = m[key]
	}
	digest, ok := node.(string)
	if !ok || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("%s %s is %v, not a digest", file, strings.Join(path, "."), node)
	}
	return digest
}

// renderedSeed parses the allowlist document out of the rendered CDS seed
// ConfigMap — the same JSON CDS feeds to pkg/allowlist.ParseJSON at startup.
func renderedSeed(t *testing.T, manifest string) *pkgallowlist.Allowlist {
	t.Helper()
	cm := renderedConfigMap(t, manifest, "c8s-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	return seed
}

// effectiveArgv is the OCI process.args an enforcer observes: the pod spec's
// command and args after kubelet expansion.
func effectiveArgv(c corev1.Container) []string {
	return runtimeArgv(c, nil)
}

// admitArgvs fails unless the seed admits (digest, argv) via some entry.
func admitArgvs(t *testing.T, seed *pkgallowlist.Allowlist, digest string, argv []string) {
	t.Helper()
	if !seed.BuildIndex().AdmitsProcess(pkgallowlist.RunningContainer{Digest: digest, Argv: argv}) {
		t.Errorf("seed does not admit %s argv %q", digest[:19], argv[:2])
	}
}

// admitPlatformContainer checks the full launch policy, including the host
// mounts required by the rendered platform installer and prep scripts.
func admitPlatformContainer(t *testing.T, seed *pkgallowlist.Allowlist, digest string, c corev1.Container) {
	t.Helper()
	mounts := make([]pkgallowlist.ObservedMount, 0, len(c.VolumeMounts))
	for _, m := range c.VolumeMounts {
		mounts = append(mounts, pkgallowlist.ObservedMount{
			Destination: m.MountPath, Class: pkgallowlist.MountHost, Storage: pkgallowlist.MountUnknown,
		})
	}
	if !seed.BuildIndex().AdmitsContainer(pkgallowlist.RunningContainer{Digest: digest, Argv: effectiveArgv(c), Mounts: mounts}) {
		t.Errorf("seed refuses platform container %s with its rendered mounts: %+v", c.Name, mounts)
	}
}

// denyArgvs fails if the seed admits (digest, argv) via any entry.
func denyArgvs(t *testing.T, seed *pkgallowlist.Allowlist, digest string, argv []string) {
	t.Helper()
	if seed.BuildIndex().AdmitsProcess(pkgallowlist.RunningContainer{Digest: digest, Argv: argv}) {
		t.Errorf("seed admits %s argv %q — the argv pin is not enforcing", digest[:19], argv[:2])
	}
}

// Every container the chart runs from the nri-image-policy image — the
// installer DaemonSet's install init and its plugin-ready pause — must be
// admitted by the seed under its exact rendered argv, and nothing else from
// that image may be admitted.
func TestChartPinnedSeedAdmitsNriInstallerArgv(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)

	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	for _, c := range allContainers(&worker) {
		admitPlatformContainer(t, seed, baseNRIDigest, c)
	}

	// The pin is argv-exact: any other command line from the same image is denied.
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", "rm -rf /"})
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "/tmp/x"})
	denyArgvs(t, seed, baseNRIDigest, []string{"sleep", "infinity"}) // argv[0] must be /bin/sh
	// The sweep's /bin/sleep pause is the one pinned holder for this image.
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", "sleep infinity"})
}

// The install script's shell carries $ throughout, escaped against the
// kubelet's expansion of the installer's args, so they must reach the runtime
// as the seed pins them.
func TestChartPinnedSeedAdmitsInstallerUnderKubeletExpansion(t *testing.T) {
	t.Parallel()
	var args []string
	for valuePath, digest := range componentTestDigests {
		args = append(args, "--set", valuePath+".digest="+digest)
	}
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	for _, c := range allContainers(&worker) {
		admitPlatformContainer(t, seed, baseNRIDigest, c)
	}
}

// A busybox in the base admits any command line on any pod.
func TestChartBootConfigCarriesNoOpenShell(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	if len(baseImages(cfg.Allowlist.Base)) == 0 {
		t.Fatal("base must stay non-empty (pull bootstrap)")
	}
	for digest, image := range baseImages(cfg.Allowlist.Base) {
		if strings.Contains(image, "busybox") {
			t.Errorf("busybox %s in base: admits any command line on any pod", digest)
		}
	}
}

// An any-argv entry for a pinned digest voids the pin (admission is the union
// across entries): the derive loop must never emit one for the installer image
// — the argvPinned skip is the only thing between the pin and a silent
// any-argv shadow.
func TestChartPinnedDigestHasNoAnyArgvShadow(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
	for _, document := range []*pkgallowlist.Allowlist{renderedSeed(t, out), &cfg.Allowlist.Base} {
		for name, w := range document.Workloads {
			for _, c := range append(append([]pkgallowlist.Container{}, w.Containers...), w.InitContainers...) {
				if c.Digest.String() == baseNRIDigest && c.AnyArgv() {
					t.Errorf("entry %q grants any argv for pinned digest %s — the pin is void", name, baseNRIDigest[:19])
				}
			}
		}
	}
}

// The pre-imported images of a test node share one long name prefix and
// differ only in their digest suffix, which is the key shape that made the
// rendered base allowlist come out in a different order per evaluation.
func importedFloorValues() string {
	var b strings.Builder
	b.WriteString("nriImagePolicy:\n  bootstrapAllowlist:\n    workloads:\n")
	for i := 0; i < 20; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("imported-%d", i)))
		digest := hex.EncodeToString(sum[:])
		ref := "import-2026-10-08@sha256:" + digest
		fmt.Fprintf(&b, "      import-2026-10-08-%s:\n", digest[:12])
		fmt.Fprintf(&b, "        label: %s\n", ref)
		b.WriteString("        containers:\n")
		fmt.Fprintf(&b, "          - digest: sha256:%s\n", digest)
		fmt.Fprintf(&b, "            image: %s\n", ref)
		b.WriteString("            command:\n              policy: any\n")
		b.WriteString("            args:\n              policy: any\n")
		b.WriteString("            mounts:\n              policy: any\n")
	}
	return b.String()
}

// The installer's own init container is admitted by one entry: the argv-exact
// pin the same chart renders for it. The two copies of that argv come from
// separate evaluations of one template, so the rendered text must be a
// function of the values alone. A base allowlist whose key order varies per
// evaluation leaves the installer's launch matching no entry, and the
// enforcer kills the container that is installing it.
func TestChartInstallerArgvPinIsRenderDeterministic(t *testing.T) {
	t.Parallel()
	values := filepath.Join(t.TempDir(), "floor.yaml")
	if err := os.WriteFile(values, []byte(importedFloorValues()), 0o600); err != nil {
		t.Fatalf("write the floor values: %v", err)
	}
	first := ""
	for render := range 3 {
		out, err := helmTemplate(t, "-f", values)
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
		install, ok := findContainer(worker.Spec.Template.Spec.InitContainers, "install")
		if !ok {
			t.Fatalf("the installer DaemonSet has no install initContainer\n%s", out)
		}
		argv := effectiveArgv(install)
		seed := renderedSeed(t, out)
		admitted := seed.BuildIndex().AdmitsProcess(pkgallowlist.RunningContainer{
			Digest: baseNRIDigest,
			Argv:   argv,
		})
		if !admitted {
			t.Fatalf("render %d: the seed does not admit the installer's own argv", render)
		}
		script := argv[len(argv)-1]
		if first == "" {
			first = script
			continue
		}
		if script != first {
			t.Errorf("render %d: the installer script is not a function of the values", render)
		}
	}
}

// Digests the component-pin tests give the chart's own images. Each is a
// distinct, well-formed sha256 the harness does not pin elsewhere.
var componentTestDigests = map[string]string{
	"image":                "sha256:1111000000000000000000000000000000000000000000000000000000000001",
	"armtlsMesh.image":     "sha256:1111000000000000000000000000000000000000000000000000000000000002",
	"volumed.image":        "sha256:1111000000000000000000000000000000000000000000000000000000000003",
	"attestationApi.image": "sha256:1111000000000000000000000000000000000000000000000000000000000004",
}

// componentPinValues reads the entrypoints the components file declares for
// every derived component, keyed by valuePath, plus the router nginx one under
// "routerNginx".
func componentPinValues(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(componentsFile)
	if err != nil {
		t.Fatalf("read %s: %v", componentsFile, err)
	}
	var values struct {
		Components []struct {
			ValuePath  string   `json:"valuePath"`
			ArgvPinned bool     `json:"argvPinned"`
			Entrypoint []string `json:"entrypoint"`
		} `json:"components"`
		RouterNginx struct {
			Entrypoint []string `json:"entrypoint"`
		} `json:"routerNginx"`
	}
	if err := sigsyaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse %s: %v", componentsFile, err)
	}
	pins := map[string][]string{"routerNginx": values.RouterNginx.Entrypoint}
	for _, c := range values.Components {
		if c.ArgvPinned {
			continue
		}
		if len(c.Entrypoint) == 0 {
			t.Errorf("component %s declares no entrypoint", c.ValuePath)
		}
		pins[c.ValuePath] = c.Entrypoint
	}
	return pins
}

// componentImageEnvValues reads the imageEnv the components file declares for
// every derived component, keyed like componentPinValues.
func componentImageEnvValues(t *testing.T) map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile(componentsFile)
	if err != nil {
		t.Fatalf("read %s: %v", componentsFile, err)
	}
	var values struct {
		Components []struct {
			ValuePath string            `json:"valuePath"`
			ImageEnv  map[string]string `json:"imageEnv"`
		} `json:"components"`
		RouterNginx struct {
			ImageEnv map[string]string `json:"imageEnv"`
		} `json:"routerNginx"`
	}
	if err := sigsyaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse %s: %v", componentsFile, err)
	}
	envs := map[string]map[string]string{"routerNginx": values.RouterNginx.ImageEnv}
	for _, c := range values.Components {
		envs[c.ValuePath] = c.ImageEnv
	}
	return envs
}

// dockerfileEntrypoint reads the exec-form ENTRYPOINT of an image Dockerfile
// in this repository.
func dockerfileEntrypoint(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	m := regexp.MustCompile(`(?m)^ENTRYPOINT\s+(\[.*\])\s*$`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("%s has no exec-form ENTRYPOINT", path)
	}
	var argv []string
	if err := json.Unmarshal(m[1], &argv); err != nil {
		t.Fatalf("%s ENTRYPOINT %s: %v", path, m[1], err)
	}
	return argv
}

// The entrypoint each component entry pins is the one its image bakes: for
// the images built here, the Dockerfile's ENTRYPOINT; for attestation-api and
// nginx, the published image's config (`crane config <ref>`), kept beside the
// digest the chart pins.
func TestChartComponentPinsMatchImageEntrypoints(t *testing.T) {
	t.Parallel()
	pins := componentPinValues(t)
	for valuePath, want := range map[string][]string{
		"image":                dockerfileEntrypoint(t, "../../cmd/c8s/Dockerfile"),
		"armtlsMesh.image":     dockerfileEntrypoint(t, "../../cmd/armtls-mesh/Dockerfile"),
		"volumed.image":        dockerfileEntrypoint(t, "../../cmd/volumed/Dockerfile"),
		"attestationApi.image": {"/attestation-api"},
		// ENTRYPOINT plus the first CMD token: docker-entrypoint.sh execs
		// whatever follows it, so the script alone pins nothing.
		"routerNginx": {"/docker-entrypoint.sh", "nginx"},
	} {
		if got := pins[valuePath]; !slices.Equal(got, want) {
			t.Errorf("%s entrypoint = %q, want %q", valuePath, got, want)
		}
	}
}

// componentRender renders the chart with every component enabled and
// digest-pinned, and derivation on, so the seed and the base carry an entry
// for each.
func componentRender(t *testing.T) string {
	t.Helper()
	args := []string{"--set", "volumed.enabled=true"}
	for valuePath, digest := range componentTestDigests {
		args = append(args, "--set", valuePath+".digest="+digest)
	}
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	return out
}

// imageDigest is the digest a container's image reference pins, or "".
func imageDigest(image string) string {
	_, digest, ok := strings.Cut(image, "@")
	if !ok {
		return ""
	}
	return digest
}

// A rendered container runs every component image, and nothing else from
// those images is admitted, by the served seed or the plugin's base: not a
// shell, and not the pinned path with a volume bound over it.
// TestChartComponentShapesAreExact covers what the rendered containers run.
func TestChartComponentEntriesPinEntrypoints(t *testing.T) {
	t.Parallel()
	out := componentRender(t)
	seed := renderedSeed(t, out)
	base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
	pins := componentPinValues(t)
	pinned := map[string][]string{}
	for valuePath, digest := range componentTestDigests {
		pinned[digest] = pins[valuePath]
	}
	nginxDigest := ""
	for _, w := range renderedPodSpecs(t, out) {
		for _, c := range w.spec.Containers {
			if strings.Contains(c.Image, "nginx-unprivileged@") {
				nginxDigest = imageDigest(c.Image)
			}
		}
	}
	if nginxDigest == "" {
		t.Fatal("the router's nginx container is not digest-pinned")
	}
	pinned[nginxDigest] = pins["routerNginx"]

	for digest, entrypoint := range pinned {
		for source, al := range map[string]*pkgallowlist.Allowlist{"seed": seed, "base": &base} {
			index := al.BuildIndex()
			for _, argv := range [][]string{
				{"/bin/sh", "-c", "cat /run/c8s/secrets/*"},
				{"/bin/busybox", "sh"},
				{entrypoint[0] + "x"},
				entrypoint[:len(entrypoint)-1],
			} {
				if len(argv) == 0 {
					continue
				}
				if index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: digest, Argv: argv}) {
					t.Errorf("%s admits %s under %q", source, digest[:19], argv)
				}
			}
			over := []pkgallowlist.ObservedMount{{Destination: entrypoint[0], Class: pkgallowlist.MountData, Storage: pkgallowlist.MountMemory}}
			if index.AdmitsContainer(pkgallowlist.RunningContainer{Digest: digest, Argv: entrypoint, Mounts: over, Env: &pkgallowlist.EnvObservation{}}) {
				t.Errorf("%s admits %s with a volume mounted over %s", source, digest[:19], entrypoint[0])
			}
		}
	}
}

// An operator entry that pins a component's entrypoint and leaves args, env
// and mounts open reaches the base under that pin, never wider. It does not
// cover the component for the fail-closed guard
// (TestChartOperatorEntryPinMustMatchEntrypoint); one that pins args and
// mounts does (TestChartPinnedOperatorEntryCoversComponent).
func TestChartOperatorEntrypointEntryReachesBase(t *testing.T) {
	t.Parallel()
	const opD = "sha256:1111000000000000000000000000000000000000000000000000000000000011"
	p := "nriImagePolicy.bootstrapAllowlist.workloads.c8s-operator.containers[0]."
	out, err := helmTemplate(t,
		"--set-string", "image.digest="+opD,
		"--set", "nriImagePolicy.policy.mode=fail-closed",
		"--set-string", p+"digest="+opD,
		"--set-string", p+"command.policy=exact",
		"--set-string", p+"command.argv[0]=/c8s",
		"--set-string", p+"args.policy=any",
		"--set-string", p+"mounts.policy=any",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
	index := base.BuildIndex()
	if !index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: opD, Argv: []string{"/c8s", "operator"}}) {
		t.Errorf("base does not admit the operator under the entry's pin: %v", base.Workloads)
	}
	if index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: opD, Argv: []string{"/bin/sh"}}) {
		t.Errorf("base widened the operator's entry to any command: %v", base.Workloads)
	}
}

// Two open-args entries for one digest whose pins are comparable both render:
// the base carries the wider one, so an any-argv `c8s allowlist add` entry
// beside a `/c8s cds-attest` application entry keeps rendering, as it did
// before pinned entries reached the base.
func TestChartOverlappingOperatorPinsKeepTheWider(t *testing.T) {
	t.Parallel()
	const opD = "sha256:1111000000000000000000000000000000000000000000000000000000000011"
	attest := "nriImagePolicy.bootstrapAllowlist.workloads.attest.containers[0]."
	args := append([]string{"--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.policy.mode=fail-closed"},
		anyArgvEntryArgs("c8s-operator", opD, "ghcr.io/confidential-dot-ai/c8s-operator@"+opD)...)
	args = append(args,
		"--set-string", attest+"digest="+opD,
		"--set-string", attest+"command.policy=exact",
		"--set-string", attest+"command.argv[0]=/c8s",
		"--set-string", attest+"command.argv[1]=cds-attest",
		"--set-string", attest+"args.policy=any",
		"--set-string", attest+"mounts.policy=any",
	)
	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("an any-argv entry beside a pinned one must render: %v\n%s", err, out)
	}
	base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
	if !base.BuildIndex().AdmitsProcess(pkgallowlist.RunningContainer{Digest: opD, Argv: []string{"/bin/sh"}}) {
		t.Errorf("base did not keep the wider any-argv shape: %v", base.Workloads)
	}
}

// With derivation on, an operator open-args entry for a component's digest
// pinned to another invocation does not displace the component's own pin from
// the base: both are admitted there, so neither is refused on a cold node.
func TestChartOperatorPinBesideDerivedComponentPin(t *testing.T) {
	t.Parallel()
	const opD = "sha256:1111000000000000000000000000000000000000000000000000000000000011"
	attest := "nriImagePolicy.bootstrapAllowlist.workloads.attest.containers[0]."
	out, err := helmTemplate(t,
		"--set-string", "image.digest="+opD,
		"--set-string", attest+"digest="+opD,
		"--set-string", attest+"command.policy=exact",
		"--set-string", attest+"command.argv[0]=/c8s",
		"--set-string", attest+"command.argv[1]=cds-attest",
		"--set-string", attest+"args.policy=any",
		"--set-string", attest+"mounts.policy=any",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
	index := base.BuildIndex()
	operator := runtimeArgv(renderedDeploymentContainer(t, out, "c8s-operator", "operator"), []string{"/c8s"})
	for _, argv := range [][]string{operator, {"/c8s", "cds-attest", "--port=1"}} {
		if !index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: opD, Argv: argv}) {
			t.Errorf("base does not admit %q", argv)
		}
	}
	if index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: opD, Argv: []string{"/bin/sh"}}) {
		t.Error("base admits the operator image under a shell")
	}
}
