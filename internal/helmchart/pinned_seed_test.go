// Tests for the chart's argv-pinned seed entries (c8s.argvPinnedEntries):
// platform images that carry a shell — the nri-image-policy installer image
// and the rke2 busybox uses (containerd-prep, local-path helper) — must be
// admitted by the served allowlist only under their exact expected argv,
// never by digest alone. The boot config's base is digest-only
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

const (
	// prepBusyboxDigest is values.yaml's nriImagePolicy.containerdPrep.image.digest.
	prepBusyboxDigest = "sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
	// localPathHelperManifest is the node image's baked local-path provisioner
	// manifest, whose helper pod the rke2.localPathHelper values pin in lockstep.
	localPathHelperManifest = "../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/local-path-storage.yaml"
)

// renderedSeed parses the allowlist document out of the rendered CDS seed
// ConfigMap — the same JSON CDS feeds to pkg/allowlist.ParseJSON at startup.
func renderedSeed(t *testing.T, manifest string) *pkgallowlist.Allowlist {
	t.Helper()
	cm := renderedConfigMap(t, manifest, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	return seed
}

// effectiveArgv is the OCI process.args an enforcer observes: the pod spec's
// command and args concatenated.
func effectiveArgv(c corev1.Container) []string {
	return append(append([]string{}, c.Command...), c.Args...)
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
// installer DaemonSet's install init and pause, the uninstall hook's
// uninstall init and pause — must be admitted by the seed under its exact
// rendered argv, and nothing else from that image may be admitted.
func TestChartPinnedSeedAdmitsNriInstallerArgv(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)

	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	for _, c := range allContainers(&worker) {
		admitPlatformContainer(t, seed, baseNRIDigest, c)
	}
	uninstall := renderedDaemonSet(t, out, "c8s-nri-image-policy-uninstall")
	for _, c := range allContainers(&uninstall) {
		admitPlatformContainer(t, seed, baseNRIDigest, c)
	}

	// The pin is argv-exact: any other command line from the same image is denied.
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", "rm -rf /"})
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "/tmp/x"})
	denyArgvs(t, seed, baseNRIDigest, []string{"sleep", "infinity"}) // argv[0] must be /bin/sh
}

// The node-as-CVM (baked) installer runs the pins script instead of the
// install script; the seed must admit exactly that argv from the nri image.
func TestChartPinnedSeedAdmitsBakedPinsArgv(t *testing.T) {
	out, err := helmTemplate(t, "--set", "nriImagePolicy.baked=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	for _, c := range allContainers(&worker) {
		admitPlatformContainer(t, seed, baseNRIDigest, c)
	}
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", "rm -rf /"})
}

// On rke2 the installer DaemonSet's containerd-prep initContainer runs the
// busybox prep image under the prep script; the seed must admit that exact
// argv and no other from that image.
func TestChartPinnedSeedAdmitsRKE2ContainerdPrepArgv(t *testing.T) {
	out, err := helmTemplate(t, "--set", "nriImagePolicy.distro=rke2")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	prep, ok := findContainer(worker.Spec.Template.Spec.InitContainers, "containerd-prep")
	if !ok {
		t.Fatalf("rke2 render missing the containerd-prep initContainer")
	}
	admitPlatformContainer(t, seed, prepBusyboxDigest, prep)
	denyArgvs(t, seed, prepBusyboxDigest, []string{"/bin/sh", "-c", "rm -rf /"})
	denyArgvs(t, seed, prepBusyboxDigest, []string{"/bin/sh", "/script/setup"})
}

// The local-path helper entry pins the node image's baked helper pod to its
// two provisioner command prefixes; the per-PVC flags stay open.
func TestChartPinnedSeedAdmitsLocalPathHelperArgv(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	helperDigest := localPathHelperDigest(t)

	for _, script := range []string{"/script/setup", "/script/teardown"} {
		admitPlatformContainer(t, seed, helperDigest, corev1.Container{
			Name: "local-path-helper", Command: []string{"/bin/sh", script},
			Args:         []string{"-p", "/opt/local-path-provisioner/pvc-123", "-s", "1073741824", "-m", "Filesystem", "-a", "create"},
			VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/opt/local-path-provisioner"}, {Name: "script", MountPath: "/script"}},
		})
	}
	denyArgvs(t, seed, helperDigest, []string{"/bin/sh", "-c", "rm -rf /"})
	denyArgvs(t, seed, helperDigest, []string{"/bin/sh", "/script/setup-evil"})
	denyArgvs(t, seed, helperDigest, []string{"/bin/busybox", "/script/setup"})
}

// base is digest-only admission — carrying an argv-pinned image there
// would bypass the pin. Neither the installer image nor any busybox may
// appear, in either the k8s or the rke2 shape.
func TestChartPinnedDigestsAbsentFromBootConfig(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--set", "nriImagePolicy.distro=rke2"},
	} {
		out, err := helmTemplate(t, args...)
		if err != nil {
			t.Fatalf("helm template %v: %v\n%s", args, err, out)
		}
		cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
		if len(baseImages(cfg.Allowlist.Base)) == 0 {
			t.Fatalf("base must stay non-empty (pull bootstrap): %v", args)
		}
		for digest, image := range baseImages(cfg.Allowlist.Base) {
			if digest == baseNRIDigest {
				t.Errorf("installer image self-allowed in base (%v): the argv pin would be bypassed", args)
			}
			if strings.Contains(image, "busybox") {
				t.Errorf("busybox %s in base (%v): admits any command line on any pod", digest, args)
			}
		}
	}
}

// localPathHelperDigest reads the helper image digest the chart pins from
// values.yaml and proves it is the digest the node image's baked manifest
// runs, with no setupCommand/teardownCommand override that would change the
// helper's effective argv away from the pinned prefixes.
func localPathHelperDigest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("c8s/values.yaml")
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	m := regexp.MustCompile(`(?ms)localPathHelper:\s*
\s*image:\s*
\s*repository: (\S+)\s*
\s*digest: "?(sha256:[0-9a-f]{64})"?`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("rke2.localPathHelper.image not found in values.yaml")
	}
	repo, digest := string(m[1]), string(m[2])

	manifest, err := os.ReadFile(localPathHelperManifest)
	if err != nil {
		t.Fatalf("read node-image manifest: %v", err)
	}
	helper := regexp.MustCompile(`(?ms)helperPod.yaml:.*?image: (\S+?@(sha256:[0-9a-f]{64}))`).FindSubmatch(manifest)
	if helper == nil {
		t.Fatalf("no digest-pinned helper image in %s", localPathHelperManifest)
	}
	// The manifest ref may carry a tag beside the digest (busybox:1.38.0@…);
	// the repository is the ref before "@", with any ":tag" stripped.
	manifestRepo, _, _ := strings.Cut(string(helper[1]), "@")
	manifestRepo, _, _ = strings.Cut(manifestRepo, ":")
	if manifestRepo != repo || string(helper[2]) != digest {
		t.Fatalf("helper image drift: chart pins %s@%s, node image runs %s — bump rke2.localPathHelper.image", repo, digest, helper[1])
	}
	for _, key := range []string{"setupCommand", "teardownCommand"} {
		if strings.Contains(string(manifest), key) {
			t.Fatalf("%s sets %s: the helper's argv is then %s, not the seeded /script pin", localPathHelperManifest, key, key)
		}
	}
	return digest
}

// An any-argv entry for a pinned digest voids the pin (admission is the union
// across entries): with deriveComponents on, the derive loop must never emit
// one for the installer or busybox images — the argvPinned skip is the only
// thing between the pin and a silent any-argv shadow.
func TestChartPinnedSeedHasNoAnyArgvShadow(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.distro=rke2",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	for _, digest := range []string{baseNRIDigest, prepBusyboxDigest, localPathHelperDigest(t)} {
		for name, w := range seed.Workloads {
			for _, c := range append(append([]pkgallowlist.Container{}, w.Containers...), w.InitContainers...) {
				if c.Digest.String() == digest && c.AnyArgv() {
					t.Errorf("entry %q grants any argv for pinned digest %s — the pin is void", name, digest[:19])
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

// componentPinValues reads the entrypoints values.yaml declares for every
// derived component, keyed by valuePath, plus the router nginx one under
// "router.nginx".
func componentPinValues(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile("c8s/values.yaml")
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	var values struct {
		Components []struct {
			ValuePath  string   `json:"valuePath"`
			ArgvPinned bool     `json:"argvPinned"`
			Entrypoint []string `json:"entrypoint"`
		} `json:"c8sComponents"`
		Router struct {
			Nginx struct {
				Entrypoint []string `json:"entrypoint"`
			} `json:"nginx"`
		} `json:"router"`
	}
	if err := sigsyaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse values.yaml: %v", err)
	}
	pins := map[string][]string{"router.nginx": values.Router.Nginx.Entrypoint}
	for _, c := range values.Components {
		if c.ArgvPinned {
			continue
		}
		if len(c.Entrypoint) == 0 {
			t.Errorf("c8sComponents %s declares no entrypoint", c.ValuePath)
		}
		pins[c.ValuePath] = c.Entrypoint
	}
	return pins
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
	pins := componentPinValues(t)
	for valuePath, want := range map[string][]string{
		"image":                dockerfileEntrypoint(t, "../../cmd/c8s/Dockerfile"),
		"cds.image":            dockerfileEntrypoint(t, "../../cmd/cds/Dockerfile"),
		"armtlsMesh.image":     dockerfileEntrypoint(t, "../../cmd/armtls-mesh/Dockerfile"),
		"volumed.image":        dockerfileEntrypoint(t, "../../cmd/volumed/Dockerfile"),
		"attestationApi.image": {"/attestation-api"},
		// ENTRYPOINT plus the first CMD token: docker-entrypoint.sh execs
		// whatever follows it, so the script alone pins nothing.
		"router.nginx": {"/docker-entrypoint.sh", "nginx"},
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
	args := []string{
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set", "volumed.enabled=true",
		"--set", "attestationApi.enabled=true",
	}
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

// Every container the chart runs from a component image must be admitted —
// by the served seed and by the plugin's base — under the argv it is rendered
// with and the mounts it holds, and nothing else from those images may be:
// not a shell, and not the pinned path with a volume bound over it.
func TestChartComponentEntriesPinEntrypoints(t *testing.T) {
	out := componentRender(t)
	seed := renderedSeed(t, out)
	base := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base
	pins := componentPinValues(t)
	pinned := map[string][]string{}
	for valuePath, digest := range componentTestDigests {
		pinned[digest] = pins[valuePath]
	}
	pinned["sha256:0000000000000000000000000000000000000000000000000000000000000001"] = pins["cds.image"]
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
	pinned[nginxDigest] = pins["router.nginx"]

	images := componentImages(t)
	// An admitted launch of each digest outside the hook, to restage with a
	// volume over its executable.
	admitted := map[string]pkgallowlist.RunningContainer{}
	for _, w := range renderedPodSpecs(t, out) {
		name := w.kind + "/" + w.name
		for _, c := range append(append([]corev1.Container{}, w.spec.InitContainers...), w.spec.Containers...) {
			digest := imageDigest(c.Image)
			entrypoint, ok := pinned[digest]
			if !ok {
				continue
			}
			argv := effectiveArgv(c)
			if len(c.Command) == 0 {
				argv = append(append([]string{}, entrypoint...), c.Args...)
			}
			mounts := make([]pkgallowlist.ObservedMount, 0, len(c.VolumeMounts))
			for _, m := range c.VolumeMounts {
				mounts = append(mounts, pkgallowlist.ObservedMount{Destination: m.MountPath, Class: pkgallowlist.MountHost, Storage: pkgallowlist.MountUnknown})
			}
			repository, _, _ := strings.Cut(c.Image, "@")
			running := pkgallowlist.RunningContainer{Digest: digest, Argv: argv, Mounts: mounts, Env: launchEnv(t, images[repository].env, c)}
			sources := map[string]*pkgallowlist.Allowlist{"seed": seed, "base": &base}
			if name == "DaemonSet/c8s-volumed-teardown" {
				// The pre-delete hook's script and pause are seed-only, like
				// the installer's (c8s.volumedHookContainers).
				delete(sources, "base")
			}
			for source, al := range sources {
				if !al.BuildIndex().AdmitsContainer(running) {
					t.Errorf("%s refuses %s container %s: argv %q, mounts %v", source, name, c.Name, argv[:min(len(argv), 3)], c.VolumeMounts)
				}
			}
			if _, ok := admitted[digest]; !ok && name != "DaemonSet/c8s-volumed-teardown" {
				admitted[digest] = running
			}
		}
	}
	for digest, entrypoint := range pinned {
		launch, seen := admitted[digest]
		if !seen {
			t.Errorf("no rendered container runs %s (pinned to %q)", digest, entrypoint)
		}
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
			over := launch
			over.Mounts = append(slices.Clone(launch.Mounts), pkgallowlist.ObservedMount{Destination: entrypoint[0], Class: pkgallowlist.MountData, Storage: pkgallowlist.MountMemory})
			if seen && index.AdmitsContainer(over) {
				t.Errorf("%s admits %s with a volume mounted over %s", source, digest[:19], entrypoint[0])
			}
		}
	}
}

// With derivation off, the seed and the base still carry the CDS and nginx
// self-entries, pinned the same way.
func TestChartSelfEntriesPinEntrypoints(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	const cdsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	pins := componentPinValues(t)
	for source, al := range map[string]pkgallowlist.Allowlist{
		"seed": *renderedSeed(t, out),
		"base": bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker").Allowlist.Base,
	} {
		index := al.BuildIndex()
		if !index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: cdsDigest, Argv: append(append([]string{}, pins["cds.image"]...), "--port=8443")}) {
			t.Errorf("%s does not admit CDS under its entrypoint", source)
		}
		if index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: cdsDigest, Argv: []string{"/c8s", "get-secret"}}) {
			t.Errorf("%s admits the CDS image in another mode", source)
		}
	}
}

// An operator entry that pins a component's entrypoint and leaves args, env
// and mounts open can start the component on a cold node, so it covers the
// component for the fail-closed guard and reaches the base under that pin.
// Pinning any other field keeps the entry seed-only (TestChartBaseSkipsPinnedEntries).
func TestChartOperatorEntrypointEntryCoversComponent(t *testing.T) {
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
		t.Fatalf("helm template should render with the component covered by an entrypoint-pinned entry: %v\n%s", err, out)
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

// An open-args entry pinned to another executable does not cover the
// component: it would reach the base and still deny the component on its
// own node. Two open-args entries pinning one digest differently cannot both
// reach the base, so the render fails.
func TestChartOperatorEntryPinMustMatchEntrypoint(t *testing.T) {
	const opD = "sha256:1111000000000000000000000000000000000000000000000000000000000011"
	entry := func(name, argv0 string) []string {
		p := "nriImagePolicy.bootstrapAllowlist.workloads." + name + ".containers[0]."
		return []string{
			"--set-string", p + "digest=" + opD,
			"--set-string", p + "command.policy=exact",
			"--set-string", p + "command.argv[0]=" + argv0,
			"--set-string", p + "args.policy=any",
			"--set-string", p + "mounts.policy=any",
		}
	}
	base := []string{"--set-string", "image.digest=" + opD, "--set", "nriImagePolicy.policy.mode=fail-closed"}
	out, err := helmTemplate(t, append(base, entry("c8s-operator", "/bin/sh")...)...)
	if err == nil {
		t.Fatalf("helm template succeeded with the component covered only by an entry pinned to /bin/sh\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "uncovered_component_digest" {
		t.Fatalf("validation error kind = %q, want uncovered_component_digest\n%s", kind, out)
	}
	out, err = helmTemplate(t, append(append(base, entry("c8s-operator", "/c8s")...), entry("c8s-operator-sh", "/bin/sh")...)...)
	if err == nil || !strings.Contains(out, "incomparable commands") {
		t.Fatalf("incomparable pins for one digest must fail the render: err=%v\n%s", err, out)
	}
}

// Two open-args entries for one digest whose pins are comparable both render:
// the base carries the wider one, so an any-argv `c8s allowlist add` entry
// beside a `/c8s cds-attest` application entry keeps rendering, as it did
// before pinned entries reached the base.
func TestChartOverlappingOperatorPinsKeepTheWider(t *testing.T) {
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
	const opD = "sha256:1111000000000000000000000000000000000000000000000000000000000011"
	attest := "nriImagePolicy.bootstrapAllowlist.workloads.attest.containers[0]."
	out, err := helmTemplate(t,
		"--set-string", "image.digest="+opD,
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
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
	for _, argv := range [][]string{{"/c8s", "operator"}, {"/c8s", "cds-attest", "--port=1"}} {
		if !index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: opD, Argv: argv}) {
			t.Errorf("base does not admit %q", argv)
		}
	}
	if index.AdmitsProcess(pkgallowlist.RunningContainer{Digest: opD, Argv: []string{"/bin/sh"}}) {
		t.Error("base admits the operator image under a shell")
	}
}
