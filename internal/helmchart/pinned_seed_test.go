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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

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
