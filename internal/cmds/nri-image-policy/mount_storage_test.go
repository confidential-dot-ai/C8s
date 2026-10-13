//go:build linux

package nriimagepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestTrustedC8sCryptDeviceThroughVerity(t *testing.T) {
	for _, tc := range []struct {
		name, mapper, uuid string
		want               bool
	}{
		{"encrypted volume", "c8s-crypt-pod-data", "CRYPT-PLAIN-test", true},
		{"name without crypt", "c8s-crypt-pod-data", "DM-LINEAR-test", false},
		{"crypt without c8s name", "unrelated", "CRYPT-PLAIN-test", false},
		{"missing uuid", "c8s-crypt-pod-data", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			crypt, verity := filepath.Join(root, "crypt"), filepath.Join(root, "verity")
			for _, dir := range []string{filepath.Join(crypt, "dm"), filepath.Join(verity, "slaves")} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for name, value := range map[string]string{"name": tc.mapper, "uuid": tc.uuid} {
				if err := os.WriteFile(filepath.Join(crypt, "dm", name), []byte(value+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(crypt, filepath.Join(verity, "slaves", "crypt")); err != nil {
				t.Fatal(err)
			}
			inspector := linuxStorageInspector{}
			for _, device := range []string{crypt, verity} {
				if got := inspector.isTrustedEncryptedDevice(device, map[string]bool{}); got != tc.want {
					t.Fatalf("device %s trusted=%v, want %v", device, got, tc.want)
				}
			}
			if inspector.isTrustedEncryptedDevice(filepath.Join(root, "missing"), map[string]bool{}) {
				t.Fatal("missing device reported encrypted")
			}
		})
	}
}

func TestTrustedEncryptedDeviceRejectsSlaveCycle(t *testing.T) {
	device := t.TempDir()
	if err := os.Mkdir(filepath.Join(device, "slaves"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(device, filepath.Join(device, "slaves", "self")); err != nil {
		t.Fatal(err)
	}
	if (linuxStorageInspector{}).isTrustedEncryptedDevice(device, map[string]bool{}) {
		t.Fatal("device cycle reported encrypted")
	}
}

func TestContainingOverlayDoesNotInheritHiddenAncestor(t *testing.T) {
	for _, nested := range []struct {
		name string
		fs   string
		want string
	}{
		{"lower-only overlay", "overlay overlay ro,lowerdir=/plaintext", ""},
		{"empty upperdir", "overlay overlay rw,upperdir=,lowerdir=/lower", ""},
		{"bare upperdir", "overlay overlay rw,upperdir,lowerdir=/lower", ""},
		{"workdir only", "overlay overlay rw,workdir=/work", ""},
		{"lookalike upperdir prefix", "overlay overlay rw,otherupperdir=/scratch", ""},
		{"lookalike upperdir suffix", "overlay overlay rw,upperdir_extra=/scratch", ""},
		{"non-overlay", "ext4 /dev/plaintext rw", ""},
		{"writable overlay", "overlay overlay rw,upperdir=/child-upper,lowerdir=/lower", "/child-upper"},
		{"upperdir first", "overlay overlay upperdir=/child-upper,rw,lowerdir=/lower", "/child-upper"},
		{"upperdir last", "overlay overlay rw,lowerdir=/lower,upperdir=/child-upper", "/child-upper"},
		{"equals in upperdir", "overlay overlay rw,upperdir=/child=upper", "/child=upper"},
	} {
		t.Run(nested.name, func(t *testing.T) {
			ancestor := "21 20 0:2 / /var rw - overlay overlay rw,upperdir=/encrypted-upper,lowerdir=/lower\n"
			child := "22 21 0:3 / /var/lib rw - " + nested.fs + "\n"
			for _, data := range []string{ancestor + child, child + ancestor} {
				file := filepath.Join(t.TempDir(), "mountinfo")
				if err := os.WriteFile(file, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				for _, source := range []string{"/var/lib", "/var/lib/kubelet/pods/x"} {
					mountpoint, got, ok := containingOverlay(file, source)
					if mountpoint != "/var/lib" || got != nested.want || ok != (nested.want != "") {
						t.Fatalf("containing overlay for %s = %q, %q, %v; want /var/lib, %q", source, mountpoint, got, ok, nested.want)
					}
				}
			}
		})
	}
}

func TestTrustedScratchRejectsIncompleteProvenance(t *testing.T) {
	for _, missing := range []string{"version", "boot_id", "device", "name", "uuid"} {
		t.Run(missing, func(t *testing.T) {
			root := t.TempDir()
			bootID := filepath.Join(root, "boot-id")
			provenance := filepath.Join(root, "provenance")
			fields := map[string]any{"version": 1, "boot_id": "boot-a", "device": "253:0", "name": "scratch", "uuid": "CRYPT-test"}
			delete(fields, missing)
			data, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			for path, content := range map[string][]byte{bootID: []byte("boot-a"), provenance: data, filepath.Join(root, "dev"): []byte("253:0")} {
				if err := os.WriteFile(path, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			i := linuxStorageInspector{provenanceFile: provenance, bootIDFile: bootID}
			if i.isTrustedScratchProvenance(root, "CRYPT-test") {
				t.Fatal("incomplete provenance trusted")
			}
			if missing == "device" {
				if err := os.Remove(filepath.Join(root, "dev")); err != nil {
					t.Fatal(err)
				}
				if i.isTrustedScratchProvenance(root, "CRYPT-test") {
					t.Fatal("missing provenance and sysfs device numbers trusted")
				}
			}
		})
	}
}

func TestContainingOverlayUsesMostSpecificMount(t *testing.T) {
	file := filepath.Join(t.TempDir(), "mountinfo")
	data := "20 1 0:1 / / rw - ext4 /dev/root rw\n" +
		"21 20 0:2 / /var rw - overlay overlay rw,lowerdir=/lower,upperdir=/scratch\\040upper,workdir=/work\n"
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	mountpoint, got, ok := containingOverlay(file, "/var/lib/kubelet/pods/x")
	if !ok || mountpoint != "/var" || got != "/scratch upper" {
		t.Fatalf("containing overlay = %q, %q, %v", mountpoint, got, ok)
	}
}

func TestContainingOverlayEscapedPaths(t *testing.T) {
	for _, tc := range []struct {
		name, encoded, decoded string
	}{
		{"space", `\040`, " "},
		{"tab", `\011`, "\t"},
		{"newline", `\012`, "\n"},
		{"backslash", `\134`, `\`},
		{"literal octal sequence", `\134040`, `\040`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "mountinfo")
			data := "21 20 0:2 / /var" + tc.encoded + "lib rw - overlay overlay rw,upperdir=/scratch" + tc.encoded + "upper\n"
			if err := os.WriteFile(file, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			for _, source := range []string{"/var" + tc.decoded + "lib", "/var" + tc.decoded + "lib/pods/x"} {
				mountpoint, got, ok := containingOverlay(file, source)
				want := "/scratch" + tc.decoded + "upper"
				if !ok || mountpoint != "/var"+tc.decoded+"lib" || got != want {
					t.Fatalf("containing overlay for %q = %q, %q, %v; want %q", source, mountpoint, got, ok, want)
				}
			}
		})
	}
}

func TestTrustedScratchRequiresCryptAndBackingSerial(t *testing.T) {
	root := t.TempDir()
	dev, class := filepath.Join(root, "dev", "dm-0"), filepath.Join(root, "class")
	for _, dir := range []string{filepath.Join(dev, "dm"), filepath.Join(dev, "slaves"), filepath.Join(class, "vda", "device")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, value string) {
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dev, "dm/name"), "scratch\n")
	write(filepath.Join(dev, "dm/uuid"), "CRYPT-PLAIN-test\n")
	write(filepath.Join(dev, "dev"), "253:0\n")
	write(filepath.Join(class, "vda", "serial"), "confai-scratch\n")
	if err := os.Symlink(filepath.Join(class, "vda"), filepath.Join(dev, "slaves", "vda")); err != nil {
		t.Fatal(err)
	}
	bootID := filepath.Join(root, "boot-id")
	provenance := filepath.Join(root, "scratch-provenance.json")
	write(bootID, "boot-a\n")
	write(provenance, `{"version":1,"boot_id":"boot-a","device":"253:0","name":"scratch","uuid":"CRYPT-PLAIN-test"}`)
	i := linuxStorageInspector{sysClassBlock: class, provenanceFile: provenance, bootIDFile: bootID}
	if !i.isTrustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("complete scratch proof rejected")
	}
	write(filepath.Join(dev, "dm/uuid"), "DM-LINEAR-test\n")
	if i.isTrustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("non-crypt scratch trusted")
	}
	write(filepath.Join(dev, "dm/uuid"), "CRYPT-PLAIN-test\n")
	write(filepath.Join(class, "vda", "device/serial"), "confai-scratch\n")
	write(filepath.Join(class, "vda", "serial"), "scratch-lookalike\n")
	if i.isTrustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("wrong backing serial trusted")
	}
	if err := os.Remove(filepath.Join(class, "vda", "serial")); err != nil {
		t.Fatal(err)
	}
	if i.isTrustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("parent device serial trusted without block device serial")
	}
	write(filepath.Join(class, "vda", "serial"), "")
	if i.isTrustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("empty block device serial trusted")
	}
	write(filepath.Join(class, "vda", "serial"), "confai-scratch\n")
	write(bootID, "boot-b\n")
	if i.isTrustedEncryptedDevice(dev, map[string]bool{}) {
		t.Fatal("stale boot provenance trusted")
	}
}

// stateOverlayFixture reproduces a booted node image: an encrypted scratch
// mapping in sysfs, the provenance record scratch-enforce.service wrote for
// this boot, the state directories the measured image declares, and a /var
// overlay whose recorded upperdir lives in the initrd's discarded namespace.
type stateOverlayFixture struct {
	inspector                        linuxStorageInspector
	mountInfo, stateConf, provenance string
	bootID, dmName, dmUUID, dmDev    string
	serial                           string
}

const deadUpperDir = "/state/1/upper"

func newStateOverlayFixture(t *testing.T) stateOverlayFixture {
	t.Helper()
	root := t.TempDir()
	devBlock, class := filepath.Join(root, "dev"), filepath.Join(root, "class")
	dm, slave := filepath.Join(root, "block", "dm-0"), filepath.Join(class, "vdb")
	stateDir := filepath.Join(root, "state.d")
	for _, dir := range []string{devBlock, stateDir, slave, filepath.Join(dm, "dm"), filepath.Join(dm, "slaves")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f := stateOverlayFixture{
		mountInfo:  filepath.Join(root, "mountinfo"),
		stateConf:  filepath.Join(stateDir, "00-base.conf"),
		provenance: filepath.Join(root, "scratch-provenance.json"),
		bootID:     filepath.Join(root, "boot-id"),
		dmName:     filepath.Join(dm, "dm/name"),
		dmUUID:     filepath.Join(dm, "dm/uuid"),
		dmDev:      filepath.Join(dm, "dev"),
		serial:     filepath.Join(slave, "serial"),
	}
	for name, content := range map[string]string{
		f.mountInfo: "20 1 253:1 / / ro - ext4 /dev/mapper/root ro\n" +
			"21 20 0:33 / /var rw - overlay overlay rw,lowerdir=/sysroot/var,upperdir=" +
			deadUpperDir + ",workdir=/state/1/work,uuid=on\n",
		f.stateConf:  "# confos base\nvar\nhome\n",
		f.provenance: `{"version":1,"boot_id":"boot-a","device":"253:0","name":"scratch","uuid":"CRYPT-PLAIN-test"}`,
		f.bootID:     "boot-a\n",
		f.dmName:     "scratch\n",
		f.dmUUID:     "CRYPT-PLAIN-test\n",
		f.dmDev:      "253:0\n",
		f.serial:     "confai-scratch\n",
	} {
		writeFixture(t, name, content)
	}
	for target, link := range map[string]string{slave: filepath.Join(dm, "slaves", "vdb"), dm: filepath.Join(devBlock, "253:0")} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	f.inspector = linuxStorageInspector{
		sysDevBlock: devBlock, sysClassBlock: class, mountInfo: f.mountInfo, stateDir: stateDir,
		provenanceFile: f.provenance, bootIDFile: f.bootID,
	}
	return f
}

func writeFixture(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// The recorded upperdir is a path the initrd created before switch_root, so it
// does not resolve in the root the inspector runs in. Following it is what the
// synthetic-tree tests cannot reproduce, because they only ever record an
// upperdir they just created.
func TestOverlayStorageClassifiesInitrdStateOverlay(t *testing.T) {
	const source = "/var/lib/kubelet/pods/pod-a/volumes/kubernetes.io~empty-dir/cache"
	if _, err := os.Stat(deadUpperDir); err == nil {
		t.Skipf("%s resolves in this root", deadUpperDir)
	}
	f := newStateOverlayFixture(t)
	if got := f.inspector.inspect(deadUpperDir, map[string]bool{}); got != allowlist.MountUnknown {
		t.Fatalf("recorded upperdir resolved to %q", got)
	}
	if got := f.inspector.overlayStorage(source, map[string]bool{}); got != allowlist.MountEncrypted {
		t.Fatalf("state overlay on encrypted scratch = %q, want %q", got, allowlist.MountEncrypted)
	}
}

func TestOverlayStorageFailsClosed(t *testing.T) {
	const source = "/var/lib/kubelet/pods/pod-a/volumes/kubernetes.io~empty-dir/cache"
	roOverlay := "21 20 0:33 / /var ro - overlay overlay ro,lowerdir=/sysroot/var\n"
	for _, tc := range []struct {
		name    string
		corrupt func(t *testing.T, f *stateOverlayFixture)
	}{
		{"mountpoint not declared", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.stateConf, "home\n")
		}},
		{"mountpoint declared only as an ancestor", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.stateConf, "var/lib\n")
		}},
		{"declaration commented out", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.stateConf, "#var\n")
		}},
		{"no declarations in the image", func(t *testing.T, f *stateOverlayFixture) {
			if err := os.Remove(f.stateConf); err != nil {
				t.Fatal(err)
			}
		}},
		{"read-only overlay", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.mountInfo, roOverlay)
		}},
		{"no provenance record", func(t *testing.T, f *stateOverlayFixture) {
			if err := os.Remove(f.provenance); err != nil {
				t.Fatal(err)
			}
		}},
		{"provenance from an earlier boot", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.bootID, "boot-b\n")
		}},
		{"provenance device escapes sysfs", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.provenance, `{"version":1,"boot_id":"boot-a","device":"253:0/../../block/dm-0","name":"scratch","uuid":"CRYPT-PLAIN-test"}`)
		}},
		{"provenance device disagrees with sysfs", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.dmDev, "253:9\n")
		}},
		{"mapping is not a crypt target", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.dmUUID, "DM-LINEAR-test\n")
		}},
		{"mapping is merely named scratch elsewhere", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.dmName, "containerd\n")
		}},
		{"backing device is not the scratch disk", func(t *testing.T, f *stateOverlayFixture) {
			writeFixture(t, f.serial, "confai-models\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStateOverlayFixture(t)
			tc.corrupt(t, &f)
			if got := f.inspector.overlayStorage(source, map[string]bool{}); got != allowlist.MountUnknown {
				t.Fatalf("storage = %q, want %q", got, allowlist.MountUnknown)
			}
		})
	}
}

func TestNoMountsBelow(t *testing.T) {
	source, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, mountInfo string
		want            bool
	}{
		{"none below", "20 1 0:1 / / rw - ext4 /dev/root rw\n21 20 0:2 / " + source + " rw - ext4 /dev/vdb rw\n", true},
		{"sibling with a shared prefix", "21 20 0:2 / " + source + "2 rw - tmpfs tmpfs rw\n", true},
		{"one below", "21 20 0:2 / " + source + "/pvc rw - ext4 /dev/vdc rw\n", false},
		{"malformed line", "21 20\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "mountinfo")
			if err := os.WriteFile(file, []byte(tc.mountInfo), 0600); err != nil {
				t.Fatal(err)
			}
			if got := (linuxStorageInspector{mountInfo: file}).NoMountsBelow(source); got != tc.want {
				t.Fatalf("NoMountsBelow(%q) = %v, want %v", source, got, tc.want)
			}
		})
	}
	if (linuxStorageInspector{mountInfo: "/nonexistent"}).NoMountsBelow(source) {
		t.Fatal("NoMountsBelow without a mount table = true, want false")
	}
}
