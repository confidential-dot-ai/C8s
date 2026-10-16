//go:build !c8s_node

package helmchart

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

// The host sweep's LIO step must remove exactly what `c8s volume attach`
// builds and nothing else, so these build the configfs tree with the real
// Attacher and run the sweep's shipped LIO snippet against it.

// lioSweepSnippet returns the body of host-sweep.sh's lio_sweep_script.
func lioSweepSnippet(t *testing.T) string {
	t.Helper()
	s := HostSweepScript()
	const open = "lio_sweep_script='\n"
	i := strings.Index(s, open)
	if i < 0 {
		t.Fatal("host-sweep.sh has no lio_sweep_script")
	}
	body := s[i+len(open):]
	j := strings.Index(body, "\n'\n")
	if j < 0 {
		t.Fatal("lio_sweep_script is not closed by a lone quote line")
	}
	return body[:j+1]
}

type lioFixture struct {
	attacher volume.Attacher
	proc     string
	log      string
	bin      string
}

// newLIOFixture lays out a fake configfs, sysfs and procfs, and stubs rmdir
// onto PATH: configfs frees a group's attributes with its directory, which
// rmdir on a temp dir will not do. The stub logs each path, and refuses any
// path containing refuse (when set) so a case can make a teardown fail.
func newLIOFixture(t *testing.T, refuse string) *lioFixture {
	t.Helper()
	dir := t.TempDir()
	f := &lioFixture{
		attacher: volume.Attacher{
			Root:        filepath.Join(dir, "config"),
			SysRoot:     filepath.Join(dir, "sys"),
			Run:         func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
			RemoveGroup: os.RemoveAll,
		},
		proc: filepath.Join(dir, "proc"),
		log:  filepath.Join(dir, "rmdir.log"),
		bin:  filepath.Join(dir, "bin"),
	}
	for _, d := range []string{
		filepath.Join(f.attacher.Root, "target", "core"),
		filepath.Join(f.attacher.Root, "target", "loopback"),
		f.attacher.SysRoot,
		f.proc,
		f.bin,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// PID 1 with the root filesystem, so the scan always has something to skip.
	f.mount(t, 1, 1, "8:1", "/dev/sda1")
	if err := os.Symlink("1", filepath.Join(f.proc, "self")); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nfor p in \"$@\"; do\n  printf '%s\\n' \"$p\" >> '" + f.log + "'\n"
	if refuse != "" {
		stub += "  case \"$p\" in *'" + refuse + "'*) exit 1 ;; esac\n"
	}
	stub += "  rm -rf \"$p\" || exit 1\ndone\n"
	if err := os.WriteFile(filepath.Join(f.bin, "rmdir"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *lioFixture) target() string { return filepath.Join(f.attacher.Root, "target") }

func (f *lioFixture) backstore(name string) string {
	return filepath.Join(f.target(), "core", "fileio_0", name)
}

func (f *lioFixture) blockDir(scsiAddr, disk string) string {
	return filepath.Join(f.attacher.SysRoot, "class", "scsi_device", scsiAddr+":0", "device", "block", disk)
}

// attach runs the real attach for name, then adds what the kernel publishes
// for the disk it creates: the portal group's SCSI address and the disk that
// address resolves to, numbered devno and held by the named devices. Returns
// the target dir.
func (f *lioFixture) attach(t *testing.T, name, scsiAddr, disk, devno string, holders ...string) string {
	t.Helper()
	before, _ := filepath.Glob(filepath.Join(f.target(), "loopback", "naa.*"))
	img := filepath.Join(t.TempDir(), name+".img")
	if err := os.WriteFile(img, make([]byte, volume.ImageBlockSize), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.attacher.Attach(context.Background(), name, img); err != nil {
		t.Fatalf("attach %s: %v", name, err)
	}
	after, _ := filepath.Glob(filepath.Join(f.target(), "loopback", "naa.*"))
	if len(after) != len(before)+1 {
		t.Fatalf("attach %s built %d targets, want 1", name, len(after)-len(before))
	}
	var target string
	for _, a := range after {
		if !strings.Contains(strings.Join(before, "\n"), a) {
			target = a
		}
	}
	if err := os.WriteFile(filepath.Join(target, "tpgt_1", "address"), []byte(scsiAddr+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	blockDev(t, f.blockDir(scsiAddr, disk), devno, false, holders...)
	return target
}

// partition adds partition part, numbered devno, to the disk at scsiAddr.
func (f *lioFixture) partition(t *testing.T, scsiAddr, disk, part, devno string) {
	t.Helper()
	blockDev(t, filepath.Join(f.blockDir(scsiAddr, disk), part), devno, true)
}

func blockDev(t *testing.T, dir, devno string, partition bool, holders ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "holders"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dev"), []byte(devno+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if partition {
		if err := os.WriteFile(filepath.Join(dir, "partition"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range holders {
		if err := os.Mkdir(filepath.Join(dir, "holders", h), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// mount gives process pid mount namespace ns, whose table holds a filesystem
// with device number devno mounted from source — as a pod's own mount
// namespace would: nothing on the host's table shows it.
func (f *lioFixture) mount(t *testing.T, pid, ns int, devno, source string) {
	t.Helper()
	dir := f.process(t, pid, ns)
	line := "36 1 " + devno + " / /mnt rw,relatime shared:1 - ext4 " + source + " rw\n"
	if err := os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
}

// process lays out /proc/<pid> with its ns/mnt link naming namespace ns; a
// zero ns leaves the link out, as for a zombie.
func (f *lioFixture) process(t *testing.T, pid, ns int) string {
	t.Helper()
	dir := filepath.Join(f.proc, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ns != 0 {
		if err := os.Symlink("mnt:["+strconv.Itoa(4026531840+ns)+"]", filepath.Join(dir, "ns", "mnt")); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// unreadable puts a directory where the script expects a file: it exists, and
// cat fails on it even for root, which a chmod would not achieve.
func unreadable(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func (f *lioFixture) run(t *testing.T) (string, int) {
	t.Helper()
	return f.runWithPath(t, f.bin+":/usr/bin:/bin")
}

func (f *lioFixture) runWithPath(t *testing.T, path string) (string, int) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", lioSweepSnippet(t), "lio-sweep", f.attacher.Root, f.attacher.SysRoot, f.proc)
	cmd.Env = append(os.Environ(), "PATH="+path)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run lio sweep: %v", err)
	}
	return string(out), code
}

func (f *lioFixture) rmdirs(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// The reported defect: an idle attached volume outlived the uninstall. The
// sweep unwinds it in Detach's order — LIO will not release a backstore a LUN
// still references — and keeps the shared HBA.
func TestHostSweepDetachesAnIdleAttachedVolume(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	target := f.attach(t, "demo", "3:0:1", "sdb", "8:16")
	f.partition(t, "3:0:1", "sdb", "sdb1", "8:17")
	// What the kernel actually returns on read, unlike what attach writes.
	if err := os.WriteFile(filepath.Join(f.backstore("demo"), "wwn", "vpd_unit_serial"),
		[]byte("T10 VPD Unit Serial Number: c8s-vol-demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d; output:\n%s", code, out)
	}
	if exists(target) || exists(f.backstore("demo")) {
		t.Fatalf("target or backstore survived the sweep; output:\n%s", out)
	}
	if !exists(filepath.Join(f.target(), "core", "fileio_0")) {
		t.Error("the sweep removed the fileio_0 HBA, which Detach leaves")
	}
	if !strings.Contains(out, "c8s volume LIO disk detached: demo") {
		t.Errorf("output does not name the detached volume:\n%s", out)
	}
	want := []string{
		filepath.Join(target, "tpgt_1", "lun", "lun_0"),
		filepath.Join(target, "tpgt_1"),
		target,
		f.backstore("demo"),
	}
	if got := f.rmdirs(t); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("rmdir order:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// Removing a disk something holds unbinds it under its user, so the sweep
// leaves it and says how to finish the job.
func TestHostSweepLeavesAHeldVolume(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	target := f.attach(t, "demo", "3:0:1", "sdb", "8:16", "dm-0")
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d; an in-use volume warns, it does not fail the sweep:\n%s", code, out)
	}
	if !exists(target) || !exists(f.backstore("demo")) {
		t.Fatal("the sweep tore down a held volume")
	}
	if len(f.rmdirs(t)) != 0 {
		t.Errorf("rmdir called on a held volume: %v", f.rmdirs(t))
	}
	if !strings.Contains(out, "dm-0") || !strings.Contains(out, "c8s volume detach demo") {
		t.Errorf("warning does not name the holder and the way out:\n%s", out)
	}
}

// A filesystem mounted from the disk or a partition does not show as a holder,
// and a mount made inside a pod's own mount namespace is not on the host's
// table either. Matching by device number across every process's mountinfo
// sees both, whatever path the mount was made through.
func TestHostSweepLeavesAVolumeMountedInAnotherNamespace(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	target := f.attach(t, "demo", "3:0:1", "sdb", "8:16")
	f.partition(t, "3:0:1", "sdb", "sdb1", "8:17")
	f.mount(t, 4242, 2, "8:17", "/dev/disk/by-uuid/x")
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !exists(target) || !exists(f.backstore("demo")) {
		t.Fatal("the sweep tore down a mounted volume")
	}
	if !strings.Contains(out, "sdb1(mounted)") {
		t.Errorf("warning does not name the mounted partition:\n%s", out)
	}
}

// btrfs (and ZFS, bcachefs) report an anonymous device number in mountinfo,
// so only the mount source ties the mount to the partition.
func TestHostSweepLeavesAVolumeMountedByAnonymousDevice(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	target := f.attach(t, "demo", "3:0:1", "sdb", "8:16")
	f.partition(t, "3:0:1", "sdb", "sdb1", "8:17")
	f.mount(t, 4242, 2, "0:45", "/dev/sdb1")
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !exists(target) || !exists(f.backstore("demo")) {
		t.Fatal("the sweep tore down a disk with a btrfs mount on it")
	}
	if !strings.Contains(out, "sdb1(mounted)") {
		t.Errorf("warning does not name the mounted partition:\n%s", out)
	}
}

// A zombie (or an exiting task) has no namespaces: its ns/mnt link does not
// resolve and its mountinfo fails to read. It holds nothing, and must not make
// every disk on a node with a zombie "unknown". A second PID in a namespace
// already read is not read again, so its state does not matter either.
func TestHostSweepIgnoresZombiesAndReadNamespaces(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	target := f.attach(t, "demo", "3:0:1", "sdb", "8:16")
	unreadable(t, filepath.Join(f.process(t, 99, 0), "mountinfo"))
	unreadable(t, filepath.Join(f.process(t, 100, 1), "mountinfo"))
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if exists(target) || exists(f.backstore("demo")) {
		t.Fatalf("an idle volume survived a sweep on a node with a zombie:\n%s", out)
	}
}

func TestHostSweepLeavesAVolumeInUseAsSwap(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	target := f.attach(t, "demo", "3:0:1", "sdb", "8:16")
	f.partition(t, "3:0:1", "sdb", "sdb2", "8:18")
	swaps := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/sdb2 partition\t1020\t0\t-2\n"
	if err := os.WriteFile(filepath.Join(f.proc, "swaps"), []byte(swaps), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !exists(target) || !exists(f.backstore("demo")) {
		t.Fatal("the sweep tore down a disk in use as swap")
	}
	if !strings.Contains(out, "sdb2(swap)") {
		t.Errorf("warning does not name the swap partition:\n%s", out)
	}
}

// State the in-use check cannot read is an unknown, not "idle": like Detach,
// the sweep refuses, and says so by failing.
func TestHostSweepFailsWhenUseCannotBeRead(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, f *lioFixture, target string)
	}{
		{"portal address", func(t *testing.T, _ *lioFixture, target string) {
			unreadable(t, filepath.Join(target, "tpgt_1", "address"))
		}},
		{"disk device number", func(t *testing.T, f *lioFixture, _ string) {
			unreadable(t, filepath.Join(f.blockDir("3:0:1", "sdb"), "dev"))
		}},
		{"a live process's mountinfo", func(t *testing.T, f *lioFixture, _ string) {
			unreadable(t, filepath.Join(f.process(t, 77, 3), "mountinfo"))
		}},
		{"no procfs", func(t *testing.T, f *lioFixture, _ string) {
			if err := os.Remove(filepath.Join(f.proc, "self")); err != nil {
				t.Fatal(err)
			}
		}},
		{"swaps", func(t *testing.T, f *lioFixture, _ string) {
			unreadable(t, filepath.Join(f.proc, "swaps"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLIOFixture(t, "")
			target := f.attach(t, "demo", "3:0:1", "sdb", "8:16")
			tc.break_(t, f, target)
			out, code := f.run(t)
			if code == 0 {
				t.Fatalf("exit 0 though whether the disk is in use is unknown:\n%s", out)
			}
			if !exists(target) || !exists(f.backstore("demo")) {
				t.Fatal("the sweep tore down a volume whose use it could not read")
			}
			if !strings.Contains(out, "cannot tell whether its disk is in use") {
				t.Errorf("failure does not say why:\n%s", out)
			}
		})
	}
}

// Only a backstore whose serial is exactly c8s-vol-<its own name>, under the
// HBA attach uses, is c8s's. Everything else on the node is the operator's.
func TestHostSweepLeavesWhatAttachDidNotBuild(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	foreign := func(hba, name, serial string) string {
		dir := filepath.Join(f.target(), "core", hba, name)
		if err := os.MkdirAll(filepath.Join(dir, "wwn"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "wwn", "vpd_unit_serial"), []byte(serial+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// One past the longest name attach accepts.
	tooLong := strings.Repeat("a", volume.MaxNameLen+1)
	kept := []string{
		foreign("fileio_0", "data", "T10 VPD Unit Serial Number: 6001405abcdef"),
		foreign("fileio_0", "other", "c8s-vol-demo"),
		foreign("fileio_0", "Demo", "c8s-vol-Demo"),
		foreign("fileio_0", tooLong, volume.SerialPrefix+tooLong),
		foreign("fileio_1", "demo", "c8s-vol-demo"),
	}
	unrelated := filepath.Join(f.target(), "loopback", "naa.5001405000000001", "tpgt_1", "lun", "lun_0")
	if err := os.MkdirAll(unrelated, 0o755); err != nil {
		t.Fatal(err)
	}
	kept = append(kept, unrelated)

	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, k := range kept {
		if !exists(k) {
			t.Errorf("the sweep removed %s, which attach did not build", k)
		}
	}
	if got := f.rmdirs(t); len(got) != 0 {
		t.Errorf("rmdir called on objects attach did not build: %v", got)
	}
}

// The shell's name bound must match attach's: the longest name attach accepts
// is swept, and one longer is left (TestHostSweepLeavesWhatAttachDidNotBuild).
func TestHostSweepDetachesALongestNameVolume(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	name := strings.Repeat("a", volume.MaxNameLen)
	target := f.attach(t, name, "3:0:1", "sdb", "8:16")
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if exists(target) || exists(f.backstore(name)) {
		t.Fatalf("a %d-character volume survived the sweep:\n%s", len(name), out)
	}
}

// One stuck volume must not shield the rest, and must fail the sweep: a
// target left serving an idle volume's image is what the step exists to stop.
func TestHostSweepFailsOnAVolumeThatWillNotDetach(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "fileio_0/stuck")
	f.attach(t, "stuck", "3:0:1", "sdb", "8:16")
	ok := f.attach(t, "fine", "3:0:2", "sdc", "8:32")
	out, code := f.run(t)
	if code == 0 {
		t.Fatalf("exit 0 with a backstore left behind:\n%s", out)
	}
	if !strings.Contains(out, "could not detach c8s volume stuck") {
		t.Errorf("failure does not name the volume:\n%s", out)
	}
	if exists(ok) || exists(f.backstore("fine")) {
		t.Errorf("the stuck volume stopped the sweep of the next one:\n%s", out)
	}
}

// A busybox-only host has no sha256sum binary, but busybox carries the applet.
func TestHostSweepFallsBackToBusyboxSha256sum(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	target := f.attach(t, "demo", "3:0:1", "sdb", "8:16")
	only := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(only, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"cat", "cut", "awk", "rm", "readlink"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("no %s on this machine", tool)
		}
		if err := os.Symlink(p, filepath.Join(only, tool)); err != nil {
			t.Fatal(err)
		}
	}
	sha, err := exec.LookPath("sha256sum")
	if err != nil {
		t.Skip("no sha256sum to stand behind the busybox stub")
	}
	busybox := "#!/bin/sh\n[ \"$1\" = sha256sum ] || exit 127\nshift\nexec '" + sha + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(only, "busybox"), []byte(busybox), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.bin, "rmdir"), filepath.Join(only, "rmdir")); err != nil {
		t.Fatal(err)
	}
	out, code := f.runWithPath(t, only)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if exists(target) || exists(f.backstore("demo")) {
		t.Fatalf("the busybox fallback did not locate the target:\n%s", out)
	}
}

// A node that never served a volume (or has no configfs at all) is a no-op.
func TestHostSweepIsANoOpWithoutLIO(t *testing.T) {
	t.Parallel()
	f := newLIOFixture(t, "")
	f.attacher.Root = filepath.Join(t.TempDir(), "absent")
	out, code := f.run(t)
	if code != 0 || strings.TrimSpace(out) != "" {
		t.Fatalf("exit %d, output %q; want a silent no-op", code, out)
	}
}

// The snippet only does anything if the sweep hands it the host's configfs,
// sysfs and procfs, from inside the host's mount and PID namespaces.
func TestHostSweepRunsTheLIOStepAgainstTheHost(t *testing.T) {
	t.Parallel()
	want := `nsenter -t 1 -m -u -i -n -p -- sh -c "$lio_sweep_script" lio-sweep /sys/kernel/config /sys /proc`
	if !strings.Contains(HostSweepScript(), want) {
		t.Errorf("host-sweep.sh does not run the LIO step in the host mount namespace as:\n  %s", want)
	}
}
