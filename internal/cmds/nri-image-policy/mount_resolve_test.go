//go:build linux

package nriimagepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// imageRootfs builds a root filesystem holding the given symlinks and
// directories, keyed by their path inside the image.
func imageRootfs(t *testing.T, symlinks map[string]string, dirs ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range symlinks {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, link)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestResolveDestination(t *testing.T) {
	root := imageRootfs(t, map[string]string{
		"/var/run":  "/run",
		"/lib":      "usr/lib",
		"/escape":   "../../..",
		"/loop":     "/loop",
		"/run/link": "/usr/lib",
	}, "/run/v", "/usr/lib")
	for _, tc := range []struct {
		destination, want string
	}{
		{"/config", "/config"},
		{"/var/run/v", "/run/v"},
		{"/var/run/v/new/dir", "/run/v/new/dir"},
		{"/lib/x", "/usr/lib/x"},
		{"/escape/etc", "/etc"},
		{"/var/run/link", "/usr/lib"},
	} {
		got, err := resolveDestination(root, tc.destination)
		if err != nil || got != tc.want {
			t.Errorf("resolveDestination(%q) = %q, %v, want %q", tc.destination, got, err, tc.want)
		}
	}
	if got, err := resolveDestination(root, "/loop/x"); err == nil {
		t.Errorf("resolveDestination(/loop/x) = %q, want a symlink loop error", got)
	}
}

// After a symlink the walk may not enter another mount: the host's own
// /var/run -> /run alias leads onto the /run tmpfs.
func TestResolveDestinationRefusesSymlinkIntoMount(t *testing.T) {
	if target, err := os.Readlink("/var/run"); err != nil || target != "/run" {
		t.Skip("/var/run is not a symlink to /run")
	}
	if crossed, err := crossesMount("/", "/run"); err != nil || !crossed {
		t.Skip("/run is not a separate mount")
	}
	if got, err := resolveDestination("/", "/var/run/v/x"); err == nil {
		t.Fatalf("resolveDestination(/, /var/run/v/x) = %q, want an error", got)
	}
	if got, err := resolveDestination("/", "/var/run"); err != nil || got != "/run" {
		t.Fatalf("resolveDestination(/, /var/run) = %q, %v, want /run", got, err)
	}
}

func TestWithholdAliasedMounts(t *testing.T) {
	root := imageRootfs(t, map[string]string{"/var/run": "/run", "/shm": "/dev/shm"}, "/run/v", "/dev/shm")
	rootfs := func(string) (string, error) { return root, nil }
	volume := func(destination string) allowlist.ObservedMount {
		return allowlist.ObservedMount{Destination: destination, Class: allowlist.MountEmptyDir, Storage: allowlist.MountMemory}
	}
	platform := func(destination string) allowlist.ObservedMount {
		return allowlist.ObservedMount{Destination: destination, Class: allowlist.MountPlatform}
	}
	for _, tc := range []struct {
		name   string
		rootfs func(string) (string, error)
		mounts []allowlist.ObservedMount
		kept   bool
	}{
		{"siblings", rootfs, []allowlist.ObservedMount{volume("/run/v"), volume("/data")}, true},
		{"volume behind an image alias of another volume", rootfs, []allowlist.ObservedMount{volume("/run/v"), volume("/var/run/v/link")}, false},
		{"platform mount behind an image alias of a volume", rootfs, []allowlist.ObservedMount{volume("/run/v"), platform("/var/run/v/hosts")}, false},
		{"volume behind an image alias of /dev/shm", rootfs, []allowlist.ObservedMount{platform("/dev/shm"), volume("/shm/x")}, false},
		{"lexical nesting is left to the policy", rootfs, []allowlist.ObservedMount{volume("/dev"), platform("/dev/termination-log")}, true},
		{"aliased destination without nesting", rootfs, []allowlist.ObservedMount{volume("/var/run/nri"), platform("/etc/hosts")}, true},
		{"no rootfs", func(string) (string, error) { return "", errors.New("gone") }, []allowlist.ObservedMount{volume("/a"), volume("/b")}, false},
		{"one mount needs no rootfs", func(string) (string, error) { return "", errors.New("gone") }, []allowlist.ObservedMount{volume("/a")}, true},
		{"platform mounts need no rootfs", func(string) (string, error) { return "", errors.New("gone") }, []allowlist.ObservedMount{platform("/etc/hosts"), platform("/dev/shm")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := withholdAliasedMounts(tc.rootfs, &api.Container{Id: "c"}, tc.mounts)
			if (got != nil) != tc.kept {
				t.Fatalf("withholdAliasedMounts(%+v) = %+v, want kept %v", tc.mounts, got, tc.kept)
			}
		})
	}
}

// The runtime follows /var/run -> /run in the image and then a symlink inside
// the volume at /run/v, so the second mount lands on /usr/lib although its
// destination sits in no volume and below no denied path as written.
func TestConfinedAdmissionResolvesImageAliases(t *testing.T) {
	root := imageRootfs(t, map[string]string{"/var/run": "/run"}, "/run/v", "/usr/lib")
	for name, tc := range map[string]struct {
		destination string
		allowed     bool
	}{
		"beside the volume":              {"/var/run/w", true},
		"through an alias of the volume": {"/var/run/v/link", false},
	} {
		t.Run(name, func(t *testing.T) {
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyConfined, DenyBelow: []string{"/usr"}}
			if err := al.Normalize(); err != nil {
				t.Fatal(err)
			}
			p, _ := newCachedPlugin(&config{
				Policy:    policyConfig{Mode: ModeFailClosed},
				Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}},
			}, al)
			p.SetReady()
			p.rootfs = func(string) (string, error) { return root, nil }
			pod := makePod("default", "pod")
			ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app"}
			if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err != nil {
				t.Fatalf("preliminary admission: %v", err)
			}
			readOnly := []string{"bind", "ro", "rprivate"}
			ctr.Mounts = []*api.Mount{
				{Type: "bind", Source: t.TempDir(), Destination: "/run/v", Options: readOnly},
				{Type: "bind", Source: t.TempDir(), Destination: tc.destination, Options: readOnly},
			}
			if err := p.StartContainer(t.Context(), pod, ctr); (err == nil) != tc.allowed {
				t.Fatalf("StartContainer(%s) error = %v, want allowed = %v", tc.destination, err, tc.allowed)
			}
		})
	}
}
