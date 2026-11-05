//go:build linux

package nriimagepolicy

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/internal/podmesh/connectbroker"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// CC1: disk-backed, symlinked and substituted credential volumes are refused.
func TestPodCredentialRootRejectsDiskAndSymlinksAndHoldsIdentity(t *testing.T) {
	requireNetNS(t)
	base := podCredentialTestDir(t)
	ram := filepath.Join(base, "ram")
	mountPodTestRAM(t, ram)
	volume := filepath.Join(ram, "volume")
	if err := os.Mkdir(volume, 0777); err != nil {
		t.Fatal(err)
	}
	held, err := openPodCredentialRootBeneath(base, volume)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	info, err := held.Stat(".")
	if err != nil || info.Mode().Perm() != 0750 {
		t.Fatalf("volume permission: %v, %v", info, err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 || stat.Gid != workloadclaims.MeshUID {
		t.Fatalf("volume ownership = %d:%d", stat.Uid, stat.Gid)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(volume, alias); err != nil {
		t.Fatal(err)
	}
	if root, err := openPodCredentialRootBeneath(base, alias); err == nil {
		root.Close()
		t.Fatal("symlink credential volume accepted")
	}
	if root, err := openPodCredentialRootBeneath(base, filepath.Dir(base)); err == nil {
		root.Close()
		t.Fatal("credential root escaped its kubelet anchor")
	}
	// The ordinary test root may be tmpfs in a container; / is the disk case.
	if root, err := openPodCredentialRootBeneath("/", "/etc"); err == nil {
		root.Close()
		t.Fatal("disk-backed credential volume accepted")
	}
	if err := samePodCredentialRoot(held, volume); err != nil {
		t.Fatalf("unchanged credential root refused: %v", err)
	}
	if err := os.Chmod(volume, 0777); err != nil {
		t.Fatal(err)
	}
	if err := samePodCredentialRoot(held, volume); err == nil {
		t.Fatal("changed credential permissions accepted")
	}
	if info, err := os.Stat(volume); err != nil || info.Mode().Perm() != 0777 {
		t.Fatal("credential verification repaired changed permissions")
	}
	if err := os.Chmod(volume, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(volume, volume+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(volume, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(volume, 0, int(workloadclaims.MeshUID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(volume, 0750); err != nil {
		t.Fatal(err)
	}
	if err := samePodCredentialRoot(held, volume); err == nil {
		t.Fatal("replaced credential root accepted")
	}
	if err := held.WriteFile("held", []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(volume, "held")); !os.IsNotExist(err) {
		t.Fatal("held root followed replacement")
	}
}

// OB5: a restart cannot reconstruct history or reuse a claimed boot identity.
func TestPodBrokerRefusesReconstructedOrReusedBootHistory(t *testing.T) {
	requireNetNS(t)
	base := podCredentialTestDir(t)
	mountPodTestRAM(t, base)
	source := filepath.Join(base, "certs")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	newBroker := podBrokerPlugins(t, base)
	pod := sandboxedPod()
	reconstructed := newBroker()
	reconstructed.bootRestart.Store(true)
	if err := reconstructed.startPodCredentials(pod, source); err == nil {
		t.Fatal("reconstructed history issued credentials")
	}
	fresh := newBroker()
	if err := fresh.startPodCredentials(pod, source); err != nil {
		t.Fatal(err)
	}
	restarted := newBroker()
	if err := restarted.startPodCredentials(pod, source); err == nil {
		t.Fatal("restart reused a claimed boot identity")
	}
}

// podBrokerPlugins returns a constructor of pod-role plugins whose broker
// opens its credential root beneath base and whose worker idles until closed.
func podBrokerPlugins(t *testing.T, base string) func() *plugin {
	t.Helper()
	oldOpen, oldRun := openPodCredentialRoot, runGuestCredentials
	openPodCredentialRoot = func(source string) (*os.Root, error) { return openPodCredentialRootBeneath(base, source) }
	runGuestCredentials = func(ctx context.Context, _ getcert.GuestConfig) error { <-ctx.Done(); return nil }
	t.Cleanup(func() { openPodCredentialRoot, runGuestCredentials = oldOpen, oldRun })
	cdsPins := testCDSPinFile(t)
	return func() *plugin {
		p := &plugin{cfg: &config{Platform: "tdx", Pod: &podConfig{}, Allowlist: allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: cdsPins}}, WorkloadClaims: workloadClaimsConfig{SocketDir: base}}, logger: discardLogger()}
		p.mesh = newMeshGate(meshPolicy{Pod: &podMeshPolicy{Peers: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:15006")}}}, discardLogger())
		if err := p.preparePodBroker(t.Context(), &http.Client{}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.closePodBroker)
		return p
	}
}

// Use an exclusively owned path beneath the production anchor so verification
// exercises openat2 custody checks without weakening them through an opener hook.
func podCredentialTestDir(t *testing.T) string {
	t.Helper()
	if err := os.MkdirAll(kubeletRoot, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(kubeletRoot, "pod-credential-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

// CC4, MM3: the guest serves the endpoint's peer connections from the credential volume
// for as long as the Pod identity lasts, to the endpoint's UID alone.
func TestPodIdentityServesTheConnectBrokerInTheCredentialVolume(t *testing.T) {
	requireNetNS(t)
	base := podCredentialTestDir(t)
	mountPodTestRAM(t, base)
	source := filepath.Join(base, "certs")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	p := podBrokerPlugins(t, base)()
	if err := p.startPodCredentials(sandboxedPod(), source); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(source, connectbroker.SocketName)
	info, err := os.Lstat(socket)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 || stat.Uid != 0 || stat.Gid != workloadclaims.MeshUID {
		t.Fatalf("broker socket = %v uid %d gid %d", info.Mode(), stat.Uid, stat.Gid)
	}
	// This test runs as root, not as the endpoint: the broker answers, and refuses.
	if _, err := connectbroker.Dial(t.Context(), socket, netip.MustParseAddrPort("203.0.113.1:15006")); !errors.Is(err, connectbroker.ErrRefused) {
		t.Fatalf("a caller that is not the endpoint got %v", err)
	}
	p.closePodBroker()
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the broker socket outlived the Pod identity")
	}
}
