//go:build linux

package nriimagepolicy

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestPodCredentialRootRejectsDiskAndSymlinksAndHoldsIdentity(t *testing.T) {
	requireNetNS(t)
	base := t.TempDir()
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
	oldOpen := openPodCredentialRoot
	openPodCredentialRoot = func(source string) (*os.Root, error) { return openPodCredentialRootBeneath(base, source) }
	t.Cleanup(func() { openPodCredentialRoot = oldOpen })
	if err := os.Rename(volume, volume+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(volume, 0700); err != nil {
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

func TestPodBrokerRefusesReconstructedOrReusedBootHistory(t *testing.T) {
	requireNetNS(t)
	base := t.TempDir()
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
	return func() *plugin {
		p := &plugin{cfg: &config{Platform: "tdx", Pod: &podConfig{}, Allowlist: allowlistConfig{Pull: pullConfig{CDSMeasurementsConfig: identityPolicyFile}}, WorkloadClaims: workloadClaimsConfig{SocketDir: base}}, logger: discardLogger()}
		if err := p.preparePodBroker(t.Context(), &http.Client{}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.closePodBroker)
		return p
	}
}

// The start that claims the boot identity is in the snapshot the worker's
// first issuance reads, so it sends no change; a later start does.
func TestEndpointStartWakesTheBrokerOnlyAfterItsFirstIssuance(t *testing.T) {
	requireNetNS(t)
	base := t.TempDir()
	mountPodTestRAM(t, base)
	source := filepath.Join(base, "certs")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	p := podBrokerPlugins(t, base)()
	pod := sandboxedPod()
	if err := p.afterPodStart(pod, source); err != nil {
		t.Fatal(err)
	}
	if len(p.podBroker.changes) != 0 {
		t.Fatal("the first issuance was asked for twice")
	}
	if err := p.afterPodStart(pod, source); err != nil {
		t.Fatal(err)
	}
	if len(p.podBroker.changes) != 1 {
		t.Fatal("a later endpoint start did not wake the broker")
	}
}
