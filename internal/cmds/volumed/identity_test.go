package volumed

import (
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

func TestPeerIdentityResolvesTheCallersPod(t *testing.T) {
	const slice = "/kubepods.slice/kubepods-burstable.slice/" +
		"kubepods-burstable-pod3f4a1b2c_5d6e_7f80_9a0b_1c2d3e4f5061.slice"
	root := procWith(t, 42, "0::"+slice+"/cri-containerd-abcd.scope\n")

	pod, err := PeerIdentity{ProcRoot: root}.Resolve(workloadclaims.PeerForPID(42))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if pod.UID != wantUID {
		t.Fatalf("uid = %q, want %q", pod.UID, wantUID)
	}
	if pod.Path != slice {
		t.Fatalf("path = %q, want %q", pod.Path, slice)
	}
}

// The runtime-assigned slice is the shallowest, so a caller that nested a
// cgroup named after another pod does not get that pod's directory.
func TestPeerIdentityTakesTheShallowestCandidate(t *testing.T) {
	root := procWith(t, 9, "0::/kubepods.slice/"+
		"kubepods-pod3f4a1b2c_5d6e_7f80_9a0b_1c2d3e4f5061.slice/"+
		"pod99999999-8888-7777-6666-555555555555/nested\n")

	pod, err := PeerIdentity{ProcRoot: root}.Resolve(workloadclaims.PeerForPID(9))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if pod.UID != wantUID {
		t.Fatalf("uid = %q, want the runtime-assigned %q", pod.UID, wantUID)
	}
}

func TestPeerIdentityRefusesACallerOutsideAnyPod(t *testing.T) {
	root := procWith(t, 3, "0::/system.slice/sshd.service\n")
	if _, err := (PeerIdentity{ProcRoot: root}).Resolve(workloadclaims.PeerForPID(3)); err == nil {
		t.Fatal("resolved a process outside any pod")
	}
}

func TestPeerIdentityRefusesAPeerWithoutCredentials(t *testing.T) {
	if _, err := (PeerIdentity{ProcRoot: t.TempDir()}).Resolve(workloadclaims.PeerForPID(0)); err == nil {
		t.Fatal("resolved a caller with no peer PID")
	}
}

func TestPeerIdentityDefaultsItsProcRoot(t *testing.T) {
	if got := (PeerIdentity{}).procRoot(); got != "/proc" {
		t.Fatalf("procRoot = %q, want /proc", got)
	}
}
