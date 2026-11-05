//go:build linux

package nriimagepolicy

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"
)

func TestApplicationPIDObservationInTheNamespace(t *testing.T) {
	requireNetNS(t)
	if err := InitializePIDNamespaceProof(); err != nil {
		t.Fatal(err)
	}
	sandbox := exec.Command("sleep", "600")
	sandbox.SysProcAttr = &unix.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}
	if err := sandbox.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sandbox.Process.Kill(); _, _ = sandbox.Process.Wait() })
	digest := "sha256:" + strings.Repeat("a", 64)
	w, err := allowlist.ParseWorkloadJSON([]byte(`{"containers":[{"digest":"` + digest + `","command":{"policy":"exact","argv":["/worker"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"},"shareProcessNamespace":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	al := &allowlist.Allowlist{Schema: allowlist.ProcessNamespaceSchema, Workloads: map[string]allowlist.Workload{"pair": *w}}
	p := &plugin{policy: newPolicyStore(al), cfg: &config{}, pidGrantDir: t.TempDir()}
	p.cfg.Allowlist.NodeTCB = true
	p.SetReady()
	pod := meshPod("default", "pair", testNetNS)
	pod.Id, pod.Uid, pod.Pid = strings.Repeat("b", 64), "pod-uid", uint32(sandbox.Process.Pid)
	p.mesh, _ = gateWithPod(pod)
	t.Cleanup(func() { _ = RemovePIDNamespace(p.pidGrantDir, pod.Id) })
	ctr := gateCtr("prefill", testWorkloadUID)
	ctr.Id, ctr.PodSandboxId = strings.Repeat("c", 64), pod.Id
	ctr.Args, ctr.Annotations = []string{"/worker"}, map[string]string{annotationImageName: digest}
	adjustment, err := p.shareApplicationNamespace(t.Context(), pod, ctr, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyPIDNamespaceAdjustment(ctr, adjustment)
	ctr.Pid, ctr.State = pod.Pid, api.ContainerState_CONTAINER_RUNNING
	policy := w.ProcessNamespacePolicy()
	if got := p.processNamespacePolicy(ctr); got != policy {
		t.Fatalf("observed policy = %q, want %q", got, policy)
	}
	launch := p.observedLaunch(t.Context(), ctr, digest, containerEnv(ctr), p.observedMounts(pod, ctr))
	if got, path := p.pidGateEvidence(pod, ctr, launch); got != policy || path == "" || !al.BuildIndex().AdmitsContainer(launch) {
		t.Fatalf("final namespace evidence did not match: %q, %q, %+v", got, path, launch)
	}
	ctr.Pid = uint32(os.Getpid())
	if p.processNamespacePolicy(ctr) != invalidPIDPolicy {
		t.Fatal("accepted a running process in the node PID namespace")
	}
	ctr.State = api.ContainerState_CONTAINER_STOPPED
	if p.processNamespacePolicy(ctr) != policy {
		t.Fatal("an exited process lost its historical namespace evidence")
	}
	grant, err := ReadPIDNamespaceGrant(p.pidGrantDir, ctr.Id)
	if err != nil || grant == nil {
		t.Fatalf("read grant: %v", err)
	}
	grant.Inode++
	data, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.pidGrantDir, ctr.Id), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if p.processNamespacePolicy(ctr) != invalidPIDPolicy {
		t.Fatal("accepted namespace evidence with a replaced identity")
	}
	if err := RemovePIDNamespaceGrant(p.pidGrantDir, ctr.Id); err != nil {
		t.Fatal(err)
	}
	if p.processNamespacePolicy(ctr) != invalidPIDPolicy {
		t.Fatal("accepted shared namespace evidence without a grant")
	}
}
