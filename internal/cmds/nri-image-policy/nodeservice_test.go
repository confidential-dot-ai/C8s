package nriimagepolicy

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

const (
	nodeServiceEntry       = "volumed"
	nodeServiceVolume      = "c8s-run"
	nodeServiceSet         = "0.43.0"
	nodeServiceContainerID = "1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f901"
)

// nodeServiceContainer is the one container a node-service entry declares:
// its digest, command, args, environment and mounts all pinned.
func nodeServiceContainer(t *testing.T) allowlist.Container {
	t.Helper()
	return allowlist.Container{
		Digest:  mustDigest(t, pushDigestB),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/usr/local/bin/c8s", "volumed"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"--state-dir", "/var/lib/c8s"}},
		Env:     allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Values: map[string]string{"C8S_LOG": "info"}},
		Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{
			Destination: "/run/c8s",
			Kind:        allowlist.MountEmptyDir,
			Source:      nodeServiceVolume,
		}}},
	}
}

// nodeServiceDocument is a served document whose set carries the volumed node
// service, retiring at retire when that is not nil. It is round-tripped
// through the wire form, so a test judges what a node is served.
func nodeServiceDocument(t *testing.T, retire *allowlist.Retirement) *allowlist.Allowlist {
	t.Helper()
	document := anyAllowlist(map[string]string{pushDigestA: "sidecar"})
	document.Components = map[string]allowlist.ComponentSet{nodeServiceSet: {
		Retire: retire,
		Entries: map[string]allowlist.Workload{nodeServiceEntry: {
			NodeService: true,
			Containers:  []allowlist.Container{nodeServiceContainer(t)},
		}},
	}}
	parsed, err := allowlist.ParseJSON(canonicalBody(t, document))
	if err != nil {
		t.Fatalf("node service document: %v", err)
	}
	return parsed
}

// nodeServicePlugin enforces the host-privilege rules with the volumed set applied.
func nodeServicePlugin(t *testing.T, retire *allowlist.Retirement) *plugin {
	t.Helper()
	return nodeServicePluginWith(t, nodeServiceDocument(t, retire))
}

// nodeServicePluginWith enforces the host-privilege rules with document applied.
func nodeServicePluginWith(t *testing.T, document *allowlist.Allowlist) *plugin {
	t.Helper()
	cfg := &config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{}), NodeTCB: true},
		Policy:    policyConfig{Mode: ModeFailClosed, Sandbox: SandboxEnforce},
	}
	p, _ := newCachedPlugin(cfg, document)
	p.SetReady()
	p.mountStorage = fixedStorage(allowlist.MountMemory)
	p.inventory = newAdmissionInventory(t.TempDir())
	p.nodeServiceGrants = newNodeServiceGrantRecords(filepath.Join(privateDir(t), "grants"))
	return p
}

// nodeServicePod is the pod a node service runs in: the node's network and pid
// namespaces, which the host-privilege rules refuse every other pod.
func nodeServicePod(sandboxID, podUID string) *api.PodSandbox {
	pod := sandboxedPod()
	pod.Id = sandboxID
	pod.Uid = podUID
	pod.Name = nodeServiceEntry
	pod.Linux.Namespaces = slices.DeleteFunc(pod.Linux.Namespaces, func(ns *api.LinuxNamespace) bool {
		return ns.Type == "network" || ns.Type == "uts" || ns.Type == "pid"
	})
	return pod
}

// nodeServiceSharedPod is a pod of ordinary shape, so a container beside the
// node service is admitted on its own.
func nodeServiceSharedPod(sandboxID, podUID string) *api.PodSandbox {
	pod := sandboxedPod()
	pod.Id = sandboxID
	pod.Uid = podUID
	pod.Name = nodeServiceEntry
	return pod
}

// nodeServiceLaunch is the container the entry declares, in pod.
func nodeServiceLaunch(pod *api.PodSandbox) *api.Container {
	ctr := sandboxedContainer()
	ctr.Id = nodeServiceContainerID
	ctr.Name = nodeServiceEntry
	ctr.PodSandboxId = pod.GetId()
	ctr.Args = []string{"/usr/local/bin/c8s", "volumed", "--state-dir", "/var/lib/c8s"}
	ctr.Env = []string{"C8S_LOG=info"}
	ctr.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestB}
	ctr.Mounts = append(mountsADenyPolicyAdmits(ctr), &api.Mount{
		Destination: "/run/c8s",
		Type:        "bind",
		Source:      "/var/lib/kubelet/pods/" + pod.GetUid() + "/volumes/kubernetes.io~empty-dir/" + nodeServiceVolume,
	})
	return ctr
}

// admitNodeService runs a container of a node service's pod through the final
// check, where the host-privilege rules apply, and records what it admits as
// admission does.
func admitNodeService(t *testing.T, p *plugin, pod *api.PodSandbox, ctr *api.Container) (imageVerdict, string) {
	t.Helper()
	imageRef := ctr.GetAnnotations()[annotationImageName]
	verdict, reason := p.checkContainerPhase(t.Context(), p.cfg, pod, ctr, imageRef, launchFinal)
	if verdict != verdictDeny {
		p.recordForInventory(t.Context(), pod, ctr, imageRef)
	}
	return verdict, reason
}

// The entry pins the whole launch, so a pod that changes one argument, one
// variable or one mount holds the node's privilege no longer.
func TestNodeServiceNeedsTheLaunchItsEntryPins(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*api.Container)
		want   imageVerdict
	}{
		{name: "the launch the entry pins", change: func(*api.Container) {}, want: verdictAllow},
		{
			name:   "another argument",
			change: func(c *api.Container) { c.Args = append(c.Args, "--debug") },
			want:   verdictDeny,
		},
		{
			name:   "another variable value",
			change: func(c *api.Container) { c.Env = []string{"C8S_LOG=debug"} },
			want:   verdictDeny,
		},
		{
			name:   "another volume behind its mount",
			change: func(c *api.Container) { c.Mounts[len(c.Mounts)-1].Source = podVolumeSource("attacker") },
			want:   verdictDeny,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := nodeServicePlugin(t, nil)
			pod := nodeServicePod(testSandboxID, testPodUID)
			ctr := nodeServiceLaunch(pod)
			tc.change(ctr)
			if verdict, reason := admitNodeService(t, p, pod, ctr); verdict != tc.want {
				t.Fatalf("verdict = %d %q, want %d", verdict, reason, tc.want)
			}
		})
	}
}

// A node service runs alone in its pod, whichever container the control plane
// starts first and whatever it calls it: the rules read the launches admission
// cleared in the sandbox, not the names the control plane chose.
func TestNodeServiceRunsAloneInItsPod(t *testing.T) {
	sidecar := func(name string) func(*api.PodSandbox) *api.Container {
		return func(pod *api.PodSandbox) *api.Container {
			ctr := nodeServiceLaunch(pod)
			ctr.Id = "2" + nodeServiceContainerID[1:]
			ctr.Name = name
			ctr.Annotations = map[string]string{annotationImageName: "registry/repo@" + pushDigestA}
			return ctr
		}
	}
	for _, tc := range []struct {
		name  string
		first func(*api.PodSandbox) *api.Container
		next  func(*api.PodSandbox) *api.Container
	}{
		{name: "the node service first", first: nodeServiceLaunch, next: sidecar("sidecar")},
		{name: "the other container first", first: sidecar("sidecar"), next: nodeServiceLaunch},
		{name: "the node service before a container of its own name", first: nodeServiceLaunch, next: sidecar(nodeServiceEntry)},
		{name: "a container of the node service's own name first", first: sidecar(nodeServiceEntry), next: nodeServiceLaunch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := nodeServicePlugin(t, nil)
			pod := nodeServiceSharedPod(testSandboxID, testPodUID)
			if verdict, reason := admitNodeService(t, p, pod, tc.first(pod)); verdict == verdictDeny {
				t.Fatalf("the pod's first container was refused: %d %q", verdict, reason)
			}
			verdict, reason := admitNodeService(t, p, pod, tc.next(pod))
			if verdict != verdictDeny || !strings.Contains(reason, "alone in its pod") {
				t.Fatalf("verdict = %d %q, want a refusal naming the rule", verdict, reason)
			}
		})
	}
}

// A second container of the node service's own launch is refused too: it has a
// container ID of its own, which the launch the sandbox recorded does not show.
func TestASecondContainerOfTheNodeServiceIsRefused(t *testing.T) {
	p := nodeServicePlugin(t, nil)
	pod := nodeServicePod(testSandboxID, testPodUID)
	if verdict, reason := admitNodeService(t, p, pod, nodeServiceLaunch(pod)); verdict != verdictAllow {
		t.Fatalf("the node's one node service was refused: %d %q", verdict, reason)
	}
	twin := nodeServiceLaunch(pod)
	twin.Id = "2" + nodeServiceContainerID[1:]
	verdict, reason := admitNodeService(t, p, pod, twin)
	if verdict != verdictDeny || !strings.Contains(reason, "alone in its pod") {
		t.Fatalf("verdict = %d %q, want a refusal naming the rule", verdict, reason)
	}
}

// The kubelet starts the entry's container again under a new ID once the
// first is gone, in the pod that holds the node service.
func TestTheNodeServiceStartsAgainUnderANewContainerID(t *testing.T) {
	p := nodeServicePlugin(t, nil)
	pod := nodeServicePod(testSandboxID, testPodUID)
	first := nodeServiceLaunch(pod)
	if verdict, reason := admitNodeService(t, p, pod, first); verdict != verdictAllow {
		t.Fatalf("the node's one node service was refused: %d %q", verdict, reason)
	}
	if err := p.RemoveContainer(t.Context(), pod, first); err != nil {
		t.Fatal(err)
	}
	restarted := nodeServiceLaunch(pod)
	restarted.Id = "2" + nodeServiceContainerID[1:]
	if verdict, reason := admitNodeService(t, p, pod, restarted); verdict != verdictAllow {
		t.Fatalf("the restarted node service was refused: %d %q", verdict, reason)
	}
}

// One pod on the node runs a node service, and its removal lets the next one
// take over.
func TestNodeServiceRunsInOnePodOnTheNode(t *testing.T) {
	p := nodeServicePlugin(t, nil)
	running := nodeServicePod(testSandboxID, testPodUID)
	if verdict, reason := admitNodeService(t, p, running, nodeServiceLaunch(running)); verdict != verdictAllow {
		t.Fatalf("the node's one node service was refused: %d %q", verdict, reason)
	}
	replacement := nodeServicePod("def456sandbox", "66666666-7777-8888-9999-000000000000")
	verdict, reason := admitNodeService(t, p, replacement, nodeServiceLaunch(replacement))
	if verdict != verdictDeny || !strings.Contains(reason, "one pod on the node") {
		t.Fatalf("verdict = %d %q, want a refusal naming the rule", verdict, reason)
	}
	if err := p.RemovePodSandbox(t.Context(), running); err != nil {
		t.Fatal(err)
	}
	if verdict, reason := admitNodeService(t, p, replacement, nodeServiceLaunch(replacement)); verdict != verdictAllow {
		t.Fatalf("the replacement was refused once the first pod was gone: %d %q", verdict, reason)
	}
}

// Admission records the node service's grant at the validation check, the hook
// whose failure fails the create, and drops the record with the container.
func TestValidationRecordsTheNodeServiceGrant(t *testing.T) {
	p := nodeServicePlugin(t, nil)
	pod := nodeServicePod(testSandboxID, testPodUID)
	ctr := nodeServiceLaunch(pod)
	req := &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr}
	if err := p.ValidateContainerAdjustment(t.Context(), req); err != nil {
		t.Fatalf("the node service's launch was refused: %v", err)
	}
	grant, err := ReadNodeServiceGrant(p.nodeServiceGrants.dir, ctr.GetId())
	if err != nil || grant.Entry != nodeServiceEntry {
		t.Fatalf("ReadNodeServiceGrant = %+v, %v, want the volumed entry", grant, err)
	}
	if err := p.RemoveContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if grant, err := ReadNodeServiceGrant(p.nodeServiceGrants.dir, ctr.GetId()); err != nil || grant.Granted() {
		t.Fatalf("the removed container kept the grant %+v, %v", grant, err)
	}
}

// A retiring set admits its node service until its deadline, so a crashed node
// service starts again, and nothing past it.
func TestNodeServiceEndsWithItsSet(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline time.Duration
		want     imageVerdict
	}{
		{name: "the deadline ahead", deadline: time.Hour, want: verdictAllow},
		{name: "the deadline past", deadline: -time.Hour, want: verdictDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			retire := &allowlist.Retirement{Deadline: allowlist.Deadline{
				Time: time.Now().Add(tc.deadline).UTC().Truncate(time.Second),
			}}
			p := nodeServicePlugin(t, retire)
			pod := nodeServicePod(testSandboxID, testPodUID)
			if verdict, reason := admitNodeService(t, p, pod, nodeServiceLaunch(pod)); verdict != tc.want {
				t.Fatalf("verdict = %d %q, want %d", verdict, reason, tc.want)
			}
		})
	}
}

// A restarted enforcer reads the node services it recorded for the containers
// containerd is already running, so the node's one pod keeps them, and a pod
// that is gone holds nothing.
func TestARestartKeepsTheNodeServiceWithItsPod(t *testing.T) {
	p := nodeServicePlugin(t, nil)
	running := nodeServicePod(testSandboxID, testPodUID)
	existing := nodeServiceLaunch(running)
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{running}, []*api.Container{existing}); err != nil {
		t.Fatal(err)
	}
	replacement := nodeServicePod("def456sandbox", "66666666-7777-8888-9999-000000000000")
	verdict, reason := admitNodeService(t, p, replacement, nodeServiceLaunch(replacement))
	if verdict != verdictDeny || !strings.Contains(reason, "one pod on the node") {
		t.Fatalf("verdict = %d %q, want a refusal naming the rule", verdict, reason)
	}
	if err := p.RemovePodSandbox(t.Context(), running); err != nil {
		t.Fatal(err)
	}
	if verdict, reason := admitNodeService(t, p, replacement, nodeServiceLaunch(replacement)); verdict != verdictAllow {
		t.Fatalf("the replacement was refused once the first pod was gone: %d %q", verdict, reason)
	}
}

// The mark is what excuses the privilege: the same launch under a set entry
// that does not carry it is held to the host-privilege rules.
func TestOnlyTheNodeServiceMarkExcusesThePrivilege(t *testing.T) {
	document := nodeServiceDocument(t, nil)
	set := document.Components[nodeServiceSet]
	entry := set.Entries[nodeServiceEntry]
	entry.NodeService = false
	set.Entries[nodeServiceEntry] = entry
	document.Components[nodeServiceSet] = set

	p := nodeServicePluginWith(t, document)
	pod := nodeServicePod(testSandboxID, testPodUID)
	verdict, reason := admitNodeService(t, p, pod, nodeServiceLaunch(pod))
	if verdict != verdictDeny || !strings.Contains(reason, "host privilege") {
		t.Fatalf("verdict = %d %q, want a host-privilege refusal", verdict, reason)
	}
}
