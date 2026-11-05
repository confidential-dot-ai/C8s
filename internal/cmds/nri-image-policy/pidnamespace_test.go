package nriimagepolicy

import (
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	"github.com/containerd/nri/pkg/api"
)

const testApplicationPIDPath = "/run/nri-image-policy-pid/namespaces/test"

func TestApplicationPIDGateKeepsSupportPrivate(t *testing.T) {
	policy := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		launch gatedContainer
		types  []*api.LinuxNamespace
		uid    uint32
		allow  bool
	}{
		{name: "private application", uid: testWorkloadUID, types: []*api.LinuxNamespace{{Type: "pid"}}, allow: true},
		{name: "shared application", uid: testWorkloadUID, types: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}, launch: gatedContainer{pidPolicy: policy, pidPath: testApplicationPIDPath}, allow: true},
		{name: "private mesh", uid: testMeshUID, types: []*api.LinuxNamespace{{Type: "pid"}}, launch: gatedContainer{role: meshRole}, allow: true},
		{name: "shared mesh", uid: testMeshUID, types: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}, launch: gatedContainer{role: meshRole, pidPolicy: policy, pidPath: testApplicationPIDPath}},
		{name: "shared certificate client", uid: testCertUID, types: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}, launch: gatedContainer{role: testCertRole, pidPolicy: policy, pidPath: testApplicationPIDPath}},
		{name: "unselected application joined", uid: testWorkloadUID, types: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}},
		{name: "missing policy", uid: testWorkloadUID, types: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}, launch: gatedContainer{pidPath: testApplicationPIDPath}},
		{name: "missing proof", uid: testWorkloadUID, types: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}, launch: gatedContainer{pidPolicy: policy}},
		{name: "unproved policy", uid: testWorkloadUID, types: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}, launch: gatedContainer{pidPolicy: invalidPIDPolicy, pidPath: testApplicationPIDPath}},
		{name: "missing PID entry", uid: testWorkloadUID, launch: gatedContainer{pidPolicy: policy, pidPath: testApplicationPIDPath}},
		{name: "different namespace", uid: testWorkloadUID, types: []*api.LinuxNamespace{{Type: "pid", Path: "/proc/1/ns/pid"}}, launch: gatedContainer{pidPolicy: policy, pidPath: testApplicationPIDPath}},
		{name: "duplicate PID entry", uid: testWorkloadUID, types: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}, {Type: "pid", Path: testApplicationPIDPath}}, launch: gatedContainer{pidPolicy: policy, pidPath: testApplicationPIDPath}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctr := gateCtr(tc.name, tc.uid)
			ctr.Linux.Namespaces = tc.types
			state := &protectedPod{}
			err := state.requireContainerAlone(*meshRoles(), ctr, tc.launch)
			if (err == nil) != tc.allow {
				t.Fatalf("namespace gate = %v, allow %t", err, tc.allow)
			}
		})
	}
}

func TestApplicationPIDAdjustmentPreservesOtherNamespaces(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edits []*api.LinuxNamespace
		allow bool
	}{
		{name: "no edit", allow: true},
		{name: "proved PID", edits: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}, allow: true},
		{name: "network", edits: []*api.LinuxNamespace{{Type: "network", Path: testApplicationPIDPath}}},
		{name: "IPC", edits: []*api.LinuxNamespace{{Type: "ipc", Path: testApplicationPIDPath}}},
		{name: "user", edits: []*api.LinuxNamespace{{Type: "user", Path: testApplicationPIDPath}}},
		{name: "PID removal", edits: []*api.LinuxNamespace{{Type: api.MarkForRemoval("pid")}}},
		{name: "missing type", edits: []*api.LinuxNamespace{{Path: testApplicationPIDPath}}},
		{name: "nil edit", edits: []*api.LinuxNamespace{nil}},
		{name: "different PID", edits: []*api.LinuxNamespace{{Type: "pid", Path: "/proc/1/ns/pid"}}},
		{name: "empty PID path", edits: []*api.LinuxNamespace{{Type: "pid"}}},
		{name: "duplicate PID", edits: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}, {Type: "pid", Path: testApplicationPIDPath}}},
		{name: "PID plus IPC", edits: []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}, {Type: "ipc", Path: testApplicationPIDPath}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launch := gatedContainer{pidPolicy: "sha256:group", pidPath: testApplicationPIDPath, namespaces: tc.edits}
			if err := launch.requireNoNetworkChange(); (err == nil) != tc.allow {
				t.Fatalf("adjustment = %v, allow %t", err, tc.allow)
			}
		})
	}
	for _, launch := range []gatedContainer{
		{pidPath: testApplicationPIDPath},
		{pidPolicy: invalidPIDPolicy, pidPath: testApplicationPIDPath},
		{pidPolicy: "sha256:group"},
		{pidPolicy: "sha256:group", pidPath: testApplicationPIDPath, netDevices: map[string]*api.LinuxNetDevice{"host": {}}},
	} {
		launch.namespaces = []*api.LinuxNamespace{{Type: "pid", Path: testApplicationPIDPath}}
		if err := launch.requireNoNetworkChange(); err == nil {
			t.Fatalf("accepted unproved adjustment or host network device: %+v", launch)
		}
	}
}

func TestApplicationPIDGroupBindsOnceUnderConcurrentAdmission(t *testing.T) {
	pod := meshPod("default", "pair", testNetNS)
	gate, state := gateWithPod(pod)
	state.meshStarted = true
	policies := []string{"sha256:first", "sha256:second"}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]error, len(policies))
	for i, policy := range policies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctr := gateCtr("app", testWorkloadUID)
			ctr.Linux.Namespaces[0].Path = testApplicationPIDPath
			_, _, results[i] = gate.admissible(pod, ctr, gatedContainer{pidPolicy: policy, pidPath: testApplicationPIDPath})
		}()
	}
	close(start)
	wg.Wait()
	if (results[0] == nil) == (results[1] == nil) {
		t.Fatalf("one group must win: %v", results)
	}
	winner := policies[0]
	if results[0] != nil {
		winner = policies[1]
	}
	if state.pidPolicy != winner {
		t.Fatalf("group binding = %q, want %q", state.pidPolicy, winner)
	}
	if _, _, err := gate.admissible(pod, gateCtr("metrics", testWorkloadUID), gatedContainer{}); err != nil {
		t.Fatalf("private application refused after group binding: %v", err)
	}
	if state.pidPolicy != winner {
		t.Fatal("private application changed the group binding")
	}
}

func TestApplicationPIDPolicySelectionAndReservedNames(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	w, err := allowlist.ParseWorkloadJSON([]byte(`{"containers":[{"digest":"` + digest + `","command":{"policy":"exact","argv":["/worker"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"},"shareProcessNamespace":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	al := &allowlist.Allowlist{Schema: allowlist.ProcessNamespaceSchema, Workloads: map[string]allowlist.Workload{"pair": *w}}
	p := &plugin{policy: newPolicyStore(al), cfg: &config{}}
	p.cfg.Allowlist.NodeTCB = true
	p.SetReady()
	pod := meshPod("default", "pair", testNetNS)
	p.mesh, _ = gateWithPod(pod)
	for _, name := range []string{workloadclaims.MeshContainerName, workloadclaims.CertContainerName, workloadclaims.VolumeContainerName, workloadclaims.SecretContainerName, workloadclaims.CertWaitContainerName} {
		ctr := gateCtr(name, testWorkloadUID)
		ctr.Args = []string{"/worker"}
		ctr.Annotations = map[string]string{annotationImageName: digest}
		if _, err := p.shareApplicationNamespace(t.Context(), pod, ctr, nil); err == nil || !strings.Contains(err.Error(), "only an admitted application") {
			t.Fatalf("reserved name %q reached namespace creation: %v", name, err)
		}
	}
	launch := allowlist.RunningContainer{Digest: digest, Argv: []string{"/worker"}, Mounts: []allowlist.ObservedMount{}}
	launch.Env, err = allowlist.ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Label = "another signed workload"
	al.Workloads["other"] = *w
	p.policy = newPolicyStore(al)
	if policies := p.processNamespacePolicies(launch); len(policies) != 2 {
		t.Fatalf("conflicting declarations collapsed: %v", policies)
	}
	conflicting := gateCtr("app", testWorkloadUID)
	conflicting.Args, conflicting.Annotations = []string{"/worker"}, map[string]string{annotationImageName: digest}
	if _, err := p.shareApplicationNamespace(t.Context(), pod, conflicting, nil); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflicting group reached namespace creation: %v", err)
	}
	w.Containers[0].ShareProcessNamespace = false
	al.Workloads = map[string]allowlist.Workload{"private": *w}
	p.policy = newPolicyStore(al)
	if policies := p.processNamespacePolicies(launch); len(policies) != 1 || policies[0] != "" {
		t.Fatalf("private policy changed: %v", policies)
	}
	ctr := gateCtr("metrics", testWorkloadUID)
	ctr.Args, ctr.Annotations = []string{"/worker"}, map[string]string{annotationImageName: digest}
	adjustment := &api.ContainerAdjustment{Annotations: map[string]string{"kept": "value"}}
	if got, err := p.shareApplicationNamespace(t.Context(), pod, ctr, adjustment); err != nil || got != adjustment {
		t.Fatalf("private launch adjustment changed: %v, %v", got, err)
	}
}

func TestApplicationPIDRecoveryRetainsGroupBinding(t *testing.T) {
	state := &protectedPod{}
	ctr := gateCtr("prefill", testWorkloadUID)
	ctr.Linux.Namespaces[0].Path = testApplicationPIDPath
	launch := gatedContainer{pidPolicy: "sha256:first", pidPath: testApplicationPIDPath}
	if err := state.restore(*meshRoles(), recoveredContainer{ctr: ctr, launch: launch}); err != nil {
		t.Fatal(err)
	}
	if state.pidPolicy != launch.pidPolicy {
		t.Fatal("recovery lost the group binding")
	}
	launch.pidPolicy = "sha256:second"
	if err := state.restore(*meshRoles(), recoveredContainer{ctr: ctr, launch: launch}); err == nil {
		t.Fatal("recovery combined different signed groups")
	}
}
