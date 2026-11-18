package nriimagepolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlistclient"
)

// revocationPlugin enforces on running containers, with pushDigestA in a
// served allowlist and pushDigestC in the base. Its containerd records kills.
func revocationPlugin(policy policyConfig) (*plugin, *policyStore, *[]string) {
	p, store := newCachedPlugin(&config{
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestC: "image-c"})},
		Policy:    policy,
	}, anyAllowlist(map[string]string{pushDigestA: "image-a"}))
	p.SetReady()
	killed := &[]string{}
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		*killed = append(*killed, id)
		return nil
	}}
	return p, store, killed
}

var enforcing = policyConfig{Mode: ModeFailClosed, EnforceExisting: true}

func runningCtr(pod *api.PodSandbox, name, digest string) *api.Container {
	ctr := makeCtrWithImage(pod.Id, name, "registry/repo@"+digest)
	ctr.State = api.ContainerState_CONTAINER_RUNNING
	return ctr
}

func TestKillRevokedKillsOnlyWhatTheAppliedAllowlistDenies(t *testing.T) {
	p, store, killed := revocationPlugin(enforcing)
	pod := makePod("default", "pod")
	revoked := runningCtr(pod, "revoked", pushDigestA)
	kept := runningCtr(pod, "kept", pushDigestB)
	base := runningCtr(pod, "base", pushDigestC)
	for _, ctr := range []*api.Container{revoked, kept, base} {
		p.running.add(pod, ctr)
	}

	store.apply(anyAllowlist(map[string]string{pushDigestB: "image-b"}), 2)
	p.KillRevoked(context.Background())

	if !slices.Equal(*killed, []string{revoked.Id}) {
		t.Fatalf("killed %v, want only %s", *killed, revoked.Id)
	}
}

// The fake's kill records nothing here: a kill would mean the gate was ignored.
func TestKillRevokedKillsNothingTheStartupCheckWouldSpare(t *testing.T) {
	for _, tc := range []struct {
		name      string
		policy    policyConfig
		namespace string
	}{
		{"audit mode", policyConfig{Mode: ModeAudit, EnforceExisting: true}, "default"},
		{"enforce_existing off", policyConfig{Mode: ModeFailClosed}, "default"},
		{"exempt namespace", policyConfig{Mode: ModeFailClosed, EnforceExisting: true, ExemptNamespaces: []string{"kube-system"}}, "kube-system"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, store, killed := revocationPlugin(tc.policy)
			pod := makePod(tc.namespace, "pod")
			p.running.add(pod, runningCtr(pod, "revoked", pushDigestA))

			store.apply(anyAllowlist(map[string]string{pushDigestB: "image-b"}), 2)
			p.KillRevoked(context.Background())

			if len(*killed) != 0 {
				t.Fatalf("killed %v", *killed)
			}
		})
	}
}

func TestSynchronizeTracksRunningContainersOfReportedPods(t *testing.T) {
	p, store, killed := revocationPlugin(enforcing)
	pod := makePod("default", "pod")
	running := runningCtr(pod, "running", pushDigestA)
	stopped := runningCtr(pod, "stopped", pushDigestA)
	stopped.State = api.ContainerState_CONTAINER_STOPPED
	orphan := runningCtr(makePod("default", "unreported"), "orphan", pushDigestA)
	if _, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{running, stopped, orphan}); err != nil {
		t.Fatal(err)
	}

	store.apply(anyAllowlist(map[string]string{pushDigestB: "image-b"}), 2)
	p.KillRevoked(context.Background())

	if !slices.Equal(*killed, []string{running.Id}) {
		t.Fatalf("killed %v, want only %s", *killed, running.Id)
	}
}

// A start admitted on the allowlist an apply then replaces is still rechecked.
// The start blocks on recording its admission, after its check passed.
func TestStartAdmittedJustBeforeARevocationIsKilled(t *testing.T) {
	p, store, killed := revocationPlugin(enforcing)
	p.inventory = newAdmissionInventory("/proc")
	served := anyAllowlist(map[string]string{pushDigestA: "image-a"})
	for name, w := range served.Workloads {
		w.Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyAny}
		served.Workloads[name] = w
	}
	store.apply(served, 1)
	pod := makePod("default", "pod")
	pod.Uid = "uid"
	ctr := makeCtrWithImageArgs(pod.Id, "app", "registry/repo@"+pushDigestA, []string{"/app"})
	ctr.Mounts = []*api.Mount{{Destination: "/scratch", Source: kubeletRoot + "/pods/uid/volumes/" + emptyDirPlugin + "/scratch", Type: "bind"}}
	p.mountStorage = fixedStorage(allowlist.MountMemory)
	// Measurement follows admission and precedes the start return, so it is
	// the deterministic pause point even when digest resolution is cached.
	admitted := make(chan struct{})
	release := make(chan struct{})
	p.measurer = pausingMeasurer{admitted: admitted, release: release}
	started := make(chan error)
	go func() { started <- p.StartContainer(context.Background(), pod, ctr) }()

	select {
	case <-admitted:
	case err := <-started:
		t.Fatalf("start returned before recording: %v", err)
	}
	store.apply(anyAllowlist(map[string]string{pushDigestB: "image-b"}), 2)
	p.KillRevoked(context.Background())
	close(release)

	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*killed, []string{ctr.Id}) {
		t.Fatalf("killed %v, want %s", *killed, ctr.Id)
	}
}

func TestRefusedStartIsNotTracked(t *testing.T) {
	p, _, _ := revocationPlugin(enforcing)
	pod := makePod("default", "pod")

	if err := p.StartContainer(context.Background(), pod, makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)); err == nil {
		t.Fatal("a container outside the allowlist started")
	}
	if tracked := p.running.list(); len(tracked) != 0 {
		t.Fatalf("a refused start is tracked: %v", tracked)
	}
}

func TestStopAndRemoveUntrackOnlyAStartedContainer(t *testing.T) {
	stopIn := func(state api.ContainerState) func(*plugin, *api.PodSandbox, *api.Container) error {
		return func(p *plugin, pod *api.PodSandbox, ctr *api.Container) error {
			ctr.State = state
			_, err := p.StopContainer(context.Background(), pod, ctr)
			return err
		}
	}
	remove := func(p *plugin, pod *api.PodSandbox, ctr *api.Container) error {
		return p.RemoveContainer(context.Background(), pod, ctr)
	}
	for _, tc := range []struct {
		name        string
		event       func(*plugin, *api.PodSandbox, *api.Container) error
		wantTracked int
	}{
		// The runtime reports an exited task as stopped, and a container the
		// orchestrator stopped as unknown.
		{"stop after its task exited", stopIn(api.ContainerState_CONTAINER_STOPPED), 0},
		{"stop by the orchestrator", stopIn(api.ContainerState_CONTAINER_UNKNOWN), 0},
		{"stop while still created", stopIn(api.ContainerState_CONTAINER_CREATED), 1},
		{"removal", remove, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _ := revocationPlugin(enforcing)
			pod := makePod("default", "pod")
			ctr := runningCtr(pod, "app", pushDigestA)
			p.running.add(pod, ctr)

			if err := tc.event(p, pod, ctr); err != nil {
				t.Fatal(err)
			}
			if got := len(p.running.list()); got != tc.wantTracked {
				t.Fatalf("%d containers tracked, want %d", got, tc.wantTracked)
			}
		})
	}
}

// pausingMeasurer holds a start between its admission verdict and its return.
type pausingMeasurer struct{ admitted, release chan struct{} }

func (m pausingMeasurer) MeasureOnce(string) (bool, error) {
	close(m.admitted)
	<-m.release
	return true, nil
}

func (pausingMeasurer) Digests() []string { return nil }

// A revoked running container costs a Pod guest its identity, and a node nothing.
func TestKillRevokedEndsThePodIdentity(t *testing.T) {
	pod := makePod("tenant", "assigned")
	pod.Uid = "runtime-uid"
	revoked := runningCtr(pod, "app", pushDigestB)

	guest, store, killed := revocationPlugin(enforcing)
	guest.cfg.Pod = &podConfig{UID: "signed-uid", Namespace: pod.Namespace, Name: pod.Name, Images: map[string]string{"app": pushDigestB}}
	guest.inventory = newAdmissionInventory(t.TempDir())
	guest.inventory.recordSandbox(pod.Id)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	guest.podBroker = &podCredentialBroker{ctx: ctx, cancel: cancel, pod: pod}
	guest.running.add(pod, revoked)

	store.apply(anyAllowlist(map[string]string{pushDigestA: "image-a"}), 2)
	guest.KillRevoked(t.Context())

	if !slices.Equal(*killed, []string{revoked.Id}) {
		t.Fatalf("killed %v, want %s", *killed, revoked.Id)
	}
	if guest.inventory.denial(pod.Id) == nil || guest.podBroker.terminal == nil {
		t.Fatal("a revoked running container kept the Pod identity")
	}

	node, nodeStore, nodeKilled := revocationPlugin(enforcing)
	node.inventory = newAdmissionInventory(t.TempDir())
	node.inventory.recordSandbox(pod.Id)
	node.running.add(pod, runningCtr(pod, "app", pushDigestB))
	nodeStore.apply(anyAllowlist(map[string]string{pushDigestA: "image-a"}), 2)
	node.KillRevoked(t.Context())
	if !slices.Equal(*nodeKilled, []string{revoked.Id}) {
		t.Fatalf("node killed %v, want %s", *nodeKilled, revoked.Id)
	}
	if node.inventory.denial(pod.Id) != nil {
		t.Fatal("a node recorded a lifetime denial for a revoked running container")
	}
}

// --- component sets: membership, mixing and ending ---

var (
	meshArgv = []string{"/usr/local/bin/c8s", "armtls-mesh"}
	certArgv = []string{"/usr/local/bin/c8s", "get-cert"}
)

// baseOnlyDigest is an image no component set declares.
const baseOnlyDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000004"

// componentBase is a measured base that binds no role, so the component
// containers of a test's pods are admitted by its sets alone.
func componentBase() *allowlist.Allowlist {
	return anyAllowlist(map[string]string{baseOnlyDigest: "base-image"})
}

// componentSetPlugin is a node enforcer serving document over base, whose
// component-set deadlines are judged by now. It records what it stops.
func componentSetPlugin(t *testing.T, now func() time.Time, base, document *allowlist.Allowlist) (*plugin, *[]string) {
	t.Helper()
	p, _ := newCachedPlugin(&config{Policy: enforcing, Allowlist: allowlistConfig{Base: base}}, anyAllowlist(nil))
	p.policy = newPolicyStore(base, newTAClock(now))
	p.policy.apply(document, 1)
	p.SetReady()
	p.inventory = newAdmissionInventory(t.TempDir())
	p.mountStorage = fixedStorage(allowlist.MountMemory)
	killed := &[]string{}
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		*killed = append(*killed, id)
		return nil
	}}
	return p, killed
}

// componentCtr is the running container componentContainer declares: its
// pinned argv and the pod volume its pinned mount rule names.
func componentCtr(pod *api.PodSandbox, name, digest string, argv []string) *api.Container {
	ctr := makeCtrWithImageArgs(pod.Id, name, "registry/repo@"+digest, argv)
	ctr.Id = pod.GetName() + "-" + name
	ctr.State = api.ContainerState_CONTAINER_RUNNING
	ctr.Mounts = []*api.Mount{{
		Destination: "/run/c8s",
		Source:      kubeletRoot + "/pods/" + pod.GetUid() + "/volumes/" + emptyDirPlugin + "/c8s-run",
		Type:        "bind",
	}}
	return ctr
}

func componentPod(name string) *api.PodSandbox {
	pod := makePod("tenant", name)
	pod.Uid = name + "-uid"
	return pod
}

func startAll(t *testing.T, p *plugin, pod *api.PodSandbox, ctrs ...*api.Container) {
	t.Helper()
	for _, ctr := range ctrs {
		if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
			t.Fatalf("start %s: %v", ctr.GetName(), err)
		}
	}
}

// One component set must admit every component container of a pod, so the
// control plane can neither mix two releases' sidecars nor pair a set's
// sidecar with one only the measured base admits. The refusal names both.
func TestComponentSetMixingIsRefused(t *testing.T) {
	document := componentSetsDocument(t, nil, map[string]allowlist.ComponentSet{
		"0.43.0": componentSet(nil,
			componentContainer(t, pushDigestA, allowlist.RoleMesh, meshArgv),
			componentContainer(t, pushDigestC, allowlist.RoleCredentials, certArgv)),
		"0.44.0": componentSet(nil, componentContainer(t, pushDigestB, allowlist.RoleCredentials, certArgv)),
	})
	for _, tc := range []struct {
		name    string
		base    *allowlist.Allowlist
		digest  string
		admitby string
	}{
		{name: "a sidecar of another set", base: componentBase(), digest: pushDigestB, admitby: "0.44.0"},
		{
			name:    "a sidecar only the base admits",
			base:    roleBase(t, pushDigestA, allowlist.RoleCredentials, certArgv),
			digest:  pushDigestA,
			admitby: "no component set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := componentSetPlugin(t, time.Now, tc.base, document)
			pod := componentPod("inference-0")
			startAll(t, p, pod, componentCtr(pod, "c8s-mesh", pushDigestA, meshArgv))

			joining := componentCtr(pod, "c8s-get-cert", tc.digest, certArgv)
			err := p.StartContainer(t.Context(), pod, joining)
			if err == nil {
				t.Fatal("a component container of another set joined the pod")
			}
			for _, named := range []string{tc.admitby, "0.43.0"} {
				if !strings.Contains(err.Error(), named) {
					t.Errorf("refusal %q does not name %s", err, named)
				}
			}
		})
	}
}

// At a deadline the whole pod on the retiring set goes — sidecars and the
// tenant container the document still admits — and the Pod is deleted so its
// controller replaces it. A pod a current set also admits runs on.
func TestADeadlineEndsThePodsOnTheRetiringSetAlone(t *testing.T) {
	taTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := taTime.Add(time.Hour)
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}
	document := componentSetsDocument(t, map[string]string{pushDigestB: "app"}, map[string]allowlist.ComponentSet{
		"0.43.0": componentSet(retiring,
			componentContainer(t, pushDigestA, allowlist.RoleMesh, meshArgv),
			componentContainer(t, pushDigestC, allowlist.RoleCredentials, certArgv)),
		"0.44.0": componentSet(nil, componentContainer(t, pushDigestA, allowlist.RoleMesh, meshArgv)),
	})
	p, killed := componentSetPlugin(t, func() time.Time { return taTime }, componentBase(), document)
	deleted := make(chan *api.PodSandbox, 2)
	p.deletePod = func(_ context.Context, pod *api.PodSandbox) error {
		deleted <- pod
		return nil
	}

	retired := componentPod("inference-0")
	sidecars := []*api.Container{
		componentCtr(retired, "c8s-mesh", pushDigestA, meshArgv),
		componentCtr(retired, "c8s-get-cert", pushDigestC, certArgv),
	}
	app := runningCtr(retired, "app", pushDigestB)
	startAll(t, p, retired, append(sidecars, app)...)
	current := componentPod("inference-1")
	currentMesh := componentCtr(current, "c8s-mesh", pushDigestA, meshArgv)
	startAll(t, p, current, currentMesh)

	p.recheckRunning(t.Context())
	if len(*killed) != 0 {
		t.Fatalf("killed %v before the deadline", *killed)
	}

	taTime = deadline
	if !p.policy.rebuildEndedSets() {
		t.Fatal("the retiring set stayed in force past its deadline")
	}
	p.recheckRunning(t.Context())

	want := []string{sidecars[0].Id, sidecars[1].Id, app.Id}
	slices.Sort(want)
	ended := slices.Clone(*killed)
	slices.Sort(ended)
	if !slices.Equal(ended, want) {
		t.Fatalf("killed %v, want every container of the ended pod %v", ended, want)
	}
	if pod := <-deleted; pod != retired {
		t.Fatalf("deleted %s/%s, want the ended pod", pod.GetNamespace(), pod.GetName())
	}
	select {
	case pod := <-deleted:
		t.Fatalf("deleted %s/%s, a pod a current set admits", pod.GetNamespace(), pod.GetName())
	default:
	}
	if p.running.contains(currentMesh.Id) != true {
		t.Fatal("a pod a current set admits lost its sidecar")
	}
}

// A write that removes a set ends its pods within one applied pull.
func TestRemovingASetEndsItsPodsOnTheNextPull(t *testing.T) {
	document := componentDocument(t, nil, componentContainer(t, pushDigestA, allowlist.RoleMesh, meshArgv))
	p, killed := componentSetPlugin(t, time.Now, componentBase(), document)
	deleted := make(chan *api.PodSandbox, 2)
	p.deletePod = func(_ context.Context, pod *api.PodSandbox) error {
		deleted <- pod
		return nil
	}
	pod := componentPod("inference-0")
	mesh := componentCtr(pod, "c8s-mesh", pushDigestA, meshArgv)
	startAll(t, p, pod, mesh)

	without := componentSetsDocument(t, nil, map[string]allowlist.ComponentSet{
		"0.44.0": componentSet(nil, componentContainer(t, pushDigestB, allowlist.RoleMesh, meshArgv)),
	})
	target := nodeTarget{store: p.policy, recheckRunning: p.recheckRunning}
	if err := target.replace(t.Context(), without, 2); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(*killed, []string{mesh.Id}) {
		t.Fatalf("killed %v, want the pod on the removed set", *killed)
	}
	if ended := <-deleted; ended != pod {
		t.Fatalf("deleted %s/%s, want the pod on the removed set", ended.GetNamespace(), ended.GetName())
	}
}

// Between a set's deadline and the tick that ends it the applied index still
// admits the set's containers: a component container starting then is refused,
// because no set in force admits it and the measured base binds it no role.
func TestAComponentContainerStartingPastTheDeadlineIsRefused(t *testing.T) {
	taTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := taTime.Add(time.Hour)
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}
	document := componentDocument(t, retiring, componentContainer(t, pushDigestA, allowlist.RoleMesh, meshArgv))
	p, _ := componentSetPlugin(t, func() time.Time { return taTime }, componentBase(), document)

	inForce := componentPod("inference-0")
	startAll(t, p, inForce, componentCtr(inForce, "c8s-mesh", pushDigestA, meshArgv))

	taTime = deadline
	ended := componentPod("inference-1")
	err := p.StartContainer(t.Context(), ended, componentCtr(ended, "c8s-mesh", pushDigestA, meshArgv))
	if err == nil {
		t.Fatal("the index the passed deadline left stale admitted a component container")
	}
	if !strings.Contains(err.Error(), "no component set in force") {
		t.Fatalf("refusal %q does not say that no component set in force admits it", err)
	}
}

// A pod off its sets is refused every start, including the tenant container
// the document still admits: the control plane may drop the Pod delete, and
// the kubelet then starts that container again. A pod on a set in force runs on.
func TestEveryStartInAPodOffItsSetsIsRefused(t *testing.T) {
	taTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	deadline := taTime.Add(time.Hour)
	retiring := &allowlist.Retirement{Deadline: allowlist.Deadline{Time: deadline}}
	document := componentSetsDocument(t, map[string]string{pushDigestB: "app"}, map[string]allowlist.ComponentSet{
		"0.43.0": componentSet(retiring, componentContainer(t, pushDigestA, allowlist.RoleMesh, meshArgv)),
		"0.44.0": componentSet(nil, componentContainer(t, pushDigestC, allowlist.RoleMesh, meshArgv)),
	})
	p, killed := componentSetPlugin(t, func() time.Time { return taTime }, componentBase(), document)

	ended := componentPod("inference-0")
	app := runningCtr(ended, "app", pushDigestB)
	startAll(t, p, ended, componentCtr(ended, "c8s-mesh", pushDigestA, meshArgv), app)
	current := componentPod("inference-1")
	startAll(t, p, current, componentCtr(current, "c8s-mesh", pushDigestC, meshArgv))

	taTime = deadline
	if !p.policy.rebuildEndedSets() {
		t.Fatal("the retiring set stayed in force past its deadline")
	}
	p.recheckRunning(t.Context())
	if len(*killed) != 2 {
		t.Fatalf("killed %v, want both containers of the pod off its sets", *killed)
	}

	restarted := runningCtr(ended, "app", pushDigestB)
	restarted.Id = app.GetId() + "-restarted"
	if err := p.StartContainer(t.Context(), ended, restarted); err == nil {
		t.Fatal("the tenant container of a pod off its sets started again")
	}
	if err := p.StartContainer(t.Context(), current, runningCtr(current, "app", pushDigestB)); err != nil {
		t.Fatalf("a pod on a set in force was refused a start: %v", err)
	}
}

// --- the fallback to the base allowlist ---

// fallbackPlugin is a node enforcer with pushDigestA served and pushDigestC in
// its base, recording what it stops and the Pods it deletes.
func fallbackPlugin(t *testing.T) (*plugin, *[]string, chan *api.PodSandbox) {
	t.Helper()
	p, _, killed := revocationPlugin(enforcing)
	deleted := make(chan *api.PodSandbox, 2)
	p.deletePod = func(_ context.Context, pod *api.PodSandbox) error {
		deleted <- pod
		return nil
	}
	return p, killed, deleted
}

// A node that falls back to its base allowlist ends every pod the served
// allowlist admitted: whole, and the Pod deleted so its controller replaces
// it. A pod the base admits runs on. A later poll re-admits.
func TestFallingBackEndsTheServedPodsWholeAndKeepsTheBaseOnes(t *testing.T) {
	p, killed, deleted := fallbackPlugin(t)
	served := makePod("tenant", "inference-0")
	sidecar, app := runningCtr(served, "c8s-mesh", pushDigestA), runningCtr(served, "app", pushDigestC)
	onBase := makePod("tenant", "node-local")
	baseOnly := runningCtr(onBase, "tool", pushDigestC)
	for _, c := range []struct {
		pod *api.PodSandbox
		ctr *api.Container
	}{{served, sidecar}, {served, app}, {onBase, baseOnly}} {
		p.running.add(c.pod, c.ctr)
	}

	target := nodeTarget{store: p.policy, recheckRunning: p.recheckRunning}
	p.policy.freshness.noteFallback()
	if !target.fallBack(t.Context()) {
		t.Fatal("the fallback reports no served document, though one was applied")
	}

	ended := slices.Clone(*killed)
	slices.Sort(ended)
	want := []string{sidecar.Id, app.Id}
	slices.Sort(want)
	if !slices.Equal(ended, want) {
		t.Fatalf("killed %v, want every container of the pod the served allowlist admitted %v", ended, want)
	}
	if pod := <-deleted; pod != served {
		t.Fatalf("deleted %s/%s, want the pod the served allowlist admitted", pod.GetNamespace(), pod.GetName())
	}
	select {
	case pod := <-deleted:
		t.Fatalf("deleted %s/%s, a pod the base allowlist admits", pod.GetNamespace(), pod.GetName())
	default:
	}
	if !p.running.contains(baseOnly.Id) {
		t.Fatal("a pod the base allowlist admits lost a container")
	}

	// A poll that lands puts the served allowlist back in force.
	if err := target.replace(t.Context(), anyAllowlist(map[string]string{pushDigestA: "image-a"}), 2); err != nil {
		t.Fatal(err)
	}
	p.policy.freshness.replied(time.Hour, true)
	if !admitsDigest(p.policy, pushDigestA) {
		t.Fatal("the node did not admit the served allowlist again")
	}
	if !p.running.contains(baseOnly.Id) {
		t.Fatal("the applied pull ended a pod the base allowlist admits")
	}
}

// After a restart a node is behind until its first poll lands. With the Trust Authority
// unreachable the startup fetch gives up and the first tick ends the pods it
// recovered that its base allowlist alone does not admit; with the Trust Authority
// answering, those pods run on.
func TestRestartEndsTheRecoveredServedPodsOnlyWithoutTheTrustAuthority(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reachable bool
		wantEnded bool
	}{
		{name: "the Trust Authority answers", reachable: true},
		{name: "the Trust Authority is unreachable", reachable: false, wantEnded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, killed, deleted := fallbackPlugin(t)
			// A restart: the served document is gone and the recovered
			// containers are back on the running set.
			p.policy = newPolicyStore(p.cfg.Allowlist.Base, localClock())
			recovered := makePod("tenant", "inference-0")
			sidecar := runningCtr(recovered, "c8s-mesh", pushDigestA)
			p.running.add(recovered, sidecar)

			handler := &flippingHandler{
				versions: []string{"1"},
				bodyByV:  map[string][]byte{"1": canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-a"}))},
			}
			handler.down.Store(!tc.reachable)
			srv := httptest.NewServer(handler)
			defer srv.Close()
			target := nodeTarget{store: p.policy, recheckRunning: p.recheckRunning}
			client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: time.Second})
			etag := ""
			if tc.reachable {
				var err error
				etag, err = pullInitial(t.Context(), pullArgs{
					client: client,
					target: target,
					pull:   quietPull(),
					logger: discardLogger(),

					timeout: time.Second,
				})
				if err != nil {
					t.Fatalf("the startup fetch failed: %v", err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			go runPullLoop(ctx, pullLoopArgs{
				pull:     quietPull(),
				client:   client,
				interval: 5 * time.Millisecond,
				timeout:  time.Second,
				etag:     etag,
				logger:   discardLogger(),

				target: target,
			})

			if tc.wantEnded {
				if pod := <-deleted; pod != recovered {
					t.Fatalf("deleted %s/%s, want the recovered pod", pod.GetNamespace(), pod.GetName())
				}
				if !slices.Equal(*killed, []string{sidecar.Id}) {
					t.Fatalf("killed %v, want the recovered container the base does not admit", *killed)
				}
				return
			}
			waitFor(t, func() bool { fresh, _ := p.policy.freshness.report(); return fresh }, "the first poll to land")
			select {
			case pod := <-deleted:
				t.Fatalf("deleted %s/%s while the Trust Authority answers", pod.GetNamespace(), pod.GetName())
			case <-time.After(50 * time.Millisecond):
			}
			if len(*killed) != 0 {
				t.Fatalf("killed %v while the Trust Authority answers", *killed)
			}
		})
	}
}
