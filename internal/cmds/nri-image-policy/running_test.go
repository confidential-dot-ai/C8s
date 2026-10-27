package nriimagepolicy

import (
	"context"
	"slices"
	"testing"

	"github.com/containerd/nri/pkg/api"
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
	revoked, kept, base := runningCtr(pod, "revoked", pushDigestA), runningCtr(pod, "kept", pushDigestB), runningCtr(pod, "base", pushDigestC)
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
	pod := makePod("default", "pod")
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo:tag")
	p.containerd.(*fakeContainerd).resolve = func(context.Context, string) (string, error) { return pushDigestA, nil }
	// A start resolves its image once, so the measurement, which follows the
	// admission verdict and precedes the start's return, is where it pauses.
	admitted, release := make(chan struct{}), make(chan struct{})
	p.measurer = pausingMeasurer{admitted: admitted, release: release}
	started := make(chan error)
	go func() { started <- p.StartContainer(context.Background(), pod, ctr) }()

	<-admitted
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
