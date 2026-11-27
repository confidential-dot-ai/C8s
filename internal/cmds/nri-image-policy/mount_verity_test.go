package nriimagepolicy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

const (
	verityTestSource      = "/opt/tools/tool"
	verityTestDestination = "/usr/bin/tool"
)

var testVerityDigest = strings.Repeat("b", 64)

// stubMeasurement replaces the kernel measurement for the test and counts the
// calls that reach it.
func stubMeasurement(t *testing.T, measure func(pid uint32, id, destination string) (string, error)) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	original := measureContainerFile
	measureContainerFile = func(pid uint32, id, destination string) (string, error) {
		calls.Add(1)
		return measure(pid, id, destination)
	}
	t.Cleanup(func() { measureContainerFile = original })
	return &calls
}

// hangMeasurement stubs a measurement that blocks until the test ends, then
// waits for every blocked call to return, so none outlives the stub.
func hangMeasurement(t *testing.T) *atomic.Int32 {
	t.Helper()
	release := make(chan struct{})
	var mu sync.Mutex
	var returned []chan struct{}
	calls := stubMeasurement(t, func(uint32, string, string) (string, error) {
		done := make(chan struct{})
		mu.Lock()
		returned = append(returned, done)
		mu.Unlock()
		defer close(done)
		<-release
		return testVerityDigest, nil
	})
	t.Cleanup(func() {
		close(release)
		mu.Lock()
		defer mu.Unlock()
		for _, done := range returned {
			<-done
		}
	})
	return calls
}

func newTestVerityCheck() *verityCheck {
	return &verityCheck{
		logger: discardLogger(),
		declared: func(source, destination string) bool {
			return source == verityTestSource && destination == verityTestDestination
		},
		budget:     time.Minute,
		digests:    map[verityTarget]string{},
		unmeasured: map[string][]string{},
	}
}

func TestVerityCheckAttach(t *testing.T) {
	bind := &api.Mount{Type: "bind", Source: verityTestSource, Destination: verityTestDestination, Options: []string{"rbind", "ro"}}
	for _, tc := range []struct {
		name     string
		check    *verityCheck
		pid      uint32
		mount    func(*api.Mount)
		evidence func(*allowlist.ObservedMount)
		measure  error
		want     string
		measured bool
	}{
		{name: "declared read-only bind", check: newTestVerityCheck(), pid: 42, want: testVerityDigest, measured: true},
		{name: "measurement fails", check: newTestVerityCheck(), pid: 42, measure: errVerityFilesystem, measured: true},
		{name: "no check", pid: 42},
		{name: "no container process", check: newTestVerityCheck()},
		{name: "writable bind", check: newTestVerityCheck(), pid: 42, mount: func(m *api.Mount) { m.Options = []string{"rbind", "rw"} }},
		{name: "overlay", check: newTestVerityCheck(), pid: 42, mount: func(m *api.Mount) { m.Type, m.Options = "overlay", []string{"ro", "lowerdir=/untrusted"} }},
		{name: "undeclared destination", check: newTestVerityCheck(), pid: 42, mount: func(m *api.Mount) { m.Destination = "/usr/bin/other" }},
		{name: "node-root file", check: newTestVerityCheck(), pid: 42, evidence: func(o *allowlist.ObservedMount) { o.Provenance = allowlist.ProvenanceNodeRoot }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubMeasurement(t, func(uint32, string, string) (string, error) {
				if tc.measure != nil {
					return "", tc.measure
				}
				return testVerityDigest, nil
			})
			m := &api.Mount{Type: bind.Type, Source: bind.Source, Destination: bind.Destination, Options: bind.Options}
			if tc.mount != nil {
				tc.mount(m)
			}
			evidence := observeHostMount(m)
			if tc.evidence != nil {
				tc.evidence(&evidence)
			}
			got := tc.check.attach(&api.Container{Id: "ctr", Pid: tc.pid}, m, evidence)
			if got.VerityDigest != tc.want || (tc.want != "") != (got.Provenance == allowlist.ProvenanceFSVerity) {
				t.Fatalf("attach(%s) = %q %q, want digest %q", tc.name, got.Provenance, got.VerityDigest, tc.want)
			}
			if measured := calls.Load() > 0; measured != tc.measured {
				t.Fatalf("attach(%s) measured = %t, want %t", tc.name, measured, tc.measured)
			}
		})
	}
}

func TestVerityCheckMeasuresOncePerCheck(t *testing.T) {
	calls := stubMeasurement(t, func(uint32, string, string) (string, error) { return testVerityDigest, nil })
	target := verityTarget{container: "ctr", pid: 42, destination: verityTestDestination}
	check := newTestVerityCheck()
	check.digest(target)
	check.digest(target)
	if got := calls.Load(); got != 1 {
		t.Fatalf("measurements in one check = %d, want 1", got)
	}
	newTestVerityCheck().digest(target)
	if got := calls.Load(); got != 2 {
		t.Fatalf("measurements in two checks = %d, want 2", got)
	}
}

func TestVerityCheckBudget(t *testing.T) {
	calls := hangMeasurement(t)
	check := newTestVerityCheck()
	check.budget = 20 * time.Millisecond
	if got, err := check.measure(verityTarget{pid: 42, destination: "/a"}); got != "" || !errors.Is(err, errVerityOverrun) {
		t.Fatalf("measure(hung) = %q, %v, want %v", got, err, errVerityOverrun)
	}
	if got, err := check.measure(verityTarget{pid: 42, destination: "/b"}); got != "" || !errors.Is(err, errVerityOverrun) {
		t.Fatalf("measure(after the budget) = %q, %v, want %v", got, err, errVerityOverrun)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("measurements = %d, want 1: the budget is the check's, not each file's", got)
	}
}

// Only measuring uses the budget: the rest of a check can take longer.
func TestVerityBudgetCountsOnlyMeasuring(t *testing.T) {
	stubMeasurement(t, func(uint32, string, string) (string, error) { return testVerityDigest, nil })
	check := newTestVerityCheck()
	check.budget = 20 * time.Millisecond
	time.Sleep(2 * check.budget)
	if got, err := check.measure(verityTarget{pid: 42, destination: "/a"}); got != testVerityDigest || err != nil {
		t.Fatalf("measure(after other work outlasted the budget) = %q, %v, want %q", got, err, testVerityDigest)
	}
}

func TestVerityCheckBoundsStragglers(t *testing.T) {
	calls := stubMeasurement(t, func(uint32, string, string) (string, error) { return testVerityDigest, nil })
	for range cap(verityWorkers) {
		verityWorkers <- struct{}{}
	}
	t.Cleanup(func() {
		for range cap(verityWorkers) {
			<-verityWorkers
		}
	})
	if got, err := newTestVerityCheck().measure(verityTarget{pid: 42, destination: "/a"}); got != "" || !errors.Is(err, errVerityBusy) {
		t.Fatalf("measure(no free worker) = %q, %v, want %v", got, err, errVerityBusy)
	}
	if calls.Load() != 0 {
		t.Fatal("measured without a worker")
	}
}

// The validation check has no container root and judges an fsVerityFile rule
// on its source alone; the start check measures the digest and decides.
func TestFSVerityDecidedAtStart(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		digest  string
		measure error
		want    bool
	}{
		{name: "pinned digest", mode: ModeFailClosed, digest: testVerityDigest, want: true},
		{name: "other digest", mode: ModeFailClosed, digest: strings.Repeat("a", 64)},
		{name: "measurement fails", mode: ModeFailClosed, measure: errVerityFilesystem},
		{name: "measurement fails in audit mode", mode: ModeAudit, measure: errVerityFilesystem, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubMeasurement(t, func(pid uint32, _, destination string) (string, error) {
				if pid != 42 || destination != verityTestDestination {
					t.Errorf("measured %s of pid %d, want %s of pid 42", destination, pid, verityTestDestination)
				}
				return tc.digest, tc.measure
			})
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: verityTestDestination, Kind: allowlist.MountFSVerityFile, Source: verityTestSource, ReadOnly: true, VerityDigest: testVerityDigest}}}
			if err := al.Normalize(); err != nil {
				t.Fatal(err)
			}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: tc.mode}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			pod.Uid = "pod-uid"
			ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
			ctr.Args = []string{"/bin/app"}
			ctr.Mounts = []*api.Mount{{Type: "bind", Source: verityTestSource, Destination: verityTestDestination, Options: []string{"rbind", "ro"}}}
			if err := p.ValidateContainerAdjustment(t.Context(), &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr}); err != nil {
				t.Fatalf("ValidateContainerAdjustment(%s) = %v, want the source alone admitted", tc.name, err)
			}
			ctr.Pid = 42
			err := p.StartContainer(context.Background(), pod, ctr)
			if (err == nil) != tc.want {
				t.Fatalf("StartContainer(%s) = %v, want admitted %t", tc.name, err, tc.want)
			}
			_, containers, _, _ := p.inventory.DigestsForSandbox(pod.Id)
			if !tc.want || tc.measure != nil {
				for _, c := range containers {
					for _, m := range c.Mounts {
						if m.Provenance == allowlist.ProvenanceFSVerity {
							t.Fatalf("recorded fs-verity evidence %+v without a measured pinned digest", m)
						}
					}
				}
				return
			}
			if len(containers) != 1 || len(containers[0].Mounts) != 1 || containers[0].Mounts[0].VerityDigest != testVerityDigest {
				t.Fatalf("inventory = %+v, want the measured digest", containers)
			}
		})
	}
}

// Mounts observed outside a check that measures carry no fs-verity evidence,
// whatever process the runtime reports.
func TestObservedMountsMeasureOnlyInACheck(t *testing.T) {
	calls := stubMeasurement(t, func(uint32, string, string) (string, error) { return testVerityDigest, nil })
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: verityTestDestination, Kind: allowlist.MountFSVerityFile, Source: verityTestSource, ReadOnly: true, VerityDigest: testVerityDigest}}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	p, _ := newCachedPlugin(&config{}, al)
	pod := makePod("default", "pod")
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
	ctr.Pid = 42
	ctr.Mounts = []*api.Mount{{Type: "bind", Source: verityTestSource, Destination: verityTestDestination, Options: []string{"rbind", "ro"}}}
	if got := p.observedMounts(t.Context(), pod, ctr); got[0].Provenance != "" || calls.Load() != 0 {
		t.Fatalf("observedMounts(no check) = %+v after %d measurements, want no evidence", got, calls.Load())
	}
	if got := p.observedMounts(p.withVerityCheck(t.Context()), pod, ctr); got[0].VerityDigest != testVerityDigest {
		t.Fatalf("observedMounts(check) = %+v, want digest %s", got, testVerityDigest)
	}
}

// Synchronize answers within one NRI request timeout, so its containers share
// one measurement budget: a hung filesystem costs it once, not per container.
func TestSynchronizeSharesOneVerityBudget(t *testing.T) {
	calls := hangMeasurement(t)
	setVerityBudget(t, 20*time.Millisecond)

	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{Destination: verityTestDestination, Kind: allowlist.MountFSVerityFile, Source: verityTestSource, ReadOnly: true, VerityDigest: testVerityDigest}}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeAudit}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
	p.SetReady()
	p.inventory = newAdmissionInventory(t.TempDir())
	pod := makePod("default", "pod")
	var ctrs []*api.Container
	for i, name := range []string{"a", "b"} {
		ctr := makeCtrWithImage(pod.Id, name, "registry/repo@"+pushDigestB)
		ctr.Pid = uint32(42 + i)
		ctr.State = api.ContainerState_CONTAINER_RUNNING
		ctr.Mounts = []*api.Mount{{Type: "bind", Source: verityTestSource, Destination: verityTestDestination, Options: []string{"rbind", "ro"}}}
		ctrs = append(ctrs, ctr)
	}
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{pod}, ctrs); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("measurements on a hung filesystem = %d, want 1: one budget per Synchronize", got)
	}
}

func TestKillRevokedSharesOneVerityBudget(t *testing.T) {
	calls := hangMeasurement(t)
	setVerityBudget(t, 20*time.Millisecond)
	p, killed := verityEnforcingPlugin(t)
	p.SetReady()
	pod := makePod("default", "pod")
	for i, name := range []string{"a", "b"} {
		ctr := verityCtr(pod, api.ContainerState_CONTAINER_RUNNING, uint32(42+i))
		ctr.Id, ctr.Name = name, name
		p.running.add(pod, ctr)
	}
	p.KillRevoked(t.Context())
	if got := calls.Load(); got != 1 {
		t.Fatalf("measurements on a hung filesystem = %d, want 1: one budget per KillRevoked", got)
	}
	if len(*killed) != 0 {
		t.Fatalf("KillRevoked stopped %v over measurements that did not run", *killed)
	}
}

// A component set in force admits an fsVerityFile bind as the workloads
// section does: on the digest measured at the start check.
func TestComponentSetFSVerityDecidedAtStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		digest string
		want   bool
	}{
		{"pinned digest", testVerityDigest, true},
		{"other digest", strings.Repeat("a", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubMeasurement(t, func(uint32, string, string) (string, error) { return tc.digest, nil })
			component := allowlist.Container{
				Digest:  mustDigest(t, pushDigestB),
				Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/bin/app"}},
				Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
				Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{{
					Destination: verityTestDestination, Kind: allowlist.MountFSVerityFile, Source: verityTestSource, ReadOnly: true, VerityDigest: testVerityDigest,
				}}},
			}
			document := componentDocument(t, nil, component)
			p, _ := newCachedPlugin(&config{Policy: enforcing, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, document)
			p.SetReady()
			p.inventory = newAdmissionInventory(t.TempDir())
			pod := makePod("default", "pod")
			ctr := verityCtr(pod, api.ContainerState_CONTAINER_CREATED, 42)
			err := p.StartContainer(t.Context(), pod, ctr)
			if (err == nil) != tc.want {
				t.Fatalf("StartContainer(%s) = %v, want admitted %t", tc.name, err, tc.want)
			}
		})
	}
}

func setVerityBudget(t *testing.T, budget time.Duration) {
	t.Helper()
	original := verityBudget
	verityBudget = budget
	t.Cleanup(func() { verityBudget = original })
}

// verityEnforcingPlugin enforces on running containers with one fsVerityFile
// rule pinning testVerityDigest, and the extra rules. Its containerd records
// kills.
func verityEnforcingPlugin(t *testing.T, extra ...allowlist.MountRule) (*plugin, *[]string) {
	t.Helper()
	al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
	rules := append([]allowlist.MountRule{{Destination: verityTestDestination, Kind: allowlist.MountFSVerityFile, Source: verityTestSource, ReadOnly: true, VerityDigest: testVerityDigest}}, extra...)
	al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: rules}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	p, _ := newCachedPlugin(&config{Policy: enforcing, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
	p.inventory = newAdmissionInventory(t.TempDir())
	killed := &[]string{}
	p.containerd = &fakeContainerd{stop: func(_ context.Context, id string) error {
		*killed = append(*killed, id)
		return nil
	}}
	return p, killed
}

func verityCtr(pod *api.PodSandbox, state api.ContainerState, pid uint32) *api.Container {
	ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
	ctr.Args = []string{"/bin/app"}
	ctr.State, ctr.Pid = state, pid
	ctr.Mounts = []*api.Mount{{Type: "bind", Source: verityTestSource, Destination: verityTestDestination, Options: []string{"rbind", "ro"}}}
	return ctr
}

// Every check of running containers measures each file again: it records the
// measured digest, keeps a container with the pinned one, and stops one whose
// file does not qualify. A file it cannot measure is judged on its source
// alone, so the container is left running, with no evidence recorded.
func TestExistingChecksMeasureFSVerity(t *testing.T) {
	for _, entry := range []struct {
		name  string
		check func(t *testing.T, p *plugin, pod *api.PodSandbox, ctr *api.Container)
	}{
		{"Synchronize", func(t *testing.T, p *plugin, pod *api.PodSandbox, ctr *api.Container) {
			p.SetReady()
			if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
				t.Fatal(err)
			}
		}},
		{"RunDeferredCheck", func(t *testing.T, p *plugin, pod *api.PodSandbox, ctr *api.Container) {
			if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{ctr}); err != nil {
				t.Fatal(err)
			}
			p.SetReady()
			p.RunDeferredCheck(t.Context())
		}},
		{"KillRevoked", func(t *testing.T, p *plugin, pod *api.PodSandbox, ctr *api.Container) {
			p.SetReady()
			p.running.add(pod, ctr)
			p.KillRevoked(t.Context())
		}},
	} {
		for _, tc := range []struct {
			name    string
			noPID   bool
			digest  string
			measure error
			busy    bool
			hang    bool
			kept    bool
		}{
			{name: "pinned digest", digest: testVerityDigest, kept: true},
			{name: "other digest", digest: strings.Repeat("a", 64)},
			{name: "not fs-verity", measure: errVerityFilesystem},
			{name: "writable mount", measure: errVerityWritable},
			{name: "process gone", measure: errNotContainerInit, kept: true},
			{name: "no free worker", busy: true, kept: true},
			{name: "overran the budget", hang: true, kept: true},
			{name: "no process", noPID: true, kept: true},
		} {
			t.Run(entry.name+"/"+tc.name, func(t *testing.T) {
				pid := uint32(42)
				if tc.noPID {
					pid = 0
				}
				if tc.hang {
					hangMeasurement(t)
					setVerityBudget(t, 20*time.Millisecond)
				} else {
					stubMeasurement(t, func(uint32, string, string) (string, error) { return tc.digest, tc.measure })
				}
				if tc.busy {
					for range cap(verityWorkers) {
						verityWorkers <- struct{}{}
					}
					t.Cleanup(func() {
						for range cap(verityWorkers) {
							<-verityWorkers
						}
					})
				}
				p, killed := verityEnforcingPlugin(t)
				pod := makePod("default", "pod")
				ctr := verityCtr(pod, api.ContainerState_CONTAINER_RUNNING, pid)
				entry.check(t, p, pod, ctr)

				if kept := len(*killed) == 0; kept != tc.kept {
					t.Fatalf("%s(%s) stopped %v, want kept %t", entry.name, tc.name, *killed, tc.kept)
				}
				if entry.name == "KillRevoked" {
					return
				}
				_, containers, _, _ := p.inventory.DigestsForSandbox(pod.Id)
				var recorded string
				for _, c := range containers {
					for _, m := range c.Mounts {
						recorded = m.VerityDigest
					}
				}
				want := ""
				if tc.measure == nil && !tc.busy && !tc.hang && !tc.noPID {
					want = tc.digest
				}
				if recorded != want {
					t.Fatalf("%s(%s) recorded digest %q, want %q", entry.name, tc.name, recorded, want)
				}
			})
		}
	}
}

// A file a measurement found wanting is denied even when a sibling file of
// the same container could not be measured: deferral covers only the latter.
func TestExistingChecksDeferOnlyUnmeasuredFiles(t *testing.T) {
	const otherSource, otherDestination = "/opt/tools/other", "/usr/bin/other"
	for _, sibling := range []error{errNotContainerInit, errVerityBusy, errVerityOverrun} {
		for _, tc := range []struct {
			first  error
			killed bool
		}{
			{first: errVerityFilesystem, killed: true},
			{first: sibling},
		} {
			t.Run(tc.first.Error()+"/"+sibling.Error(), func(t *testing.T) {
				stubMeasurement(t, func(_ uint32, _, destination string) (string, error) {
					if destination == verityTestDestination {
						return "", tc.first
					}
					return "", sibling
				})
				p, killed := verityEnforcingPlugin(t, allowlist.MountRule{Destination: otherDestination, Kind: allowlist.MountFSVerityFile, Source: otherSource, ReadOnly: true, VerityDigest: testVerityDigest})
				p.SetReady()
				pod := makePod("default", "pod")
				ctr := verityCtr(pod, api.ContainerState_CONTAINER_RUNNING, 42)
				ctr.Mounts = append(ctr.Mounts, &api.Mount{Type: "bind", Source: otherSource, Destination: otherDestination, Options: []string{"rbind", "ro"}})
				p.running.add(pod, ctr)
				p.KillRevoked(t.Context())
				if got := len(*killed) == 1; got != tc.killed {
					t.Fatalf("KillRevoked(%v beside %v) stopped %v, want stopped %t", tc.first, sibling, *killed, tc.killed)
				}
			})
		}
	}
}

// A container stopped before the enforcer connected, such as a completed init
// container, has no process to measure; the startup check leaves it be.
func TestStartupCheckSparesStoppedFSVerityContainer(t *testing.T) {
	calls := stubMeasurement(t, func(uint32, string, string) (string, error) { return testVerityDigest, nil })
	p, killed := verityEnforcingPlugin(t)
	p.SetReady()
	pod := makePod("default", "pod")
	if _, err := p.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{verityCtr(pod, api.ContainerState_CONTAINER_STOPPED, 0)}); err != nil {
		t.Fatal(err)
	}
	if len(*killed) != 0 || calls.Load() != 0 {
		t.Fatalf("Synchronize(stopped) stopped %v after %d measurements, want none", *killed, calls.Load())
	}
}

// The start check refuses a container whose file it could not measure: only
// checks of running containers judge such a file on its source alone.
func TestStartRefusesUnmeasuredFSVerity(t *testing.T) {
	stubMeasurement(t, func(uint32, string, string) (string, error) { return "", errNotContainerInit })
	p, _ := verityEnforcingPlugin(t)
	p.SetReady()
	pod := makePod("default", "pod")
	pod.Uid = "pod-uid"
	if err := p.StartContainer(t.Context(), pod, verityCtr(pod, api.ContainerState_CONTAINER_CREATED, 42)); err == nil {
		t.Fatal("StartContainer(unmeasured) admitted, want refused")
	}
}
