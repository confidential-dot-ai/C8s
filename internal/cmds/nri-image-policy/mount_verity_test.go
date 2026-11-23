package nriimagepolicy

import (
	"context"
	"errors"
	"strings"
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

func newTestVerityCheck() *verityCheck {
	return &verityCheck{
		logger: discardLogger(),
		declared: func(source, destination string) bool {
			return source == verityTestSource && destination == verityTestDestination
		},
		deadline: time.Now().Add(time.Minute),
		digests:  map[verityTarget]string{},
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
	release := make(chan struct{})
	defer close(release)
	calls := stubMeasurement(t, func(uint32, string, string) (string, error) {
		<-release
		return testVerityDigest, nil
	})
	check := newTestVerityCheck()
	check.deadline = time.Now().Add(20 * time.Millisecond)
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
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	calls := stubMeasurement(t, func(uint32, string, string) (string, error) {
		<-release
		return testVerityDigest, nil
	})
	original := verityBudget
	verityBudget = 20 * time.Millisecond
	t.Cleanup(func() { verityBudget = original })

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
