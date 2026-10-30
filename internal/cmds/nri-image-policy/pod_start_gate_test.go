package nriimagepolicy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/podstart"
)

func podStartFixture(t *testing.T, ready bool) (*plugin, *api.PodSandbox, *api.Container, *fakeRegister) {
	t.Helper()
	reg := &fakeRegister{value: launchSeed}
	measurer, err := openMeasurer(measureFixture(t, reg), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	pod := makePod("tenant", "assigned-node")
	pod.Uid = "runtime-uid"
	p := newTestPlugin(&config{
		Pod:       &podConfig{UID: "signed-uid", Namespace: pod.Namespace, Name: pod.Name, Images: map[string]string{"app": pushDigestA}},
		Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "app"})},
		Policy:    policyConfig{Mode: ModeFailClosed},
		Measure:   measureConfig{RTMR3: true},
	})
	if ready {
		p.SetReady()
	}
	p.measurer = measurer
	p.inventory = newAdmissionInventory(t.TempDir())
	p.inventory.recordSandbox(pod.Id)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	p.podBroker = &podCredentialBroker{ctx: ctx, cancel: cancel, pod: pod}
	ctr := makeCtrWithImageArgs(pod.Id, "app", "image@"+pushDigestA, []string{"/app"})
	ctr.Pid, ctr.Env = 1234, []string{}
	p.containerd = &fakeContainerd{verify: func(ctx context.Context, containerID, sandboxID, digest string) error {
		if containerID != ctr.Id || sandboxID != pod.Id || digest != pushDigestA {
			return errors.New("unexpected selected-image binding in Pod start fixture")
		}
		return ctx.Err()
	}}
	return p, pod, ctr, reg
}

func podStartRequest(pod *api.PodSandbox, ctr *api.Container) podstart.Request {
	return podstart.Request{ContainerID: ctr.Id, SandboxID: pod.Id, PID: ctr.Pid}
}

func TestPodRuntimeStartRequiresFinalAdmissionExactlyOnce(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "initializing", true: "ready"}[ready], func(t *testing.T) {
			p, pod, ctr, reg := podStartFixture(t, ready)
			request := podStartRequest(pod, ctr)
			if err := p.consumePodStart(t.Context(), request); err == nil {
				t.Fatal("created container started without admission")
			}
			if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err != nil {
				t.Fatal(err)
			}
			if err := p.consumePodStart(t.Context(), request); err == nil {
				t.Fatal("preliminary creation admission authorized a runtime start")
			}
			if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
				t.Fatal(err)
			}
			if reg.value != runtimemeasure.FromDigestsSeeded(launchSeed, []string{pushDigestA}) {
				t.Fatal("permission became available before image measurement")
			}
			var admitted atomic.Int32
			var consumers sync.WaitGroup
			for range 8 {
				consumers.Go(func() {
					if err := p.consumePodStart(t.Context(), request); err == nil {
						admitted.Add(1)
					}
				})
			}
			consumers.Wait()
			if admitted.Load() != 1 {
				t.Fatalf("%d concurrent starts admitted, want exactly one", admitted.Load())
			}
		})
	}
}

func TestPodStartFailuresIssueNoPermission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*plugin, *api.Container, *fakeRegister)
	}{
		{"image mismatch", func(p *plugin, _ *api.Container, _ *fakeRegister) {
			p.containerd = &fakeContainerd{verify: func(context.Context, string, string, string) error { return errors.New("wrong image") }}
		}},
		{"allowlist denial", func(p *plugin, _ *api.Container, _ *fakeRegister) { p.policy = newPolicyStore(nil) }},
		{"failed extend", func(_ *plugin, _ *api.Container, r *fakeRegister) { r.fail = errors.New("extend failed") }},
		{"missing journal", func(p *plugin, _ *api.Container, _ *fakeRegister) { p.measurer = nil }},
		{"missing inventory", func(p *plugin, _ *api.Container, _ *fakeRegister) { p.inventory = nil }},
		{"lost history", func(p *plugin, c *api.Container, _ *fakeRegister) {
			p.inventory.record("unexplained", c.PodSandboxId, "previous", "", nil, nil)
		}},
		{"missing broker", func(p *plugin, _ *api.Container, _ *fakeRegister) { p.podBroker = nil }},
		{"ended broker", func(p *plugin, _ *api.Container, _ *fakeRegister) { p.podBroker.terminal = errors.New("ended") }},
		{"cancelled broker", func(p *plugin, _ *api.Container, _ *fakeRegister) { p.podBroker.cancel() }},
		{"runtime disconnected", func(p *plugin, _ *api.Container, _ *fakeRegister) { p.disconnectPodStarts() }},
		{"missing process", func(_ *plugin, c *api.Container, _ *fakeRegister) { c.Pid = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, pod, ctr, reg := podStartFixture(t, true)
			tc.change(p, ctr, reg)
			if err := p.StartContainer(t.Context(), pod, ctr); err == nil {
				t.Fatal("failed final admission succeeded")
			}
			if len(p.podStarts) != 0 || p.consumePodStart(t.Context(), podStartRequest(pod, ctr)) == nil {
				t.Fatal("failed final admission left a usable permission")
			}
		})
	}
}

func TestPodPermissionRequiresSameCreatedProcess(t *testing.T) {
	p, pod, ctr, _ := podStartFixture(t, true)
	if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	request := podStartRequest(pod, ctr)
	for _, wrong := range []podstart.Request{
		{ContainerID: "other", SandboxID: request.SandboxID, PID: request.PID},
		{ContainerID: request.ContainerID, SandboxID: "other", PID: request.PID},
		{ContainerID: request.ContainerID, SandboxID: request.SandboxID, PID: request.PID + 1},
	} {
		if err := p.consumePodStart(t.Context(), wrong); err == nil {
			t.Fatalf("permission accepted mismatched process %+v", wrong)
		}
	}
	if err := p.consumePodStart(t.Context(), request); err != nil {
		t.Fatalf("matching created process refused: %v", err)
	}
}

func TestPodPermissionInvalidatedBeforeRuntimeStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *plugin, *api.PodSandbox, *api.Container)
	}{
		{"stop", func(t *testing.T, p *plugin, pod *api.PodSandbox, c *api.Container) {
			_, _ = p.StopContainer(t.Context(), pod, c)
		}},
		{"remove", func(t *testing.T, p *plugin, pod *api.PodSandbox, c *api.Container) {
			_ = p.RemoveContainer(t.Context(), pod, c)
		}},
		{"identity ended", func(_ *testing.T, p *plugin, _ *api.PodSandbox, _ *api.Container) {
			p.endPodIdentity(errors.New("ended"))
		}},
		{"runtime lost", func(_ *testing.T, p *plugin, _ *api.PodSandbox, _ *api.Container) { p.disconnectPodStarts() }},
		{"synchronized", func(t *testing.T, p *plugin, _ *api.PodSandbox, _ *api.Container) {
			_, _ = p.Synchronize(t.Context(), nil, nil)
		}},
		{"inventory lost", func(_ *testing.T, p *plugin, pod *api.PodSandbox, _ *api.Container) {
			p.inventory.removeSandbox(pod.Id)
		}},
		{"expired", func(_ *testing.T, p *plugin, _ *api.PodSandbox, c *api.Container) {
			grant := p.podStarts[c.Id]
			grant.expires = time.Now().Add(-time.Second)
			p.podStarts[c.Id] = grant
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, pod, ctr, _ := podStartFixture(t, true)
			if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
				t.Fatal(err)
			}
			tc.change(t, p, pod, ctr)
			if err := p.consumePodStart(t.Context(), podStartRequest(pod, ctr)); err == nil {
				t.Fatal("invalidated admission still authorized a runtime start")
			}
		})
	}
}

func TestPodRetryReplacesPreviousPermissionForSameName(t *testing.T) {
	p, pod, ctr, _ := podStartFixture(t, true)
	if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	previous := podStartRequest(pod, ctr)
	ctr.Id, ctr.Pid = "replacement", ctr.Pid+1
	if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	if p.consumePodStart(t.Context(), previous) == nil {
		t.Fatal("replacement retained the previous process's permission")
	}
	if err := p.consumePodStart(t.Context(), podStartRequest(pod, ctr)); err != nil {
		t.Fatal(err)
	}
}

func TestPodFailedRetryRevokesEarlierPermission(t *testing.T) {
	p, pod, ctr, _ := podStartFixture(t, true)
	if err := p.StartContainer(t.Context(), pod, ctr); err != nil {
		t.Fatal(err)
	}
	p.containerd = &fakeContainerd{verify: func(context.Context, string, string, string) error {
		return errors.New("selected rootfs changed")
	}}
	if err := p.StartContainer(t.Context(), pod, ctr); err == nil {
		t.Fatal("retry admitted changed runtime content")
	}
	if p.consumePodStart(t.Context(), podStartRequest(pod, ctr)) == nil {
		t.Fatal("failed retry left its earlier permission usable")
	}
}

func TestPodCancelledCallbackCannotGrantLate(t *testing.T) {
	p, pod, ctr, _ := podStartFixture(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	p.containerd = &fakeContainerd{verify: func(context.Context, string, string, string) error {
		close(entered)
		<-release
		return nil
	}}
	finished := make(chan error, 1)
	go func() { finished <- p.StartContainer(ctx, pod, ctr) }()
	<-entered
	cancel()
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("cancelled callback granted admission after verification returned")
	}
	if p.consumePodStart(t.Context(), podStartRequest(pod, ctr)) == nil {
		t.Fatal("cancelled callback left permission for an already-created process")
	}
}

type failedPodStartListener struct {
	net.Listener
	err error
}

func (l failedPodStartListener) Accept() (net.Conn, error) { return nil, l.err }
func (failedPodStartListener) Close() error                { return nil }
func (failedPodStartListener) Addr() net.Addr              { return &net.UnixAddr{Name: "failed", Net: "unix"} }

func TestPodStartServerFailureEndsRuntimeAuthority(t *testing.T) {
	p, _, _, _ := podStartFixture(t, true)
	p.stub = &fakeStub{}
	failure := errors.New("permission listener failed")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := p.runWithPodStarts(ctx, failedPodStartListener{err: failure}); !errors.Is(err, failure) {
		t.Fatalf("server failure = %v", err)
	}
	if !p.podStartDisconnected.Load() {
		t.Fatal("failed permission server retained runtime authority")
	}
}
