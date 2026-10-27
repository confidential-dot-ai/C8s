package nriimagepolicy

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
)

func TestWaitingPodDeniesEveryAdmissionHook(t *testing.T) {
	for _, name := range []string{"pause", "app", "c8s-mesh"} {
		p := newTestPlugin(&config{Pod: &podConfig{Waiting: true}})
		pod := makePod("tenant", "unassigned")
		ctr := makeCtrWithImage(pod.Id, name, "repo@"+pushDigestA)
		if err := p.RunPodSandbox(context.Background(), pod); err == nil || !strings.Contains(err.Error(), "waiting") {
			t.Fatal("waiting guest admitted a sandbox")
		}
		if _, _, err := p.CreateContainer(context.Background(), pod, ctr); err == nil || !strings.Contains(err.Error(), "waiting") {
			t.Fatal("waiting guest created a container")
		}
		if err := p.StartContainer(context.Background(), pod, ctr); err == nil || !strings.Contains(err.Error(), "waiting") {
			t.Fatal("waiting guest started a container")
		}
		if err := p.preparePodBroker(context.Background(), nil); err != nil || p.podBroker != nil {
			t.Fatal("waiting guest created a credential broker")
		}
	}
}

type emptyRestartMeasurer struct{ digests []string }

func (m emptyRestartMeasurer) MeasureOnce(string) (bool, error) { return false, nil }
func (m emptyRestartMeasurer) Digests() []string                { return m.digests }

func TestGenericWaitingRegistrationSurvivesRestartBeforeCDSReadiness(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "registered")
	for attempt := range 2 {
		p, actions := gatedPlugin(t, marker)
		p.cfg.Pod = &podConfig{Waiting: true, Generic: true}
		p.ready.Store(false)
		sock := filepath.Join(t.TempDir(), "health.sock")
		if err := startHealthServer(t.Context(), healthServerConfig{logger: discardLogger(), plugin: p, addr: "unix://" + sock, readTimeout: time.Second, writeTimeout: time.Second}); err != nil {
			t.Fatal(err)
		}
		client := unixHealthClient(sock)
		if code, body := healthz(t, client); code != http.StatusServiceUnavailable || body.PodRegistered {
			t.Fatal("unregistered plugin authorized assignment")
		}
		if _, err := p.Synchronize(t.Context(), nil, nil); err != nil {
			t.Fatal(err)
		}
		code, body := healthz(t, client)
		if code != http.StatusServiceUnavailable || !body.PodRegistered || !body.PodWaiting || body.PodUID != "" || p.Ready() || actions.powerOffs != 0 {
			t.Fatalf("waiting registration depended on CDS readiness: %+v", body)
		}
		if p.bootRestart.Load() != (attempt == 1) {
			t.Fatal("test did not exercise a real same-boot restart")
		}
		p.disconnectPodStarts()
		if _, body := healthz(t, client); body.PodRegistered {
			t.Fatal("lost NRI connection retained assignment authority")
		}
		client.CloseIdleConnections()
	}
}

func TestGenericRestartRequiresEveryEmptyAssignmentPrerequisite(t *testing.T) {
	for _, condition := range []string{"allowed", "static", "waiting", "uid", "journal-unavailable", "history", "sandbox", "container", "manifest", "symlink"} {
		t.Run(condition, func(t *testing.T) {
			p := newTestPlugin(&config{Pod: &podConfig{Generic: true, UID: "assigned"}})
			p.measurer = emptyRestartMeasurer{}
			manifest := filepath.Join(t.TempDir(), "pod.yaml")
			var pods []*api.PodSandbox
			var ctrs []*api.Container
			switch condition {
			case "static":
				p.cfg.Pod.Generic = false
			case "waiting":
				p.cfg.Pod.Waiting = true
			case "uid":
				p.cfg.Pod.UID = ""
			case "journal-unavailable":
				p.measurer = nil
			case "history":
				p.measurer = emptyRestartMeasurer{digests: []string{pushDigestA}}
			case "sandbox":
				pods = []*api.PodSandbox{makePod("tenant", "pod")}
			case "container":
				ctrs = []*api.Container{{Id: "created"}}
			case "manifest":
				if err := os.WriteFile(manifest, []byte("already assigned"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing", manifest); err != nil {
					t.Fatal(err)
				}
			}
			if got := p.emptyGenericAssignment(pods, ctrs, manifest); got != (condition == "allowed") {
				t.Fatalf("restart exception %s = %v", condition, got)
			}
		})
	}
}
