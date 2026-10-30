//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

// The first process must observe its owned CDS reachable, then continuously
// unreachable for two minutes before its one successful exit. Only the RAM
// marker survives that restart; no control endpoint or guest privilege exists.
const cloudCDSScript = `import errno
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# EmptyDir's writable directory is checked before readiness; permission loss
# cannot masquerade as the successful outage-triggered exit.
try:
    fd = os.open("/restart/.writable", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    os.unlink("/restart/.writable")
except OSError:
    sys.exit(42)

seen = threading.Event()

def observe_cds():
    deadline = time.monotonic() + 600
    reachable_deadline = time.monotonic() + 60
    reachable = False
    failed_since = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((sys.argv[1], 8443), timeout=2):
                pass
        except OSError as error:
            if not isinstance(error, TimeoutError) and error.errno not in (errno.ECONNREFUSED, errno.ECONNRESET, errno.ETIMEDOUT):
                os._exit(43)
            if reachable:
                if failed_since is None:
                    failed_since = time.monotonic()
                if time.monotonic() - failed_since >= 120:
                    try:
                        fd = os.open("/restart/once", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                        os.close(fd)
                    except OSError:
                        os._exit(44)
                    os._exit(0)
            elif time.monotonic() >= reachable_deadline:
                os._exit(45)
        else:
            reachable = True
            seen.set()
            failed_since = None
        time.sleep(1)
    os._exit(46)

if os.path.exists("/restart/once"):
    seen.set()
else:
    threading.Thread(target=observe_cds, daemon=True).start()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/live" or (self.path == "/ready" and seen.is_set()) else 503)
        self.end_headers()

    def log_message(self, *_args):
        pass

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
`

// Finalize the exact workload only after the owned CDS endpoint is known.
func (r *cloudRun) cdsWorkload(cds endpoint) (*corev1.Pod, map[string]any, error) {
	address, parseErr := netip.ParseAddr(cds.Host)
	if parseErr != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || cds.Name != "cds" || cds.Port != 8443 {
		return nil, nil, errors.New("CDS workload requires its owned dedicated endpoint")
	}
	pod, policy, err := r.workload("a", nil)
	if err != nil {
		return nil, nil, err
	}
	app := &pod.Spec.Containers[0]
	app.Args = append(app.Args, cds.Host)
	rules := policy["workloads"].(map[string]any)["cloud-a"].(map[string]any)["containers"].([]any)
	rules[0].(map[string]any)["args"].(map[string]any)["argv"] = app.Args
	return pod, policy, nil
}

// cdsPolicies keeps the served-only rule separate from the immutable launch
// policy. An unexpected admission source must fail before scheduling the Pod.
func (r *cloudRun) cdsPolicies(cfg *Config) ([]byte, []byte, error) {
	baseRaw, err := os.ReadFile(cfg.WorkloadsFile)
	if err != nil {
		return nil, nil, err
	}
	base, err := pkgallowlist.ParseJSON(baseRaw)
	if err != nil || len(base.Workloads) != 1 || len(base.Workloads["pod-mesh-membership"].Containers) != 1 {
		return nil, nil, errors.New("CDS outage requires an immutable mesh-only launch policy")
	}
	appRaw, err := cloudPrivateRead(filepath.Join(r.dir, "cds-app-policy.json"), 64<<10)
	if err != nil {
		return nil, nil, err
	}
	app, err := pkgallowlist.ParseJSON(appRaw)
	if err != nil || len(app.Workloads) != 1 || len(app.Workloads["cloud-a"].Containers) != 1 {
		return nil, nil, errors.New("CDS outage requires exactly one separate application rule")
	}
	meshRule, appRule := base.Workloads["pod-mesh-membership"].Containers[0], app.Workloads["cloud-a"].Containers[0]
	if meshRule.Image != r.cfg.MeshImage || meshRule.Digest.String() != strings.TrimPrefix(r.cfg.MeshImage, "ghcr.io/confidential-dot-ai/armtls-mesh@") || appRule.Image != podfixture.PythonImage || appRule.Digest == meshRule.Digest {
		return nil, nil, errors.New("served-only application overlaps the immutable mesh policy")
	}
	before, err := base.Canonical()
	if err != nil {
		return nil, nil, err
	}
	base.Workloads["cloud-a"] = app.Workloads["cloud-a"]
	after, err := base.Canonical()
	return before, after, err
}

// CDS seeds its measured platform entries before merging the signed launch
// workloads. Freeze that authenticated baseline only after proving the exact
// launch rule survives and no entry can already admit the application.
func cloudCDSServedPolicies(launch, application, baseline []byte) ([]byte, []byte, error) {
	base, err := pkgallowlist.ParseJSON(launch)
	if err != nil {
		return nil, nil, err
	}
	added, err := pkgallowlist.ParseJSON(application)
	if err != nil {
		return nil, nil, err
	}
	served, err := pkgallowlist.ParseJSON(baseline)
	if err != nil {
		return nil, nil, err
	}
	app, exists := added.Workloads["cloud-a"]
	if !exists || len(app.Containers) != 1 {
		return nil, nil, errors.New("missing exact application policy")
	}
	if _, exists = served.Workloads["cloud-a"]; exists {
		return nil, nil, errors.New("application already present in CDS baseline")
	}
	for name, want := range base.Workloads {
		got, exists := served.Workloads[name]
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		if !exists || !bytes.Equal(wantJSON, gotJSON) {
			return nil, nil, errors.New("CDS baseline changed an immutable launch rule")
		}
	}
	for _, workload := range served.Workloads {
		for _, containers := range [][]pkgallowlist.Container{workload.InitContainers, workload.Containers} {
			for _, container := range containers {
				if container.Digest == app.Containers[0].Digest || container.Image == app.Containers[0].Image {
					return nil, nil, errors.New("CDS baseline already admits the application image")
				}
			}
		}
	}
	before, err := served.Canonical()
	if err != nil {
		return nil, nil, err
	}
	served.Workloads["cloud-a"] = app
	after, err := served.Canonical()
	return before, after, err
}

// Diagnostics expose only bounded entry names and hashes, never policy argv,
// grants or credentials. Full canonical policies remain in private evidence.
func cloudCDSPolicySummary(raw []byte) map[string]any {
	var doc struct {
		Workloads map[string]json.RawMessage `json:"workloads"`
	}
	_ = json.Unmarshal(raw, &doc)
	keys := slices.Sorted(maps.Keys(doc.Workloads))
	return map[string]any{"sha256": cloudHash(raw), "workloadCount": len(keys), "keys": keys[:min(len(keys), 64)]}
}

func (r *cloudRun) cdsPolicyMismatch(stage string, expected, actual []byte, reason error) error {
	return errors.Join(reason, cloudWrite(filepath.Join(r.dir, "cds-policy-"+stage+"-mismatch.json"), map[string]any{
		"at": time.Now().UTC(), "expected": cloudCDSPolicySummary(expected), "actual": cloudCDSPolicySummary(actual),
	}))
}

func (r *cloudRun) cdsPolicyRequire(stage string, expected, actual []byte) error {
	if bytes.Equal(expected, actual) {
		return nil
	}
	return r.cdsPolicyMismatch(stage, expected, actual, errors.New("owned CDS policy differs from the frozen complete policy"))
}

func (r *cloudRun) cdsPolicyUpdate(ctx context.Context, cfg *Config, cds endpoint, add bool) error {
	launch, application, err := r.cdsPolicies(cfg)
	if err != nil {
		return err
	}
	_, actual, err := r.policy(ctx, cds)
	if err != nil {
		return err
	}
	baselinePath := filepath.Join(r.dir, "cds-policy-baseline.json")
	baseline := actual
	if add {
		if _, statErr := os.Lstat(baselinePath); !os.IsNotExist(statErr) {
			return errors.New("CDS baseline already captured or inaccessible")
		}
	} else {
		baseline, err = cloudPrivateRead(baselinePath, 2<<20)
		if err != nil {
			return err
		}
	}
	base, added, err := cloudCDSServedPolicies(launch, application, baseline)
	if err != nil {
		return r.cdsPolicyMismatch("baseline", launch, baseline, err)
	}
	before, after, action := base, added, "add"
	args := []string{"allowlist", "apply", filepath.Join(r.dir, "cds-app-policy.json")}
	if !add {
		before, after, action = added, base, "delete"
		args = []string{"allowlist", "delete", "cloud-a"}
	}
	if err = r.cdsPolicyRequire(action+"-before", before, actual); err != nil {
		return err
	}
	if add {
		if err = cloudWriteBytes(baselinePath, base); err != nil {
			return err
		}
	}
	if err = cloudWrite(filepath.Join(r.dir, "cds-policy-"+action+"-intent.json"), map[string]any{"at": time.Now().UTC(), "baselineSHA256": cloudHash(base), "before": json.RawMessage(before), "after": json.RawMessage(after)}); err != nil {
		return err
	}
	args = append(args, r.cdsOptions(cds)...)
	args = append(args, "--operator-key", filepath.Join(r.dir, "cds-operator.key"))
	if _, err = r.cli(ctx, args...); err != nil {
		return err
	}
	_, actual, err = r.policy(ctx, cds)
	if err != nil {
		return err
	}
	if err = r.cdsPolicyRequire(action+"-after", after, actual); err != nil {
		return err
	}
	return cloudWrite(filepath.Join(r.dir, "cds-policy-"+action+".json"), map[string]any{"at": time.Now().UTC(), "canonical": json.RawMessage(actual), "sha256": cloudHash(actual)})
}

type cloudCDSPhase string

const (
	cloudCDSActive     cloudCDSPhase = "active"
	cloudCDSRevocation cloudCDSPhase = "revocation"
)

type cloudCDSState struct {
	MeshReady bool
	Ready     bool
	Running   bool
	Restarts  int32
	AppStart  time.Time
	MeshStart time.Time
	Exit      *podstatus.ContainerTerminated
}

func cloudCDSStatus(p podstatus.PodProjection, rec *record, phase cloudCDSPhase) (cloudCDSState, error) {
	var out cloudCDSState
	if phase != cloudCDSActive && phase != cloudCDSRevocation {
		return out, errors.New("unknown CDS observation phase")
	}
	doc, err := rec.document()
	if err != nil {
		return out, err
	}
	if p.Metadata.UID != string(rec.UID) || p.Metadata.Namespace != rec.Namespace || p.Metadata.Name != rec.Name+"-"+doc.Node.Name || (p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodPending) || len(p.Status.ContainerStatuses) != 1 || len(p.Status.InitContainerStatuses) != 1 {
		return out, errors.New("CDS scenario status has another Pod or unexpected containers")
	}
	app, mesh := p.Status.ContainerStatuses[0], p.Status.InitContainerStatuses[0]
	if app.Name != "app" || mesh.Name != workloadclaims.MeshContainerName || mesh.RestartCount != 0 || mesh.State == nil || mesh.State.Running == nil || mesh.State.Waiting != nil || mesh.State.Terminated != nil || mesh.State.Running.StartedAt == nil || mesh.State.Running.StartedAt.IsZero() || (mesh.LastState != nil && (mesh.LastState.Running != nil || mesh.LastState.Waiting != nil || mesh.LastState.Terminated != nil)) || (phase == cloudCDSActive && !mesh.Ready) {
		return out, errors.New("CDS scenario mesh changed or stopped")
	}
	if app.RestartCount < 0 || app.RestartCount > 2 || app.State == nil {
		return out, errors.New("CDS scenario application has invalid restart state")
	}
	states := 0
	if app.State.Running != nil {
		states++
	}
	if app.State.Waiting != nil {
		states++
	}
	if app.State.Terminated != nil {
		states++
	}
	if states != 1 || (app.Ready && app.State.Running == nil) || (app.LastState != nil && (app.LastState.Running != nil || app.LastState.Waiting != nil)) {
		return out, errors.New("CDS scenario application has contradictory state")
	}
	out.MeshReady = mesh.Ready
	out.MeshStart, out.Restarts = mesh.State.Running.StartedAt.Time, app.RestartCount
	out.Ready, out.Running = app.Ready && p.Status.Phase == corev1.PodRunning, app.State.Running != nil
	if out.Running {
		if app.State.Running.StartedAt == nil || app.State.Running.StartedAt.IsZero() {
			return out, errors.New("CDS scenario application has no start time")
		}
		out.AppStart = app.State.Running.StartedAt.Time
	}
	out.Exit = app.State.Terminated
	if out.Exit == nil && app.LastState != nil {
		out.Exit = app.LastState.Terminated
	}
	if out.Exit != nil && (out.Exit.StartedAt == nil || out.Exit.StartedAt.IsZero() || out.Exit.FinishedAt == nil || out.Exit.FinishedAt.IsZero() || out.Exit.FinishedAt.Before(out.Exit.StartedAt)) {
		return out, errors.New("CDS scenario termination has incomplete chronology")
	}
	return out, nil
}

// A count-zero running observation after the minimum outage duration is required
// before accepting any exit. Guest timestamps alone do not establish elapsed time.
func cloudCDSRestart(before, current cloudCDSState, held bool) (bool, error) {
	if !current.MeshStart.Equal(before.MeshStart) || current.Restarts > 1 {
		return false, errors.New("unexpected mesh or additional application restart during CDS outage")
	}
	if current.Restarts == 0 && current.Running {
		if !current.AppStart.Equal(before.AppStart) || current.Exit != nil {
			return false, errors.New("initial application start changed without its expected restart")
		}
		return false, nil
	}
	if !held {
		return false, errors.New("application exited before seventy seconds of confirmed CDS outage")
	}
	exit := current.Exit
	if exit == nil || exit.StartedAt == nil || exit.FinishedAt == nil || !exit.StartedAt.Time.Equal(before.AppStart) || exit.ExitCode != 0 || exit.Signal != 0 {
		return false, errors.New("application did not perform its single planned successful exit")
	}
	if current.Running && (current.Restarts != 1 || !current.AppStart.After(before.AppStart) || current.AppStart.Before(exit.FinishedAt.Time)) {
		return false, errors.New("application restart does not follow its planned exit")
	}
	return current.Running && current.Ready, nil
}

func cloudCDSRevoked(before, current cloudCDSState) (bool, error) {
	if !current.MeshStart.Equal(before.MeshStart) || current.Restarts < 1 || current.Restarts > 2 {
		return false, errors.New("CDS revocation changed mesh identity or admitted additional restarts")
	}
	if current.Running {
		if current.Restarts != 1 || !current.AppStart.Equal(before.AppStart) {
			return false, errors.New("revoked application started again")
		}
		return false, nil
	}
	exit := current.Exit
	return !current.MeshReady && !current.Ready && exit != nil && exit.StartedAt != nil && exit.FinishedAt != nil && exit.StartedAt.Time.Equal(before.AppStart), nil
}
