package podstatus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The pod-role units the assignment path starts, in this order: containerd
// launches the admission plugin it pre-registers, and the kubelet starts only
// once that plugin reports the assigned pod registered. Neither unit starts
// at boot (images/node-guest/c8s/mkosi.extra/etc/systemd/system).
const (
	podRuntimeUnit = "podcvm-containerd.service"
	podKubeletUnit = "podcvm-kubelet.service"
)

// errAssignmentAbandoned ends the apply retries: the assigned outputs differ
// from what is installed, or the plugin ended the pod identity, and neither
// changes within this boot.
var errAssignmentAbandoned = errors.New("assignment abandoned")

// errPodIdentityEnded is the health report of a plugin that ended the pod identity.
var errPodIdentityEnded = errors.New("pod identity ended")

type guestAssignmentRuntime struct {
	journal string
}

// available makes no mutations: before an assignment nothing runs, so the only
// observation is that the register measured no workload.
func (g guestAssignmentRuntime) available(context.Context) error {
	digests, err := armtls.ReadRuntimeExtensions(g.journal)
	if err != nil {
		return err
	}
	if len(digests) != 0 {
		return errors.New("unassigned guest has measured containers")
	}
	return nil
}

func (g guestAssignmentRuntime) apply(ctx context.Context, runtime nodeservices.PodRuntime) error {
	manifests, err := openAssignmentRoot(nodeservices.PodDir + "/manifests")
	if err != nil {
		return err
	}
	defer manifests.Close()
	if err := fileutil.RequireRAMBackedRoot(manifests); err != nil {
		return err
	}
	policy, err := openAssignmentRoot("/etc/nri/conf.d")
	if err != nil {
		return err
	}
	defer policy.Close()
	return installAssignment(ctx, runtime, manifests, policy, startUnit, assignmentHealth)
}

// installAssignment is restartable at every boundary. The policy is written
// before the runtime starts, the manifest only once the plugin the runtime
// launched reports the assigned pod registered, and the kubelet last, so it
// never reads a manifest the plugin is not yet guarding. A published policy or
// manifest is immutable; a recovery with both in place still starts the units,
// which is idempotent, so a crash between the manifest and the kubelet is
// recovered too.
func installAssignment(ctx context.Context, runtime nodeservices.PodRuntime, manifests, policy *os.Root, start func(context.Context, string) error, health func(context.Context, string) error) error {
	if runtime.UID == "" || len(runtime.Policy) == 0 || len(runtime.Manifest) == 0 {
		return errors.New("incomplete assigned runtime")
	}
	manifestInstalled, err := assignmentOutputInstalled(manifests, "pod.yaml", runtime.Manifest, "refusing to replace an assigned manifest")
	if err != nil {
		return err
	}
	policyInstalled, err := assignmentOutputInstalled(policy, "image-policy.yaml", runtime.Policy, "assigned runtime policy differs from its immutable assignment")
	if err != nil {
		return err
	}
	if manifestInstalled && !policyInstalled {
		return fmt.Errorf("%w: assigned manifest was published without its policy", errAssignmentAbandoned)
	}
	if !policyInstalled {
		if err := fileutil.WriteAtomicRoot(policy, "image-policy.yaml", runtime.Policy, 0600); err != nil {
			return err
		}
	}
	if err := start(ctx, podRuntimeUnit); err != nil {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for err := health(ctx, runtime.UID); err != nil; err = health(ctx, runtime.UID) {
		if errors.Is(err, errPodIdentityEnded) {
			return fmt.Errorf("%w: %w", errAssignmentAbandoned, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	if !manifestInstalled {
		// The service lifetime lock excludes another installer.
		if err := fileutil.WriteAtomicRoot(manifests, "pod.yaml", runtime.Manifest, 0600); err != nil {
			return err
		}
	}
	return start(ctx, podKubeletUnit)
}

// assignmentOutputInstalled reports whether name already holds want; another
// content is refused with mismatch, since an assignment output never changes.
func assignmentOutputInstalled(root *os.Root, name string, want []byte, mismatch string) (bool, error) {
	data, err := readAssignmentOutput(root, name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(data, want) {
		return false, fmt.Errorf("%w: %s", errAssignmentAbandoned, mismatch)
	}
	return true, nil
}

func readAssignmentOutput(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("assignment output is not a private regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBody {
		return nil, errors.New("assignment output exceeds size limit")
	}
	return data, nil
}

// startUnit starts one pod-role unit; a unit already running is left alone.
// No request bytes become arguments.
func startUnit(ctx context.Context, unit string) error {
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "start", unit).Run(); err != nil {
		return fmt.Errorf("start %s: %w", unit, err)
	}
	return nil
}

func assignmentHealth(ctx context.Context, uid string) error {
	return assignmentHealthAt(ctx, uid, pluginHealthSocket)
}

// pluginHealthSocket is where the admission plugin answers GET /healthz.
const pluginHealthSocket = "/run/nri-image-policy/health.sock"

// pluginHealth is the part of the plugin's health body the status service reads.
type pluginHealth struct {
	Status        string `json:"status"`
	PodUID        string `json:"pod_uid"`
	PodRegistered bool   `json:"pod_registered"`
	PodEnded      bool   `json:"pod_ended"`
}

func readPluginHealth(ctx context.Context, socket string) (pluginHealth, int, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/healthz", nil)
	if err != nil {
		return pluginHealth{}, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return pluginHealth{}, 0, err
	}
	defer resp.Body.Close()
	var health pluginHealth
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&health); err != nil {
		return pluginHealth{}, resp.StatusCode, err
	}
	return health, resp.StatusCode, nil
}

// podIdentityEnded reports whether the plugin ended the pod identity for this
// boot. A plugin that cannot be reached is an error: the kubelet's status alone
// cannot stand for a pod whose admission is gone.
func podIdentityEnded(ctx context.Context) (bool, error) {
	return podIdentityEndedAt(ctx, pluginHealthSocket)
}

func podIdentityEndedAt(ctx context.Context, socket string) (bool, error) {
	health, _, err := readPluginHealth(ctx, socket)
	if err != nil {
		return false, err
	}
	return health.PodEnded, nil
}

func assignmentHealthAt(ctx context.Context, uid, socket string) error {
	health, code, err := readPluginHealth(ctx, socket)
	if err != nil {
		return err
	}
	if health.PodEnded {
		return errPodIdentityEnded
	}
	// Registration installs the floor before CDS's first pull (503). Waiting
	// for the pull would make the assignment depend on it.
	if (code != http.StatusOK && code != http.StatusServiceUnavailable) || !health.PodRegistered || health.PodUID != uid {
		return errors.New("pod admission has not installed the expected assignment")
	}
	return nil
}
