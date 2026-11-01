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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// Only unavailable observations may be retried after restarting the empty runtime.
var errAssignmentRuntimeUnavailable = errors.New("assignment runtime observation unavailable")

type guestAssignmentRuntime struct {
	journal string
	pods    func(context.Context) ([]byte, error)
}

// available makes no mutations. An empty journal is insufficient by itself:
// pause sandboxes are not workload measurements, so check CRI and kubelet too.
func (g guestAssignmentRuntime) available(ctx context.Context) error {
	if err := g.empty(ctx); err != nil {
		return err
	}
	return assignmentHealth(ctx, "")
}

func (g guestAssignmentRuntime) empty(ctx context.Context) error {
	digests, err := armtls.ReadRuntimeExtensions(g.journal)
	if err != nil {
		return err
	}
	if len(digests) != 0 {
		return errors.New("unassigned guest has measured containers")
	}
	body, err := g.pods(ctx)
	if err != nil {
		return fmt.Errorf("%w: kubelet: %w", errAssignmentRuntimeUnavailable, err)
	}
	var pods corev1.PodList
	if err := json.Unmarshal(body, &pods); err != nil {
		return err
	}
	if pods.Kind != "PodList" || len(pods.Items) != 0 {
		return errors.New("unassigned kubelet is not empty")
	}
	return emptyAssignmentCRI(ctx)
}

func emptyAssignmentCRI(ctx context.Context) error {
	return emptyAssignmentCRIAt(ctx, "/run/k3s/containerd/containerd.sock")
}

func emptyAssignmentCRIAt(ctx context.Context, socket string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// The fixed guest-local Unix socket is root-owned; no network transport.
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := cri.NewRuntimeServiceClient(conn)
	pods, err := client.ListPodSandbox(ctx, &cri.ListPodSandboxRequest{})
	if err != nil {
		return fmt.Errorf("%w: CRI sandboxes: %w", errAssignmentRuntimeUnavailable, err)
	}
	if len(pods.Items) != 0 {
		return errors.New("unassigned runtime is not empty")
	}
	containers, err := client.ListContainers(ctx, &cri.ListContainersRequest{})
	if err != nil {
		return fmt.Errorf("%w: CRI containers: %w", errAssignmentRuntimeUnavailable, err)
	}
	if len(containers.Containers) != 0 {
		return errors.New("unassigned runtime is not empty")
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
	return installAssignment(ctx, runtime, manifests, policy, g.empty, restartAssignmentRuntime, assignmentHealth)
}

// installAssignment is restartable at every boundary. An already published
// manifest is immutable; neither its runtime nor its journal is reset.
func installAssignment(ctx context.Context, runtime nodeservices.PodRuntime, manifests, policy *os.Root, empty, restart func(context.Context) error, health func(context.Context, string) error) error {
	if runtime.UID == "" || len(runtime.Policy) == 0 || len(runtime.Manifest) == 0 {
		return errors.New("incomplete assigned runtime")
	}
	if installed, err := assignmentInstalled(manifests, policy, runtime); err != nil || installed {
		return err
	}
	if err := empty(ctx); err != nil {
		return err
	}
	if err := fileutil.WriteAtomicRoot(policy, "image-policy.yaml", runtime.Policy, 0600); err != nil {
		return err
	}
	if err := restart(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := health(ctx, runtime.UID); err == nil {
			// Type=simple kubelet can still be starting after systemctl returns.
			if err := empty(ctx); err == nil {
				break
			} else if !errors.Is(err, errAssignmentRuntimeUnavailable) {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	if installed, err := assignmentInstalled(manifests, policy, runtime); err != nil || installed {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The service lifetime lock excludes another installer. The manifest is last:
	// kubelet cannot run a Pod with the old waiting policy or an unready plugin.
	return fileutil.WriteAtomicRoot(manifests, "pod.yaml", runtime.Manifest, 0600)
}

func assignmentInstalled(manifests, policy *os.Root, runtime nodeservices.PodRuntime) (bool, error) {
	data, err := readAssignmentOutput(manifests, "pod.yaml")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(data, runtime.Manifest) {
		return false, errors.New("refusing to replace an assigned manifest")
	}
	data, err = readAssignmentOutput(policy, "image-policy.yaml")
	if err != nil {
		return false, err
	}
	if !bytes.Equal(data, runtime.Policy) {
		return false, errors.New("assigned runtime policy differs from its immutable assignment")
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

func restartAssignmentRuntime(ctx context.Context) error {
	// Restart both: containerd is a kubelet Requires dependency, so restarting
	// only containerd may leave kubelet stopped. No request bytes become arguments.
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", "podcvm-containerd.service", "podcvm-kubelet.service").Run(); err != nil {
		return fmt.Errorf("restart empty Pod runtime: %w", err)
	}
	return nil
}

func assignmentHealth(ctx context.Context, uid string) error {
	return assignmentHealthAt(ctx, uid, "/run/nri-image-policy/health.sock")
}

func assignmentHealthAt(ctx context.Context, uid, socket string) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var health struct {
		Status        string `json:"status"`
		PodUID        string `json:"pod_uid"`
		PodWaiting    bool   `json:"pod_waiting"`
		PodRegistered bool   `json:"pod_registered"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&health); err != nil {
		return err
	}
	// Registration installs the base and waiting guard before CDS's first pull.
	// Waiting for the pull would incorrectly make generic assignment depend on it.
	if (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable) || !health.PodRegistered || health.PodUID != uid || health.PodWaiting != (uid == "") {
		return errors.New("pod admission has not installed the expected assignment")
	}
	return nil
}
