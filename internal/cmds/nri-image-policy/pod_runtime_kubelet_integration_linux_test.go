//go:build linux && pod_runtime_integration

package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	containerdclient "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Kubelet is the real pinned release binary and owns the static Pod throughout.
// This complements the CRI recovery lane: its /pods result must retain both
// actual tasks after kubelet, containerd and the full plugin process restart.
func TestPodRuntimeKubeletRecoveryIntegration(t *testing.T) {
	requireRuntimeRecoveryIsolation(t)
	var app, mesh runtimeFixture
	readRuntimeJSON(t, "/validation/fixture.json", &app)
	readRuntimeJSON(t, "/validation/mesh-fixture.json", &mesh)
	var inputs struct {
		RunID string `json:"runId"`
	}
	readRuntimeJSON(t, "/validation/inputs.json", &inputs)
	if inputs.RunID == "" {
		t.Fatal("missing runtime invocation identity")
	}
	ctx, cancel := context.WithTimeout(namespaces.WithNamespace(t.Context(), "k8s.io"), 150*time.Second)
	defer cancel()
	cfg := recoveryRuntimeConfig(t, app, mesh)
	cfg.Pod.Name = "runtime-recovery-guest"
	cfg.Policy.BootMarkerPath = filepath.Join(recoveryRuntimeDir, "kubelet-registered")
	mountPodTestRAM(t, cfg.WorkloadClaims.SocketDir)
	seed := runtimemeasure.Seed([]byte("runtime recovery launch key fixture"))
	if err := os.WriteFile(filepath.Join(recoveryRuntimeDir, "register"), seed[:], 0600); err != nil {
		t.Fatal(err)
	}
	configureRecoveryCDS(t, cfg)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	configBytes, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(DefaultConfigPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	manifests := filepath.Join(recoveryRuntimeDir, "static-pods")
	if err := os.MkdirAll(manifests, 0700); err != nil {
		t.Fatal(err)
	}
	var kubeletConfig map[string]any
	if err := yaml.Unmarshal(readRecoveryFile(t, "/validation/kubelet-base.yaml"), &kubeletConfig); err != nil {
		t.Fatal(err)
	}
	kubeletConfig["staticPodPath"] = manifests
	kubeletConfig["containerRuntimeEndpoint"] = "unix://" + recoveryRuntimeSocket
	kubeletConfig["cgroupDriver"] = "cgroupfs"
	kubeletConfig["cgroupsPerQOS"] = false
	kubeletConfig["enforceNodeAllocatable"] = []string{}
	kubeletConfig["resolvConf"] = "/etc/resolv.conf"
	kubeletConfig["fileCheckFrequency"] = "1s"
	kubeletConfig["syncFrequency"] = "1s"
	kubeletBytes, err := yaml.Marshal(kubeletConfig)
	if err != nil {
		t.Fatal(err)
	}
	kubeletPath := filepath.Join(recoveryRuntimeDir, "kubelet.yaml")
	if err := os.WriteFile(kubeletPath, kubeletBytes, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := kubeletRecoveryManifest(app, mesh)
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifests, "pod.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	daemon := startRecoveryProcess(t, "kubelet-containerd-1", "/validation/runtime/containerd", "--config", "/validation/recovery-containerd.toml")
	waitRecoveryRuntime(t, ctx)
	client, err := containerdclient.New(recoveryRuntimeSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	conn, err := grpc.NewClient("unix://"+recoveryRuntimeSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	runtime := cri.NewRuntimeServiceClient(conn)
	plugin := startRecoveryPlugin(t, "kubelet-plugin-1")
	waitRecoveryPlugin(t, ctx, plugin)
	startKubelet := func(name string) *recoveryProcess {
		return startRecoveryProcess(t, name, "/validation/runtime/kubelet", "--config", kubeletPath, "--hostname-override=guest", "--root-dir=/var/lib/kubelet", "--v=2")
	}
	kubelet := startKubelet("kubelet-1")
	beforePod := waitRecoveryKubeletPod(t, ctx, kubelet, cfg.Pod.Name)
	before := waitRecoveryClaims(t, ctx, 2)
	appID := strings.TrimPrefix(beforePod.Status.ContainerStatuses[0].ContainerID, "containerd://")
	meshID := strings.TrimPrefix(beforePod.Status.InitContainerStatuses[0].ContainerID, "containerd://")
	if appID == "" || meshID == "" || appID == meshID {
		t.Fatal("kubelet did not report distinct actual tasks")
	}
	appPID, meshPID := recoveryTaskPID(t, ctx, client, appID), recoveryTaskPID(t, ctx, client, meshID)
	oldKubeletPID, oldPluginPID, oldDaemonPID := kubelet.cmd.Process.Pid, plugin.cmd.Process.Pid, daemon.cmd.Process.Pid
	kubelet.stop(t, false)
	plugin.stop(t, false)
	daemon.stop(t, false)
	journal := readRecoveryFile(t, journalPath(cfg))
	register := readRecoveryFile(t, filepath.Join(recoveryRuntimeDir, "register"))
	daemon = startRecoveryProcess(t, "kubelet-containerd-2", "/validation/runtime/containerd", "--config", "/validation/recovery-containerd.toml")
	waitRecoveryRuntime(t, ctx)
	plugin = startRecoveryPlugin(t, "kubelet-plugin-2")
	waitRecoveryPlugin(t, ctx, plugin)
	kubelet = startKubelet("kubelet-2")
	afterPod := waitRecoveryKubeletPod(t, ctx, kubelet, cfg.Pod.Name)
	after := waitRecoveryClaims(t, ctx, 2)
	if after.Revision < before.Revision {
		t.Fatal("kubelet recovery rewound the admission revision")
	}
	before.Revision = after.Revision
	beforeWire, err := before.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	afterWire, err := after.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeWire, afterWire) || beforePod.UID != afterPod.UID || beforePod.Status.ContainerStatuses[0].ContainerID != afterPod.Status.ContainerStatuses[0].ContainerID || beforePod.Status.InitContainerStatuses[0].ContainerID != afterPod.Status.InitContainerStatuses[0].ContainerID {
		t.Fatal("real kubelet/runtime/plugin restart changed Pod identity or actual tasks")
	}
	if appPID != recoveryTaskPID(t, ctx, client, appID) || meshPID != recoveryTaskPID(t, ctx, client, meshID) {
		t.Fatal("kubelet recovery replaced a running task")
	}
	if !bytes.Equal(journal, readRecoveryFile(t, journalPath(cfg))) || !bytes.Equal(register, readRecoveryFile(t, filepath.Join(recoveryRuntimeDir, "register"))) || !bytes.Equal(configBytes, readRecoveryFile(t, DefaultConfigPath)) || !bytes.Equal(manifestBytes, readRecoveryFile(t, manifestPath)) {
		t.Fatal("kubelet recovery changed assignment or measurement")
	}
	if oldKubeletPID == kubelet.cmd.Process.Pid || oldPluginPID == plugin.cmd.Process.Pid || oldDaemonPID == daemon.cmd.Process.Pid {
		t.Fatal("real runtime service process was not replaced")
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(15 * time.Second)
	for {
		pods, err := runtime.ListPodSandbox(ctx, &cri.ListPodSandboxRequest{Filter: &cri.PodSandboxFilter{State: &cri.PodSandboxStateValue{State: cri.PodSandboxState_SANDBOX_READY}}})
		if err == nil && len(pods.Items) == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("kubelet did not stop its static Pod: %+v %v", pods, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	kubelet.stop(t, false)
	retained, err := runtime.ListPodSandbox(ctx, &cri.ListPodSandboxRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, pod := range retained.Items {
		if _, err := runtime.RemovePodSandbox(ctx, &cri.RemovePodSandboxRequest{PodSandboxId: pod.Id}); err != nil {
			t.Fatal(err)
		}
	}
	remaining, err := runtime.ListPodSandbox(ctx, &cri.ListPodSandboxRequest{})
	if err != nil || len(remaining.Items) != 0 {
		t.Fatalf("kubelet runtime cleanup incomplete: %+v %v", remaining, err)
	}
	plugin.stop(t, false)
	daemon.stop(t, false)
	result := map[string]any{"runId": inputs.RunID, "runtimePodUID": string(afterPod.UID), "credentialInstanceId": after.InstanceID(), "appContainerId": appID, "meshContainerId": meshID, "appPID": appPID, "meshPID": meshPID, "kubeletProcessIds": []int{oldKubeletPID, kubelet.cmd.Process.Pid}, "pluginProcessIds": []int{oldPluginPID, plugin.cmd.Process.Pid}, "containerdProcessIds": []int{oldDaemonPID, daemon.cmd.Process.Pid}, "assignmentPreserved": true, "fullClaimsPreserved": true, "tasksPreserved": true, "kubeletReportedRunning": true, "sandboxCleanup": true, "scope": "actual standalone static Pod kubelet, containerd and full NRI plugin processes; native snapshotter/cgroupfs and digest-pinned release CNI; simulated TEE/CDS transport; no certificate issuance assertion"}
	wire, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/validation/artifacts/kubelet-recovery-result.json", append(wire, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func kubeletRecoveryManifest(app, mesh runtimeFixture) *corev1.Pod {
	no, yes := false, true
	uid, meshUID := int64(workloadclaims.CredentialsUID), int64(workloadclaims.MeshUID)
	grace := int64(1)
	always := corev1.ContainerRestartPolicyAlways
	security := &corev1.SecurityContext{RunAsUser: &uid, RunAsGroup: &uid, AllowPrivilegeEscalation: &no, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
	meshSecurity := security.DeepCopy()
	meshSecurity.RunAsUser = &meshUID
	meshSecurity.RunAsGroup = &meshUID
	return &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Name: "runtime-recovery", Namespace: "validation"}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &no, EnableServiceLinks: &no, TerminationGracePeriodSeconds: &grace, RestartPolicy: corev1.RestartPolicyAlways, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &yes}, Volumes: []corev1.Volume{{Name: podmesh.CertVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}}}, InitContainers: []corev1.Container{{Name: workloadclaims.MeshContainerName, Image: mesh.Reference, ImagePullPolicy: corev1.PullNever, Command: []string{"/marker-workload", "mesh"}, RestartPolicy: &always, SecurityContext: meshSecurity, VolumeMounts: []corev1.VolumeMount{{Name: podmesh.CertVolumeName, MountPath: podmesh.CertDir, ReadOnly: true}}}}, Containers: []corev1.Container{{Name: "app", Image: app.Reference, ImagePullPolicy: corev1.PullNever, Command: []string{"/marker-workload", "live-app"}, SecurityContext: security}}}}
}

func waitRecoveryKubeletPod(t *testing.T, ctx context.Context, process *recoveryProcess, name string) corev1.Pod {
	t.Helper()
	until := time.Now().Add(35 * time.Second)
	for {
		select {
		case err := <-process.done:
			process.stopped = true
			t.Fatalf("real kubelet exited: %v", err)
		default:
		}
		// Pin the actual kubelet's self-signed serving certificate. The private
		// runner owns both the file and loopback listener; no verification bypass.
		pem, err := os.ReadFile("/var/lib/kubelet/pki/kubelet.crt")
		if err == nil {
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				t.Fatal("invalid real kubelet certificate")
			}
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "guest", MinVersion: tls.VersionTLS12}}
			client := &http.Client{Transport: transport, Timeout: time.Second}
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:10250/pods", nil)
			response, requestErr := client.Do(request)
			if requestErr == nil {
				var pods corev1.PodList
				decode := json.NewDecoder(response.Body).Decode(&pods)
				_ = response.Body.Close()
				if decode == nil && response.StatusCode == http.StatusOK {
					for _, pod := range pods.Items {
						if pod.Name == name && pod.Status.Phase == corev1.PodRunning && len(pod.Status.ContainerStatuses) == 1 && len(pod.Status.InitContainerStatuses) == 1 && pod.Status.ContainerStatuses[0].State.Running != nil && pod.Status.InitContainerStatuses[0].State.Running != nil {
							transport.CloseIdleConnections()
							return pod
						}
					}
				}
			}
			transport.CloseIdleConnections()
			err = requestErr
		}
		if time.Now().After(until) || ctx.Err() != nil {
			if err == nil {
				err = errors.New("kubelet has not reported its running static Pod")
			}
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
