//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// runHostSweep removes the host artifacts from every Linux node after the
// release is gone: a short-lived privileged DaemonSet runs host-sweep.sh as an
// init container on each node. The CLI waits for it to complete everywhere
// (rollout status blocks until every pod has passed init), then deletes it.
func runHostSweep(ctx context.Context, namespace, release string, cfg hostUninstallConfig) error {
	// The mesh re-asserts its base-chain iptables jumps on a
	// watchdog, so sweeping while a mesh pod still runs leaks the rules the
	// sweep just deleted (helm --wait=false leaves pods terminating).
	meshSelector := fmt.Sprintf("app.kubernetes.io/instance=%s,app.kubernetes.io/name=armtls-mesh", release)
	if err := waitPodsGone(ctx, namespace, meshSelector); err != nil {
		return fmt.Errorf("waiting for armtls-mesh pods to terminate: %w", err)
	}

	// The sweep pods are privileged; re-assert the namespace's privileged
	// pod-security labels (idempotent — the install already set them, but on
	// the --host-sweep-only path the namespace may have been deleted).
	if err := applyNamespace(ctx, namespace); err != nil {
		return err
	}

	manifest, err := json.Marshal(hostSweepDaemonSet(release, namespace, cfg))
	if err != nil {
		return fmt.Errorf("render sweep manifest: %w", err)
	}
	name := hostSweepName(release)
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # DaemonSet/%s (host sweep)\n", name)
	kc := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	kc.Stdin = bytes.NewReader(manifest)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl apply sweep DaemonSet: %w", err)
	}

	if err := kubectlRun(ctx, "rollout", "status", "daemonset/"+name,
		"-n", namespace, "--timeout=5m"); err != nil {
		// Leave the DaemonSet in place: its sweep container logs are the
		// only record of which node failed and why.
		return hostSweepError(ctx, namespace, release, cfg, err)
	}

	return kubectlRun(ctx, "delete", "daemonset", name, "-n", namespace, "--ignore-not-found")
}

func hostSweepName(release string) string {
	return release + "-host-sweep"
}

const (
	hostSweepComponent = "host-sweep"
	sweepContainerName = "sweep"
)

func hostSweepSelector(release string) string {
	return fmt.Sprintf("app.kubernetes.io/instance=%s,app.kubernetes.io/component=%s", release, hostSweepComponent)
}

type unfinishedSweep struct {
	// report is "<node or pod>: <what its sweep came to>".
	report string
	// needsNodeRemoval is set where the kubelet started no sweep container.
	needsNodeRemoval bool
}

// hostSweepError names, per node, the state of a sweep the rollout wait gave up on.
func hostSweepError(ctx context.Context, namespace, release string, cfg hostUninstallConfig, cause error) error {
	inspect := sweepInspectSteps(namespace, release)
	pods, err := sweepPods(ctx, namespace, release)
	if err != nil {
		return fmt.Errorf("host sweep did not complete: %w\nreading its pods failed too: %w\n%s", cause, err, inspect)
	}
	report := append(unfinishedSweepReport(pods, cfg), inspect)
	return fmt.Errorf("host sweep did not complete: %w\n%s", cause, strings.Join(report, "\n"))
}

// One line per node whose sweep did not finish, plus the node-level removal
// where a kubelet started none.
func unfinishedSweepReport(pods []corev1.Pod, cfg hostUninstallConfig) []string {
	if len(pods) == 0 {
		return []string{"  the sweep DaemonSet has no pod on any node", nodeRemovalSteps(cfg)}
	}
	var report []string
	nodeRemoval := false
	for _, sweep := range unfinishedSweeps(pods) {
		report = append(report, "  "+sweep.report)
		nodeRemoval = nodeRemoval || sweep.needsNodeRemoval
	}
	if nodeRemoval {
		report = append(report, nodeRemovalSteps(cfg))
	}
	return report
}

func sweepInspectSteps(namespace, release string) string {
	name := hostSweepName(release)
	return fmt.Sprintf("inspect it with 'kubectl -n %s describe pod -l %s' and 'kubectl -n %s logs ds/%s -c %s', then remove it with 'kubectl -n %s delete ds %s'",
		namespace, hostSweepSelector(release), namespace, name, sweepContainerName, namespace, name)
}

func nodeRemovalSteps(cfg hostUninstallConfig) string {
	return fmt.Sprintf("A node whose kubelet starts no sweep container keeps enforcing until the plugin comes off it on the node itself: in %s/config.toml delete the c8s-nri-image-policy managed block and the c8s-nri-image-policy prefix of the lines that carry one, delete %s, and run '%s'; or delete the node's VM and let its pool replace it. Then re-run c8s uninstall",
		cfg.ContainerdConfigDir,
		path.Join(cfg.NriPluginDir, cfg.NriPluginFilename),
		cfg.RestartCommand)
}

func sweepPods(ctx context.Context, namespace, release string) ([]corev1.Pod, error) {
	selector := hostSweepSelector(release)
	out, err := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", namespace, "-l", selector, "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get pods -n %s -l %s: %w", namespace, selector, withStderr(err))
	}
	var list corev1.PodList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse the sweep pods: %w", err)
	}
	return list.Items, nil
}

func unfinishedSweeps(pods []corev1.Pod) []unfinishedSweep {
	var unfinished []unfinishedSweep
	for _, pod := range pods {
		if sweep, ok := unfinishedSweepOf(pod); ok {
			unfinished = append(unfinished, sweep)
		}
	}
	slices.SortFunc(unfinished, func(a, b unfinishedSweep) int { return strings.Compare(a.report, b.report) })
	return unfinished
}

// ok=false for a sweep that exited successfully.
func unfinishedSweepOf(pod corev1.Pod) (unfinishedSweep, bool) {
	subject := pod.Spec.NodeName
	if subject == "" {
		subject = "pod " + pod.Name
	}
	state := sweepContainerState(pod)
	var came string
	switch {
	case state.Terminated != nil:
		if state.Terminated.ExitCode == 0 {
			return unfinishedSweep{}, false
		}
		came = fmt.Sprintf("the sweep exited %d (%s)", state.Terminated.ExitCode, state.Terminated.Reason)
	case state.Running != nil:
		came = "the sweep is still running"
	case state.Waiting != nil:
		came = "the kubelet has not started the sweep: " + waitingState(*state.Waiting)
	default:
		came = fmt.Sprintf("the kubelet reports no sweep container (the pod is %s)", pod.Status.Phase)
	}
	return unfinishedSweep{
		report:           subject + ": " + came,
		needsNodeRemoval: state.Running == nil && state.Terminated == nil,
	}, true
}

// sweepContainerState is the zero state where the kubelet reports no sweep container.
func sweepContainerState(pod corev1.Pod) corev1.ContainerState {
	for _, status := range pod.Status.InitContainerStatuses {
		if status.Name == sweepContainerName {
			return status.State
		}
	}
	return corev1.ContainerState{}
}

// A container the node's image policy refused carries the refusal in its message.
func waitingState(waiting corev1.ContainerStateWaiting) string {
	if waiting.Message == "" {
		return waiting.Reason
	}
	return waiting.Reason + ": " + waiting.Message
}

// hostSweepDaemonSet renders the sweep DaemonSet: every linux node (a node can
// carry the leftovers of an earlier install's shapes, or have lost the label
// that marks it confidential), tolerating all taints, with host-sweep.sh as
// an init container and a pause container whose readiness lets `kubectl
// rollout status` double as "every node finished sweeping".
func hostSweepDaemonSet(release, namespace string, cfg hostUninstallConfig) *appsv1.DaemonSet {
	labels := map[string]string{
		"app.kubernetes.io/name":      "c8s-operator",
		"app.kubernetes.io/instance":  release,
		"app.kubernetes.io/component": hostSweepComponent,
	}
	nodeSelector := map[string]string{linuxNodeLabel: linuxNodeValue}
	privileged := true
	pullSecrets := make([]corev1.LocalObjectReference, 0, len(cfg.ImagePullSecretRef))
	for _, n := range cfg.ImagePullSecretRef {
		pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: n})
	}
	return &appsv1.DaemonSet{
		APIVersion: "apps/v1", Kind: "DaemonSet",
		Name:      hostSweepName(release),
		Namespace: namespace,
		Labels:    labels,
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					// hostPID: the sweep nsenters into PID 1 for host binaries
					// (systemctl, iptables, losetup) and the runtime restart.
					HostPID: true,
					// On the node's network the sandbox needs no CNI address.
					HostNetwork:  true,
					NodeSelector: nodeSelector,
					// The install's pull secret, so the sweep image pulls on
					// private-mirror clusters too (chart-wide values).
					ImagePullSecrets: pullSecrets,
					// Sweep control-plane and otherwise-tainted nodes too.
					Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					InitContainers: []corev1.Container{{
						Name:            sweepContainerName,
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         cfg.SweepArgv,
						Env: []corev1.EnvVar{
							{Name: "HOST_CONTAINERD_DIR", Value: cfg.ContainerdConfigDir},
							{Name: "RESTART_COMMAND", Value: cfg.RestartCommand},
							{Name: "NRI_PLUGIN_DIR", Value: cfg.NriPluginDir},
							// Read by the sweeps earlier charts pinned.
							{Name: "NRI_PLUGIN_FILENAME", Value: cfg.NriPluginFilename},
							{Name: "NRI_CONFIG_DIR", Value: cfg.NriConfigDir},
							{Name: "NRI_RUNTIME_DIR", Value: cfg.NriRuntimeDir},
							{Name: "NRI_CACHE_DIR", Value: cfg.NriCacheDir},
						},
						// Removing a runtime from a host requires privileges
						// and the host root mounted.
						SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
						VolumeMounts:    []corev1.VolumeMount{{Name: "host", MountPath: "/host"}},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
					}},
					Containers: []corev1.Container{{
						Name:            "pause",
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						// The pod lives only until the CLI's rollout-status
						// wait returns anyway.
						Command: cfg.PauseArgv,
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("10m"),
								corev1.ResourceMemory: resource.MustParse("16Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
						},
					}},
					Volumes: []corev1.Volume{{
						Name:     "host",
						HostPath: &corev1.HostPathVolumeSource{Path: "/"},
					}},
				},
			},
		},
	}
}
