package podprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type guestReader func(context.Context, *record, string) (podstatus.PodProjection, error)

// attestConfig writes the frozen public trust material of one allocation to a
// private temporary directory, because podstatus.AttestConfig takes paths. The
// caller removes the directory when the connection is done.
func attestConfig(address, launchKey string, manifest []byte) (podstatus.AttestConfig, func(), error) {
	dir, err := os.MkdirTemp("", "c8s-pod-trust-")
	if err != nil {
		return podstatus.AttestConfig{}, nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	key, man := filepath.Join(dir, "pubkey"), filepath.Join(dir, "manifest.json")
	if err := errors.Join(os.WriteFile(key, []byte(launchKey), 0o600), os.WriteFile(man, manifest, 0o600)); err != nil {
		cleanup()
		return podstatus.AttestConfig{}, nil, err
	}
	return podstatus.AttestConfig{Node: address, LaunchKeyPubPath: key, ImageManifestPath: man, Timeout: 15 * time.Second}, cleanup, nil
}

func readGuest(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
	var projection podstatus.PodProjection
	cfg, cleanup, err := attestConfig(address, rec.Request.Trust.LaunchKey, rec.Manifest)
	if err != nil {
		return projection, err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	data, err := podstatus.Get(ctx, cfg)
	if err != nil {
		return projection, errors.New("guest status attestation unavailable")
	}
	if err := decode(data, &projection); err != nil {
		return projection, errors.New("guest status projection is invalid")
	}
	return projection, nil
}

// validateInstance checks that the instance the cloud returned is the one the
// intent created: its identity, labels, image, platform and size.
func validateInstance(intent *instanceIntent, in *instance) error {
	if in == nil || in.ID == "" {
		return errors.New("cloud returned no instance identity")
	}
	if intent.InstanceID != "" && intent.InstanceID != in.ID {
		return errors.New("cloud returned another instance")
	}
	family, version, _ := strings.Cut(intent.Request.Image, "@")
	if in.Image.Family != family || in.Image.Version != version || in.Tee != intent.Request.Tee {
		return errors.New("cloud instance differs from the frozen image request")
	}
	if in.Compute.VCPUs < intent.VCPUs || in.Compute.MemoryGiB < (intent.MemoryMiB+1023)/1024 {
		return errors.New("cloud instance is smaller than the advertised workload capacity")
	}
	for k, v := range intent.Request.Labels {
		if in.Labels[k] != v {
			return errors.New("cloud instance ownership differs from its create intent")
		}
	}
	return nil
}

// endpoints resolves the status address, the application endpoints and, under
// the dedicated address mode, the pod address from the instance's public
// endpoints, one per rule the network spec wanted.
func endpoints(network networkSpec, in *instance) (string, []endpoint, string, error) {
	wanted := make(map[string]int, len(network.Ingress))
	for _, rule := range network.Ingress {
		wanted[rule.Name] = rule.Port
	}
	seen := map[string]bool{}
	var status, podIP string
	var apps []endpoint
	for _, ep := range in.Endpoints {
		port, ok := wanted[ep.Name]
		if !ok {
			continue
		}
		ip, err := netip.ParseAddr(ep.Host)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ep.Port < 1 || ep.Port > 65535 || seen[ep.Name] {
			return "", nil, "", errors.New("cloud returned an invalid or duplicate public endpoint")
		}
		seen[ep.Name] = true
		if network.PublicIP == "dedicated" {
			if ep.Port != port || (podIP != "" && podIP != ep.Host) {
				return "", nil, "", errors.New("dedicated endpoints do not preserve the Pod address and ports")
			}
			podIP = ep.Host
		}
		if ep.Name == "pod-status" {
			status = net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
		} else {
			apps = append(apps, ep)
		}
	}
	if status == "" || len(seen) != len(wanted) {
		return "", nil, "", errors.New("waiting for all Cloud Pod endpoints")
	}
	return status, apps, podIP, nil
}

// projectedStatus accepts a guest report only for the frozen pod, named as the
// guest's kubelet reports a static pod on the node the allocation booted as,
// and projects the guest's fields onto a pod status.
func projectedStatus(rec *record, projection podstatus.PodProjection, pod *corev1.Pod, podIP, guestNode string) (corev1.PodStatus, error) {
	var out corev1.PodStatus
	doc, err := rec.document()
	if err != nil {
		return out, err
	}
	meta := projection.Metadata
	if meta.UID != string(rec.UID) || meta.Namespace != rec.Namespace || meta.Name != rec.Name+"-"+guestNode {
		return out, errors.New("attested guest status names another Pod")
	}
	guest, err := launchconfig.ParsePodManifest([]byte(doc.Pod.Manifest))
	if err != nil {
		return out, err
	}
	// Decode only the dedicated projection, not an arbitrary guest Pod object.
	b, err := json.Marshal(projection.Status)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, err
	}
	out.ContainerStatuses = filterStatuses(out.ContainerStatuses, guest.Spec.Containers, false)
	out.InitContainerStatuses = filterStatuses(out.InitContainerStatuses, guest.Spec.InitContainers, true)
	out.PodIP = podIP
	if podIP != "" {
		out.PodIPs = []corev1.PodIP{{IP: podIP}}
	}
	conditions := []corev1.PodCondition{}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled {
			conditions = append(conditions, c)
		}
	}
	for _, c := range out.Conditions {
		if c.Type != corev1.PodScheduled {
			conditions = append(conditions, c)
		}
	}
	out.Conditions = conditions
	return out, nil
}

// filterStatuses omits the guest's mesh endpoint container and names each
// container's image from the frozen pod rather than from the guest.
func filterStatuses(statuses []corev1.ContainerStatus, containers []corev1.Container, mesh bool) []corev1.ContainerStatus {
	images := map[string]string{}
	for _, c := range containers {
		images[c.Name] = c.Image
	}
	var out []corev1.ContainerStatus
	for _, s := range statuses {
		if mesh && s.Name == workloadclaims.MeshContainerName {
			continue
		}
		if image, ok := images[s.Name]; ok {
			s.Image = image
		}
		out = append(out, s)
	}
	return out
}

func unknownStatus(pod *corev1.Pod, reason string, now time.Time) corev1.PodStatus {
	out := *pod.Status.DeepCopy()
	if out.Phase == "" {
		out.Phase = corev1.PodPending
	}
	out.Reason = reason
	for _, t := range []corev1.PodConditionType{corev1.PodReady, corev1.ContainersReady} {
		condition := corev1.PodCondition{Type: t, Status: corev1.ConditionUnknown, Reason: reason, LastTransitionTime: metav1.NewTime(now)}
		found := false
		for i := range out.Conditions {
			if out.Conditions[i].Type == t {
				if out.Conditions[i].Status == condition.Status {
					condition.LastTransitionTime = out.Conditions[i].LastTransitionTime
				}
				out.Conditions[i] = condition
				found = true
				break
			}
		}
		if !found {
			out.Conditions = append(out.Conditions, condition)
		}
	}
	for i := range out.ContainerStatuses {
		out.ContainerStatuses[i].Ready = false
	}
	for i := range out.InitContainerStatuses {
		out.InitContainerStatuses[i].Ready = false
	}
	return out
}

func failedStatus(pod *corev1.Pod, reason string, now time.Time) corev1.PodStatus {
	out := unknownStatus(pod, reason, now)
	out.Phase = corev1.PodFailed
	for i := range out.Conditions {
		if out.Conditions[i].Type == corev1.PodReady || out.Conditions[i].Type == corev1.ContainersReady {
			out.Conditions[i].Status = corev1.ConditionFalse
		}
	}
	return out
}

func endpointJSON(apps []endpoint) (string, error) {
	b, err := json.Marshal(apps)
	if err != nil {
		return "", fmt.Errorf("encode Pod endpoints: %w", err)
	}
	return string(b), nil
}
