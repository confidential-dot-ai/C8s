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
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type guestReader func(context.Context, *record, string) (podstatus.PodProjection, error)

func readGuest(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
	var projection podstatus.PodProjection
	// AttestConfig's existing API takes paths. Use only frozen public trust
	// material here, in a private temporary directory, never a tenant path.
	dir, err := os.MkdirTemp("", "c8s-pod-status-")
	if err != nil {
		return projection, err
	}
	defer os.RemoveAll(dir)
	key, manifest := filepath.Join(dir, "pubkey"), filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(key, []byte(rec.Request.Trust.LaunchKey), 0o600); err != nil {
		return projection, err
	}
	if err := os.WriteFile(manifest, rec.Manifest, 0o600); err != nil {
		return projection, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	data, err := podstatus.Get(ctx, podstatus.AttestConfig{Node: address, LaunchKeyPubPath: key, ImageManifestPath: manifest, Timeout: 15 * time.Second})
	if err != nil {
		return projection, errors.New("guest status attestation unavailable")
	}
	if err := decode(data, &projection); err != nil {
		return projection, errors.New("guest status projection is invalid")
	}
	return projection, nil
}

func validateInstance(rec *record, in *instance) error {
	if in == nil || !strings.HasPrefix(in.ID, "i-") || len(validation.IsDNS1123Label(in.ID)) != 0 {
		return errors.New("cloud returned an invalid instance identity")
	}
	if rec.InstanceID != "" && rec.InstanceID != in.ID {
		return errors.New("cloud returned another instance")
	}
	family, version, _ := strings.Cut(rec.Request.Image, "@")
	if in.Image.Family != family || in.Image.Version != version || in.Tee != rec.Request.Tee {
		return errors.New("cloud instance differs from the frozen image request")
	}
	if in.Compute.VCPUs < rec.VCPUs || in.Compute.MemoryGiB < (rec.MemoryMiB+1023)/1024 {
		return errors.New("cloud instance is smaller than the advertised workload capacity")
	}
	for k, v := range rec.Request.Labels {
		if in.Labels[k] != v {
			return errors.New("cloud instance ownership differs from its create intent")
		}
	}
	return nil
}

func endpoints(rec *record, in *instance) (string, []endpoint, string, error) {
	if err := validateInstance(rec, in); err != nil {
		return "", nil, "", err
	}
	wanted := make(map[string]int, len(rec.Request.Network.Ingress))
	for _, rule := range rec.Request.Network.Ingress {
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
		if rec.Request.Network.PublicIP == "dedicated" {
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

func projectedStatus(rec *record, projection podstatus.PodProjection, pod *corev1.Pod, podIP string) (corev1.PodStatus, error) {
	var out corev1.PodStatus
	doc, err := rec.document()
	if err != nil {
		return out, err
	}
	meta := projection.Metadata
	if meta.UID != string(rec.UID) || meta.Namespace != rec.Namespace || meta.Name != rec.Name+"-"+doc.Node.Name {
		return out, errors.New("attested guest status names another Pod")
	}
	guest, err := launchconfig.ParsePodManifest([]byte(doc.Pod.Manifest))
	if err != nil {
		return out, err
	}
	if projection.Status.Phase != corev1.PodPending && projection.Status.Phase != corev1.PodRunning && projection.Status.Phase != corev1.PodSucceeded && projection.Status.Phase != corev1.PodFailed && projection.Status.Phase != corev1.PodUnknown {
		return out, errors.New("guest reported an invalid Pod phase")
	}
	// Decode only the dedicated projection, not an arbitrary guest Pod object.
	b, err := json.Marshal(projection.Status)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, err
	}
	out.ContainerStatuses, err = filterStatuses(out.ContainerStatuses, guest.Spec.Containers, false)
	if err != nil {
		return out, err
	}
	out.InitContainerStatuses, err = filterStatuses(out.InitContainerStatuses, guest.Spec.InitContainers, true)
	if err != nil {
		return out, err
	}
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
	seen := map[corev1.PodConditionType]bool{}
	for _, c := range out.Conditions {
		if c.Type == corev1.PodScheduled {
			continue
		}
		if seen[c.Type] || (c.Status != corev1.ConditionTrue && c.Status != corev1.ConditionFalse && c.Status != corev1.ConditionUnknown) {
			return out, errors.New("guest status contains invalid conditions")
		}
		seen[c.Type] = true
		conditions = append(conditions, c)
	}
	out.Conditions = conditions
	return out, nil
}

func filterStatuses(statuses []corev1.ContainerStatus, containers []corev1.Container, mesh bool) ([]corev1.ContainerStatus, error) {
	images := map[string]string{}
	for _, c := range containers {
		images[c.Name] = c.Image
	}
	seen := map[string]bool{}
	var out []corev1.ContainerStatus
	for _, s := range statuses {
		if seen[s.Name] {
			return nil, errors.New("guest status repeats a container")
		}
		seen[s.Name] = true
		if mesh && s.Name == workloadclaims.MeshContainerName {
			continue
		}
		image, ok := images[s.Name]
		if !ok {
			return nil, errors.New("guest status contains an unknown workload container")
		}
		s.Image = image
		out = append(out, s)
	}
	return out, nil
}

func unknownStatus(pod *corev1.Pod, reason string, now time.Time) corev1.PodStatus {
	out := *pod.Status.DeepCopy()
	if out.Phase == "" {
		out.Phase = corev1.PodPending
	}
	out.Reason = reason
	out.Message = "Waiting for verified Pod CVM status"
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
	out.Message = "The Pod CVM has ended; a new Pod UID is required for a new launch"
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
