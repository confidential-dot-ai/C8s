package podprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type guestReader func(context.Context, *record, string) (podstatus.PodProjection, error)

// maxGuestBody bounds one pod status projection.
const maxGuestBody = 4 << 20

// attest is the fresh attestation of a guest; a seam for tests.
var attest = podstatus.Attest

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

// readGuest attests the instance with the record's frozen launch key and
// manifest, then reads the pod status only from the serving key the
// assignment was signed over: every guest launched from the same document
// passes the attestation, the key tells this pod's guest from another. No
// certificate matches an empty key.
func readGuest(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
	var projection podstatus.PodProjection
	cfg, cleanup, err := attestConfig(address, rec.Request.Trust.LaunchKey, rec.Manifest)
	if err != nil {
		return projection, err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, client, err := attest(ctx, cfg)
	if err != nil {
		return projection, guestFailure(ctx, "guest status attestation unavailable", err)
	}
	defer client.CloseIdleConnections()
	if client, err = pinServingKey(client, rec.ServingKey); err != nil {
		return projection, err
	}
	defer client.CloseIdleConnections()
	data, err := get(ctx, client, "https://"+address+podstatus.PodPath)
	if err != nil {
		return projection, guestFailure(ctx, "guest status unavailable", err)
	}
	if err := decode(data, &projection); err != nil {
		return projection, errors.New("guest status projection is invalid")
	}
	return projection, nil
}

// errNoServingKey withholds a status read until an assignment saved the key.
var errNoServingKey = errors.New("no serving key is saved for the Pod CVM")

// guestStatus reads status only from the serving key saved with the
// assignment, whichever reader is installed.
func (r *Reconciler) guestStatus(ctx context.Context, rec *record, address string) (podstatus.PodProjection, error) {
	if len(rec.ServingKey) == 0 {
		return podstatus.PodProjection{}, errNoServingKey
	}
	return r.guest(ctx, rec, address)
}

// guestFailure logs the detail of a failed guest exchange and returns only
// msg, which reaches the Pod's status path without endpoint or trust details.
func guestFailure(ctx context.Context, msg string, err error) error {
	log.FromContext(ctx).Info(msg, "cause", err.Error())
	return errors.New(msg)
}

// pinServingKey returns a client that accepts only connections served with
// the SPKI want, before the checks the attested client already makes.
func pinServingKey(client *http.Client, want []byte) (*http.Client, error) {
	base, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("attested client has no TLS transport")
	}
	tr := base.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	verify := tr.TLSClientConfig.VerifyConnection
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := servingKeyIs(cs, want); err != nil {
			return err
		}
		if verify != nil {
			return verify(cs)
		}
		return nil
	}
	return &http.Client{Timeout: client.Timeout, CheckRedirect: client.CheckRedirect, Transport: tr}, nil
}

func servingKeyIs(cs tls.ConnectionState, want []byte) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("guest presented no certificate")
	}
	got, err := x509.MarshalPKIXPublicKey(cs.PeerCertificates[0].PublicKey)
	if err != nil || !bytes.Equal(got, want) {
		return errors.New("guest serving key differs from the assigned one")
	}
	return nil
}

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxGuestBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guest returned HTTP %d", resp.StatusCode)
	}
	return data, nil
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
		// A peer's endpoint dials this public port through its mesh endpoint,
		// which refuses the mesh control ports before any handshake. The cloud
		// chooses the port, so one it allocates there is refused, never published.
		if workloadclaims.IsMeshPort(ep.Port) {
			return "", nil, "", errors.New("cloud allocated a public endpoint on a mesh control port")
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
	meta := projection.Metadata
	if meta.UID != string(rec.UID) || meta.Namespace != rec.Namespace || meta.Name != rec.Name+"-"+guestNode {
		return out, errors.New("attested guest status names another Pod")
	}
	guest, err := podlaunch.ParsePodManifest(rec.Pod)
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
	// The projection carries no reason. A failed phase no container
	// termination explains is the guest's ended pod identity; the provider
	// names it.
	if out.Phase == corev1.PodFailed && !anyTerminated(out.ContainerStatuses) && !anyTerminated(out.InitContainerStatuses) {
		out.Reason = podIdentityEndedReason
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
	for _, c := range out.Conditions {
		if c.Type != corev1.PodScheduled {
			conditions = append(conditions, c)
		}
	}
	out.Conditions = conditions
	return out, nil
}

func anyTerminated(statuses []corev1.ContainerStatus) bool {
	for _, s := range statuses {
		if s.State.Terminated != nil {
			return true
		}
	}
	return false
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

// statusMessages gives each provider status reason a fixed message. The
// message never carries error text or guest data.
var statusMessages = map[string]string{
	"PodCVMOptInRequired":      "The Pod lacks the Pod CVM opt-in annotation",
	"LaunchRefused":            "The provider refused to launch the Pod",
	"CapacityLimit":            "The provider's maxPods limit is reached",
	"ProviderNodeUnavailable":  "The provider does not own its virtual node",
	"FrozenPodChanged":         "The Pod specification differs from its launch",
	"AllocationPending":        "Waiting for a Pod CVM allocation",
	"CloudUnavailable":         "The cloud API is unavailable",
	rateLimitedReason:          "Cloud is rate limiting this provider's requests",
	cloudRejectedReason:        "Cloud rejected the provider's request",
	"InsufficientCapacity":     "No Cloud host has room for this Pod CVM size",
	"InstanceStarting":         "The Pod CVM instance is starting",
	"EndpointsPending":         "Waiting for the Pod CVM endpoints",
	"AttestationUnavailable":   "The Pod CVM status attestation is unavailable",
	"GuestStatusRefused":       "The Pod CVM status does not match the Pod",
	"AssignmentPending":        "Waiting for the Pod CVM to accept its assignment",
	"InstanceEnded":            "The Pod CVM instance ended",
	"InstanceGone":             "The Pod CVM instance no longer exists",
	"InstanceIdentityMismatch": "The cloud instance differs from the launch",
	"GuestRebooted":            "The Pod CVM rebooted",
	"UnexpectedAssignedGuest":  "The Pod CVM reports a Pod it was not assigned",
	verificationTimeoutReason:  "The Pod CVM was not verified in time",
}

func unknownStatus(pod *corev1.Pod, reason string, now time.Time) corev1.PodStatus {
	out := *pod.Status.DeepCopy()
	if out.Phase == "" {
		out.Phase = corev1.PodPending
	}
	out.Reason = reason
	out.Message = statusMessages[reason]
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
