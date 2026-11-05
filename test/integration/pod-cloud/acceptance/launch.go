package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// identityKey derives the guest's static name and Cloud idempotency key from
// the launcher and the Pod UID, so a retried launch can never mint a second VM.
func identityKey(provider, uid string) string {
	sum := sha256.Sum256([]byte(provider + "\x00" + uid))
	return "podcvm-" + hex.EncodeToString(sum[:20])
}

// launch signs one Pod's launch document and freezes the Cloud create request
// that carries it. The pod's confidential.ai/cw annotation, when present, is
// the workload ID the leaf extension carries; the document must name the same.
func (c *Config) launch(pod *corev1.Pod) (createRequest, error) {
	var req createRequest
	if err := launchconfig.ValidateProviderPod(pod); err != nil {
		return req, err
	}
	guest := guestPod(pod)
	manifest, err := json.Marshal(guest)
	if err != nil {
		return req, err
	}
	name := identityKey(c.ProviderID, string(pod.UID))
	if len(pod.Name)+1+len(name) > 253 {
		return req, errors.New("pod name is too long for the guest's static Pod name")
	}
	doc := launchconfig.Document{
		SchemaVersion: launchconfig.SchemaVersion, ClusterID: c.ClusterID, Role: launchconfig.Pod, Image: c.image,
		Node: launchconfig.Node{Name: name}, Server: launchconfig.ServerConfig{Address: c.ServerAddress, OperatorPublicKey: c.serverPub},
		PodOperatorPublicKey: c.pub, Workloads: c.workloads, CDS: c.cds,
		Pod: &launchconfig.PodSpec{UID: string(pod.UID), Namespace: pod.Namespace, Name: pod.Name, WorkloadID: pod.Annotations[workloadclaims.AnnotationWorkloadID], Manifest: string(manifest), MeshPeers: c.MeshPeers},
	}
	data, sig, err := launchconfig.SignDocument(doc, c.key)
	if err != nil {
		return req, err
	}
	if len(data) > 64<<10 {
		return req, errors.New("signed Pod document exceeds the Cloud 64 KiB limit")
	}
	ports, err := doc.Pod.IngressPorts()
	if err != nil {
		return req, err
	}
	rules := []ingress{{Name: "pod-status", Port: 8443}}
	for _, p := range ports {
		rules = append(rules, ingress{Name: fmt.Sprintf("app-%d", p), Port: int(p)})
	}
	return createRequest{
		Image: c.Image, Size: c.Size, Location: c.Location, Tee: c.tee(), Name: name, Count: 1,
		Labels:  map[string]string{"podcvm-provider": c.ProviderID, "podcvm-uid": strings.TrimPrefix(name, "podcvm-")},
		Network: networkSpec{PublicIP: c.PublicIP, Ingress: rules}, Readiness: readinessSpec{TCPPorts: []int{}},
		Trust: trustSpec{LaunchKey: c.pub, InitData: initData{Format: launchconfig.SchemaVersion, Document: data, Signature: []byte(sig)}},
	}, nil
}

// genericLaunch signs a Pod-role document without a Pod: the guest boots
// generic and waits for one signed assignment through its status service.
func (c *Config) genericLaunch(name string) (createRequest, error) {
	doc := launchconfig.Document{SchemaVersion: launchconfig.SchemaVersion, ClusterID: c.ClusterID, Role: launchconfig.Pod, Image: c.image, Node: launchconfig.Node{Name: name}, Server: launchconfig.ServerConfig{Address: c.ServerAddress, OperatorPublicKey: c.serverPub}, PodOperatorPublicKey: c.pub, CDS: c.cds}
	data, sig, err := launchconfig.SignDocument(doc, c.key)
	if err != nil {
		return createRequest{}, err
	}
	if len(data) > 64<<10 {
		return createRequest{}, errors.New("generic launch exceeds the Cloud 64 KiB limit")
	}
	return createRequest{Image: c.Image, Size: c.Size, Location: c.Location, Tee: c.tee(), Name: name, Count: 1, Labels: map[string]string{"podcvm-provider": c.ProviderID, "podcvm-uid": strings.TrimPrefix(name, "podcvm-")}, Network: networkSpec{PublicIP: c.PublicIP, Ingress: []ingress{{Name: "pod-status", Port: 8443}}}, Readiness: readinessSpec{TCPPorts: []int{}}, Trust: trustSpec{LaunchKey: c.pub, InitData: initData{Format: launchconfig.SchemaVersion, Document: data, Signature: []byte(sig)}}}, nil
}

// guestPod removes the submitting side's scheduling state. The guest's
// standalone kubelet owns its node name, service links and lifecycle.
func guestPod(pod *corev1.Pod) *corev1.Pod {
	p := pod.DeepCopy()
	p.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}
	p.ObjectMeta = metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace, UID: pod.UID, Labels: maps.Clone(pod.Labels), Annotations: maps.Clone(pod.Annotations)}
	for k := range p.Annotations {
		if strings.HasPrefix(k, "kubernetes.io/config.") {
			delete(p.Annotations, k)
		}
	}
	p.Spec.NodeName = ""
	p.Spec.NodeSelector = nil
	p.Spec.Affinity = nil
	p.Spec.Tolerations = nil
	p.Spec.TopologySpreadConstraints = nil
	p.Spec.SchedulingGates = nil
	p.Spec.SchedulerName = ""
	p.Spec.ServiceAccountName = ""
	p.Spec.DeprecatedServiceAccount = ""
	p.Spec.EnableServiceLinks = new(false)
	p.Spec.Priority = nil
	p.Spec.PriorityClassName = ""
	p.Spec.PreemptionPolicy = nil
	for _, containers := range [][]corev1.Container{p.Spec.InitContainers, p.Spec.Containers} {
		for i := range containers {
			for j := range containers[i].Env {
				e := &containers[i].Env[j]
				if e.ValueFrom == nil || e.ValueFrom.FieldRef == nil {
					continue
				}
				if value, ok := metadataField(pod, e.ValueFrom.FieldRef.FieldPath); ok {
					e.Value = value
					e.ValueFrom = nil
				}
			}
		}
	}
	p.Status = corev1.PodStatus{}
	return p
}

func metadataField(pod *corev1.Pod, path string) (string, bool) {
	switch path {
	case "metadata.name":
		return pod.Name, true
	case "metadata.namespace":
		return pod.Namespace, true
	case "metadata.uid":
		return string(pod.UID), true
	}
	for prefix, values := range map[string]map[string]string{"metadata.labels['": pod.Labels, "metadata.annotations['": pod.Annotations} {
		if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, "']") {
			return values[strings.TrimSuffix(strings.TrimPrefix(path, prefix), "']")], true
		}
	}
	return "", false
}

// tee names the Cloud TEE for the configured image. Every launch of this
// launcher, per-pod or generic, asks for the same one, so a generic guest and
// the pod assigned to it never differ in platform.
func (c *Config) tee() string {
	if c.image.Platform == "snp" {
		return "sev-snp"
	}
	return "tdx"
}
