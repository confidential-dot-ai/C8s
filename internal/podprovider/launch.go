package podprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
	"github.com/confidential-dot-ai/c8s/internal/podmesh"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func identityKey(provider, uid string) string {
	sum := sha256.Sum256([]byte(provider + "\x00" + uid))
	return recordPrefix + hex.EncodeToString(sum[:20])
}

// launch freezes the pod and its client document and builds the create request for its generic
// instance: the signed generic document and the pod's own ingress rules. The
// frozen pod, the entries and the peers are checked here as the guest will
// check the assignment, so a pod the guest would refuse is refused before any
// record exists.
func (c *Config) launch(pod *corev1.Pod) (createRequest, []byte, []byte, error) {
	var req createRequest
	if err := podlaunch.ValidateProviderPod(pod); err != nil {
		return req, nil, nil, err
	}
	if err := c.fits(pod); err != nil {
		return req, nil, nil, err
	}
	clientDocument, err := podlaunch.ClientDocument(pod)
	if err != nil {
		return req, nil, nil, err
	}
	guest := guestPod(pod)
	manifest, err := json.Marshal(guest)
	if err != nil {
		return req, nil, nil, err
	}
	peers, err := json.Marshal(c.peers())
	if err != nil {
		return req, nil, nil, err
	}
	doc := c.document(identityKey(c.ProviderID, string(pod.UID)))
	if _, err := podlaunch.Assign(&doc, manifest, []byte(c.workloads), peers, clientDocument); err != nil {
		return req, nil, nil, err
	}
	ports, err := podmesh.IngressPorts(guest)
	if err != nil {
		return req, nil, nil, err
	}
	req, err = c.signedRequest(doc, ports)
	return req, manifest, clientDocument, err
}

// peers is the operator-configured peer list, never nil: the assignment
// carries an empty list for a pod with no peers.
func (c *Config) peers() []string {
	if c.MeshPeers == nil {
		return []string{}
	}
	return c.MeshPeers
}

// document is the generic launch document every pod CVM of this provider
// boots under: the cluster, image and CDS trust the operator
// configured, signed by the pod launch key. It names no pod and carries no
// allowlist entries; those travel in the assignment.
func (c *Config) document(name string) podlaunch.Document {
	return podlaunch.Document{
		SchemaVersion: podlaunch.SchemaVersion, ClusterID: c.ClusterID, Role: podlaunch.Pod, Image: c.image,
		Node: podlaunch.Node{Name: name}, PodOperatorPublicKey: c.pub, CDS: c.cds,
	}
}

// signedRequest signs the document and builds the create request around it:
// the status port is always reachable, plus one ingress rule per application
// port. The instance is labelled with the provider and the allocation identity.
func (c *Config) signedRequest(doc podlaunch.Document, ports []uint16) (createRequest, error) {
	data, sig, err := podlaunch.SignDocument(doc, c.key)
	if err != nil {
		return createRequest{}, err
	}
	// The cloud refuses a larger document for good. Refuse it here, before
	// any record exists, or the pod would be held forever behind a create
	// that can never succeed.
	if len(data) > 64<<10 {
		return createRequest{}, errors.New("signed launch document exceeds the Cloud 64 KiB limit")
	}
	rules := []ingress{{Name: "pod-status", Port: 8443}}
	for _, p := range ports {
		rules = append(rules, ingress{Name: fmt.Sprintf("%s%d", workloadclaims.PodCVMAppEndpointPrefix, p), Port: int(p)})
	}
	name := doc.Node.Name
	return createRequest{
		Image: c.Image, Size: c.Size, Location: c.Location, Tee: c.tee(), Name: name, Count: 1,
		Labels:  map[string]string{providerLabel: c.ProviderID, allocationLabel: strings.TrimPrefix(name, recordPrefix)},
		Network: networkSpec{PublicIP: c.PublicIP, Ingress: rules}, Readiness: readinessSpec{TCPPorts: []int{}},
		Trust: trustSpec{LaunchKey: c.pub, InitData: initData{Format: podlaunch.SchemaVersion, Document: data, Signature: []byte(sig)}},
	}, nil
}

// guestPod removes the external scheduler's state. The guest's standalone
// kubelet owns its node name, service links and lifecycle.
func guestPod(pod *corev1.Pod) *corev1.Pod {
	p := pod.DeepCopy()
	p.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}
	p.ObjectMeta = metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace, UID: pod.UID, Labels: maps.Clone(pod.Labels), Annotations: maps.Clone(pod.Annotations)}
	delete(p.Annotations, Annotation)
	delete(p.Annotations, endpointsAnnotation)
	// The client document travels as its own signed assignment member.
	delete(p.Annotations, workloadclaims.AnnotationClientDocument)
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

func (c *Config) fits(pod *corev1.Pod) error {
	// Counting every init sidecar and regular init container simultaneously
	// is conservative and leaves the configured reserve for image layers and
	// guest services. Never promise a workload more than one CVM provides.
	var cpu, memory int64
	maxCPU := resource.NewMilliQuantity(c.VCPUs*1000, resource.DecimalSI)
	maxMemory := resource.NewQuantity((c.MemoryMiB-c.ReservedMemoryMiB)*(1<<20), resource.BinarySI)
	for _, ctr := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		for _, list := range []corev1.ResourceList{ctr.Resources.Requests, ctr.Resources.Limits} {
			for k, q := range list {
				if k != corev1.ResourceCPU && k != corev1.ResourceMemory {
					return errors.New("pod CVM supports CPU and memory resources only")
				}
				limit := maxMemory
				if k == corev1.ResourceCPU {
					limit = maxCPU
				}
				if q.Sign() < 0 || q.Cmp(*limit) > 0 {
					return errors.New("container resources exceed the configured CVM workload capacity")
				}
			}
		}
		cpu += max(ctr.Resources.Requests.Cpu().MilliValue(), ctr.Resources.Limits.Cpu().MilliValue())
		memory += max(ctr.Resources.Requests.Memory().Value(), ctr.Resources.Limits.Memory().Value())
		if cpu > maxCPU.MilliValue() || memory > maxMemory.Value() {
			return errors.New("pod resources exceed the configured CVM workload capacity")
		}
	}
	return nil
}

// tee names the Cloud TEE for the configured image. Every pod CVM of this
// provider asks for the same one.
func (c *Config) tee() string {
	if c.image.Platform == "snp" {
		return "sev-snp"
	}
	return "tdx"
}
