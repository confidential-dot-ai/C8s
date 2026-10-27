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

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func identityKey(provider, uid string) string {
	sum := sha256.Sum256([]byte(provider + "\x00" + uid))
	return "podcvm-" + hex.EncodeToString(sum[:20])
}

func (c *Config) launch(pod *corev1.Pod) (createRequest, error) {
	var req createRequest
	if err := launchconfig.ValidateProviderPod(pod); err != nil {
		return req, err
	}
	if err := c.fits(pod); err != nil {
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
		PodOperatorPublicKey: c.pub, Workloads: c.workloads,
		Pod: &launchconfig.PodSpec{UID: string(pod.UID), Namespace: pod.Namespace, Name: pod.Name, Manifest: string(manifest), MeshPeers: c.MeshPeers},
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
	tee := "tdx"
	if c.image.Platform == "snp" {
		tee = "sev-snp"
	}
	return createRequest{
		Image: c.Image, Size: c.Size, Location: c.Location, Tee: tee, Name: name, Count: 1,
		Labels:  map[string]string{"podcvm-provider": c.ProviderID, "podcvm-uid": strings.TrimPrefix(name, "podcvm-")},
		Network: networkSpec{PublicIP: c.PublicIP, Ingress: rules}, Readiness: readinessSpec{TCPPorts: []int{}},
		Trust: trustSpec{LaunchKey: c.pub, InitData: initData{Format: "c8s-launch/v1", Document: data, Signature: []byte(sig)}},
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
