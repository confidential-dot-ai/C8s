package launchconfig

import (
	"errors"
	"fmt"

	"github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

// PodSpec names the pod a pod-role boot runs. Manifest is a v1 Pod in YAML
// or JSON; its metadata must repeat UID, Namespace and Name so the identity
// the provider reports and the pod kubelet runs cannot diverge.
type PodSpec struct {
	UID       string `yaml:"uid" json:"uid"`
	Namespace string `yaml:"namespace" json:"namespace"`
	Name      string `yaml:"name" json:"name"`
	Manifest  string `yaml:"manifest" json:"manifest"`
}

// validate is defence in depth: NRI's sandbox policy is the enforcement
// point. It refuses what the pod role can never need, so a bad document
// fails at signing time instead of at container start.
func (p *PodSpec) validate() error {
	if p.UID == "" || len(p.UID) > 128 || len(validation.IsDNS1123Subdomain(p.UID)) != 0 {
		return fmt.Errorf("pod.uid must be a lowercase UID")
	}
	if !dnsLabel(p.Namespace) {
		return fmt.Errorf("pod.namespace must be an RFC1123 label")
	}
	if len(validation.IsDNS1123Subdomain(p.Name)) != 0 {
		return fmt.Errorf("pod.name must be an RFC1123 subdomain")
	}
	pod, err := ParsePodManifest([]byte(p.Manifest))
	if err != nil {
		return err
	}
	if string(pod.UID) != p.UID || pod.Namespace != p.Namespace || pod.Name != p.Name {
		return fmt.Errorf("pod.manifest metadata must match pod.uid, pod.namespace and pod.name")
	}
	s := pod.Spec
	if s.HostNetwork || s.HostPID || s.HostIPC {
		return fmt.Errorf("pod.manifest must not use host namespaces")
	}
	if len(s.EphemeralContainers) != 0 {
		return fmt.Errorf("pod.manifest must not carry ephemeral containers")
	}
	for _, v := range s.Volumes {
		if v.EmptyDir == nil {
			return fmt.Errorf("pod.manifest volume %q: only emptyDir volumes are supported", v.Name)
		}
	}
	for _, c := range append(append([]corev1.Container{}, s.InitContainers...), s.Containers...) {
		if err := pinnedImage(c.Image); err != nil {
			return fmt.Errorf("pod.manifest container %q image %q: %w", c.Name, c.Image, err)
		}
		for _, port := range c.Ports {
			if port.HostPort != 0 || port.HostIP != "" {
				return fmt.Errorf("pod.manifest container %q must not use a hostPort or hostIP", c.Name)
			}
		}
		if sc := c.SecurityContext; sc != nil && sc.Privileged != nil && *sc.Privileged {
			return fmt.Errorf("pod.manifest container %q must not be privileged", c.Name)
		}
	}
	return nil
}

// pinnedImage accepts only an image reference that names its digest. A tag
// resolves through the image store at the time of the check, so a tag-only
// reference does not identify the image the pod CVM admits, measures and
// runs; a reference with a digest does, whatever tag it also carries.
func pinnedImage(image string) error {
	ref, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return err
	}
	canonical, ok := ref.(reference.Canonical)
	if !ok {
		return errors.New("must pin the image by digest (name@sha256:<hex>)")
	}
	// The measured list, the allowlist and the journal carry sha256 digests
	// only, so refuse another algorithm here rather than at admission.
	if canonical.Digest().Algorithm() != "sha256" {
		return fmt.Errorf("digest algorithm %s is not sha256", canonical.Digest().Algorithm())
	}
	return nil
}

// ParsePodManifest strictly decodes a v1 Pod from YAML or JSON.
func ParsePodManifest(data []byte) (*corev1.Pod, error) {
	var pod corev1.Pod
	if err := yaml.UnmarshalStrict(data, &pod); err != nil {
		return nil, fmt.Errorf("pod.manifest: %w", err)
	}
	if pod.APIVersion != "v1" || pod.Kind != "Pod" {
		return nil, fmt.Errorf("pod.manifest must be a v1 Pod")
	}
	if len(pod.Spec.Containers) == 0 {
		return nil, fmt.Errorf("pod.manifest has no containers")
	}
	return &pod, nil
}
