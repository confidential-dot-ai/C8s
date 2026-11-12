package nriimagepolicy

import (
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func (c *config) validatePodImages() error {
	if len(c.Pod.Images) == 0 {
		return fmt.Errorf("the Pod requires its staged container image pins")
	}
	for name, pin := range c.Pod.Images {
		if len(validation.IsDNS1123Label(name)) != 0 {
			return fmt.Errorf("pod.images has invalid container name %q", name)
		}
		if !types.IsCanonicalDigest(pin) {
			return fmt.Errorf("pod.images[%q] must be a canonical sha256 digest", name)
		}
	}
	var endpoint string
	if c.Allowlist.Base != nil {
		for _, workload := range c.Allowlist.Base.Workloads {
			for _, container := range slices.Concat(workload.InitContainers, workload.Containers) {
				if container.Role != meshRole {
					continue
				}
				if endpoint != "" {
					return fmt.Errorf("the Pod requires exactly one measured mesh image declaration")
				}
				endpoint = container.Digest.String()
			}
		}
	}
	if endpoint == "" || c.Pod.Images[workloadclaims.MeshContainerName] != endpoint {
		return fmt.Errorf("pod.images must bind the mesh endpoint to its measured image")
	}
	return nil
}
