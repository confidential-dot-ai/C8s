package worker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// staticPodTemplates holds the measured static-pod manifests.
const staticPodTemplates = "/usr/lib/c8s/worker/static-pods"

// gpuOnlyAnnotation, set to "true", marks a template whose pod fails on a
// node without an NVIDIA GPU.
const gpuOnlyAnnotation = "confidential.ai/gpu-only"

// pciDevices lists the node's PCI functions. The worker kernel has no PCI
// hotplug, so the set is fixed by the time stage runs.
const pciDevices = "/sys/bus/pci/devices"

// staticPods renders every template under rootDir's staticPodTemplates, each
// a v1 Pod, leaving out a gpuOnlyAnnotation template on a node without an
// NVIDIA GPU: each container's command and args get values as the floor's
// argv pins do (nodeservices.ArgvWithValues), and a template naming a floor
// placeholder anywhere else is refused.
func staticPods(rootDir string, values map[string]string) ([]fileutil.NewFile, error) {
	dir := filepath.Join(rootDir, staticPodTemplates)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("static pod templates: %w", err)
	}
	gpu, err := hasNVIDIAGPU(rootDir)
	if err != nil {
		return nil, err
	}
	pods := make([]fileutil.NewFile, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("static pod template %s is not a regular file", entry.Name())
		}
		data, gpuOnly, err := renderStaticPod(filepath.Join(dir, entry.Name()), values)
		if err != nil {
			return nil, fmt.Errorf("static pod template %s: %w", entry.Name(), err)
		}
		if gpuOnly && !gpu {
			continue
		}
		pods = append(pods, fileutil.NewFile{Name: entry.Name(), Data: data, Mode: 0o644})
	}
	return pods, nil
}

// hasNVIDIAGPU reports whether rootDir's node has a PCI function of NVIDIA's
// vendor ID, the check gpu-cc-enforce.sh makes.
func hasNVIDIAGPU(rootDir string) (bool, error) {
	vendors, err := filepath.Glob(filepath.Join(rootDir, pciDevices, "*", "vendor"))
	if err != nil {
		return false, err
	}
	for _, vendor := range vendors {
		data, err := os.ReadFile(vendor)
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(string(data)) == "0x10de" {
			return true, nil
		}
	}
	return false, nil
}

// decodeStaticPod decodes data strictly as a named v1 Pod.
func decodeStaticPod(data []byte) (*corev1.Pod, error) {
	var pod corev1.Pod
	if err := yaml.UnmarshalStrict(data, &pod); err != nil {
		return nil, err
	}
	if pod.APIVersion != "v1" || pod.Kind != "Pod" || pod.Name == "" {
		return nil, fmt.Errorf("is %s %s %q, not a named v1 Pod", pod.APIVersion, pod.Kind, pod.Name)
	}
	return &pod, nil
}

// renderStaticPod renders the template at path and reports whether it is
// marked gpuOnlyAnnotation.
func renderStaticPod(path string, values map[string]string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	pod, err := decodeStaticPod(data)
	if err != nil {
		return nil, false, err
	}
	for _, containers := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for i := range containers {
			for _, argv := range []*[]string{&containers[i].Command, &containers[i].Args} {
				if *argv, err = nodeservices.ArgvWithValues(*argv, values); err != nil {
					return nil, false, fmt.Errorf("container %s: %w", containers[i].Name, err)
				}
			}
		}
	}
	rendered, err := yaml.Marshal(pod)
	if err != nil {
		return nil, false, err
	}
	if placeholder := nodeservices.NamedPlaceholder(rendered); placeholder != "" {
		return nil, false, fmt.Errorf("names %s outside a container's \"<flag>=<placeholder>\" argv", placeholder)
	}
	return rendered, pod.Annotations[gpuOnlyAnnotation] == "true", nil
}
