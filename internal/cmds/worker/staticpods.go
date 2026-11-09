package worker

import (
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// staticPodTemplates holds the measured static-pod manifests.
const staticPodTemplates = "/usr/lib/c8s/worker/static-pods"

// staticPods renders every template under rootDir's staticPodTemplates, each
// a v1 Pod: each container's command and args get values as the floor's argv
// pins do (nodeservices.ArgvWithValues), and a template naming a floor
// placeholder anywhere else is refused.
func staticPods(rootDir string, values map[string]string) ([]fileutil.NewFile, error) {
	dir := filepath.Join(rootDir, staticPodTemplates)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("static pod templates: %w", err)
	}
	pods := make([]fileutil.NewFile, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("static pod template %s is not a regular file", entry.Name())
		}
		data, err := renderStaticPod(filepath.Join(dir, entry.Name()), values)
		if err != nil {
			return nil, fmt.Errorf("static pod template %s: %w", entry.Name(), err)
		}
		pods = append(pods, fileutil.NewFile{Name: entry.Name(), Data: data, Mode: 0o644})
	}
	return pods, nil
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

func renderStaticPod(path string, values map[string]string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pod, err := decodeStaticPod(data)
	if err != nil {
		return nil, err
	}
	for _, containers := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for i := range containers {
			for _, argv := range []*[]string{&containers[i].Command, &containers[i].Args} {
				if *argv, err = nodeservices.ArgvWithValues(*argv, values); err != nil {
					return nil, fmt.Errorf("container %s: %w", containers[i].Name, err)
				}
			}
		}
	}
	rendered, err := yaml.Marshal(pod)
	if err != nil {
		return nil, err
	}
	if placeholder := nodeservices.NamedPlaceholder(rendered); placeholder != "" {
		return nil, fmt.Errorf("names %s outside a container's \"<flag>=<placeholder>\" argv", placeholder)
	}
	return rendered, nil
}
