package worker

import (
	"bytes"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/distribution/reference"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// staticPodEntry is the base entry, marked StaticPod, that pins every
// container of the static pod template data as the kubelet runs it: digest,
// command and args (their placeholders filled at stage, as the template's), the
// declared environment with the node name the kubelet fills and the variables
// it and containerd add, and the template's mounts.
func staticPodEntry(data []byte) (string, allowlist.Workload, error) {
	pod, err := decodeStaticPod(data)
	if err != nil {
		return "", allowlist.Workload{}, err
	}
	volumes, err := templateVolumes(pod.Spec)
	if err != nil {
		return "", allowlist.Workload{}, fmt.Errorf("pod %s: %w", pod.Name, err)
	}
	entry := map[string][]any{}
	for key, containers := range map[string][]corev1.Container{"initContainers": pod.Spec.InitContainers, "containers": pod.Spec.Containers} {
		for _, c := range containers {
			container, err := containerEntry(c, volumes)
			if err != nil {
				return "", allowlist.Workload{}, fmt.Errorf("pod %s container %s: %w", pod.Name, c.Name, err)
			}
			entry[key] = append(entry[key], container)
		}
	}
	encoded, err := yaml.Marshal(entry)
	if err != nil {
		return "", allowlist.Workload{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(encoded))
	dec.KnownFields(true)
	var w allowlist.Workload
	if err := dec.Decode(&w); err != nil {
		return "", allowlist.Workload{}, fmt.Errorf("pod %s: %w", pod.Name, err)
	}
	w.StaticPod = true
	return pod.Name, w, nil
}

// templateVolumes are spec's volumes by name, after refusing a template whose
// pod could take anything from the control plane: Service links, cluster DNS,
// a runtime class, pull secrets, a service account, resource claims,
// ephemeral containers, or a volume other than a hostPath or an in-memory
// emptyDir. A static pod's host paths come from its measured template.
func templateVolumes(spec corev1.PodSpec) (map[string]corev1.Volume, error) {
	switch {
	case spec.EnableServiceLinks == nil || *spec.EnableServiceLinks:
		return nil, fmt.Errorf("enableServiceLinks must be false")
	case spec.DNSPolicy != corev1.DNSDefault:
		return nil, fmt.Errorf("dnsPolicy must be %s, the node's resolver", corev1.DNSDefault)
	case namesAPIObjects(spec):
		return nil, fmt.Errorf("names a runtime class, pull secrets, a service account, resource claims or ephemeral containers")
	}
	volumes := map[string]corev1.Volume{}
	for _, v := range spec.Volumes {
		if !isHostPath(v) && !isMemoryEmptyDir(v) {
			return nil, fmt.Errorf("volume %s is neither a hostPath nor an in-memory emptyDir", v.Name)
		}
		volumes[v.Name] = v
	}
	return volumes, nil
}

// namesAPIObjects reports whether spec names a runtime class, pull secrets, a
// service account, resource claims or ephemeral containers.
func namesAPIObjects(spec corev1.PodSpec) bool {
	return spec.RuntimeClassName != nil ||
		len(spec.ImagePullSecrets) > 0 ||
		spec.ServiceAccountName != "" ||
		spec.DeprecatedServiceAccount != "" ||
		len(spec.ResourceClaims) > 0 ||
		len(spec.EphemeralContainers) > 0
}

// isHostPath reports whether v is a hostPath volume at an absolute path.
func isHostPath(v corev1.Volume) bool {
	return v.HostPath != nil && v.EmptyDir == nil && path.IsAbs(v.HostPath.Path)
}

// isMemoryEmptyDir reports whether v is an emptyDir volume in memory.
func isMemoryEmptyDir(v corev1.Volume) bool {
	return v.EmptyDir != nil && v.HostPath == nil && v.EmptyDir.Medium == corev1.StorageMediumMemory
}

// containerEntry is c's allowlist container, as YAML values.
func containerEntry(c corev1.Container, volumes map[string]corev1.Volume) (map[string]any, error) {
	ref, err := reference.ParseNormalizedNamed(c.Image)
	if err != nil {
		return nil, fmt.Errorf("image: %w", err)
	}
	digested, ok := ref.(reference.Digested)
	if !ok {
		return nil, fmt.Errorf("image %s is not referenced by digest", c.Image)
	}
	if len(c.Command) == 0 {
		return nil, fmt.Errorf("names no command")
	}
	if len(c.EnvFrom) > 0 || len(c.Resources.Claims) > 0 {
		return nil, fmt.Errorf("takes envFrom or resource claims")
	}
	if expands(c) {
		return nil, fmt.Errorf("names $(...) or $$, which the kubelet expands from variables the control plane sets")
	}
	// containerd's CRI sets HOSTNAME; serviceLinks admits the variables the
	// kubelet adds, whose names are shaped like a Service's.
	variables := map[string]any{"HOSTNAME": map[string]any{"present": true}}
	for _, e := range c.Env {
		switch {
		case e.ValueFrom == nil:
			variables[e.Name] = map[string]any{"exact": e.Value}
		case e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "spec.nodeName":
			variables[e.Name] = map[string]any{"present": true}
		default:
			return nil, fmt.Errorf("env %s takes a value other than spec.nodeName from the API", e.Name)
		}
	}
	args := map[string]any{"policy": allowlist.PolicyDeny}
	if len(c.Args) > 0 {
		args = map[string]any{"policy": allowlist.PolicyExact, "argv": c.Args}
	}
	var rules []any
	for _, m := range c.VolumeMounts {
		v, ok := volumes[m.Name]
		switch {
		case !ok:
			return nil, fmt.Errorf("mounts undeclared volume %s", m.Name)
		case m.SubPath != "" || m.SubPathExpr != "":
			return nil, fmt.Errorf("mounts a subPath of volume %s", m.Name)
		case v.HostPath != nil:
			rules = append(rules, map[string]any{"destination": m.MountPath, "kind": string(allowlist.MountHost), "source": v.HostPath.Path, "readOnly": m.ReadOnly})
		case m.ReadOnly:
			return nil, fmt.Errorf("mounts emptyDir %s read-only", m.Name)
		default:
			rules = append(rules, map[string]any{"destination": m.MountPath, "kind": string(allowlist.MountEmptyDir), "source": m.Name})
		}
	}
	mounts := map[string]any{"policy": allowlist.PolicyDeny}
	if len(rules) > 0 {
		mounts = map[string]any{"policy": allowlist.PolicyExact, "rules": rules}
	}
	return map[string]any{
		"digest":  digested.Digest().String(),
		"image":   c.Image,
		"command": map[string]any{"policy": allowlist.PolicyExact, "argv": c.Command},
		"args":    args,
		"mounts":  mounts,
		"env":     map[string]any{"policy": allowlist.PolicyMatch, "variables": variables, "serviceLinks": true},
	}, nil
}

// expands reports whether c names a $(VAR) reference or its escape in its
// command, args or env values.
func expands(c corev1.Container) bool {
	values := slices.Concat(c.Command, c.Args)
	for _, e := range c.Env {
		values = append(values, e.Value)
	}
	return slices.ContainsFunc(values, func(v string) bool {
		return strings.Contains(v, "$(") || strings.Contains(v, "$$")
	})
}
