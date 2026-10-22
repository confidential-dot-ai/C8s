package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Pinned launches are the base entries that let a node component hold more
// host privilege than the host network: the node exempts a launch from its
// sandbox policy only when a base entry fixes its command, args and mounts and
// constrains its environment. They are derived, never written by hand:
//
//   - from a booted node, for components RKE2 deploys from its own charts
//     (-launches, -pin-daemonset). The capture is the pod list and the
//     `crictl inspect` of each container, so the argv, environment and mounts
//     are the ones containerd handed the node's admission plugin;
//   - from the baked manifest, for components this image deploys itself
//     (-pin-manifest, -image-config).
//
// The environment is matched per variable: a value the pod spec takes from the
// API (valueFrom) or the runtime sets (HOSTNAME) is matched present, every
// other value exact, and the kubelet's service links are admitted by shape.

const (
	pinnedBegin = "# BEGIN pinned system launches"
	pinnedEnd   = "# END pinned system launches"
)

// recordedContainer is the part of `crictl inspect` output a pin reads.
// daemonSetPod is what a DaemonSet appends to its name to name a pod.
var daemonSetPod = regexp.MustCompile(`^-[a-z0-9]{5}$`)

type recordedContainer struct {
	Status struct {
		Labels   map[string]string `json:"labels"`
		ImageRef string            `json:"imageRef"`
	} `json:"status"`
	Info struct {
		SandboxID   string `json:"sandboxID"`
		RuntimeSpec struct {
			Process struct {
				Args []string `json:"args"`
				Env  []string `json:"env"`
			} `json:"process"`
			Mounts []struct {
				Destination string   `json:"destination"`
				Type        string   `json:"type"`
				Source      string   `json:"source"`
				Options     []string `json:"options"`
			} `json:"mounts"`
		} `json:"runtimeSpec"`
	} `json:"info"`
}

// launch is one container to pin, in the order its pod runs it.
type launch struct {
	name      string
	init      bool
	container allowlist.Container
}

// capturedLaunches pins every container of the named DaemonSets
// (namespace/name) from the capture under dir: pods.json, `kubectl get pods
// -o json` holding a pod of each DaemonSet, whose spec says which variables
// come from the API, and containers/*.json, the `crictl inspect` of each of
// that DaemonSet's containers on the node.
func capturedLaunches(dir string, daemonsets []string) (map[string][]launch, error) {
	data, err := os.ReadFile(filepath.Join(dir, "pods.json"))
	if err != nil {
		return nil, err
	}
	var pods corev1.PodList
	if err := json.Unmarshal(data, &pods); err != nil {
		return nil, fmt.Errorf("pods.json: %w", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "containers", "*.json"))
	if err != nil {
		return nil, err
	}
	var recorded []recordedContainer
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var c recordedContainer
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		recorded = append(recorded, c)
	}

	out := map[string][]launch{}
	for _, ds := range daemonsets {
		namespace, name, ok := strings.Cut(ds, "/")
		if !ok {
			return nil, fmt.Errorf("-pin-daemonset %q: want namespace/name", ds)
		}
		var pod *corev1.Pod
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Namespace == namespace && slices.ContainsFunc(p.OwnerReferences, func(o metav1.OwnerReference) bool { return o.Kind == "DaemonSet" && o.Name == name }) {
				pod = p
				break
			}
		}
		if pod == nil {
			return nil, fmt.Errorf("no pod of DaemonSet %s in %s", ds, dir)
		}
		var launches []launch
		for _, spec := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
			i := slices.IndexFunc(recorded, func(c recordedContainer) bool {
				l := c.Status.Labels
				return l["io.kubernetes.pod.namespace"] == namespace && daemonSetPod.MatchString(strings.TrimPrefix(l["io.kubernetes.pod.name"], name)) && l["io.kubernetes.container.name"] == spec.Name
			})
			if i < 0 {
				return nil, fmt.Errorf("DaemonSet %s container %s has no recorded launch in %s", ds, spec.Name, dir)
			}
			c, err := pinRecorded(recorded[i], spec)
			if err != nil {
				return nil, fmt.Errorf("pod %s/%s container %s: %w", pod.Namespace, pod.Name, spec.Name, err)
			}
			launches = append(launches, launch{name: spec.Name, init: slices.ContainsFunc(pod.Spec.InitContainers, func(x corev1.Container) bool { return x.Name == spec.Name }), container: c})
		}
		out[name] = launches
	}
	return out, nil
}

func pinRecorded(rc recordedContainer, spec corev1.Container) (allowlist.Container, error) {
	ref := rc.Status.ImageRef
	_, digest, ok := strings.Cut(ref, "@")
	if !ok {
		return allowlist.Container{}, fmt.Errorf("image %q is not digest-pinned", ref)
	}
	var mounts []*api.Mount
	for _, m := range rc.Info.RuntimeSpec.Mounts {
		mounts = append(mounts, &api.Mount{Destination: m.Destination, Type: m.Type, Source: m.Source, Options: m.Options})
	}
	rules, err := mountRules(nriimagepolicy.ObserveRecordedMounts(rc.Status.Labels["io.kubernetes.pod.uid"], rc.Info.SandboxID, rc.Status.Labels["io.kubernetes.container.name"], mounts))
	if err != nil {
		return allowlist.Container{}, err
	}
	env := map[string]string{}
	for _, entry := range rc.Info.RuntimeSpec.Process.Env {
		name, value, _ := strings.Cut(entry, "=")
		env[name] = value
	}
	return pinnedContainer(ref, digest, rc.Info.RuntimeSpec.Process.Args, rules, env, valueFromNames(spec))
}

// manifestLaunch pins the first container of the DaemonSet in manifest,
// over the image environment in config (the image's config JSON, as `crane
// config` prints it).
func manifestLaunch(manifest, config string) (string, launch, error) {
	data, err := os.ReadFile(manifest)
	if err != nil {
		return "", launch{}, err
	}
	var ds appsv1.DaemonSet
	if err := sigsyaml.Unmarshal(data, &ds); err != nil {
		return "", launch{}, fmt.Errorf("%s: %w", manifest, err)
	}
	pod := ds.Spec.Template.Spec
	if len(pod.InitContainers) != 0 || len(pod.Containers) != 1 {
		return "", launch{}, fmt.Errorf("%s: want one container and no init containers", manifest)
	}
	spec := pod.Containers[0]
	if len(spec.Command) == 0 {
		return "", launch{}, fmt.Errorf("%s: container %s runs its image's entrypoint; spell out its command", manifest, spec.Name)
	}
	_, digest, ok := strings.Cut(spec.Image, "@")
	if !ok {
		return "", launch{}, fmt.Errorf("%s: image %q is not digest-pinned", manifest, spec.Image)
	}
	raw, err := os.ReadFile(config)
	if err != nil {
		return "", launch{}, err
	}
	var image struct {
		Config struct {
			Env []string `json:"Env"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &image); err != nil {
		return "", launch{}, fmt.Errorf("%s: %w", config, err)
	}
	env := map[string]string{}
	for _, entry := range image.Config.Env {
		name, value, _ := strings.Cut(entry, "=")
		env[name] = value
	}
	for _, e := range spec.Env {
		env[e.Name] = e.Value
	}
	volumes := map[string]corev1.Volume{}
	for _, v := range pod.Volumes {
		volumes[v.Name] = v
	}
	var rules []allowlist.MountRule
	for _, m := range spec.VolumeMounts {
		v := volumes[m.Name]
		switch {
		case v.HostPath != nil:
			rules = append(rules, allowlist.MountRule{Destination: m.MountPath, Kind: allowlist.MountHost, Source: v.HostPath.Path, ReadOnly: m.ReadOnly})
		case v.EmptyDir != nil:
			rules = append(rules, allowlist.MountRule{Destination: m.MountPath, Kind: allowlist.MountEmptyDir, Source: m.Name})
		default:
			return "", launch{}, fmt.Errorf("%s: volume %s has a source a pin cannot name", manifest, m.Name)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Destination < rules[j].Destination })
	c, err := pinnedContainer(spec.Image, digest, slices.Concat(spec.Command, spec.Args), rules, env, valueFromNames(spec))
	if err != nil {
		return "", launch{}, err
	}
	return ds.Name, launch{name: spec.Name, container: c}, nil
}

func valueFromNames(spec corev1.Container) map[string]bool {
	names := map[string]bool{}
	for _, e := range spec.Env {
		if e.ValueFrom != nil {
			names[e.Name] = true
		}
	}
	return names
}

// mountRules turns admission's view of a recorded container's mounts into the
// exact rules that admit them: platform mounts need no rule.
func mountRules(observed []allowlist.ObservedMount) ([]allowlist.MountRule, error) {
	var rules []allowlist.MountRule
	for _, m := range observed {
		rule := allowlist.MountRule{Destination: m.Destination}
		switch m.Class {
		case allowlist.MountPlatform:
			continue
		case allowlist.MountEmptyDir:
			rule.Kind, rule.Source = allowlist.MountEmptyDir, m.Volume
		case allowlist.MountData:
			rule.Kind, rule.Source = allowlist.MountData, m.Volume
			rule.Node = !strings.HasPrefix(m.Destination, allowlist.DataMountPrefix)
		case allowlist.MountHost:
			rule.Kind, rule.Source, rule.ReadOnly = allowlist.MountHost, m.Source, m.ReadOnly
		default:
			return nil, fmt.Errorf("mount %s has class %q, which a pin cannot name", m.Destination, m.Class)
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Destination < rules[j].Destination })
	return rules, nil
}

// pinnedContainer is the exact entry for one launch.
func pinnedContainer(image, digest string, argv []string, rules []allowlist.MountRule, env map[string]string, fromAPI map[string]bool) (allowlist.Container, error) {
	d, err := types.ParseDigest(digest)
	if err != nil {
		return allowlist.Container{}, err
	}
	if len(argv) == 0 {
		return allowlist.Container{}, fmt.Errorf("empty argv")
	}
	mounts := allowlist.MountPolicy{Policy: allowlist.PolicyDeny}
	if len(rules) > 0 {
		mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: rules}
	}
	variables := map[string]allowlist.EnvMatcher{}
	for name, value := range env {
		switch {
		case allowlist.ServiceLinkName(name):
		case name == "HOSTNAME" || fromAPI[name]:
			variables[name] = presentMatcher()
		default:
			variables[name] = exactMatcher(value)
		}
	}
	return allowlist.Container{
		Digest:  d,
		Image:   image,
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: argv},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
		Mounts:  mounts,
		Env:     allowlist.EnvPolicy{Policy: allowlist.PolicyMatch, Variables: variables, ServiceLinks: true},
	}, nil
}

func presentMatcher() allowlist.EnvMatcher {
	return matcher(map[string]any{"present": true})
}

func exactMatcher(value string) allowlist.EnvMatcher {
	return matcher(map[string]any{"exact": value})
}

func matcher(spec map[string]any) allowlist.EnvMatcher {
	data, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}
	var m allowlist.EnvMatcher
	if err := json.Unmarshal(data, &m); err != nil {
		panic(err)
	}
	return m
}

// renderPinned formats the pinned launches as base workloads at the
// template's indent, one per component, sorted by name.
func renderPinned(components map[string][]launch) (string, error) {
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		w := allowlist.Workload{Label: name}
		for _, l := range components[name] {
			if l.init {
				w.InitContainers = append(w.InitContainers, l.container)
			} else {
				w.Containers = append(w.Containers, l.container)
			}
		}
		var doc strings.Builder
		enc := yaml.NewEncoder(&doc)
		enc.SetIndent(2)
		if err := enc.Encode(map[string]allowlist.Workload{name + "-launches": w}); err != nil {
			return "", err
		}
		for _, line := range strings.Split(strings.TrimSuffix(doc.String(), "\n"), "\n") {
			b.WriteString("      " + line + "\n")
		}
	}
	return b.String(), nil
}
