package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type workloadRef struct {
	kind      string
	name      string
	namespace string
	// port is the TLS port from the ref's optional :<port> suffix, or 0 when
	// absent. Only consumed for the ref --upstream selects.
	port int
}

type workloadAdoption struct {
	cwID string
	ref  workloadRef
}

func validateWorkloadAdoptionFlags(releaseNamespace string, adoptions []workloadAdoption, wait bool) error {
	if len(adoptions) == 0 {
		return nil
	}
	uninjected := []string{releaseNamespace, workloadclaims.RouterNamespace}
	for _, a := range adoptions {
		if slices.Contains(uninjected, a.ref.namespace) {
			return fmt.Errorf("--%s cannot target %q; that namespace is excluded from c8s workload injection", flagWorkloadRef, a.ref.namespace)
		}
	}
	if !wait {
		return fmt.Errorf("--%s requires --wait=true so the c8s webhook is ready before existing workloads roll", flagWorkloadRef)
	}
	return nil
}

// upstreamAddress derives the --upstream route's backend address from the
// adopted workload it names: its headless-Service FQDN with the port from that
// ref's :<port> suffix, so the router dials the Service the operator
// provisions. Empty --upstream yields "".
func upstreamAddress(upstream string, adoptions []workloadAdoption) (string, error) {
	if upstream == "" {
		return "", nil
	}
	for _, a := range adoptions {
		if a.cwID == upstream {
			if a.ref.port == 0 {
				return "", fmt.Errorf("--%s %q names a --%s with no :<port>; add the upstream port to that ref (<cw-id>=<namespace>/<kind>/<name>:<port>)", flagUpstream, upstream, flagWorkloadRef)
			}
			return fmt.Sprintf("%s:%d", webhook.WorkloadServiceFQDN(upstream, a.ref.namespace), a.ref.port), nil
		}
	}
	return "", fmt.Errorf("--%s %q must name a --%s confidential.ai/cw id so router routes to an adopted workload", flagUpstream, upstream, flagWorkloadRef)
}

func collectWorkloadAdoptions(rawRefs []string) ([]workloadAdoption, error) {
	adoptions := make([]workloadAdoption, 0, len(rawRefs))
	for _, raw := range rawRefs {
		cwID, refText, err := parseWorkloadAdoptionRef(raw)
		if err != nil {
			return nil, err
		}
		if err := validateWorkloadID(cwID, flagWorkloadRef); err != nil {
			return nil, err
		}
		ref, err := parseWorkloadRef(refText, flagWorkloadRef)
		if err != nil {
			return nil, err
		}
		adoptions = append(adoptions, workloadAdoption{cwID: cwID, ref: ref})
	}
	return dedupeWorkloadAdoptions(adoptions)
}

func validateWorkloadID(cwID, flagName string) error {
	if webhook.WorkloadServiceName(cwID) == "" {
		return fmt.Errorf("--%s confidential.ai/cw id %q must make c8s-<id> a DNS-1035 label: start with a letter, then lowercase letters, digits, or '-', end alphanumeric, <=63 chars total", flagName, cwID)
	}
	return nil
}

func parseWorkloadAdoptionRef(raw string) (cwID, ref string, err error) {
	cwID, ref, ok := strings.Cut(strings.TrimSpace(raw), "=")
	if !ok || strings.TrimSpace(cwID) == "" || strings.TrimSpace(ref) == "" {
		return "", "", errWorkloadRefFormat(flagWorkloadRef)
	}
	return strings.TrimSpace(cwID), strings.TrimSpace(ref), nil
}

func dedupeWorkloadAdoptions(in []workloadAdoption) ([]workloadAdoption, error) {
	seenByWorkload := map[string]workloadAdoption{}
	seenByCWID := map[string]string{}
	out := make([]workloadAdoption, 0, len(in))
	for _, a := range in {
		key := a.ref.namespace + "/" + a.ref.kind + "/" + a.ref.name
		if existing, ok := seenByWorkload[key]; ok {
			if existing.cwID != a.cwID {
				return nil, fmt.Errorf("workload %s is listed with conflicting confidential.ai/cw ids %q and %q", key, existing.cwID, a.cwID)
			}
			if existing.ref.port != a.ref.port {
				return nil, fmt.Errorf("workload %s is listed with conflicting upstream ports %d and %d", key, existing.ref.port, a.ref.port)
			}
			continue
		}
		// One cw id names one confidential workload: it maps to a single
		// c8s-<id> headless Service whose selector matches every pod carrying
		// the label, so two different workloads under one id would silently
		// share an identity and cross-wire that Service's endpoints.
		if other, ok := seenByCWID[a.cwID]; ok {
			return nil, fmt.Errorf("confidential.ai/cw id %q is assigned to two different workloads %s and %s", a.cwID, other, key)
		}
		seenByWorkload[key] = a
		seenByCWID[a.cwID] = key
		out = append(out, a)
	}
	return out, nil
}

func parseWorkloadRef(ref, flagName string) (workloadRef, error) {
	namespace, rest, ok := strings.Cut(ref, "/")
	if !ok {
		return workloadRef{}, errWorkloadRefFormat(flagName)
	}
	kind, namePort, ok := strings.Cut(rest, "/")
	if !ok || namespace == "" || kind == "" || namePort == "" || strings.Contains(namePort, "/") {
		return workloadRef{}, errWorkloadRefFormat(flagName)
	}
	// The <name> may carry an optional :<port> upstream suffix.
	name, portText, hasPort := strings.Cut(namePort, ":")
	if name == "" {
		return workloadRef{}, errWorkloadRefFormat(flagName)
	}
	port := 0
	if hasPort {
		// strconv.Itoa round-trip rejects non-canonical spellings Atoi would
		// otherwise accept (a leading '+' or sign, or leading zeros).
		p, err := strconv.Atoi(portText)
		if err != nil || strconv.Itoa(p) != portText || len(validation.IsValidPortNum(p)) > 0 {
			return workloadRef{}, fmt.Errorf("--%s port %q in %q must be an integer in 1-65535", flagName, portText, ref)
		}
		port = p
	}
	// namespace and name are DNS-1123 subdomains; reject anything else here so a
	// bad ref fails with a clear message instead of an opaque kubectl error.
	if errs := validation.IsDNS1123Subdomain(namespace); len(errs) > 0 {
		return workloadRef{}, fmt.Errorf("--%s namespace %q is not a valid DNS-1123 subdomain: %s", flagName, namespace, strings.Join(errs, "; "))
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return workloadRef{}, fmt.Errorf("--%s workload name %q is not a valid DNS-1123 subdomain: %s", flagName, name, strings.Join(errs, "; "))
	}
	return workloadRef{kind: normalizeWorkloadKind(kind), name: name, namespace: namespace, port: port}, nil
}

func errWorkloadRefFormat(flagName string) error {
	return fmt.Errorf("--%s must be <cw-id>=<namespace>/<kind>/<name>[:<port>] (kind is any resource exposing a pod template at spec.template, e.g. deployment, statefulset, daemonset, or an operator CRD; :<port> is the TLS port the router dials, required on the --upstream ref)", flagName)
}

// normalizeWorkloadKind canonicalizes the built-in aliases and passes any other
// kind through verbatim for kubectl to resolve. A dotted kind.group form is
// accepted; parseWorkloadRef splits on the first '/', so the group survives.
func normalizeWorkloadKind(kind string) string {
	lower := strings.ToLower(kind)
	switch lower {
	case "deployment", "deploy", "deployments":
		return "deployment"
	case "statefulset", "sts", "statefulsets":
		return "statefulset"
	case "daemonset", "ds", "daemonsets":
		return "daemonset"
	}
	return lower
}

func patchAdoptedWorkload(ctx context.Context, ref workloadRef, workloadID string) error {
	patch, err := confidentialWorkloadPatch(workloadID)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "+ kubectl patch %s %s -n %s --type merge # set pod-template %s=%s\n", ref.kind, ref.name, ref.namespace, webhook.AnnotationWorkload, workloadID)
	kc := exec.CommandContext(ctx, "kubectl", "patch", ref.kind, ref.name, "-n", ref.namespace, "--type", "merge", "-p", string(patch))
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("patch adopted workload %s/%s in namespace %s: %w", ref.kind, ref.name, ref.namespace, err)
	}
	return nil
}

func confidentialWorkloadPatch(workloadID string) ([]byte, error) {
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{
						webhook.AnnotationWorkload: workloadID,
					},
				},
			},
		},
	}
	return json.Marshal(patch)
}

func adoptedWorkloadTemplate(ctx context.Context, ref workloadRef) (corev1.PodTemplateSpec, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", ref.kind, ref.name, "-n", ref.namespace, "-o", "json").CombinedOutput()
	if err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("preflight adopted workload %s/%s in namespace %s: kubectl get failed: %w: %s", ref.kind, ref.name, ref.namespace, err, strings.TrimSpace(string(out)))
	}
	template, err := workloadPodTemplate(out)
	if err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("read adopted workload %s/%s in namespace %s: %w", ref.kind, ref.name, ref.namespace, err)
	}
	return template, nil
}

// reportAdoptedImages prints the images C8s pins into the NRI allowlist for one
// adopted workload, and flags each image referenced by a mutable tag rather than
// a digest. A tag is a TOCTOU risk: the digest read here (and pinned) can differ
// from what the operator's rollout actually pulls later. An unparseable ref is
// reported verbatim; workloadImageAllowlistEntry rejects it downstream.
func reportAdoptedImages(a workloadAdoption, images []string) {
	fmt.Fprintf(os.Stdout, "+ adopt %s -> %s/%s/%s (%d image(s))\n", a.cwID, a.ref.namespace, a.ref.kind, a.ref.name, len(images))
	for _, image := range images {
		fmt.Fprintf(os.Stdout, "    %s\n", image)
		if !imagePinnedByDigest(image) {
			fmt.Fprintf(os.Stderr, "warning: adopted workload %s image %s is pinned by tag, not digest; the digest resolved now may differ from what the rollout pulls\n", a.cwID, image)
		}
	}
}

// imagePinnedByDigest reports whether an image reference carries an explicit
// digest. An unparseable ref counts as not pinned (its parse fails again,
// fatally, in workloadImageAllowlistEntry).
func imagePinnedByDigest(image string) bool {
	named, err := reference.ParseDockerRef(image)
	if err != nil {
		return false
	}
	_, pinned := named.(reference.Digested)
	return pinned
}

// workloadPodTemplate reads the pod template at spec.template, which every
// supported kind exposes. A kind without one yields an empty template.
func workloadPodTemplate(data []byte) (corev1.PodTemplateSpec, error) {
	var workload struct {
		Spec struct {
			Template corev1.PodTemplateSpec `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(data, &workload); err != nil {
		return corev1.PodTemplateSpec{}, fmt.Errorf("decode pod template: %w", err)
	}
	return workload.Spec.Template, nil
}

// podImages are a pod template's images, init and main containers apart: a
// declared init container may have exited, so an allowlist entry must list it
// as one or a pod past its init phase would not match it.
type podImages struct {
	Init []string
	Main []string
}

// all returns every image once, init containers first.
func (p podImages) all() []string {
	return append(slices.Clone(p.Init), p.Main...)
}

func podTemplateImages(template corev1.PodTemplateSpec) podImages {
	var images podImages
	seen := map[string]bool{}
	// Main first: an image that also runs as an init container is declared
	// once, as a main, which admits it in both roles.
	for _, c := range template.Spec.Containers {
		if c.Image != "" && !seen[c.Image] {
			seen[c.Image] = true
			images.Main = append(images.Main, c.Image)
		}
	}
	for _, c := range template.Spec.InitContainers {
		if c.Image != "" && !seen[c.Image] {
			seen[c.Image] = true
			images.Init = append(images.Init, c.Image)
		}
	}
	// EphemeralContainers are intentionally skipped: they cannot be set on a
	// workload pod template (only added to a live Pod via the ephemeralcontainers
	// subresource), so a workload read here never carries them.
	return images
}

// adoptedWorkload is one --workload-ref with its pod template.
type adoptedWorkload struct {
	workloadAdoption
	template corev1.PodTemplateSpec
}

// injectedMountRules lists the container's memory-backed emptyDir destinations.
func injectedMountRules(template corev1.PodTemplateSpec, c corev1.Container) ([]string, error) {
	for _, a := range []string{webhook.AnnotationSecrets, webhook.AnnotationVolumes} {
		if template.Annotations[a] != "" {
			return nil, fmt.Errorf("it requests %s, whose injected mounts install does not model", a)
		}
	}
	certVolume := webhook.CertVolumeName
	volumes := map[string]corev1.Volume{}
	for _, v := range template.Spec.Volumes {
		volumes[v.Name] = v
	}
	var dests []string
	for _, m := range c.VolumeMounts {
		v, ok := volumes[m.Name]
		switch {
		case m.SubPath != "" || m.SubPathExpr != "":
			return nil, fmt.Errorf("container %s mounts a subPath of volume %s at %s, which the node observes as a data mount", c.Name, m.Name, m.MountPath)
		case !ok && m.Name == certVolume:
		case !ok:
			return nil, fmt.Errorf("container %s mounts undeclared volume %s", c.Name, m.Name)
		case v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory:
			return nil, fmt.Errorf("container %s mounts volume %s at %s, which is not a memory-backed emptyDir", c.Name, m.Name, m.MountPath)
		}
		dests = append(dests, path.Clean(m.MountPath))
	}
	sort.Strings(dests)
	return dests, nil
}

// adoptedEntry is the allowlist entry install writes for one adopted workload
// and the pod CDS matches it against once the pod runs: its main containers
// and native sidecars, with the mounts the node observes. A completed init
// container is not in pod; the entry declares it, so it may be absent.
type adoptedEntry struct {
	workload pkgallowlist.Workload
	pod      []pkgallowlist.RunningContainer
}

func appendResolvedWorkloadImageArgs(ctx context.Context, helmArgs []string, workloads []adoptedWorkload, upstream string) ([]string, map[string]adoptedEntry, error) {
	return buildWorkloadImageArgs(helmArgs, workloads, upstream, os.Stderr, func(ref string) (string, error) {
		digest, err := crane.Digest(ctx, ref)
		if err != nil {
			return "", err
		}
		return digest, nil
	})
}

// buildWorkloadImageArgs renders one bootstrapAllowlist.workloads entry per
// adopted workload, named after its cw id and declaring every container of its
// pod template, in its own role, under any command, args and env. Mounts are
// exact: each container may mount only what the injected pod mounts
// (injectedMountRules), so a host that adds a hostPath over the app's code or
// config gets no admission and no name. Containers with the same image and
// mounts are declared once; an init container also run as a main is admitted
// by the main. One entry for the whole container set is what lets CDS match a
// multi-container pod and stamp the cw id on its leaf, which a workload route
// backend requires (route policy B1).
//
// A workload whose mounts cannot be modelled exactly is refused when it is the
// upstream cw id; any other gets an entry admitting any mounts, a warning on
// warn, and no entry in the returned map.
func buildWorkloadImageArgs(helmArgs []string, workloads []adoptedWorkload, upstream string, warn io.Writer, resolve func(ref string) (string, error)) ([]string, map[string]adoptedEntry, error) {
	entries := map[string]adoptedEntry{}
	for _, w := range workloads {
		prefix := "nriImagePolicy.bootstrapAllowlist.workloads." + w.cwID + "."
		label := w.ref.namespace + "/" + w.ref.kind + "/" + w.ref.name
		helmArgs = append(helmArgs, "--set-string", prefix+"label="+label)
		e := adoptedEntry{workload: pkgallowlist.Workload{Label: label}}
		containers := slices.Concat(w.template.Spec.Containers, w.template.Spec.InitContainers)
		mounts := make([][]string, len(containers))
		exact := true
		for i, c := range containers {
			if c.Image == "" {
				continue
			}
			var err error
			if mounts[i], err = injectedMountRules(w.template, c); err != nil {
				if w.cwID == upstream {
					return nil, nil, fmt.Errorf("adopted workload %s: %w; install cannot write its allowlist entry, so write one named %q yourself (c8s allowlist)", w.cwID, err, w.cwID)
				}
				fmt.Fprintf(warn, "warning: adopted workload %s: %v; install writes its allowlist entry with any mounts, so a route to it trusts those mounts\n", w.cwID, err)
				exact = false
				break
			}
		}
		mains := len(w.template.Spec.Containers)
		for i, c := range containers {
			if c.Image == "" {
				continue
			}
			digest, ref, err := workloadImageAllowlistEntry(c.Image, resolve)
			if err != nil {
				return nil, nil, err
			}
			declared := adoptedContainer(digest, ref, mounts[i], exact)
			init := i >= mains
			if !init || c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
				e.pod = append(e.pod, observedContainer(digest, mounts[i]))
			}
			same := func(o pkgallowlist.Container) bool {
				return o.Digest == declared.Digest && slices.Equal(o.Mounts.Rules, declared.Mounts.Rules)
			}
			if slices.ContainsFunc(e.workload.Containers, same) || init && slices.ContainsFunc(e.workload.InitContainers, same) {
				continue
			}
			field, list := "containers", &e.workload.Containers
			if init {
				field, list = "initContainers", &e.workload.InitContainers
			}
			helmArgs = append(helmArgs, containerArgs(fmt.Sprintf("%s%s[%d].", prefix, field, len(*list)), declared)...)
			*list = append(*list, declared)
		}
		if exact {
			entries[w.cwID] = e
		}
	}
	return helmArgs, entries, nil
}

// adoptedContainer declares digest under any command, args and env. With
// exact, it mounts exactly the memory-backed emptyDirs at dests; without, any
// mounts.
func adoptedContainer(digest types.Digest, ref string, dests []string, exact bool) pkgallowlist.Container {
	c := pkgallowlist.Container{
		Digest:  digest,
		Image:   ref,
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		Env:     pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyAny},
	}
	if exact && len(dests) == 0 {
		c.Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyDeny}
	} else if exact {
		rules := make([]pkgallowlist.MountRule, 0, len(dests))
		for _, dest := range dests {
			rules = append(rules, pkgallowlist.MountRule{Destination: dest, Kind: pkgallowlist.MountEmptyDir})
		}
		c.Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyExact, Rules: rules}
	} else {
		c.Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyAny}
	}
	return c
}

// observedContainer is digest running with the memory-backed emptyDirs at
// dests, as the node reports it. Its argv is unknown to install.
func observedContainer(digest types.Digest, dests []string) pkgallowlist.RunningContainer {
	mounts := []pkgallowlist.ObservedMount{}
	for _, dest := range dests {
		mounts = append(mounts, pkgallowlist.ObservedMount{Destination: dest, Class: pkgallowlist.MountEmptyDir, Storage: pkgallowlist.MountMemory})
	}
	return pkgallowlist.RunningContainer{Digest: digest.String(), Argv: []string{}, Mounts: mounts}
}

func containerArgs(key string, c pkgallowlist.Container) []string {
	args := []string{
		"--set-string", key + "digest=" + c.Digest.String(),
		"--set-string", key + "image=" + c.Image,
		"--set-string", key + "command.policy=any",
		"--set-string", key + "args.policy=any",
		"--set-string", key + "env.policy=any",
	}
	if c.Mounts.Policy != "" {
		args = append(args, "--set-string", key+"mounts.policy="+c.Mounts.Policy)
	}
	for i, r := range c.Mounts.Rules {
		rule := fmt.Sprintf("%smounts.rules[%d].", key, i)
		args = append(args, "--set-string", rule+"destination="+r.Destination, "--set-string", rule+"kind="+string(r.Kind))
	}
	return args
}

// describers returns, sorted, the entries that describe pod once their
// command, args and env admit any: install cannot see the pod's argv or env,
// so an entry admitting its images and mounts under some argv counts.
func describers(workloads map[string]pkgallowlist.Workload, pod []pkgallowlist.RunningContainer) []string {
	var names []string
	for name, w := range workloads {
		if anyProcess(w).Diff(pod).Describes() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// checkAdoptedEntries refuses an adopted workload whose pod another entry of
// the seed this install renders also describes. CDS would then match neither,
// the pod's leaf would carry no workload name, and the router would refuse it
// as a workload backend. The seed is the chart's own (seedWorkloads).
func checkAdoptedEntries(adopted map[string]adoptedEntry, values map[string]any) error {
	if len(adopted) == 0 {
		return nil
	}
	seed, err := seedWorkloads(values)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(adopted)) {
		names := describers(seed, adopted[name].pod)
		if !slices.Contains(names, name) {
			return fmt.Errorf("the allowlist entry %s does not describe the pod of adopted workload %s; drop the -f entry of that name", name, name)
		}
		if others := slices.DeleteFunc(names, func(n string) bool { return n == name }); len(others) > 0 {
			return fmt.Errorf("adopted workload %s runs only images and mounts that allowlist entries %s also admit, so CDS cannot tell which entry names its pod and stamps none; give it an image of its own", name, strings.Join(others, ", "))
		}
	}
	return nil
}

// seedWorkloads mirrors the chart's c8s.allowlistSeedJSON from the values it
// renders, less the entries that pin their command lines: the
// bootstrapAllowlist.workloads entries. A component entry pins its command,
// args and mount table (c8s.podShapes), so it describes only the component's
// own pod.
func seedWorkloads(values map[string]any) (map[string]pkgallowlist.Workload, error) {
	seed := map[string]pkgallowlist.Workload{}
	workloads, _ := nestedMap(values, "nriImagePolicy", "bootstrapAllowlist", "workloads")
	for name, raw := range workloads {
		data, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		w, err := pkgallowlist.ParseWorkloadJSON(data)
		if err != nil {
			return nil, fmt.Errorf("nriImagePolicy.bootstrapAllowlist.workloads.%s: %w", name, err)
		}
		seed[name] = *w
	}
	return seed, nil
}

func workloadImageAllowlistEntry(image string, resolve func(ref string) (string, error)) (digest types.Digest, ref string, err error) {
	named, err := reference.ParseDockerRef(image)
	if err != nil {
		return types.Digest{}, "", fmt.Errorf("parse adopted workload image %q: %w", image, err)
	}
	repo := reference.TrimNamed(named).String()
	raw := ""
	if digested, ok := named.(reference.Digested); ok {
		raw = digested.Digest().String()
	} else if raw, err = resolve(named.String()); err != nil {
		return types.Digest{}, "", err
	}
	// ParseDigest enforces sha256:<64 hex> (NRI allowlist keys must be sha256)
	// and lowercases the hex so the emitted key matches containerd's lookup form.
	parsed, err := types.ParseDigest(raw)
	if err != nil {
		return types.Digest{}, "", fmt.Errorf("adopted workload image %q digest %q is not sha256; NRI allowlist entries must be sha256: %w", image, raw, err)
	}
	return parsed, repo + "@" + parsed.String(), nil
}
