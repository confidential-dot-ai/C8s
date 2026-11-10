//go:build !c8s_node

package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestImagePreflightUsesRequestedRepositories(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	const requested = "us-artifactregistry.gcr.io/gke-release/kube-proxy:v1"
	const alias = "gke.gcr.io/kube-proxy:v1"
	exempt := nriimagepolicy.ExemptRepositories{"kube-system": {"us-artifactregistry.gcr.io/gke-release/"}}
	for _, tc := range []struct {
		name, request, status string
		covered               bool
	}{
		{"runtime alias", requested, alias, true},
		{"status cannot grant exemption", alias, requested, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := daemonSetPod("kube-system", "proxy", tc.request, digest)
			pod.Status.ContainerStatuses[0].Image = tc.status
			pods := []corev1.Pod{pod}
			uncovered := uncoveredPlatformImages(pods, "c8s-system", exempt, nil)
			unknown := unresolvedImages(pods, "c8s-system", exempt)
			if (len(uncovered)+len(unknown) == 0) != tc.covered {
				t.Errorf("uncovered=%v, unknown=%v, want covered=%v", uncovered, unknown, tc.covered)
			}
			if got := exemptNamespaceImages(pods, exempt); (len(got) == 1) != tc.covered {
				t.Errorf("exempt images = %v, want covered=%v", got, tc.covered)
			}
		})
	}
}

func TestImagePreflightMatchesStatusByContainerNameAndKind(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	other := "sha256:" + strings.Repeat("2", 64)
	pod := deploymentPod("tenant", "app", "example.test/app:v1", digest)
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar", Image: "example.test/sidecar:v1"})
	pod.Spec.InitContainers = []corev1.Container{{Name: "prepare", Image: "example.test/init:v1"}}
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "example.test/debug:v1"}}}
	pod.Status.ContainerStatuses = append([]corev1.ContainerStatus{{Name: "sidecar", Image: "example.test/sidecar:v1", ImageID: other}}, pod.Status.ContainerStatuses...)
	pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{Name: "orphan", Image: "example.test/orphan:v1", ImageID: digest})
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "prepare", Image: "example.test/init:v1", ImageID: digest, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}
	pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "debug", Image: "example.test/debug:v1", ImageID: other}}
	got := uncoveredWorkloadImages([]corev1.Pod{pod}, "c8s-system", nil, nil)
	want := []string{
		"tenant/app  example.test/app@" + digest,
		"tenant/app  example.test/debug@" + other,
		"tenant/app  example.test/init@" + digest,
		"tenant/app  example.test/sidecar@" + other,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("uncovered images = %v, want %v", got, want)
	}
}

func TestImagePreflightReportsUnresolvedContainers(t *testing.T) {
	pod := daemonSetPod("addons", "pending", "example.test/app:v1", "")
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "example.test/init:v1"}}
	pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "example.test/debug:v1"}}}
	values := map[string]any{"nriImagePolicy": map[string]any{"policy": map[string]any{"mode": "fail-closed"}}}
	var out bytes.Buffer
	warn, err := preflightImagePolicy(&out, values, nil, nil, "c8s-system", []corev1.Pod{pod}, false)
	if err != nil || warn != "" {
		t.Fatalf("an unresolved image must remain advisory: warning=%q, error=%v", warn, err)
	}
	for _, want := range []string{"cannot resolve", "addons/pending (main)", "addons/pending (init)", "addons/pending (debug)", "example.test/app:v1", "example.test/init:v1", "example.test/debug:v1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report omits %q:\n%s", want, out.String())
		}
	}
}

func TestImagePreflightDoesNotUseStaleDigests(t *testing.T) {
	old := "sha256:" + strings.Repeat("1", 64)
	current := "sha256:" + strings.Repeat("2", 64)
	for _, tc := range []struct{ request, status string }{
		{"example.test/app:v2", "example.test/app:v1"},
		{"new.test/app:v2", "example.test/app:v1"},
		{"example.test/app@" + current, "example.test/app:v1"},
		{"example.test/app:v2", "example.test/app@" + old},
	} {
		pod := deploymentPod("tenant", "app", tc.request, old)
		pod.Status.ContainerStatuses[0].Image = tc.status
		images := collectPodImages([]corev1.Pod{pod}, func(corev1.Pod, podImage) bool { return true })
		if len(images) != 1 || images[0].digest != "" || images[0].unresolvedReason == "" {
			t.Errorf("request %s: images = %v, want an unresolved image", tc.request, images)
		}
	}
}

func TestImagePreflightUsesUnpulledSpecPins(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	pod := daemonSetPod("addons", "pinned", "example.test/app@"+digest, "")
	pod.Status.ContainerStatuses = nil
	if got := uncoveredPlatformImages([]corev1.Pod{pod}, "c8s-system", nil, nil); len(got) != 1 {
		t.Fatalf("unpulled pinned image = %v, want uncovered", got)
	}
	if got := uncoveredPlatformImages([]corev1.Pod{pod}, "c8s-system", nil, map[string]bool{digest: true}); len(got) != 0 {
		t.Fatalf("covered pin = %v, want none", got)
	}
}

func TestImagePreflightUsesServedWorkloadAndInitDigests(t *testing.T) {
	mainDigest := "sha256:" + testSeedDigest
	initDigest := "sha256:" + strings.Repeat("3", 64)
	otherDigest := "sha256:" + strings.Repeat("4", 64)
	document := strings.Replace(testSeedDocument("tenant"), `"tenant":{`, `"tenant":{"initContainers":[{"digest":"`+initDigest+`","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}],`, 1)
	served, err := pkgallowlist.ParseServedJSON([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]any{"nriImagePolicy": map[string]any{"policy": map[string]any{"mode": "fail-closed"}}}
	pods := []corev1.Pod{
		deploymentPod("tenant", "served-workload", "example.test/app:v1", mainDigest),
		deploymentPod("c8s-router", "served-router", "example.test/router:v1", mainDigest),
		daemonSetPod("addons", "served-init", "example.test/init:v1", initDigest),
		deploymentPod("tenant", "uncovered", "example.test/other:v1", otherDigest),
	}
	var out bytes.Buffer
	if warn, err := preflightImagePolicy(&out, values, nil, servedImageDigests(served), "c8s-system", pods, false); warn != "" || err != nil {
		t.Fatalf("served platform digest must be covered: warning=%q, error=%v", warn, err)
	}
	for _, name := range []string{"served-workload", "served-router", "served-init"} {
		if strings.Contains(out.String(), name) {
			t.Errorf("report falsely names %s:\n%s", name, out.String())
		}
	}
	if !strings.Contains(out.String(), "tenant/uncovered") {
		t.Errorf("report omits an uncovered workload:\n%s", out.String())
	}
	out.Reset()
	if _, err := preflightImagePolicy(&out, values, nil, nil, "c8s-system", pods, false); err == nil || !strings.Contains(err.Error(), "cannot confirm coverage") {
		t.Fatalf("unavailable CDS must preserve the platform guard: %v", err)
	}
	if !strings.Contains(out.String(), "served-workload") || !strings.Contains(out.String(), "served-router") {
		t.Errorf("unavailable CDS must report uncertain coverage:\n%s", out.String())
	}
}

func TestImagePreflightClassifiesBeforeDeduplicating(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	pods := []corev1.Pod{
		daemonSetPod("addons", "exempt", "provider.test/app:v1", digest),
		daemonSetPod("addons", "uncovered", "other.test/app:v1", digest),
	}
	exempt := nriimagepolicy.ExemptRepositories{"addons": {"provider.test/"}}
	for range 2 {
		got := uncoveredPlatformImages(pods, "c8s-system", exempt, nil)
		if len(got) != 1 || !strings.Contains(got[0], "addons/uncovered") {
			t.Fatalf("uncovered images = %v", got)
		}
		slices.Reverse(pods)
	}
}
