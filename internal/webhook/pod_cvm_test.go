package webhook

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const podCVMTestImage = "registry.example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func podCVMConfig() Config {
	cfg := meshConfig()
	cfg.PodCVMProviderEnabled = true
	return cfg
}

func podCVMWorkload() *corev1.Pod {
	pod := podWithApp()
	pod.Annotations = map[string]string{AnnotationPodCVM: "true"}
	pod.Spec.AutomountServiceAccountToken = new(false)
	pod.Spec.Containers[0].Image = podCVMTestImage
	return pod
}

func podCVMRequest(t *testing.T, old, pod *corev1.Pod, subresource string) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	req := podRequest("tenant", raw, subresource)
	if old != nil {
		oldRaw, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		req.Operation = admissionv1.Update
		req.OldObject = runtime.RawExtension{Raw: oldRaw}
	}
	return req
}

func assertPodCVMResponse(t *testing.T, cfg Config, req admission.Request, allowed bool, reason string) {
	t.Helper()
	m, v := meshHandlers(t, cfg)
	for name, handler := range map[string]admission.Handler{"mutator": m, "validator": v} {
		response := handler.Handle(t.Context(), req)
		if response.Allowed != allowed {
			t.Fatalf("%s allowed=%v, want %v: %+v", name, response.Allowed, allowed, response.Result)
		}
		if !allowed && (response.Result == nil || !strings.Contains(response.Result.Message, reason)) {
			t.Fatalf("%s denial=%+v, want %q", name, response.Result, reason)
		}
	}
}

func TestPodCVMCreateRoutesWithoutHostInjection(t *testing.T) {
	for _, serviceAccount := range []string{"", "default"} {
		t.Run("service-account="+serviceAccount, func(t *testing.T) {
			m, v := meshHandlers(t, podCVMConfig())
			pod := podCVMWorkload()
			pod.Namespace = ""
			pod.Spec.ServiceAccountName = serviceAccount
			pod.Spec.NodeSelector = map[string]string{"topology.kubernetes.io/zone": "zone-a"}
			pod.Spec.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/arch", Operator: corev1.NodeSelectorOpIn, Values: []string{"amd64"}}},
				}}},
			}}
			pod.Spec.Tolerations = []corev1.Toleration{{Key: "maintenance", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute}}
			mutated := admit(t, m, pod, "tenant")
			if mutated.UID != "" || mutated.Spec.NodeName != "" {
				t.Fatal("CREATE supplied identity or bypassed the Kubernetes scheduler")
			}
			if mutated.Spec.NodeSelector[AnnotationPodCVM] != "true" || mutated.Spec.NodeSelector["topology.kubernetes.io/zone"] != "zone-a" {
				t.Fatal("mutation did not combine the virtual node selector with existing scheduling constraints")
			}
			if !reflect.DeepEqual(mutated.Spec.Affinity, pod.Spec.Affinity) || len(mutated.Spec.Tolerations) != 2 || mutated.Spec.Tolerations[0] != pod.Spec.Tolerations[0] {
				t.Fatal("mutation discarded the workload's scheduler constraints")
			}
			if len(mutated.Spec.InitContainers) != 0 || mutated.Annotations[AnnotationInjected] != "" || len(mutated.Spec.Volumes) != 0 {
				t.Fatal("Pod CVM received host-owned platform containers or credential mounts")
			}
			if !reflect.DeepEqual(mutated.Spec.Containers, pod.Spec.Containers) {
				t.Fatal("host mutation changed guest workload containers")
			}
			if response := validate(t, v, mutated, "tenant"); !response.Allowed {
				t.Fatalf("validator rejected routed Pod: %+v", response.Result)
			}
			if second := admit(t, m, mutated, "tenant"); !reflect.DeepEqual(second, mutated) {
				t.Fatal("Pod CVM mutation is not idempotent")
			}
		})
	}
}

func TestPodCVMValidatorRequiresRoutingWithoutMutator(t *testing.T) {
	_, v := meshHandlers(t, podCVMConfig())
	pod := podCVMWorkload()
	for _, missing := range []string{"both", "selector", "toleration"} {
		t.Run(missing, func(t *testing.T) {
			candidate := pod.DeepCopy()
			if err := routePodCVM(candidate, true); err != nil {
				t.Fatal(err)
			}
			if missing != "toleration" {
				candidate.Spec.NodeSelector = nil
			}
			if missing != "selector" {
				candidate.Spec.Tolerations = nil
			}
			response := validate(t, v, candidate, "tenant")
			if response.Allowed || !strings.Contains(response.Result.Message, "missing its required") {
				t.Fatalf("unrouted Pod accepted: %+v", response.Result)
			}
		})
	}
}

func TestPodCVMRejectsUnsupportedGuestRequests(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*corev1.Pod)
		want   string
	}{
		{"implicit automount", func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = nil }, "automountServiceAccountToken"},
		{"enabled automount", func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = new(true) }, "automountServiceAccountToken"},
		{"service account", func(p *corev1.Pod) { p.Spec.ServiceAccountName = "privileged" }, "service account"},
		{"unpinned image", func(p *corev1.Pod) { p.Spec.Containers[0].Image = "registry.example/app:latest" }, "pin the image"},
		{"unpinned init", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "registry.example/init:latest"}}
		}, "pin the image"},
		{"host network", func(p *corev1.Pod) { p.Spec.HostNetwork = true }, "host namespaces"},
		{"host PID", func(p *corev1.Pod) { p.Spec.HostPID = true }, "host namespaces"},
		{"host IPC", func(p *corev1.Pod) { p.Spec.HostIPC = true }, "host namespaces"},
		{"shared PID", func(p *corev1.Pod) { p.Spec.ShareProcessNamespace = new(true) }, "shareProcessNamespace"},
		{"host port", func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8080, HostPort: 8080}}
		}, "hostPort"},
		{"privileged", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: new(true)}
		}, "privileged"},
		{"secret volume", func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "secret", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "secret"}}}}
		}, "only emptyDir"},
		{"disk emptyDir", func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		}, "medium: Memory"},
		{"image pull secret", func(p *corev1.Pod) { p.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "registry"}} }, "imagePullSecrets"},
		{"secret environment", func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "token"}}}}
		}, "environment references"},
		{"ConfigMap environment", func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "CONFIG", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{Key: "config"}}}}
		}, "environment references"},
		{"envFrom", func(p *corev1.Pod) { p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{Prefix: "EXTERNAL_"}} }, "envFrom"},
		{"runtime class", func(p *corev1.Pod) { p.Spec.RuntimeClassName = new("other") }, "runtimeClassName"},
		{"prebound", func(p *corev1.Pod) { p.Spec.NodeName = "physical-worker" }, "Kubernetes scheduler"},
		{"selector conflict", func(p *corev1.Pod) { p.Spec.NodeSelector[AnnotationPodCVM] = "false" }, "selector conflicts"},
		{"toleration conflict", func(p *corev1.Pod) { p.Spec.Tolerations[0].Value = "false" }, "exact NoSchedule"},
		{"host injection", func(p *corev1.Pod) { p.Annotations[AnnotationInjected] = "true" }, "host-side injection"},
		{"host secret request", func(p *corev1.Pod) { p.Annotations[AnnotationSecrets] = "TOKEN=/workload/token" }, "host-side injection"},
		{"platform container", func(p *corev1.Pod) { p.Spec.Containers[0].Name = workloadclaims.MeshContainerName }, "reserved"},
		{"foreign namespace", func(p *corev1.Pod) { p.Namespace = "other" }, "namespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := podCVMWorkload()
			if err := routePodCVM(pod, true); err != nil {
				t.Fatal(err)
			}
			tc.change(pod)
			assertPodCVMResponse(t, podCVMConfig(), podCVMRequest(t, nil, pod, ""), false, tc.want)
		})
	}
}

func TestPodCVMRejectsAlreadyProjectedServiceAccountToken(t *testing.T) {
	pod := podAfterServiceAccountAdmission()
	pod.Annotations = map[string]string{AnnotationPodCVM: "true"}
	pod.Spec.AutomountServiceAccountToken = new(false)
	pod.Spec.Containers[0].Image = podCVMTestImage
	pod.Spec.InitContainers[0].Image = podCVMTestImage
	assertPodCVMResponse(t, podCVMConfig(), podCVMRequest(t, nil, pod, ""), false, "only emptyDir")
}

func TestPodCVMModeCannotChangeOnUpdate(t *testing.T) {
	for _, previous := range []bool{false, true} {
		old := podCVMWorkload()
		if !previous {
			delete(old.Annotations, AnnotationPodCVM)
		}
		updated := old.DeepCopy()
		if previous {
			delete(updated.Annotations, AnnotationPodCVM)
		} else {
			updated.Annotations[AnnotationPodCVM] = "true"
		}
		assertPodCVMResponse(t, podCVMConfig(), podCVMRequest(t, old, updated, ""), false, "fixed when the Pod is created")
	}
	req := podCVMRequest(t, nil, podCVMWorkload(), "")
	req.Operation = admissionv1.Update
	assertPodCVMResponse(t, podCVMConfig(), req, false, "previous Pod")
}

func TestScheduledPodCVMFreezesWorkloadAndReferencedMetadata(t *testing.T) {
	old := podCVMWorkload()
	old.Spec.NodeName = "pod-cvm-provider"
	old.Labels = map[string]string{"release": "one"}
	old.Annotations["tenant/config"] = "one"
	old.Spec.Containers[0].Env = []corev1.EnvVar{
		{Name: "RELEASE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.labels['release']"}}},
		{Name: "CONFIG", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.annotations['tenant/config']"}}},
	}
	if err := routePodCVM(old, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*corev1.Pod)
	}{
		{"image", func(p *corev1.Pod) { p.Spec.Containers[0].Image = strings.ReplaceAll(podCVMTestImage, "a", "b") }},
		{"arguments", func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"changed"} }},
		{"assignment", func(p *corev1.Pod) { p.Spec.NodeName = "another-node" }},
		{"selector", func(p *corev1.Pod) { delete(p.Spec.NodeSelector, AnnotationPodCVM) }},
		{"toleration", func(p *corev1.Pod) { p.Spec.Tolerations = nil }},
		{"referenced label", func(p *corev1.Pod) { p.Labels["release"] = "two" }},
		{"referenced annotation", func(p *corev1.Pod) { p.Annotations["tenant/config"] = "two" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updated := old.DeepCopy()
			tc.change(updated)
			assertPodCVMResponse(t, podCVMConfig(), podCVMRequest(t, old, updated, ""), false, "immutable")
		})
	}
	for _, enabled := range []bool{false, true} {
		cfg := podCVMConfig()
		cfg.PodCVMProviderEnabled = enabled
		updated := old.DeepCopy()
		updated.Finalizers = []string{"confidential.ai/pod-cvm"}
		updated.Labels["controller.example/observed"] = "yes"
		updated.Annotations["confidential.ai/pod-cvm-endpoints"] = "[]"
		updated.Status.Phase = corev1.PodRunning
		for _, subresource := range []string{"", "status"} {
			assertPodCVMResponse(t, cfg, podCVMRequest(t, old, updated, subresource), true, "")
		}
	}
}

func TestPodCVMSchedulerCanBindPendingPod(t *testing.T) {
	old := podCVMWorkload()
	if err := routePodCVM(old, true); err != nil {
		t.Fatal(err)
	}
	bound := old.DeepCopy()
	bound.Spec.NodeName = "pod-cvm-provider"
	assertPodCVMResponse(t, podCVMConfig(), podCVMRequest(t, old, bound, ""), true, "")
}

func TestPodCVMDisabledAndEphemeralContainersFailClosed(t *testing.T) {
	pod := podCVMWorkload()
	assertPodCVMResponse(t, meshConfig(), podCVMRequest(t, nil, pod, ""), false, "provider is disabled")
	assertPodCVMResponse(t, podCVMConfig(), podCVMRequest(t, pod, pod, "ephemeralcontainers"), false, "ephemeralcontainers")
	pod.Annotations[AnnotationPodCVM] = "TRUE"
	assertPodCVMResponse(t, podCVMConfig(), podCVMRequest(t, nil, pod, ""), false, "must be true or false")
}

func TestPodCVMNodeCannotBeSelectedWithoutOptIn(t *testing.T) {
	for _, change := range []func(*corev1.Pod){
		func(p *corev1.Pod) { p.Spec.NodeSelector = map[string]string{AnnotationPodCVM: "true"} },
		func(p *corev1.Pod) {
			p.Spec.Tolerations = []corev1.Toleration{{Key: AnnotationPodCVM, Operator: corev1.TolerationOpExists}}
		},
		func(p *corev1.Pod) { p.Spec.Tolerations = []corev1.Toleration{{Operator: corev1.TolerationOpExists}} },
		func(p *corev1.Pod) {
			p.Spec.Tolerations = []corev1.Toleration{{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
		},
	} {
		pod := podWithApp()
		change(pod)
		assertPodCVMResponse(t, podCVMConfig(), podCVMRequest(t, nil, pod, ""), false, AnnotationPodCVM)
	}
}

func TestPodCVMPreservesOrdinaryHostMeshInjection(t *testing.T) {
	m, v := meshHandlers(t, podCVMConfig())
	pod := podWithApp()
	mutated := admit(t, m, pod, "tenant")
	if containerNamed(mutated, workloadclaims.MeshContainerName) == nil || containerNamed(mutated, workloadclaims.CertContainerName) == nil {
		t.Fatal("ordinary workload lost host mesh or credential injection")
	}
	if mutated.Spec.NodeSelector[AnnotationPodCVM] != "" {
		t.Fatal("ordinary workload was routed to the virtual node")
	}
	if response := validate(t, v, mutated, "tenant"); !response.Allowed {
		t.Fatalf("ordinary injected Pod refused: %+v", response.Result)
	}
	disabled, _ := meshHandlers(t, Config{})
	pod.Spec.Tolerations = []corev1.Toleration{{Operator: corev1.TolerationOpExists}}
	if response := disabled.Handle(context.Background(), podCVMRequest(t, nil, pod, "")); !response.Allowed {
		t.Fatalf("disabled provider changed ordinary passthrough: %+v", response.Result)
	}
}
