package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestAdmissionRequiresInventoryForEveryInjection(t *testing.T) {
	for _, annotated := range []bool{false, true} {
		cfg := meshConfig()
		cfg.WorkloadClaimsHostDir = ""
		m, v := meshHandlers(t, cfg)
		pod := podWithApp()
		if annotated {
			pod.Annotations = map[string]string{AnnotationWorkload: "api"}
		}
		inj, err := parseAnnotations(pod, "tenant")
		if err != nil {
			t.Fatal(err)
		}
		injected := pod.DeepCopy()
		mutatePod(injected, inj, cfg)
		for name, response := range map[string]bool{
			"mutator":   mutationResponse(t, m, pod).Allowed,
			"validator": validate(t, v, injected, "tenant").Allowed,
		} {
			if response {
				t.Errorf("%s admitted injection without inventory (annotated=%v)", name, annotated)
			}
		}
		cfg.GetCertImage = ""
		m, v = meshHandlers(t, cfg)
		if !mutationResponse(t, m, pod).Allowed || !validate(t, v, pod, "tenant").Allowed {
			t.Error("disabled injection denied the pod")
		}
	}
}

func TestAdmissionRejectsDetailsWithoutWorkload(t *testing.T) {
	cfg := meshConfig()
	m, v := meshHandlers(t, cfg)
	for _, annotation := range []string{AnnotationSecrets, AnnotationVolumes} {
		pod := podWithApp()
		pod.Annotations = map[string]string{annotation: "DB=/api/db"}
		if mutationResponse(t, m, pod).Allowed || validate(t, v, pod, "tenant").Allowed {
			t.Errorf("admitted %s without cw", annotation)
		}
	}
}

func mutationResponse(t *testing.T, m *podMutator, pod *corev1.Pod) admission.Response {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return m.Handle(context.Background(), podRequest("tenant", raw, ""))
}

func TestInitialMutationRejectsRenderedProbes(t *testing.T) {
	m, v := meshHandlers(t, meshConfig())
	for _, forgedShape := range []bool{false, true} {
		pod := podWithProbedApp()
		if forgedShape {
			pod = admit(t, m, pod, "tenant")
		} else {
			pod.Spec.Containers[0].ReadinessProbe.HTTPGet.Path = "/probe/8080/healthz"
			pod.Spec.Containers[0].ReadinessProbe.HTTPGet.Port = intstr.FromInt32(15021)
		}
		if mutationResponse(t, m, pod).Allowed {
			t.Errorf("CREATE admitted a rendered probe (forged shape=%v)", forgedShape)
		}
		if forgedShape {
			if !validate(t, v, pod, "tenant").Allowed {
				t.Error("validator refused generated probes")
			}
			raw, err := json.Marshal(pod)
			if err != nil {
				t.Fatal(err)
			}
			req := podRequest("tenant", raw, "ephemeralcontainers")
			req.Operation = admissionv1.Update
			if !m.Handle(context.Background(), req).Allowed || !v.Handle(context.Background(), req).Allowed {
				t.Error("ephemeral update refused generated probes")
			}
		}
	}
}

func TestAdmissionRejectsUnsupportedMemberProbeShapes(t *testing.T) {
	for _, nativeInit := range []bool{false, true} {
		for _, rendered := range []bool{false, true} {
			for _, kind := range []string{"tcpSocket", "grpc", "postStart", "preStop", "httpHeaders", "timeoutSeconds", "scheme"} {
				t.Run(fmt.Sprintf("init=%v/rendered=%v/%s", nativeInit, rendered, kind), func(t *testing.T) {
					m, v := meshHandlers(t, meshConfig())
					pod := podWithProbedApp()
					if nativeInit {
						app := pod.Spec.Containers[0]
						app.Name = "cache"
						always := corev1.ContainerRestartPolicyAlways
						app.RestartPolicy = &always
						pod.Spec.InitContainers = []corev1.Container{app}
					}
					if rendered {
						pod = admit(t, m, pod, "tenant")
					}
					name := "app"
					if nativeInit {
						name = "cache"
					}
					c := appContainerNamed(t, pod, name)
					switch kind {
					case "tcpSocket":
						c.ReadinessProbe.ProbeHandler = corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(8080)}}
					case "grpc":
						c.ReadinessProbe.ProbeHandler = corev1.ProbeHandler{GRPC: &corev1.GRPCAction{Port: 8080}}
					case "postStart", "preStop":
						hook := &corev1.LifecycleHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(8080)}}
						c.Lifecycle = &corev1.Lifecycle{}
						if kind == "postStart" {
							c.Lifecycle.PostStart = hook
						} else {
							c.Lifecycle.PreStop = hook
						}
					case "httpHeaders":
						c.ReadinessProbe.HTTPGet.HTTPHeaders = []corev1.HTTPHeader{
							{
								Name:  "Authorization",
								Value: "token",
							},
						}
					case "timeoutSeconds":
						c.ReadinessProbe.TimeoutSeconds = 6
					case "scheme":
						c.ReadinessProbe.HTTPGet.Scheme = corev1.URISchemeHTTPS
					}
					for handler, resp := range map[string]admission.Response{
						"mutator":   mutationResponse(t, m, pod),
						"validator": validate(t, v, pod, "tenant"),
					} {
						if resp.Allowed {
							t.Errorf("%s admitted %s", handler, kind)
						} else if handler == "validator" && (resp.Result == nil || !strings.Contains(resp.Result.Message, kind)) {
							t.Errorf("validator denial = %+v, want %s", resp.Result, kind)
						}
					}
				})
			}
		}
	}
}

func TestAdmissionAcceptsForwardedProbeTimeoutBudget(t *testing.T) {
	for _, timeout := range []int32{0, 1, 5} {
		m, v := meshHandlers(t, meshConfig())
		pod := podWithProbedApp()
		pod.Spec.Containers[0].ReadinessProbe.TimeoutSeconds = timeout
		if !validate(t, v, admit(t, m, pod, "tenant"), "tenant").Allowed {
			t.Errorf("validator refused timeoutSeconds=%d", timeout)
		}
	}
}
