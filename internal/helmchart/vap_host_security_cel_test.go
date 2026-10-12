// Behaviorally evaluates the rendered tenant pod-security policies with cel-go.
// Kubernetes performs schema-aware VAP type checking at apply time; these tests
// evaluate the same rendered expressions over dynamic admission objects so each
// security boundary is exercised directly.
package helmchart

import (
	"testing"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

const (
	testClaimsHostDir   = "/var/run/nri-image-policy"
	testClaimsMountPath = "/run/c8s/workload-claims"
	testC8sImage        = "ghcr.io/confidential-dot-ai/c8s-operator:dev"
)

func renderedHostSecurityPolicies(t *testing.T) map[string][]admissionregv1.Validation {
	t.Helper()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	policies := map[string][]admissionregv1.Validation{}
	iterateManifests(t, out, func(doc []byte) bool {
		var policy admissionregv1.ValidatingAdmissionPolicy
		if err := sigsyaml.Unmarshal(doc, &policy); err != nil {
			return false
		}
		if policy.Kind == "ValidatingAdmissionPolicy" &&
			(policy.Name == "c8s-deny-host-namespaces" || policy.Name == "c8s-deny-host-namespaces-ephemeral") {
			policies[policy.Name] = policy.Spec.Validations
		}
		return false
	})
	for _, name := range []string{
		"c8s-deny-host-namespaces",
		"c8s-deny-host-namespaces-ephemeral",
	} {
		if _, ok := policies[name]; !ok {
			t.Fatalf("%s policy not rendered", name)
		}
	}
	return policies
}

func restrictedTestSecurityContext(explicitRuntimeDefaults bool) map[string]any {
	sc := map[string]any{
		"allowPrivilegeEscalation": false,
		"privileged":               false,
		"runAsUser":                int64(1000),
		"capabilities": map[string]any{
			"drop": []any{"ALL"},
			"add":  []any{"NET_BIND_SERVICE"},
		},
		"appArmorProfile": map[string]any{"type": "RuntimeDefault"},
		"seLinuxOptions":  map[string]any{"type": "container_t"},
		"procMount":       "Default",
	}
	if explicitRuntimeDefaults {
		sc["runAsNonRoot"] = true
		sc["seccompProfile"] = map[string]any{"type": "RuntimeDefault"}
	}
	return sc
}

func restrictedTestContainer(name string, explicitRuntimeDefaults bool) map[string]any {
	return map[string]any{
		"name":            name,
		"image":           "registry.example/restricted:test",
		"securityContext": restrictedTestSecurityContext(explicitRuntimeDefaults),
	}
}

func validClaimsSidecar(name, mode string) map[string]any {
	sidecar := restrictedTestContainer(name, false)
	sidecar["image"] = testC8sImage
	sidecar["restartPolicy"] = "Always"
	sidecar["args"] = []any{mode}
	// The node plugin supplies the claims mount through NRI, below the Pod spec.
	return sidecar
}

func validRestrictedTestPod() map[string]any {
	app := restrictedTestContainer("app", false)
	cert := validClaimsSidecar("c8s-cert", "get-cert")
	debugger := restrictedTestContainer("debugger", false)
	return map[string]any{
		"metadata": map[string]any{
			"name": "restricted",
			"annotations": map[string]any{
				"confidential.ai/cw":           "restricted",
				"confidential.ai/c8s-injected": "true",
			},
			"labels": map[string]any{"confidential.ai/cw": "restricted"},
		},
		"spec": map[string]any{
			"securityContext": map[string]any{
				"runAsNonRoot":   true,
				"runAsUser":      int64(1000),
				"seccompProfile": map[string]any{"type": "RuntimeDefault"},
				"appArmorProfile": map[string]any{
					"type": "RuntimeDefault",
				},
				"seLinuxOptions": map[string]any{"type": "container_t"},
				"sysctls": []any{map[string]any{
					"name":  "net.ipv4.ip_unprivileged_port_start",
					"value": "1024",
				}},
			},
			"volumes": []any{
				map[string]any{"name": "settings", "configMap": map[string]any{}},
			},
			"containers":          []any{app},
			"initContainers":      []any{cert},
			"ephemeralContainers": []any{debugger},
		},
	}
}

func validRestrictedEphemeralUpdate() map[string]any {
	// The ephemeralcontainers endpoint admits a full Pod, including inherited
	// security settings and every previously added ephemeral container.
	return validRestrictedTestPod()
}

func hostSecuritySpec(object map[string]any) map[string]any {
	return object["spec"].(map[string]any)
}

func hostSecurityContainer(object map[string]any, field string) map[string]any {
	return hostSecuritySpec(object)[field].([]any)[0].(map[string]any)
}

func hostSecurityContainerSC(object map[string]any, field string) map[string]any {
	return hostSecurityContainer(object, field)["securityContext"].(map[string]any)
}

func TestHostSecurityPodPolicyAllowsRestrictedPod(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	allTrue(t, validations, validRestrictedTestPod())

	v134Fields := validRestrictedTestPod()
	v134PodSC := hostSecuritySpec(v134Fields)["securityContext"].(map[string]any)
	v134PodSC["seLinuxOptions"] = map[string]any{"type": "container_engine_t"}
	v134PodSC["sysctls"] = []any{
		map[string]any{"name": "net.ipv4.tcp_rmem", "value": "4096 131072 6291456"},
		map[string]any{"name": "net.ipv4.tcp_wmem", "value": "4096 16384 4194304"},
	}
	allTrue(t, validations, v134Fields)

	withFetchers := validRestrictedTestPod()
	withFetchers["metadata"].(map[string]any)["annotations"].(map[string]any)["confidential.ai/c8s-secrets"] = "api-key=/prod/api-key"
	withFetchers["metadata"].(map[string]any)["annotations"].(map[string]any)["confidential.ai/c8s-volumes"] = "data=/prod/data"
	hostSecuritySpec(withFetchers)["initContainers"] = append(
		hostSecuritySpec(withFetchers)["initContainers"].([]any),
		validClaimsSidecar("c8s-secret", "get-secret"),
		validClaimsSidecar("c8s-volume", "get-volume"),
	)
	allTrue(t, validations, withFetchers)

	withoutSidecars := validRestrictedTestPod()
	spec := hostSecuritySpec(withoutSidecars)
	delete(spec, "initContainers")
	spec["volumes"] = []any{map[string]any{
		"name":     "scratch",
		"emptyDir": map[string]any{},
	}}
	allTrue(t, validations, withoutSidecars)

	explicitContainerDefaults := validRestrictedTestPod()
	podSC := hostSecuritySpec(explicitContainerDefaults)["securityContext"].(map[string]any)
	delete(podSC, "runAsNonRoot")
	delete(podSC, "seccompProfile")
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		sc := hostSecurityContainerSC(explicitContainerDefaults, field)
		sc["runAsNonRoot"] = true
		sc["seccompProfile"] = map[string]any{"type": "Localhost"}
	}
	allTrue(t, validations, explicitContainerDefaults)
}

func TestHostSecurityPoliciesAllowNRIClaimsSidecars(t *testing.T) {
	policies := renderedHostSecurityPolicies(t)
	for _, image := range []string{testC8sImage, "ghcr.io/confidential-dot-ai/c8s-operator:previous"} {
		for _, sidecar := range []struct{ name, mode, annotation string }{
			{"c8s-cert", "get-cert", "confidential.ai/cw"},
			{"c8s-secret", "get-secret", "confidential.ai/c8s-secrets"},
			{"c8s-volume", "get-volume", "confidential.ai/c8s-volumes"},
		} {
			t.Run(image+"/"+sidecar.mode, func(t *testing.T) {
				makePod := func() map[string]any {
					object := validRestrictedTestPod()
					annotations := object["metadata"].(map[string]any)["annotations"].(map[string]any)
					if sidecar.annotation != "confidential.ai/cw" {
						annotations[sidecar.annotation] = "data=/prod/data"
					}
					container := validClaimsSidecar(sidecar.name, sidecar.mode)
					container["image"] = image
					hostSecuritySpec(object)["initContainers"] = []any{container}
					return object
				}
				old, object := makePod(), makePod()
				old["metadata"].(map[string]any)["finalizers"] = []any{"batch.kubernetes.io/job-tracking"}
				object["metadata"].(map[string]any)["labels"].(map[string]any)["example.com/observed"] = "true"
				for _, validations := range policies {
					// There is no chart-image exception to maintain after an upgrade:
					// both Pod shapes are Restricted and declare no hostPath.
					allTrueAdmission(t, validations, object, nil, "CREATE")
					allTrueAdmission(t, validations, object, old, "UPDATE")
				}
			})
		}
	}
}

func TestHostSecurityPoliciesDenyEveryHostPath(t *testing.T) {
	policies := renderedHostSecurityPolicies(t)
	for _, tc := range []struct {
		name, volume, path, hostType, field, mode string
	}{
		{"node root", "node-root", "/", "Directory", "containers", "get-cert"},
		{"legacy cert claims", "c8s-workload-claims", testClaimsHostDir, "Directory", "initContainers", "get-cert"},
		{"legacy secret claims", "c8s-workload-claims", testClaimsHostDir, "Directory", "initContainers", "get-secret"},
		{"legacy volume claims", "c8s-workload-claims", testClaimsHostDir, "Directory", "initContainers", "get-volume"},
		{"aliased claims", "claims-alias", testClaimsHostDir, "Directory", "ephemeralContainers", "get-cert"},
		{"claims DirectoryOrCreate", "c8s-workload-claims", testClaimsHostDir, "DirectoryOrCreate", "initContainers", "get-cert"},
		{"claims without mount", "c8s-workload-claims", testClaimsHostDir, "", "", "get-cert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makePod := func() map[string]any {
				object := validRestrictedTestPod()
				annotations := object["metadata"].(map[string]any)["annotations"].(map[string]any)
				annotations["confidential.ai/c8s-secrets"] = "data=/prod/data"
				annotations["confidential.ai/c8s-volumes"] = "data=/prod/data"
				name := map[string]string{"get-cert": "c8s-cert", "get-secret": "c8s-secret", "get-volume": "c8s-volume"}[tc.mode]
				container := validClaimsSidecar(name, tc.mode)
				spec := hostSecuritySpec(object)
				spec["initContainers"] = []any{container}
				hostPath := map[string]any{"path": tc.path}
				if tc.hostType != "" {
					hostPath["type"] = tc.hostType
				}
				spec["volumes"] = append(spec["volumes"].([]any), map[string]any{
					"name": tc.volume, "hostPath": hostPath,
				})
				if tc.field != "" {
					hostSecurityContainer(object, tc.field)["volumeMounts"] = []any{map[string]any{
						"name": tc.volume, "mountPath": testClaimsMountPath, "readOnly": true,
					}}
				}
				return object
			}
			old, object := makePod(), makePod()
			for _, validations := range policies {
				anyFalseAdmission(t, validations, object, nil, "CREATE")
			}
			// Even an unchanged, previously admitted claims sidecar and volume
			// cannot authorize a hostPath after the chart image changes.
			for _, pod := range []map[string]any{old, object} {
				hostSecurityContainer(pod, "initContainers")["image"] = "ghcr.io/confidential-dot-ai/c8s-operator:previous"
			}
			delete(hostSecuritySpec(old), "ephemeralContainers")
			object["metadata"].(map[string]any)["labels"].(map[string]any)["example.com/observed"] = "true"
			for _, validations := range policies {
				// Includes pods/ephemeralcontainers, whose full Pod admission
				// object must preserve main's blanket hostPath denial.
				anyFalseAdmission(t, validations, object, old, "UPDATE")
			}
		})
	}
}

func TestHostSecurityPoliciesAllowRestrictedClaimsVolumeName(t *testing.T) {
	object := validRestrictedTestPod()
	spec := hostSecuritySpec(object)
	spec["volumes"] = append(spec["volumes"].([]any), map[string]any{
		"name": "c8s-workload-claims", "emptyDir": map[string]any{},
	})
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		hostSecurityContainer(object, field)["volumeMounts"] = []any{map[string]any{
			"name": "c8s-workload-claims", "mountPath": "/scratch", "readOnly": true,
		}}
	}
	for _, validations := range renderedHostSecurityPolicies(t) {
		// A Restricted-safe volume's name grants no access to the node.
		allTrueAdmission(t, validations, object, validRestrictedTestPod(), "UPDATE")
	}
}

func TestHostSecurityPodPolicyRejectsProbeAndLifecycleHosts(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"liveness HTTP", func(c map[string]any) {
			c["livenessProbe"] = map[string]any{
				"httpGet": map[string]any{"host": "127.0.0.1", "port": int64(8080)},
			}
		}},
		{"readiness TCP", func(c map[string]any) {
			c["readinessProbe"] = map[string]any{
				"tcpSocket": map[string]any{"host": "127.0.0.1", "port": int64(8080)},
			}
		}},
		{"startup HTTP", func(c map[string]any) {
			c["startupProbe"] = map[string]any{
				"httpGet": map[string]any{"host": "localhost", "port": int64(8080)},
			}
		}},
		{"postStart HTTP", func(c map[string]any) {
			c["lifecycle"] = map[string]any{
				"postStart": map[string]any{
					"httpGet": map[string]any{"host": "localhost", "port": int64(8080)},
				},
			}
		}},
		{"preStop TCP", func(c map[string]any) {
			c["lifecycle"] = map[string]any{
				"preStop": map[string]any{
					"tcpSocket": map[string]any{"host": "localhost", "port": int64(8080)},
				},
			}
		}},
	}
	for _, field := range []string{"containers", "initContainers"} {
		for _, tc := range tests {
			t.Run(field+" "+tc.name, func(t *testing.T) {
				object := validRestrictedTestPod()
				tc.mutate(hostSecurityContainer(object, field))
				anyFalse(t, validations, object)
			})
		}
	}
}

func TestHostSecurityPodPolicyRejectsNamespaceAndVolumeBypasses(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"host network", func(o map[string]any) { hostSecuritySpec(o)["hostNetwork"] = true }},
		{"host pid", func(o map[string]any) { hostSecuritySpec(o)["hostPID"] = true }},
		{"host ipc", func(o map[string]any) { hostSecuritySpec(o)["hostIPC"] = true }},
		{"disallowed volume source", func(o map[string]any) {
			hostSecuritySpec(o)["volumes"].([]any)[0] = map[string]any{
				"name": "network-share",
				"nfs":  map[string]any{"server": "127.0.0.1", "path": "/"},
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object := validRestrictedTestPod()
			tc.mutate(object)
			anyFalse(t, validations, object)
		})
	}

	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		t.Run(field+" host port", func(t *testing.T) {
			object := validRestrictedTestPod()
			hostSecurityContainer(object, field)["ports"] = []any{map[string]any{
				"containerPort": int64(1019),
				"hostPort":      int64(1019),
			}}
			anyFalse(t, validations, object)
		})
	}
}

func TestHostSecurityPodPolicyRejectsContainerSecurityBypasses(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		t.Run(field, func(t *testing.T) {
			tests := []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"host process", func(sc map[string]any) {
					sc["windowsOptions"] = map[string]any{"hostProcess": true}
				}},
				{"privileged", func(sc map[string]any) { sc["privileged"] = true }},
				{"privilege escalation", func(sc map[string]any) {
					sc["allowPrivilegeEscalation"] = true
				}},
				{"missing privilege escalation", func(sc map[string]any) {
					delete(sc, "allowPrivilegeEscalation")
				}},
				{"run as root", func(sc map[string]any) { sc["runAsUser"] = int64(0) }},
				{"runAsNonRoot override false", func(sc map[string]any) {
					sc["runAsNonRoot"] = false
				}},
				{"capabilities missing drop", func(sc map[string]any) {
					delete(sc["capabilities"].(map[string]any), "drop")
				}},
				{"capabilities do not drop all", func(sc map[string]any) {
					sc["capabilities"].(map[string]any)["drop"] = []any{"NET_RAW"}
				}},
				{"capabilities add sys admin", func(sc map[string]any) {
					sc["capabilities"].(map[string]any)["add"] = []any{"SYS_ADMIN"}
				}},
				{"unconfined seccomp override", func(sc map[string]any) {
					sc["seccompProfile"] = map[string]any{"type": "Unconfined"}
				}},
				{"unconfined apparmor", func(sc map[string]any) {
					sc["appArmorProfile"] = map[string]any{"type": "Unconfined"}
				}},
				{"unsafe selinux type", func(sc map[string]any) {
					sc["seLinuxOptions"] = map[string]any{"type": "spc_t"}
				}},
				{"custom selinux user", func(sc map[string]any) {
					sc["seLinuxOptions"] = map[string]any{"type": "container_t", "user": "system_u"}
				}},
				{"custom selinux role", func(sc map[string]any) {
					sc["seLinuxOptions"] = map[string]any{"type": "container_t", "role": "system_r"}
				}},
				{"unmasked proc", func(sc map[string]any) { sc["procMount"] = "Unmasked" }},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					object := validRestrictedTestPod()
					tc.mutate(hostSecurityContainerSC(object, field))
					anyFalse(t, validations, object)
				})
			}
		})
	}
}

func TestHostSecurityPodPolicyRejectsPodSecurityBypasses(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces"]
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"pod host process", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["windowsOptions"] =
				map[string]any{"hostProcess": true}
		}},
		{"pod run as root", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["runAsUser"] = int64(0)
		}},
		{"missing inherited runAsNonRoot", func(o map[string]any) {
			delete(hostSecuritySpec(o)["securityContext"].(map[string]any), "runAsNonRoot")
		}},
		{"missing inherited seccomp", func(o map[string]any) {
			delete(hostSecuritySpec(o)["securityContext"].(map[string]any), "seccompProfile")
		}},
		{"pod unconfined apparmor", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["appArmorProfile"] =
				map[string]any{"type": "Unconfined"}
		}},
		{"legacy unconfined apparmor", func(o map[string]any) {
			o["metadata"].(map[string]any)["annotations"] = map[string]any{
				"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
			}
		}},
		{"pod unsafe selinux type", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] =
				map[string]any{"type": "spc_t"}
		}},
		{"pod custom selinux user", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] =
				map[string]any{"type": "container_t", "user": "system_u"}
		}},
		{"pod custom selinux role", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] =
				map[string]any{"type": "container_t", "role": "system_r"}
		}},
		{"unsafe sysctl", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["sysctls"] =
				[]any{map[string]any{"name": "kernel.core_pattern", "value": "|/bin/sh"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object := validRestrictedTestPod()
			tc.mutate(object)
			anyFalse(t, validations, object)
		})
	}
}

func TestHostSecurityPoliciesPreserveRestrictedPodDefaults(t *testing.T) {
	policies := renderedHostSecurityPolicies(t)
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		allowed bool
	}{
		{"absent pod defaults", func(o map[string]any) {
			delete(hostSecuritySpec(o), "securityContext")
		}, true},
		{"absent metadata", func(o map[string]any) {
			delete(o, "metadata")
		}, true},
		{"safe legacy apparmor", func(o map[string]any) {
			o["metadata"].(map[string]any)["annotations"] = map[string]any{
				"container.apparmor.security.beta.kubernetes.io/debugger": "runtime/default",
			}
		}, true},
		{"pod runAsNonRoot false", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["runAsNonRoot"] = false
		}, false},
		{"pod root uid", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["runAsUser"] = int64(0)
		}, false},
		{"pod unconfined seccomp", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seccompProfile"] = map[string]any{"type": "Unconfined"}
		}, false},
		{"pod unconfined apparmor", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["appArmorProfile"] = map[string]any{"type": "Unconfined"}
		}, false},
		{"pod unsafe selinux type", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] = map[string]any{"type": "spc_t"}
		}, false},
		{"pod custom selinux user", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] = map[string]any{"type": "container_t", "user": "system_u"}
		}, false},
		{"pod custom selinux role", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seLinuxOptions"] = map[string]any{"type": "container_t", "role": "system_r"}
		}, false},
		{"pod unsafe sysctl", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["sysctls"] = []any{map[string]any{
				"name": "kernel.core_pattern", "value": "|/bin/sh",
			}}
		}, false},
		{"unconfined legacy apparmor", func(o map[string]any) {
			o["metadata"].(map[string]any)["annotations"] = map[string]any{
				"container.apparmor.security.beta.kubernetes.io/debugger": "unconfined",
			}
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object, old := validRestrictedEphemeralUpdate(), validRestrictedTestPod()
			for _, pod := range []map[string]any{object, old} {
				for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
					hostSecurityContainer(pod, field)["securityContext"] = restrictedTestSecurityContext(true)
				}
				tc.mutate(pod)
			}
			delete(hostSecuritySpec(old), "ephemeralContainers")
			for name, validations := range policies {
				t.Run(name, func(t *testing.T) {
					// Restricted rejects explicit unsafe Pod settings even when
					// every container declares safe overrides of those defaults.
					if tc.allowed {
						allTrueAdmission(t, validations, object, old, "UPDATE")
					} else {
						anyFalseAdmission(t, validations, object, old, "UPDATE")
					}
				})
			}
		})
	}
}

func TestHostSecurityEphemeralPolicyPreservesHostIsolation(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces-ephemeral"]
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		allowed bool
	}{
		{"absent optional host settings", func(map[string]any) {}, true},
		{"explicit safe host settings", func(o map[string]any) {
			for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
				hostSecuritySpec(o)[field] = false
			}
			for _, field := range []string{"containers", "initContainers"} {
				hostSecurityContainer(o, field)["ports"] = []any{map[string]any{
					"containerPort": int64(8080), "hostPort": int64(0),
				}}
			}
		}, true},
		{"existing host network", func(o map[string]any) { hostSecuritySpec(o)["hostNetwork"] = true }, false},
		{"existing host pid", func(o map[string]any) { hostSecuritySpec(o)["hostPID"] = true }, false},
		{"existing host ipc", func(o map[string]any) { hostSecuritySpec(o)["hostIPC"] = true }, false},
		{"existing application host port", func(o map[string]any) {
			hostSecurityContainer(o, "containers")["ports"] = []any{map[string]any{
				"containerPort": int64(1019), "hostPort": int64(1019),
			}}
		}, false},
		{"existing init host port", func(o map[string]any) {
			hostSecurityContainer(o, "initContainers")["ports"] = []any{map[string]any{
				"containerPort": int64(1019), "hostPort": int64(1019),
			}}
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object, old := validRestrictedEphemeralUpdate(), validRestrictedTestPod()
			// These fields are unchanged by the subresource update. Main's
			// full-Pod host-isolation checks still apply to the new debugger.
			tc.mutate(object)
			tc.mutate(old)
			delete(hostSecuritySpec(old), "ephemeralContainers")
			if tc.allowed {
				allTrueAdmission(t, validations, object, old, "UPDATE")
			} else {
				anyFalseAdmission(t, validations, object, old, "UPDATE")
			}
		})
	}
}

func TestHostSecurityEphemeralPolicyBehaviors(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces-ephemeral"]
	allTrue(t, validations, map[string]any{"spec": map[string]any{}})
	allTrue(t, validations, validRestrictedEphemeralUpdate())

	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{"host port", func(c, _ map[string]any) {
			c["ports"] = []any{map[string]any{
				"containerPort": int64(1019),
				"hostPort":      int64(1019),
			}}
		}},
		{"host process", func(_, sc map[string]any) {
			sc["windowsOptions"] = map[string]any{"hostProcess": true}
		}},
		{"privileged", func(_, sc map[string]any) { sc["privileged"] = true }},
		{"privilege escalation", func(_, sc map[string]any) {
			sc["allowPrivilegeEscalation"] = true
		}},
		{"missing privilege escalation", func(_, sc map[string]any) {
			delete(sc, "allowPrivilegeEscalation")
		}},
		{"runAsNonRoot false", func(_, sc map[string]any) {
			sc["runAsNonRoot"] = false
		}},
		{"run as root", func(_, sc map[string]any) { sc["runAsUser"] = int64(0) }},
		{"capabilities missing drop", func(_, sc map[string]any) {
			delete(sc["capabilities"].(map[string]any), "drop")
		}},
		{"capabilities do not drop all", func(_, sc map[string]any) {
			sc["capabilities"].(map[string]any)["drop"] = []any{"NET_RAW"}
		}},
		{"capabilities add sys admin", func(_, sc map[string]any) {
			sc["capabilities"].(map[string]any)["add"] = []any{"SYS_ADMIN"}
		}},
		{"unconfined seccomp", func(_, sc map[string]any) {
			sc["seccompProfile"] = map[string]any{"type": "Unconfined"}
		}},
		{"unconfined apparmor", func(_, sc map[string]any) {
			sc["appArmorProfile"] = map[string]any{"type": "Unconfined"}
		}},
		{"unsafe selinux type", func(_, sc map[string]any) {
			sc["seLinuxOptions"] = map[string]any{"type": "spc_t"}
		}},
		{"custom selinux user", func(_, sc map[string]any) {
			sc["seLinuxOptions"] = map[string]any{"type": "container_t", "user": "system_u"}
		}},
		{"custom selinux role", func(_, sc map[string]any) {
			sc["seLinuxOptions"] = map[string]any{"type": "container_t", "role": "system_r"}
		}},
		{"unmasked proc", func(_, sc map[string]any) { sc["procMount"] = "Unmasked" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object := validRestrictedEphemeralUpdate()
			container := hostSecurityContainer(object, "ephemeralContainers")
			tc.mutate(container, container["securityContext"].(map[string]any))
			anyFalse(t, validations, object)
		})
	}
}

func TestHostSecurityEphemeralPolicyInheritance(t *testing.T) {
	validations := renderedHostSecurityPolicies(t)["c8s-deny-host-namespaces-ephemeral"]
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		allowed bool
	}{
		{"inherited RuntimeDefault", func(map[string]any) {}, true},
		{"inherited Localhost", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seccompProfile"] = map[string]any{"type": "Localhost"}
		}, true},
		{"explicit defaults without pod context", func(o map[string]any) {
			delete(hostSecuritySpec(o), "securityContext")
			hostSecurityContainer(o, "ephemeralContainers")["securityContext"] = restrictedTestSecurityContext(true)
		}, true},
		{"explicit values cannot bypass unsafe pod defaults", func(o map[string]any) {
			sc := hostSecuritySpec(o)["securityContext"].(map[string]any)
			sc["runAsNonRoot"] = false
			sc["seccompProfile"] = map[string]any{"type": "Unconfined"}
			hostSecurityContainer(o, "ephemeralContainers")["securityContext"] = restrictedTestSecurityContext(true)
		}, false},
		{"missing pod context", func(o map[string]any) {
			delete(hostSecuritySpec(o), "securityContext")
		}, false},
		{"missing runAsNonRoot", func(o map[string]any) {
			delete(hostSecuritySpec(o)["securityContext"].(map[string]any), "runAsNonRoot")
		}, false},
		{"false inherited runAsNonRoot", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["runAsNonRoot"] = false
		}, false},
		{"missing seccomp", func(o map[string]any) {
			delete(hostSecuritySpec(o)["securityContext"].(map[string]any), "seccompProfile")
		}, false},
		{"unconfined inherited seccomp", func(o map[string]any) {
			hostSecuritySpec(o)["securityContext"].(map[string]any)["seccompProfile"] = map[string]any{"type": "Unconfined"}
		}, false},
		{"multiple inherited and explicit debuggers", func(o map[string]any) {
			spec := hostSecuritySpec(o)
			spec["ephemeralContainers"] = append(spec["ephemeralContainers"].([]any), restrictedTestContainer("second-debugger", true))
		}, true},
		{"unsafe second debugger", func(o map[string]any) {
			second := restrictedTestContainer("second-debugger", true)
			second["securityContext"].(map[string]any)["runAsNonRoot"] = false
			spec := hostSecuritySpec(o)
			spec["ephemeralContainers"] = append(spec["ephemeralContainers"].([]any), second)
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			object, old := validRestrictedEphemeralUpdate(), validRestrictedTestPod()
			delete(hostSecuritySpec(old), "ephemeralContainers")
			tc.mutate(object)
			if tc.allowed {
				allTrueAdmission(t, validations, object, old, "UPDATE")
			} else {
				anyFalseAdmission(t, validations, object, old, "UPDATE")
			}
		})
	}
}
