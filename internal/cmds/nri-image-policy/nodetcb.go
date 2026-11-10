package nriimagepolicy

import (
	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The kubelet sets kubernetes.io/config.source on every pod it runs,
// overwriting whatever the API object carries, and passes it to the runtime as
// a sandbox annotation: "file" for a pod read from its manifest directory,
// "api" for one created through the API server.
const (
	configSourceAnnotation = "kubernetes.io/config.source"
	staticPodSource        = "file"
)

// StaticPodAnnotations reports the annotations of a pod the kubelet read from
// its manifest directory.
func StaticPodAnnotations(annotations map[string]string) bool {
	return annotations[configSourceAnnotation] == staticPodSource
}

// staticPod reports a pod the kubelet read from its manifest directory.
func staticPod(pod *api.PodSandbox) bool {
	return StaticPodAnnotations(pod.GetAnnotations())
}

// nodeTCBExempt reports whether the measured base excuses a launch holding
// host privilege: a kubelet static pod whose launch a base entry pins
// (allowlist.Container.LaunchPinned). Its manifest is written on the worker
// alone, from the measured image and the worker document, while the control
// plane that writes every other pod sits outside this TEE.
//
// An open entry (command, args or mounts any) therefore admits its image but
// never hands a pod host privilege, the host network included.
func (p *plugin) nodeTCBExempt(pod *api.PodSandbox, rc allowlist.RunningContainer) bool {
	return staticPod(pod) && p.policy.baseAdmitsPinned(rc)
}
