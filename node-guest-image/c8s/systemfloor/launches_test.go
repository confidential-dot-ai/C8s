package main

import (
	"strings"
	"testing"
)

// The capture of a booted node pins each Cilium container's own argv, mounts
// and environment: platform mounts and service links are left out, values the
// API supplies are matched present, and the rest exact.
func TestCapturedLaunchesPinTheRecordedCilium(t *testing.T) {
	launches, err := capturedLaunches("../launches", []string{"kube-system/cilium"})
	if err != nil {
		t.Fatal(err)
	}
	block, err := renderPinned(launches)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cilium-launches:",
		"- --config-dir=/tmp/cilium/config-map",
		"BIN_PATH:\n                  exact: /opt/cni/bin",
		"K8S_NODE_NAME:\n                  present: true",
		"kind: data\n                  source: clustermesh-secrets\n                  node: true",
		"serviceLinks: true",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("pinned block lacks %q", want)
		}
	}
	for _, unwanted := range []string{"termination-log", "kube-api-access", "/etc/hosts", "RKE2_COREDNS", "policy: any"} {
		if strings.Contains(block, unwanted) {
			t.Errorf("pinned block names %q", unwanted)
		}
	}
	if _, err := capturedLaunches("../launches", []string{"kube-system/cilium-operator"}); err == nil {
		t.Error("pinned a DaemonSet the capture does not hold")
	}
}

// A baked manifest pins its container's launch over the image environment;
// one that runs the image's entrypoint is refused.
func TestManifestLaunchPinsTheDevicePlugin(t *testing.T) {
	name, l, err := manifestLaunch("../mkosi.extra/var/lib/rancher/rke2/server/manifests/nvidia-device-plugin.yaml", "../launches/k8s-device-plugin-config.json")
	if err != nil {
		t.Fatal(err)
	}
	if name != "nvidia-device-plugin" || !l.container.LaunchPinned() {
		t.Fatalf("manifestLaunch = %s %+v, want a pinned nvidia-device-plugin launch", name, l.container)
	}
	block, err := renderPinned(map[string][]launch{name: {l}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"- nvidia-device-plugin", "CDI_FEATURE_FLAGS:\n                  exact: disable-ipc-discoverer", "source: /var/run/cdi"} {
		if !strings.Contains(block, want) {
			t.Errorf("device plugin pin lacks %q", want)
		}
	}
}
