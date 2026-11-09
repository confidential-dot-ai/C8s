// Package profile checks the pod profile against the worker profile it
// overlays.
package profile

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"sigs.k8s.io/yaml"
)

const (
	workerExtra = "../worker/mkosi.extra"
	podExtra    = "mkosi.extra"
	units       = "etc/systemd/system"
)

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// presetted is what 40-pod.preset says of each unit.
func presetted(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(read(t, filepath.Join(podExtra, "usr/lib/systemd/system-preset/40-pod.preset")), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && !strings.HasPrefix(fields[0], "#") {
			out[fields[1]] = fields[0]
		}
	}
	return out
}

// A worker unit that needs the worker document would pull worker staging in,
// and worker staging powers a pod CVM off: each one is replaced by this
// profile or left off by its preset, and nothing this profile ships needs it.
func TestNothingStartsWorkerStaging(t *testing.T) {
	preset := presetted(t)
	if preset["worker-stage.service"] != "disable" {
		t.Fatal("40-pod.preset must disable worker-stage.service")
	}
	worker, err := os.ReadDir(filepath.Join(workerExtra, units))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range worker {
		name := entry.Name()
		if name == "worker-stage.service" || !strings.Contains(read(t, filepath.Join(workerExtra, units, name)), "worker-stage.service") {
			continue
		}
		replaced, err := os.ReadFile(filepath.Join(podExtra, units, name))
		if err == nil {
			if strings.Contains(string(replaced), "worker-stage") {
				t.Errorf("%s replaces the worker's unit but still names worker staging", name)
			}
			continue
		}
		pathUnit := strings.TrimSuffix(name, ".service") + ".path"
		if preset[name] != "disable" && preset[pathUnit] != "disable" {
			t.Errorf("worker unit %s needs worker staging and 40-pod.preset leaves it on", name)
		}
	}
	pod, err := os.ReadDir(filepath.Join(podExtra, units))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range pod {
		if strings.Contains(read(t, filepath.Join(podExtra, units, entry.Name())), "worker-stage") {
			t.Errorf("%s names worker staging", entry.Name())
		}
	}
}

// podcvm-status starts the runtime and the kubelet once a pod is assigned
// (internal/cmds/podstatus), so neither starts at boot.
func TestTheAssignmentStartsTheRuntime(t *testing.T) {
	preset := presetted(t)
	for _, name := range []string{"podcvm-containerd.service", "podcvm-kubelet.service"} {
		unit := read(t, filepath.Join(podExtra, units, name))
		if strings.Contains(unit, "[Install]") || preset[name] == "enable" {
			t.Errorf("%s must not start at boot", name)
		}
	}
	for _, name := range []string{"pod-stage.service", "podcvm-status.service"} {
		if preset[name] != "enable" {
			t.Errorf("40-pod.preset must enable %s", name)
		}
	}
	if !strings.Contains(read(t, filepath.Join(podExtra, units, "podcvm-containerd.service")), "Wants=nri-image-policy.service\n") {
		t.Error("podcvm-containerd.service must bring up the admission plugin containerd requires")
	}
}

// The standalone kubelet dials the containerd the worker's configuration binds.
func TestKubeletDialsTheWorkersContainerd(t *testing.T) {
	var containerd struct {
		Plugins map[string]struct {
			Address string `toml:"address"`
		} `toml:"plugins"`
	}
	if err := toml.Unmarshal([]byte(read(t, filepath.Join(workerExtra, "etc/containerd/config.toml"))), &containerd); err != nil {
		t.Fatal(err)
	}
	address := containerd.Plugins["io.containerd.server.v1.grpc"].Address
	var kubelet struct {
		ContainerRuntimeEndpoint string `json:"containerRuntimeEndpoint"`
		StaticPodPath            string `json:"staticPodPath"`
	}
	if err := yaml.Unmarshal([]byte(read(t, filepath.Join(podExtra, "usr/lib/c8s/pod-runtime/kubelet.yaml"))), &kubelet); err != nil {
		t.Fatal(err)
	}
	if address == "" || kubelet.ContainerRuntimeEndpoint != "unix://"+address {
		t.Fatalf("kubelet dials %q, containerd binds %q", kubelet.ContainerRuntimeEndpoint, address)
	}
	if !slices.Contains([]string{"/run/c8s-pod/manifests"}, kubelet.StaticPodPath) {
		t.Fatalf("kubelet reads static pods from %q, not where the assignment publishes them", kubelet.StaticPodPath)
	}
}

// A pod CVM is launched with a small scratch disk or none: the worker's
// scratch gate relaxes its size floor on the marker this profile bakes, or it
// powers every pod CVM off.
func TestScratchGateKnowsThePodImage(t *testing.T) {
	if _, err := os.Stat(filepath.Join(podExtra, "usr/lib/c8s/pod-image")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, filepath.Join(workerExtra, "usr/local/bin/scratch-enforce.sh")), "POD_IMAGE_MARKER:-/usr/lib/c8s/pod-image}") {
		t.Fatal("scratch-enforce.sh does not key the pod exemption on /usr/lib/c8s/pod-image")
	}
}
