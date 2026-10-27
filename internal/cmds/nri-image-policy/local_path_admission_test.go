package nriimagepolicy

import (
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

func TestRemovedLocalPathContainersDenied(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(cfg.Mesh.ExemptNamespaces, "local-path-storage") {
		t.Error("removed addon namespace retains mesh exemption")
	}
	// Exercise image admission independently of the mesh identity gate.
	cfg.Mesh = nil
	for _, tc := range []struct {
		name, image string
		argv        []string
	}{
		{"setup", "busybox@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d", []string{"/bin/sh", "/script/setup", "-p", "/"}},
		{"teardown", "busybox@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d", []string{"/bin/sh", "/script/teardown", "-p", "/"}},
		{"provisioner shell", "rancher/local-path-provisioner@sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f", []string{"/bin/sh", "-c", "id"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin(cfg)
			p.SetReady()
			pod := meshPod("local-path-storage", "helper", testNetNS)
			ctr := makeCtrWithImageArgs(pod.Id, "helper", tc.image, tc.argv)
			ctr.User = &api.User{Uid: 0}
			ctr.Mounts = []*api.Mount{{Destination: "/script", Source: "/operator-script", Type: "bind"}, {Destination: "/host", Source: "/", Type: "bind"}}
			if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err == nil || !strings.Contains(err.Error(), "image not in allowlist") {
				t.Fatal("removed local-path image admitted")
			}
		})
	}
}
