package nriimagepolicy

import (
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestLocalPathMeshExemptionKeepsImageAndLaunchAdmission(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	helperArgv := []string{"/bin/sh", "/script/setup"}
	cfg.Allowlist.Base.Workloads["local-path-helper-test"] = workloadAllowlist(t, pushDigestA, pushDigestB, helperArgv).Workloads["w"]

	for _, tc := range []struct {
		name    string
		image   string
		argv    []string
		wantErr bool
	}{
		{
			name:    "unapproved image",
			image:   "registry/repo@" + pushDigestC,
			argv:    helperArgv,
			wantErr: true,
		},
		{
			name:  "exact helper launch",
			image: "registry/repo@" + pushDigestB,
			argv:  helperArgv,
		},
		{
			name:    "changed helper launch",
			image:   "registry/repo@" + pushDigestB,
			argv:    []string{"/bin/sh", "-c", "id"},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin(cfg)
			p.mesh = newMeshGate(*cfg.Mesh, discardLogger())
			p.SetReady()
			pod := meshPod("local-path-storage", "helper", testNetNS)
			ctr := makeCtrWithImageArgs(pod.Id, "helper", tc.image, tc.argv)
			ctr.User = &api.User{Uid: 0}
			if p.mesh.hosts(pod) {
				t.Fatal("local-path-storage is covered by the mesh gate")
			}
			_, _, err := createAndStart(p, t.Context(), pod, ctr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("admission error = %v, want error %v", err, tc.wantErr)
			}
		})
	}

	t.Run("measured provisioner", func(t *testing.T) {
		p := newTestPlugin(cfg)
		p.mesh = newMeshGate(*cfg.Mesh, discardLogger())
		p.mountStorage = fixedStorage(allowlist.MountEncrypted)
		p.SetReady()
		pod := meshPod("local-path-storage", "provisioner", testNetNS)
		pod.Uid = "5a1d-pod"
		spec := bakedWorkloads(t, "local-path-storage.yaml")[0].Spec.Template.Spec
		c := spec.Containers[0]
		ctr := bakedLaunch(t, pod, spec, c, launchEnv(t, pod, c, bakedManifestImageEnv(t)[digestOf(c.Image)]))
		if _, _, err := createAndStart(p, t.Context(), pod, ctr); err != nil {
			t.Fatalf("the measured provisioner is refused: %v", err)
		}
	})
}
