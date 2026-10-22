package nriimagepolicy

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// localPathManifest is the optional provisioner manifest a C8S_LOCAL_PATH=1
// build bakes.
const localPathManifest = "../../../node-guest-image/c8s/local-path/local-path-storage.yaml"

// withoutLocalPath deletes the template's local-path blocks the way
// mkosi.sync does for a default build: every line from a "# BEGIN local-path"
// marker through the next "# END local-path" marker.
func withoutLocalPath(rendered string) string {
	var out []string
	skip := false
	for _, line := range strings.Split(rendered, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "# BEGIN local-path"):
			skip = true
		case strings.HasPrefix(trimmed, "# END local-path"):
			skip = false
		case !skip:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// A default build carries neither the provisioner's base entry nor its
// namespace's mesh exemption (#872).
func TestNodeImageBootConfigWithoutLocalPath(t *testing.T) {
	cfg, err := parseConfig([]byte(withoutLocalPath(renderNodeImagePolicy(t))))
	if err != nil {
		t.Fatalf("the default build's boot config does not parse: %v", err)
	}
	for name, workload := range cfg.Allowlist.Base.Workloads {
		for _, container := range workload.Containers {
			if strings.Contains(container.Image, "local-path") {
				t.Errorf("default base entry %s admits %s", name, container.Image)
			}
		}
	}
	if slices.Contains(cfg.Mesh.ExemptNamespaces, "local-path-storage") {
		t.Error("default mesh policy still exempts local-path-storage")
	}
}

// The provisioner entry in the local-path block admits exactly the image the
// optional manifest runs.
func TestLocalPathBlockMatchesManifest(t *testing.T) {
	manifest, err := os.ReadFile(localPathManifest)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`image: (rancher/local-path-provisioner:\S+@(sha256:[0-9a-f]{64}))`).FindSubmatch(manifest)
	if m == nil {
		t.Fatalf("no digest-pinned provisioner image in %s", localPathManifest)
	}
	rendered := renderNodeImagePolicy(t)
	cfg, err := parseConfig([]byte(rendered))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Allowlist.Base.BuildIndex().AdmitsDigest(string(m[2])) {
		t.Errorf("the local-path block does not admit %s, the image %s runs", m[1], localPathManifest)
	}
	if cfg, err := parseConfig([]byte(withoutLocalPath(rendered))); err != nil || cfg.Allowlist.Base.BuildIndex().AdmitsDigest(string(m[2])) {
		t.Errorf("the provisioner digest %s is admitted outside the local-path block (err %v)", m[2], err)
	}
}

func TestLocalPathMeshExemptionKeepsImageAndLaunchAdmission(t *testing.T) {
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	var provisionerImage string
	for _, workload := range cfg.Allowlist.Base.Workloads {
		for _, container := range workload.Containers {
			if strings.HasPrefix(container.Image, "rancher/local-path-provisioner:") {
				provisionerImage = container.Image
			}
		}
	}
	if provisionerImage == "" {
		t.Fatal("measured base has no local-path provisioner")
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
			name:  "measured provisioner",
			image: provisionerImage,
			argv:  []string{"local-path-provisioner", "--debug", "start", "--config", "/etc/config/config.json"},
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
			pod.Linux.Namespaces = append(pod.Linux.Namespaces, &api.LinuxNamespace{Type: "ipc"}, &api.LinuxNamespace{Type: "uts"})
			ctr := makeCtrWithImageArgs(pod.Id, "helper", tc.image, tc.argv)
			ctr.Linux = &api.LinuxContainer{Namespaces: []*api.LinuxNamespace{{Type: cgroupNamespace}}}
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
}
