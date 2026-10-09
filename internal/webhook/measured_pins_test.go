package webhook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A baked node grants a platform role from its own measured base allowlist,
// which pins the argv the role is granted for. mkosi.sync renders that
// template by placeholder substitution, so nothing type-checks its pins
// against the containers this package builds: a drift fails here instead of
// leaving an injected container role-less on a confidential node.
const (
	measuredPolicyTemplate = "../../node-guest-image/c8s/image-policy.yaml.in"
	meshDockerfile         = "../../cmd/armtls-mesh/Dockerfile"
	operatorDockerfile     = "../../cmd/c8s/Dockerfile"
)

// The digests mkosi.sync substitutes, distinct so the two images' entries stay
// apart.
var (
	meshImageDigest     = "sha256:" + strings.Repeat("1a", 32)
	operatorImageDigest = "sha256:" + strings.Repeat("2b", 32)
	routerImageDigest   = "sha256:" + strings.Repeat("3c", 32)
)

// The roles the enforcer's measured base names
// (internal/cmds/nri-image-policy/roles.go).
const (
	meshRole       = "mesh"
	credentialRole = "credentials"
)

func TestMeasuredBaseAdmitsTheInjectedArgv(t *testing.T) {
	base := measuredBase(t)
	pod := injectedPod(t)
	meshEntrypoint := imageEntrypoint(t, meshDockerfile)
	operatorEntrypoint := imageEntrypoint(t, operatorDockerfile)
	for _, tc := range []struct {
		entry      string
		role       string
		digest     string
		entrypoint []string
		container  string
	}{
		{"c8s-mesh-endpoint", meshRole, meshImageDigest, meshEntrypoint, reservedMeshContainerName},
		{"c8s-get-cert", credentialRole, operatorImageDigest, operatorEntrypoint, reservedCertContainerName},
		{"c8s-probe-file", credentialRole, operatorImageDigest, operatorEntrypoint, reservedCertWaitContainerName},
		{"c8s-get-secret", credentialRole, operatorImageDigest, operatorEntrypoint, reservedSecretContainerName},
		{"c8s-get-volume", credentialRole, operatorImageDigest, operatorEntrypoint, reservedVolumeContainerName},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			entry, ok := base.Workloads[tc.entry]
			if !ok {
				t.Fatalf("the measured base carries no %q entry, so %s holds no role", tc.entry, tc.container)
			}
			if got := entry.Containers[0].Role; got != tc.role {
				t.Errorf("entry %q grants the role %q, want %q", tc.entry, got, tc.role)
			}
			argv := processArgv(tc.entrypoint, containerNamed(pod, tc.container))
			only := &allowlist.Allowlist{
				Schema:    base.Schema,
				Workloads: map[string]allowlist.Workload{tc.entry: entry},
			}
			launch := allowlist.RunningContainer{
				Digest: tc.digest,
				Argv:   argv,
			}
			if !only.BuildIndex().AdmitsProcess(launch) {
				t.Errorf("entry %q does not admit %v, the argv the injector gives %s", tc.entry, argv, tc.container)
			}
		})
	}
}

// The endpoint holds the UID the pod ruleset lets out unwrapped, so its entry
// pins the mounts it takes the role with, not only its argv.
func TestMeasuredMeshEntryPinsTheInjectedMounts(t *testing.T) {
	entry := measuredBase(t).Workloads["c8s-mesh-endpoint"].Containers[0]
	mesh := containerNamed(injectedPod(t), reservedMeshContainerName)
	want := make([]allowlist.MountRule, 0, len(mesh.VolumeMounts))
	for _, mount := range mesh.VolumeMounts {
		want = append(want, allowlist.MountRule{
			Destination: mount.MountPath,
			Kind:        allowlist.MountEmptyDir,
		})
	}
	if entry.Mounts.Policy != allowlist.PolicyExact || !slices.Equal(entry.Mounts.Rules, want) {
		t.Errorf("the mesh entry pins mounts %q %v, want exact %v, the injected mounts",
			entry.Mounts.Policy, entry.Mounts.Rules, want)
	}
}

// injectedPod is a pod carrying every platform container: the endpoint, the
// credential sidecars, and the fetchers its annotations ask for.
func injectedPod(t *testing.T) *corev1.Pod {
	t.Helper()
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db"}},
		Volumes:    volumesSpec{Specs: []string{"weights"}},
	}, secretsConfig())
	return pod
}

// measuredBase parses the node image's policy template.
func measuredBase(t *testing.T) *allowlist.Allowlist {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(measuredPolicyTemplate))
	if err != nil {
		t.Fatalf("read the node-image policy template: %v", err)
	}
	rendered := strings.NewReplacer(
		"@MESH_DIGEST@", meshImageDigest,
		"@OPERATOR_DIGEST@", operatorImageDigest,
		"@ROUTER_DIGEST@", routerImageDigest,
	).Replace(string(body))
	var doc struct {
		Allowlist struct {
			Base allowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yaml.Unmarshal([]byte(rendered), &doc); err != nil {
		t.Fatalf("parse the node-image policy template: %v", err)
	}
	return &doc.Allowlist.Base
}

// processArgv is the argv the node observes: a container's own command, or the
// image entrypoint the container's args follow.
func processArgv(entrypoint []string, c *corev1.Container) []string {
	if len(c.Command) > 0 {
		return append(slices.Clone(c.Command), c.Args...)
	}
	return append(slices.Clone(entrypoint), c.Args...)
}

// imageEntrypoint is the ENTRYPOINT a C8s image is built with, the prefix of
// every argv its containers run.
func imageEntrypoint(t *testing.T, dockerfile string) []string {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(dockerfile))
	if err != nil {
		t.Fatalf("read %s: %v", dockerfile, err)
	}
	match := regexp.MustCompile(`(?m)^ENTRYPOINT (\[.*\])$`).FindStringSubmatch(string(body))
	if match == nil {
		t.Fatalf("%s declares no ENTRYPOINT in exec form", dockerfile)
	}
	var entrypoint []string
	if err := json.Unmarshal([]byte(match[1]), &entrypoint); err != nil {
		t.Fatalf("parse the ENTRYPOINT of %s: %v", dockerfile, err)
	}
	return entrypoint
}
