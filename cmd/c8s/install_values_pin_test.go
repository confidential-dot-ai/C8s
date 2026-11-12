//go:build !c8s_node

package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Every fixture below is a literal: the computed values are pinned byte for
// byte, so an operator key, a pin or a digest generated per run would not do.
const testPinOperatorKeys = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+ozuS8lfikNld52SnfWYj1/SlUGr
mG5PZp8/jAWmARD163wkoiQC2tlHUNJ6nqkN79y37EBKHGFV3B3CW+Ah6A==
-----END PUBLIC KEY-----
`

const (
	testPinVLLMDigest = "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	testPinEdgeDigest = "sha256:e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
)

// testPinNodeCIDR must stay outside the pod range clusterKubectl's node
// publishes, 10.42.0.0/24.
const testPinNodeCIDR = "192.0.2.0/24"

// pinnedCDSPinFile is cdsPinDocument with the operator key fixed.
func pinnedCDSPinFile(t *testing.T) string {
	t.Helper()
	config := strings.Join([]string{
		"schemaVersion: c8s-cds/v1",
		"clusterID: test",
		"operatorPublicKeys: |\n  " + strings.ReplaceAll(strings.TrimSpace(testPinOperatorKeys), "\n", "\n  "),
		`workloads: '{"schema":"c8s.allowlist/v1","workloads":{"` + installSeedEntryName + `":` + testSeedEntry + `}}'`,
		`nodes: '{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":"` + strings.Repeat("ab", 48) + `"}]}'`,
		"nodeCIDRs:\n  - " + testPinNodeCIDR,
		"leafDNSNames:\n  - router.example.com",
	}, "\n") + "\n"
	file, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return writePin(t, `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"`+
		strings.Repeat("cd", 48)+`","launch_file":`+string(file)+`}]}`)
}

// pinnedOperatorKeysFile is the --operator-keys bundle, at the fixed key.
func pinnedOperatorKeysFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator-keys.pem")
	if err := os.WriteFile(path, []byte(testPinOperatorKeys), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// adoptedDeploymentFile is a one-container Deployment mounting volume at
// /scratch, as `kubectl get -o json` emits it.
func adoptedDeploymentFile(t *testing.T, name, image string, volume corev1.VolumeSource) string {
	t.Helper()
	data, err := json.Marshal(appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ws"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{Name: "scratch", VolumeSource: volume}},
				Containers: []corev1.Container{{
					Name:         "app",
					Image:        image,
					VolumeMounts: []corev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}},
				}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// pinnedInstallStubs is a healthy cluster carrying the registry secret and the
// two adopted workloads: vllm mounts a memory emptyDir, edge a host path its
// entry cannot model exactly.
func pinnedInstallStubs(t *testing.T) *installStubs {
	t.Helper()
	s := newInstallStubs(t, "", false)
	vllm := adoptedDeploymentFile(t, "vllm", "ghcr.io/acme/vllm:v1",
		corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}})
	edge := adoptedDeploymentFile(t, "edge", "ghcr.io/acme/edge:v1",
		corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/srv"}})
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get secret regcred -n c8s-system -o json") echo '{"type":"kubernetes.io/dockerconfigjson"}' ;;
"get deployment vllm -n ws -o json") /bin/cat '`+vllm+`' ;;
"get deployment edge -n ws -o json") /bin/cat '`+edge+`' ;;
`))
	// One digest per adopted image: two entries at one digest would leave CDS
	// unable to tell which names the pod.
	s.f.tool(t, "crane", `case "$2" in
*vllm*) echo `+testPinVLLMDigest+` ;;
*) echo `+testPinEdgeDigest+` ;;
esac`)
	return s
}

// pinnedInstallBuilderFlags are the flags of every value builder the install
// has beyond the image pins and the CDS, which it always computes.
func pinnedInstallBuilderFlags(t *testing.T) map[string][]string {
	t.Helper()
	return map[string][]string{
		"volumed":           {"--volumes"},
		"image pull secret": {"--image-pull-secret", "regcred"},
		"operator keys":     {"--operator-keys", pinnedOperatorKeysFile(t)},
		"adopted workloads": {
			flagArg(flagWorkloadRef), "infer=ws/deployment/vllm",
			flagArg(flagWorkloadRef), "edge=ws/deployment/edge",
		},
	}
}

// installComputedValues runs an install and returns the computed values file
// helm read as its last -f, with the install's stderr.
func installComputedValues(t *testing.T, extra ...string) (computed []byte, stderr string) {
	t.Helper()
	s := pinnedInstallStubs(t)
	pin := pinnedCDSPinFile(t)
	args := append([]string{
		"install", "--platform=aks-snp", "--force",
		flagArg(flagCDSAddress), installCDSAddressUnreachable,
		flagArg(flagCDSPin), pin,
	}, extra...)
	var err error
	stderr = captureStderr(t, func() { err = runC8s(t, args...) })
	if err != nil {
		t.Fatalf("install %v: %v\nstderr:\n%s", extra, err, stderr)
	}
	data, err := os.ReadFile(s.computed)
	if err != nil {
		t.Fatalf("read the computed values helm received: %v", err)
	}
	return data, stderr
}

func TestInstallComputedValuesAreTheDocumentHelmReads(t *testing.T) {
	var flags []string
	for _, name := range []string{"volumed", "image pull secret", "operator keys", "adopted workloads"} {
		flags = append(flags, pinnedInstallBuilderFlags(t)[name]...)
	}
	computed, stderr := installComputedValues(t, flags...)
	if got := string(computed); got != wantPinnedComputedValues {
		t.Errorf("computed values =\n%s\nwant\n%s", got, wantPinnedComputedValues)
	}
	if echo := "+ computed values:\n" + wantPinnedComputedValues; strings.Count(stderr, echo) != 1 {
		t.Errorf("stderr =\n%s\nwant it to echo the computed values once, as\n%s", stderr, echo)
	}
}

// The builders' key paths are disjoint, so the order they are merged in does
// not decide what helm and the operator see: each builder's own run carries
// every leaf it writes at the value the install of all of them writes.
func TestInstallComputedValueBuildersWriteDisjointPaths(t *testing.T) {
	union := map[string]string{}
	owner := map[string]string{}
	for name, flags := range pinnedInstallBuilderFlags(t) {
		computed, _ := installComputedValues(t, flags...)
		for path, value := range installValueLeaves(t, computed) {
			if other, set := union[path]; set && other != value {
				t.Errorf("the %s and %s builders both write %s (%s vs %s)", owner[path], name, path, other, value)
			}
			union[path], owner[path] = value, name
		}
	}
	var all []string
	for _, flags := range pinnedInstallBuilderFlags(t) {
		all = append(all, flags...)
	}
	computed, _ := installComputedValues(t, all...)
	if leaves := installValueLeaves(t, computed); !maps.Equal(leaves, union) {
		t.Errorf("the install's computed leaves are %v, want every builder's own, %v", leaves, union)
	}
}

// installValueLeaves flattens a computed values document to one scalar per
// dotted path, list elements as path[i].
func installValueLeaves(t *testing.T, document []byte) map[string]string {
	t.Helper()
	var tree map[string]any
	if err := yaml.Unmarshal(document, &tree); err != nil {
		t.Fatalf("the computed values are not yaml: %v\n%s", err, document)
	}
	leaves := map[string]string{}
	var walk func(prefix string, value any)
	walk = func(prefix string, value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				walk(strings.TrimPrefix(prefix+"."+key, "."), child)
			}
		case []any:
			for i, child := range v {
				walk(prefix+"["+strconv.Itoa(i)+"]", child)
			}
		default:
			leaves[prefix] = fmt.Sprintf("%#v", v)
		}
	}
	walk("", tree)
	return leaves
}

// wantPinnedComputedValues is the whole document, as helm and the operator
// read it: the image pins, the CDS address and pin content, volumed, the pull
// secret, the operator keys' content and one entry per adopted workload.
const wantPinnedComputedValues = `armtlsMesh:
    image:
        digest: sha256:abababababababababababababababababababababababababababababababab
        repository: ghcr.io/confidential-dot-ai/armtls-mesh
attestationApi:
    image:
        digest: sha256:abababababababababababababababababababababababababababababababab
        repository: ghcr.io/confidential-dot-ai/attestation-api
cds:
    address: 127.0.0.1:1
    measurementsConfig: '{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","launch_file":"schemaVersion: c8s-cds/v1\nclusterID: test\noperatorPublicKeys: |\n  -----BEGIN PUBLIC KEY-----\n  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+ozuS8lfikNld52SnfWYj1/SlUGr\n  mG5PZp8/jAWmARD163wkoiQC2tlHUNJ6nqkN79y37EBKHGFV3B3CW+Ah6A==\n  -----END PUBLIC KEY-----\nworkloads: ''{\"schema\":\"c8s.allowlist/v1\",\"workloads\":{\"app\":{\"label\":\"registry/app@sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"containers\":[{\"digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"image\":\"registry/app@sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"command\":{\"policy\":\"any\"},\"args\":{\"policy\":\"any\"},\"mounts\":{\"policy\":\"any\"}}]}}}''\nnodes: ''{\"schema_version\":\"1\",\"tee\":\"sev-snp\",\"measurements\":[{\"name\":\"node\",\"measurement\":\"abababababababababababababababababababababababababababababababababababababababababababababababab\"}]}''\nnodeCIDRs:\n  - 192.0.2.0/24\nleafDNSNames:\n  - router.example.com\n"}]}'
    operatorKeys: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+ozuS8lfikNld52SnfWYj1/SlUGr
        mG5PZp8/jAWmARD163wkoiQC2tlHUNJ6nqkN79y37EBKHGFV3B3CW+Ah6A==
        -----END PUBLIC KEY-----
image:
    digest: sha256:abababababababababababababababababababababababababababababababab
    repository: ghcr.io/confidential-dot-ai/c8s-operator
imagePullSecret: regcred
nriImagePolicy:
    bootstrapAllowlist:
        workloads:
            edge:
                containers:
                    - args:
                        policy: any
                      command:
                        policy: any
                      digest: sha256:e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2
                      env:
                        policy: any
                      image: ghcr.io/acme/edge@sha256:e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2
                      mounts:
                        policy: any
                label: ws/deployment/edge
            infer:
                containers:
                    - args:
                        policy: any
                      command:
                        policy: any
                      digest: sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
                      env:
                        policy: any
                      image: ghcr.io/acme/vllm@sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
                      mounts:
                        policy: exact
                        rules:
                            - destination: /scratch
                              kind: emptyDir
                label: ws/deployment/vllm
    image:
        digest: sha256:abababababababababababababababababababababababababababababababab
        repository: ghcr.io/confidential-dot-ai/nri-image-policy
volumed:
    enabled: true
    image:
        digest: sha256:abababababababababababababababababababababababababababababababab
        repository: ghcr.io/confidential-dot-ai/volumed
`
