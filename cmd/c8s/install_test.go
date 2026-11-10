//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/charts"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsca"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/cmds/routes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/verify"
	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var errTestResolve = errors.New("simulated resolve failure")

func TestCDSPinPreflight(t *testing.T) {
	dir := t.TempDir()
	file := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	named := file("named.yaml", "cds:\n  address: 10.9.9.9:8443\n  measurementsConfig: '{}'\n")
	addressOnly := file("address.yaml", "cds:\n  address: 10.9.9.9:8443\n")
	emptied := file("emptied.yaml", "cds:\n  address: \"\"\n")
	for _, tc := range []struct {
		name         string
		address, pin string
		values       []string
		wantErr      bool
	}{
		{name: "nothing named", wantErr: true},
		{name: "address and pin", address: "10.9.9.9:8443", pin: "cds-pin.json"},
		{name: "address alone", address: "10.9.9.9:8443", wantErr: true},
		{name: "pin alone", pin: "cds-pin.json", wantErr: true},
		{name: "cds.address and cds.measurementsConfig", values: []string{named}},
		{name: "cds.address alone", values: []string{addressOnly}, wantErr: true},
		{name: "later file keeps the CDS", values: []string{addressOnly, named}},
		{name: "later file drops the address", values: []string{named, emptied}, wantErr: true},
		{name: "cds.operatorKeys names no CDS", values: []string{file("k.yaml", "cds:\n  operatorKeys: pem\n")}, wantErr: true},
		{name: "router disabled still needs a CDS", values: []string{file("r.yaml", "router:\n  enabled: false\n")}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := cdsPreflight(tc.address, tc.pin, tc.values)
			if (err != nil) != tc.wantErr {
				t.Fatalf("cdsPreflight() = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestReleaseChartVersion(t *testing.T) {
	for cliVersion, want := range map[string]string{
		"":                       "",
		"abc1234":                "",
		"dev":                    "",
		"v0.1.0":                 "0.1.0",
		"v0.1.0-5-gabc1234":      "",
		"v0.1.0-dirty":           "",
		"v0.92.0-beta.2":         "0.92.0-beta.2",
		"v0.92.0-beta.2-1-gabc1": "",
	} {
		got, ok := releaseChartVersion(cliVersion)
		if got != want || ok != (want != "") {
			t.Errorf("releaseChartVersion(%q) = %q, %v, want %q", cliVersion, got, ok, want)
		}
	}
}

func TestNamespaceManifestSetsPrivilegedPodSecurityLabels(t *testing.T) {
	data, err := namespaceManifest("c8s-system")
	if err != nil {
		t.Fatalf("namespaceManifest: %v", err)
	}

	var ns corev1.Namespace
	if err := json.Unmarshal(data, &ns); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, data)
	}

	if ns.APIVersion != "v1" || ns.Kind != "Namespace" {
		t.Fatalf("manifest TypeMeta = %s/%s, want v1/Namespace", ns.APIVersion, ns.Kind)
	}
	if ns.Name != "c8s-system" {
		t.Fatalf("manifest name = %q, want c8s-system", ns.Name)
	}
	// The install always ships privileged pods, so the namespace must permit
	// them regardless of flags; a CIS-hardened cluster default would otherwise
	// reject them at admission.
	for _, mode := range []string{"enforce", "warn", "audit"} {
		key := "pod-security.kubernetes.io/" + mode
		if got := ns.Labels[key]; got != "privileged" {
			t.Fatalf("label %s = %q, want privileged", key, got)
		}
	}
}

// The helm argv ordering is load-bearing: operator -f files before the computed
// file (last -f wins, so computed values win on the keys they set).
func TestBuildInstallHelmArgsOrdering(t *testing.T) {
	prevRel, prevNs := installRelease, installNamespace
	defer func() { installRelease, installNamespace = prevRel, prevNs }()
	installRelease, installNamespace = "c8s", "c8s-system"

	// Two operator -f files, wait on: computed file is LAST -f.
	assertArgsEqual(t, buildInstallHelmArgs("/chart", "/tmp/computed.yaml", []string{"a.yaml", "b.yaml"}, true), []string{
		"upgrade", "--install", "c8s", "/chart", "--namespace", "c8s-system",
		"-f", "a.yaml", "-f", "b.yaml", "-f", "/tmp/computed.yaml",
		"--wait", "--timeout=5m",
	})

	// No operator -f, wait off: computed file the only -f, no --wait.
	assertArgsEqual(t, buildInstallHelmArgs("/chart", "/tmp/computed.yaml", nil, false), []string{
		"upgrade", "--install", "c8s", "/chart", "--namespace", "c8s-system",
		"-f", "/tmp/computed.yaml",
	})

}

// --platform is one of the stock values files, or empty for -f to set the
// platform keys.
func TestValidatePlatform(t *testing.T) {
	for _, platform := range append([]string{""}, cloudPlatforms...) {
		if err := validatePlatform(platform); err != nil {
			t.Errorf("validatePlatform(%q) = %v, want nil", platform, err)
		}
	}
	if err := validatePlatform("aks"); err == nil {
		t.Error("validatePlatform(aks) = nil, want error")
	}
}

// Every --platform names a stock file the embedded chart carries, and the
// operator's own -f files come after it, as helm's precedence needs.
func TestCloudPlatformsHaveStockFiles(t *testing.T) {
	for _, platform := range cloudPlatforms {
		files := orderedValuesFiles(helmchart.CloudChartFSPath, platform, []string{"own.yaml"})
		if _, err := charts.FS.ReadFile(files[0]); err != nil {
			t.Errorf("--platform %s: %v", platform, err)
		}
		if want := []string{filepath.Join(helmchart.CloudChartFSPath, "values-"+platform+".yaml"), "own.yaml"}; !reflect.DeepEqual(files, want) {
			t.Errorf("--platform %s selects %v, want %v", platform, files, want)
		}
	}
	if files := orderedValuesFiles(helmchart.CloudChartFSPath, "", []string{"own.yaml"}); !reflect.DeepEqual(files, []string{"own.yaml"}) {
		t.Errorf("no --platform selects %v, want the -f files alone", files)
	}
}

func TestAppendVolumedInstallArgsDisabledIsNoOp(t *testing.T) {
	got := appendVolumedInstallArgs([]string{"upgrade"}, false)
	assertArgsEqual(t, got, []string{"upgrade"})
}

func TestAppendVolumedInstallArgsEnablesTheNodeAgent(t *testing.T) {
	got := appendVolumedInstallArgs([]string{"upgrade"}, true)
	assertArgsEqual(t, got, []string{"upgrade", "--set", "volumed.enabled=true"})
}

func TestParseWorkloadRef(t *testing.T) {
	tests := []struct {
		ref     string
		want    workloadRef
		wantErr []string
	}{
		{
			ref:  "workloads/deployment/vllm",
			want: workloadRef{kind: "deployment", name: "vllm", namespace: "workloads"},
		},
		{
			ref:  "workloads/sts/infer",
			want: workloadRef{kind: "statefulset", name: "infer", namespace: "workloads"},
		},
		{
			ref:  "workloads/ds/gpu-worker",
			want: workloadRef{kind: "daemonset", name: "gpu-worker", namespace: "workloads"},
		},
		{
			// A non-stock kind passes through verbatim for kubectl to resolve.
			ref:  "workloads/controller/infer",
			want: workloadRef{kind: "controller", name: "infer", namespace: "workloads"},
		},
		{
			// A dotted kind.group survives the middle-'/' split.
			ref:  "workloads/nodeset.example.net/worker",
			want: workloadRef{kind: "nodeset.example.net", name: "worker", namespace: "workloads"},
		},
		{
			// An optional :<port> suffix is the router upstream port.
			ref:  "vllm/deployment/router:8000",
			want: workloadRef{kind: "deployment", name: "router", namespace: "vllm", port: 8000},
		},
		{
			ref:     "vllm/deployment/router:0",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			ref:     "vllm/deployment/router:https",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			ref:     "vllm/deployment/router:70000",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			// A leading colon leaves an empty name before the :<port>.
			ref:     "vllm/deployment/:8000",
			wantErr: []string{"--workload-ref", "<namespace>/<kind>/<name>"},
		},
		{
			// Non-canonical port spellings Atoi would accept are rejected.
			ref:     "vllm/deployment/router:+8000",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			ref:     "vllm/deployment/router:08000",
			wantErr: []string{"--workload-ref", "1-65535"},
		},
		{
			ref:     "deployment/vllm",
			wantErr: []string{"--workload-ref", "<namespace>/<kind>/<name>"},
		},
		{
			ref:     "vllm",
			wantErr: []string{"--workload-ref", "<namespace>/<kind>/<name>"},
		},
		{
			ref:     "",
			wantErr: []string{"--workload-ref", "<namespace>/<kind>/<name>"},
		},
		{
			// A mis-split leaking an '=' into the name.
			ref:     "ns/deployment/na=me",
			wantErr: []string{"--workload-ref", "DNS-1123"},
		},
		{
			ref:     "ns/deployment/UPPER",
			wantErr: []string{"--workload-ref", "DNS-1123"},
		},
		{
			ref:     "BadNS/deployment/vllm",
			wantErr: []string{"--workload-ref", "namespace", "DNS-1123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got, err := parseWorkloadRef(tt.ref, flagWorkloadRef)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("ref = %+v, want %+v", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %v, got nil", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

func TestValidateWorkloadAdoptionFlags(t *testing.T) {
	tests := []struct {
		name      string
		releaseNS string
		refs      []string
		wait      bool
		wantErr   []string
	}{
		{name: "no ref is valid", wait: false},
		{name: "adopt in a separate namespace is valid", releaseNS: "c8s-system", refs: []string{"router=workloads/deployment/vllm"}, wait: true},
		{name: "ref rejects release namespace", releaseNS: "c8s-system", refs: []string{"router=c8s-system/deployment/vllm"}, wait: true, wantErr: []string{"--workload-ref", "c8s-system", "excluded"}},
		{name: "ref rejects the router namespace", releaseNS: "c8s-system", refs: []string{"router=c8s-router/deployment/vllm"}, wait: true, wantErr: []string{"--workload-ref", workloadclaims.RouterNamespace, "excluded"}},
		{name: "ref requires wait", releaseNS: "c8s-system", refs: []string{"router=workloads/deployment/vllm"}, wait: false, wantErr: []string{"--workload-ref", "--wait=true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adoptions, err := collectWorkloadAdoptions(tt.refs)
			if err != nil {
				t.Fatalf("collectWorkloadAdoptions: %v", err)
			}
			err = validateWorkloadAdoptionFlags(tt.releaseNS, adoptions, tt.wait)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %v, got nil", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

// TestUpstreamAddress drives the derivation behind the --upstream route
// backend address and the --upstream validation. The port comes from the
// selected ref's :<port> suffix, not a separate flag.
func TestUpstreamAddress(t *testing.T) {
	tests := []struct {
		name     string
		refs     []string
		upstream string
		want     string
		wantErr  []string
	}{
		{name: "no upstream yields empty", refs: []string{"router=vllm/deployment/vllm-router:8000"}, want: ""},
		{name: "selects a ref by cw id", refs: []string{"router=vllm/deployment/vllm-router:8000", "engine=vllm/deployment/vllm-engine"}, upstream: "router", want: "c8s-router.vllm.svc.cluster.local:8000"},
		{name: "selects the other ref", refs: []string{"router=vllm/deployment/vllm-router", "engine=vllm/deployment/vllm-engine:30000"}, upstream: "engine", want: "c8s-engine.vllm.svc.cluster.local:30000"},
		{name: "upstream must name a ref", refs: []string{"router=vllm/deployment/vllm-router:8000"}, upstream: "missing", wantErr: []string{"--upstream", "missing", "--workload-ref"}},
		{name: "selected ref needs a port", refs: []string{"router=vllm/deployment/vllm-router"}, upstream: "router", wantErr: []string{"--upstream", "router", "no :<port>"}},
		// The port must be on the SELECTED ref: a port on a different ref does
		// not satisfy the selected one.
		{name: "port on a different ref does not count", refs: []string{"router=vllm/deployment/vllm-router", "engine=vllm/deployment/vllm-engine:30000"}, upstream: "router", wantErr: []string{"--upstream", "router", "no :<port>"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adoptions, err := collectWorkloadAdoptions(tt.refs)
			if err != nil {
				t.Fatalf("collectWorkloadAdoptions: %v", err)
			}
			got, err := upstreamAddress(tt.upstream, adoptions)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("upstreamAddress = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %v, got nil", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

func TestCollectWorkloadAdoptions(t *testing.T) {
	got, err := collectWorkloadAdoptions([]string{
		"vllm-router=vllm/deployment/vllm-deployment-router",
		"vllm-engine=vllm/deployment/vllm-engine",
	})
	if err != nil {
		t.Fatalf("collectWorkloadAdoptions: %v", err)
	}
	want := []workloadAdoption{
		{cwID: "vllm-router", ref: workloadRef{kind: "deployment", name: "vllm-deployment-router", namespace: "vllm"}},
		{cwID: "vllm-engine", ref: workloadRef{kind: "deployment", name: "vllm-engine", namespace: "vllm"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adoptions = %+v, want %+v", got, want)
	}
}

func TestCollectWorkloadAdoptionsRejectsMalformedAdditionalRef(t *testing.T) {
	_, err := collectWorkloadAdoptions([]string{"vllm/deployment/vllm-engine"})
	if err == nil {
		t.Fatal("expected malformed --workload-ref to fail")
	}
	for _, want := range []string{"--workload-ref", "<cw-id>=<namespace>/<kind>/<name>"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCollectWorkloadAdoptionsRejectsInvalidWorkloadID(t *testing.T) {
	_, err := collectWorkloadAdoptions([]string{"Bad_ID=vllm/deployment/vllm-engine"})
	if err == nil {
		t.Fatal("expected invalid workload id to fail")
	}
	for _, want := range []string{"--workload-ref", "Bad_ID", "DNS-1035"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCollectWorkloadAdoptionsRejectsConflictingDuplicateRef(t *testing.T) {
	_, err := collectWorkloadAdoptions([]string{"vllm-router=vllm/deployment/vllm", "vllm-engine=vllm/deployment/vllm"})
	if err == nil {
		t.Fatal("expected conflicting duplicate workload ref to fail")
	}
	for _, want := range []string{"vllm/deployment/vllm", "vllm-router", "vllm-engine"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCollectWorkloadAdoptionsRejectsConflictingPort(t *testing.T) {
	// Same workload + same cw id but different :<port> must error, not silently
	// dedup to the first ref's port.
	_, err := collectWorkloadAdoptions([]string{"vllm=vllm/deployment/x:8000", "vllm=vllm/deployment/x:9000"})
	if err == nil {
		t.Fatal("expected conflicting upstream ports to fail")
	}
	for _, want := range []string{"vllm/deployment/x", "8000", "9000"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCollectWorkloadAdoptionsRejectsSharedCWID(t *testing.T) {
	_, err := collectWorkloadAdoptions([]string{"shared=vllm/deployment/a", "shared=vllm/deployment/b"})
	if err == nil {
		t.Fatal("expected one cw id on two workloads to fail")
	}
	for _, want := range []string{"shared", "vllm/deployment/a", "vllm/deployment/b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestConfidentialWorkloadPatchAnnotatesPodTemplate(t *testing.T) {
	data, err := confidentialWorkloadPatch("infer")
	if err != nil {
		t.Fatalf("confidentialWorkloadPatch: %v", err)
	}
	var patch map[string]any
	if err := json.Unmarshal(data, &patch); err != nil {
		t.Fatalf("patch is not JSON: %v\n%s", err, data)
	}
	spec := patch["spec"].(map[string]any)
	template := spec["template"].(map[string]any)
	metadata := template["metadata"].(map[string]any)
	annotations := metadata["annotations"].(map[string]any)
	if got := annotations[webhook.AnnotationWorkload]; got != "infer" {
		t.Fatalf("%s = %#v, want infer", webhook.AnnotationWorkload, got)
	}
}

func TestWorkloadPodTemplateImages(t *testing.T) {
	deployment := appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Image: "ghcr.io/acme/init:v1"}},
					Containers: []corev1.Container{
						{Image: "ghcr.io/acme/router:v1"},
						{Image: "ghcr.io/acme/router:v1"},
					},
				},
			},
		},
	}
	data, err := json.Marshal(deployment)
	if err != nil {
		t.Fatalf("marshal deployment: %v", err)
	}
	template, err := workloadPodTemplate(data)
	if err != nil {
		t.Fatalf("workloadPodTemplate: %v", err)
	}
	got := podTemplateImages(template)
	want := podImages{Init: []string{"ghcr.io/acme/init:v1"}, Main: []string{"ghcr.io/acme/router:v1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("images = %v, want %v", got, want)
	}

	// A CRD carrying its pod template at spec.template decodes the same way,
	// with no matching Go type.
	crd := []byte(`{
		"apiVersion": "example.net/v1beta1",
		"kind": "NodeSet",
		"spec": {"template": {"spec": {"containers": [{"image": "ghcr.io/acme/worker:v3"}]}}}
	}`)
	template, err = workloadPodTemplate(crd)
	if err != nil {
		t.Fatalf("workloadPodTemplate crd: %v", err)
	}
	if got, want := podTemplateImages(template), (podImages{Main: []string{"ghcr.io/acme/worker:v3"}}); !reflect.DeepEqual(got, want) {
		t.Fatalf("crd images = %v, want %v", got, want)
	}
}

func TestBuildWorkloadImageArgsWritesOneEntryPerWorkload(t *testing.T) {
	const (
		dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		dC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)
	resolve := func(ref string) (string, error) {
		switch ref {
		case "ghcr.io/acme/router:v1", "ghcr.io/acme/router:latest":
			return dB, nil
		case "ghcr.io/acme/engine:v2":
			return dA, nil
		}
		t.Fatalf("unexpected ref resolved: %q", ref)
		return "", nil
	}
	scratch := corev1.VolumeMount{Name: "scratch", MountPath: "/scratch/"}
	got, entries, err := buildWorkloadImageArgs([]string{"upgrade"}, []adoptedWorkload{
		{
			workloadAdoption: workloadAdoption{cwID: "infer", ref: workloadRef{kind: "deployment", name: "vllm", namespace: "ws"}},
			template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Volumes:        []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}}},
				InitContainers: []corev1.Container{{Name: "init", Image: "busybox@" + dC}},
				// Two tags of one image are one container.
				Containers: []corev1.Container{
					{Name: "router", Image: "ghcr.io/acme/router:v1"},
					{Name: "engine", Image: "ghcr.io/acme/engine:v2", VolumeMounts: []corev1.VolumeMount{scratch}},
					{Name: "router2", Image: "ghcr.io/acme/router:latest"},
				},
			}},
		},
	}, "", io.Discard, resolve)
	if err != nil {
		t.Fatalf("buildWorkloadImageArgs: %v", err)
	}
	container := func(field string, i int, digest, ref string, mounts ...string) []string {
		p := fmt.Sprintf("nriImagePolicy.bootstrapAllowlist.workloads.infer.%s[%d].", field, i)
		policy := "exact"
		if len(mounts) == 0 {
			policy = "deny"
		}
		args := []string{
			"--set-string", p + "digest=" + digest,
			"--set-string", p + "image=" + ref,
			"--set-string", p + "command.policy=any",
			"--set-string", p + "args.policy=any",
			"--set-string", p + "env.policy=any",
			"--set-string", p + "mounts.policy=" + policy,
		}
		for i, m := range mounts {
			r := fmt.Sprintf("%smounts.rules[%d].", p, i)
			args = append(args, "--set-string", r+"destination="+m, "--set-string", r+"kind=emptyDir")
		}
		return args
	}
	want := []string{"upgrade", "--set-string", "nriImagePolicy.bootstrapAllowlist.workloads.infer.label=ws/deployment/vllm"}
	want = append(want, container("containers", 0, dB, "ghcr.io/acme/router@"+dB)...)
	want = append(want, container("containers", 1, dA, "ghcr.io/acme/engine@"+dA, "/scratch")...)
	want = append(want, container("initContainers", 0, dC, "docker.io/library/busybox@"+dC)...)
	assertArgsEqual(t, got, want)
	if slices.ContainsFunc(got, func(a string) bool { return strings.HasSuffix(a, "mounts.policy=any") }) {
		t.Fatal("an adopted workload's entry admits any mount")
	}
	// install hands these args to helm as a values file, so they must build
	// one, and the entry in it must be one CDS accepts.
	tree, err := valueArgsToTree(got[1:])
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	workloads, _ := nestedMap(tree, "nriImagePolicy", "bootstrapAllowlist", "workloads")
	raw, err := json.Marshal(workloads["infer"])
	if err != nil {
		t.Fatal(err)
	}
	w, err := pkgallowlist.ParseWorkloadJSON(raw)
	if err != nil {
		t.Fatalf("ParseWorkloadJSON(%s) = %v", raw, err)
	}
	i := slices.IndexFunc(w.Containers, func(c pkgallowlist.Container) bool { return c.Digest.String() == dA })
	if i < 0 {
		t.Fatalf("parsed entry %+v lacks the engine image", w)
	}
	if m := w.Containers[i].Mounts; m.Policy != pkgallowlist.PolicyExact || len(m.Rules) != 1 {
		t.Fatalf("engine mounts = %+v, want exact /scratch", m)
	}
	e := entries["infer"]
	if got, want := normalized(t, e.workload), normalized(t, *w); got != want {
		t.Fatalf("entries[infer].workload = %s, want the entry helm renders, %s", got, want)
	}
	// The pod CDS sees runs every main, router twice; the init has exited.
	var running []string
	for _, r := range e.pod {
		running = append(running, r.Digest)
	}
	if want := []string{dB, dA, dB}; !slices.Equal(running, want) {
		t.Fatalf("entries[infer].pod = %v, want %v", running, want)
	}
	if !w.Diff(e.pod).Describes() {
		t.Fatalf("entry %+v does not describe its pod %+v", *w, e.pod)
	}
}

// TestBuildWorkloadImageArgsKeepsRoles: one image under two mount sets is
// two declarations, an init container keeps its role, and a native sidecar
// runs in the pod CDS matches.
func TestBuildWorkloadImageArgsKeepsRoles(t *testing.T) {
	busybox := "busybox@sha256:" + strings.Repeat("b", 64)
	proxy := "proxy@sha256:" + strings.Repeat("e", 64)
	always := corev1.ContainerRestartPolicyAlways
	tmpl := corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}}},
		InitContainers: []corev1.Container{
			{Name: "prep", Image: busybox, VolumeMounts: []corev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}}},
			{Name: "proxy", Image: proxy, RestartPolicy: &always},
		},
		Containers: []corev1.Container{{Name: "app", Image: busybox}},
	}}
	_, entries, err := buildWorkloadImageArgs(nil, []adoptedWorkload{{workloadAdoption: workloadAdoption{cwID: "web"}, template: tmpl}}, "", io.Discard, nil)
	if err != nil {
		t.Fatalf("buildWorkloadImageArgs() = %v, want an entry", err)
	}
	e := entries["web"]
	if len(e.workload.Containers) != 1 || len(e.workload.InitContainers) != 2 || len(e.workload.InitContainers[0].Mounts.Rules) != 1 {
		t.Fatalf("entry = %+v, want main busybox, init busybox with /scratch, init proxy", e.workload)
	}
	if len(e.pod) != 2 || e.pod[1].Digest != "sha256:"+strings.Repeat("e", 64) {
		t.Fatalf("pod = %+v, want app and the proxy sidecar", e.pod)
	}
	al := &pkgallowlist.Allowlist{Workloads: map[string]pkgallowlist.Workload{"web": e.workload}}
	if name, _, err := al.MatchWorkload(e.pod); err != nil || name != "web" {
		t.Fatalf("MatchWorkload(pod) = %q, %v, want web", name, err)
	}
}

// templateRunning is a pod template with one container running image.
func templateRunning(image string) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}}}
}

// TestBuildWorkloadImageArgsRefusesUnmodelledMounts: when the --upstream
// target mounts what an exact rule cannot admit, or what the host controls,
// install writes no entry for it.
func TestBuildWorkloadImageArgsRefusesUnmodelledMounts(t *testing.T) {
	withVolume := func(v corev1.VolumeSource) corev1.PodTemplateSpec {
		tmpl := templateRunning("busybox@sha256:" + strings.Repeat("c", 64))
		tmpl.Spec.Volumes = []corev1.Volume{{Name: "v", VolumeSource: v}}
		tmpl.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "v", MountPath: "/app"}}
		return tmpl
	}
	secrets := templateRunning("busybox@sha256:" + strings.Repeat("c", 64))
	secrets.Annotations = map[string]string{webhook.AnnotationSecrets: "db"}
	subPath := withVolume(corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}})
	subPath.Spec.Containers[0].VolumeMounts[0].SubPath = "app"
	for name, tmpl := range map[string]corev1.PodTemplateSpec{
		"memory emptyDir subPath": subPath,
		"hostPath":                withVolume(corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/srv"}}),
		"configMap":               withVolume(corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}),
		"disk emptyDir":           withVolume(corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}),
		"secrets":                 secrets,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := buildWorkloadImageArgs(nil, []adoptedWorkload{{workloadAdoption: workloadAdoption{cwID: "web"}, template: tmpl}}, "web", io.Discard, nil)
			if err == nil || !strings.Contains(err.Error(), `write one named "web" yourself`) {
				t.Fatalf("buildWorkloadImageArgs() = %v, want the refusal", err)
			}
		})
	}
}

// TestBuildWorkloadImageArgsUnmodelledMountsOffUpstream: an adopted workload
// that is not the --upstream target keeps an entry admitting any mounts, which
// the node admits with its injected certificate volume, with a warning, and
// the same workload as the target is refused.
func TestBuildWorkloadImageArgsUnmodelledMountsOffUpstream(t *testing.T) {
	tmpl := templateRunning("busybox@sha256:" + strings.Repeat("c", 64))
	tmpl.Spec.Volumes = []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{}}}}
	tmpl.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "v", MountPath: "/app"}}
	adopted := []adoptedWorkload{
		{workloadAdoption: workloadAdoption{cwID: "web"}, template: tmpl},
		{workloadAdoption: workloadAdoption{cwID: "infer"}, template: templateRunning("example/infer@sha256:" + strings.Repeat("d", 64))},
	}
	var warn bytes.Buffer
	args, entries, err := buildWorkloadImageArgs(nil, adopted, "infer", &warn, nil)
	if err != nil {
		t.Fatalf("buildWorkloadImageArgs(upstream infer) = %v, want nil", err)
	}
	if !strings.Contains(warn.String(), "warning: adopted workload web") || !strings.Contains(warn.String(), "a route to it trusts those mounts") {
		t.Fatalf("warning = %q, want one warning that a route to web trusts its mounts", warn.String())
	}
	if _, ok := entries["web"]; ok {
		t.Fatalf("entries = %v, want no modelled entry for web", slices.Sorted(maps.Keys(entries)))
	}
	if _, ok := entries["infer"]; !ok {
		t.Fatalf("entries = %v, want infer", slices.Sorted(maps.Keys(entries)))
	}
	web := "nriImagePolicy.bootstrapAllowlist.workloads.web.containers[0]."
	if !slices.Contains(args, web+"digest=sha256:"+strings.Repeat("c", 64)) || !slices.Contains(args, web+"mounts.policy=any") {
		t.Fatalf("args = %q, want a web container admitting any mounts", args)
	}
	if _, _, err := buildWorkloadImageArgs(nil, adopted, "web", io.Discard, nil); err == nil || !strings.Contains(err.Error(), `write one named "web" yourself`) {
		t.Fatalf("buildWorkloadImageArgs(upstream web) = %v, want the refusal", err)
	}
}

// TestAdoptMeFixtureGetsAnEntry: the kind harness's adopted workload is one
// install can write an entry for, so the fixture does not depend on the
// any-mounts floor to be admitted and named.
func TestAdoptMeFixtureGetsAnEntry(t *testing.T) {
	data, err := os.ReadFile("../../test/integration/cluster/manifests/adopt-me.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var deployment appsv1.Deployment
	for _, doc := range strings.Split(string(data), "\n---\n") {
		if strings.Contains(doc, "kind: Deployment") {
			if err := sigsyaml.Unmarshal([]byte(doc), &deployment); err != nil {
				t.Fatal(err)
			}
		}
	}
	raw, err := json.Marshal(deployment)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := workloadPodTemplate(raw)
	if err != nil {
		t.Fatal(err)
	}
	adoption := workloadAdoption{cwID: "web", ref: workloadRef{namespace: "adopted", kind: "deployment", name: "web"}}
	got, entries, err := buildWorkloadImageArgs(nil, []adoptedWorkload{{workloadAdoption: adoption, template: tmpl}}, "", io.Discard, nil)
	if err != nil {
		t.Fatalf("buildWorkloadImageArgs(adopt-me) = %v", err)
	}
	if !slices.Contains(got, "nriImagePolicy.bootstrapAllowlist.workloads.web.containers[0].mounts.policy=deny") || slices.ContainsFunc(got, func(arg string) bool {
		return strings.Contains(arg, "mounts.rules[")
	}) {
		t.Fatalf("adopt-me entry = %v, want empty mounts", got)
	}
	// The NRI plugin's tests match this entry against the mounts it observes
	// on the injected container.
	entry, err := json.MarshalIndent(entries["web"].workload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	const golden = "../../test/integration/cluster/testdata/adopt-me-entry.json"
	if os.Getenv("C8S_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, append(entry, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(entry)+"\n" {
		t.Fatalf("adopt-me entry = %s, want %s (C8S_UPDATE_GOLDEN=1 rewrites it)", entry, want)
	}
}

func TestCheckAdoptedEntries(t *testing.T) {
	const (
		dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		dN = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	)
	pod := func(digests ...string) corev1.PodTemplateSpec {
		var tmpl corev1.PodTemplateSpec
		for i, d := range digests {
			tmpl.Spec.Containers = append(tmpl.Spec.Containers, corev1.Container{Name: fmt.Sprint("c", i), Image: "example/app@" + d})
		}
		return tmpl
	}
	withInit := func(tmpl corev1.PodTemplateSpec, digest string) corev1.PodTemplateSpec {
		tmpl.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "example/init@" + digest}}
		return tmpl
	}
	withScratch := func(tmpl corev1.PodTemplateSpec) corev1.PodTemplateSpec {
		tmpl.Spec.Volumes = []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}}}
		tmpl.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}}
		return tmpl
	}
	image := func(digest string) map[string]any {
		return map[string]any{"repository": "example/component", "digest": digest}
	}
	values := func(workloads map[string]any, extra map[string]any) map[string]any {
		if workloads == nil {
			workloads = map[string]any{}
		}
		v := map[string]any{
			"router":         map[string]any{"enabled": true, "nginx": map[string]any{"image": map[string]any{"repository": "nginxinc/nginx-unprivileged", "digest": dN}}},
			"nriImagePolicy": map[string]any{"bootstrapAllowlist": map[string]any{"workloads": workloads}},
		}
		return helmchart.MergeValues(v, extra)
	}
	anyContainer := func(digest string) map[string]any {
		return map[string]any{"digest": digest, "command": map[string]any{"policy": "any"}, "args": map[string]any{"policy": "any"}, "mounts": map[string]any{"policy": "any"}}
	}
	perDigest := map[string]any{"a": map[string]any{"containers": []any{anyContainer(dA)}}}
	tests := []struct {
		name    string
		adopt   map[string]corev1.PodTemplateSpec
		values  map[string]any
		wantErr string
	}{
		{"multi-container pod beside per-digest entries", map[string]corev1.PodTemplateSpec{"web": pod(dA, dB)}, values(perDigest, nil), ""},
		{"single image with an unconstrained per-digest entry", map[string]corev1.PodTemplateSpec{"web": pod(dA)}, values(perDigest, nil), "entries a also admit"},
		{"argv-pinned -f entry counts, as on CDS", map[string]corev1.PodTemplateSpec{"web": pod(dA)},
			values(map[string]any{"a": map[string]any{"containers": []any{map[string]any{"digest": dA, "command": map[string]any{"policy": "exact", "argv": []any{"/serve"}}, "mounts": map[string]any{"policy": "any"}}}}}, nil), "entries a also admit"},
		{"own -f entry is replaced", map[string]corev1.PodTemplateSpec{"web": pod(dA)}, values(map[string]any{"web": map[string]any{"containers": []any{anyContainer(dA)}}}, nil), ""},
		{"two adoptions, one image set", map[string]corev1.PodTemplateSpec{"web": pod(dA, dB), "api": pod(dA, dB)}, values(nil, nil), "entries web also admit"},
		{"init image does not make a pod ambiguous", map[string]corev1.PodTemplateSpec{"web": withInit(pod(dA), dB), "api": pod(dB)}, values(nil, nil), ""},
		{"same image, different mounts", map[string]corev1.PodTemplateSpec{"web": pod(dA), "api": withScratch(pod(dA))}, values(nil, nil), ""},
		{"component image", map[string]corev1.PodTemplateSpec{"web": pod(dA)}, values(nil, map[string]any{"cds": map[string]any{"image": image(dA)}}), ""},
		{"router nginx image", map[string]corev1.PodTemplateSpec{"web": pod(dN)}, values(nil, nil), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var adopted []adoptedWorkload
			for _, id := range slices.Sorted(maps.Keys(tc.adopt)) {
				adopted = append(adopted, adoptedWorkload{workloadAdoption: workloadAdoption{cwID: id}, template: tc.adopt[id]})
			}
			args, entries, err := buildWorkloadImageArgs(nil, adopted, "", io.Discard, nil)
			if err != nil {
				t.Fatal(err)
			}
			computed, err := valueArgsToTree(args)
			if err != nil {
				t.Fatal(err)
			}
			err = checkAdoptedEntries(entries, helmchart.MergeValues(tc.values, computed))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkAdoptedEntries() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkAdoptedEntries() = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildWorkloadImageArgsFailsClosedOnResolveError(t *testing.T) {
	_, _, err := buildWorkloadImageArgs(nil, []adoptedWorkload{{template: templateRunning("ghcr.io/acme/router:v1")}}, "", io.Discard, func(string) (string, error) {
		return "", errTestResolve
	})
	if err == nil {
		t.Fatal("expected workload image resolver failure to abort")
	}
}

// A workload image already pinned by a non-sha256 digest (distribution/reference
// accepts sha512) must fail closed with a message naming the sha256 constraint,
// since the NRI allowlist keys on sha256 only.
func TestBuildWorkloadImageArgsRejectsNonSHA256Digest(t *testing.T) {
	sha512Image := "busybox@sha512:ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
	_, _, err := buildWorkloadImageArgs(nil, []adoptedWorkload{{template: templateRunning(sha512Image)}}, "", io.Discard, func(string) (string, error) {
		t.Fatal("resolve must not run for an already-digested image")
		return "", nil
	})
	if err == nil {
		t.Fatal("expected non-sha256 pinned digest to be rejected")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("error %q should name the sha256 constraint", err.Error())
	}
}

func TestImagePinnedByDigest(t *testing.T) {
	cases := []struct {
		image string
		want  bool
	}{
		{"busybox@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", true},
		{"ghcr.io/acme/router:v1@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", true},
		{"ghcr.io/acme/router:v1", false},
		{"busybox", false},
		{"busybox:latest", false},
		{"not a ref", false},
	}
	for _, c := range cases {
		if got := imagePinnedByDigest(c.image); got != c.want {
			t.Errorf("imagePinnedByDigest(%q) = %v, want %v", c.image, got, c.want)
		}
	}
}

func TestCheckImagePullSecret(t *testing.T) {
	tests := []struct {
		name    string
		sec     *corev1.Secret
		wantErr bool
		wantIn  []string // substrings the error must carry (the fix, not just the failure)
	}{
		{name: "dockerconfigjson secret exists", sec: &corev1.Secret{Type: corev1.SecretTypeDockerConfigJson}, wantErr: false},
		{name: "legacy dockercfg secret exists", sec: &corev1.Secret{Type: corev1.SecretTypeDockercfg}, wantErr: false},
		{
			name:    "missing secret",
			sec:     nil,
			wantErr: true,
			wantIn:  []string{"kubectl create secret docker-registry"},
		},
		{
			// kubelet silently skips non-registry Secret types, so this would
			// otherwise only surface as ImagePullBackOff.
			name:    "wrong secret type",
			sec:     &corev1.Secret{Type: corev1.SecretTypeOpaque},
			wantErr: true,
			wantIn:  []string{string(corev1.SecretTypeDockerConfigJson)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkImagePullSecret(tt.sec, "c8s-system", "ghcr-secret")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %t", err, tt.wantErr)
			}
			for _, want := range tt.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

// The only distro signal kubectl can see is the build metadata a bundled
// kubelet stamps onto its version. A node reporting none is upstream's as far
// as the install can tell, and one reporting no version at all is skipped.
func TestBundledKubeletNodes(t *testing.T) {
	got := bundledKubeletNodes([]string{
		"node-a\tv1.29.5+rke2r1",
		"node-b\tv1.29.5",
		"node-c\tv1.30.0+k3s1",
		"",
		"malformed-no-tab",
	})
	if want := []string{"node-a", "node-c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("bundledKubeletNodes = %v, want %v", got, want)
	}
	if got := bundledKubeletNodes(nil); got != nil {
		t.Errorf("bundledKubeletNodes(nil) = %v, want none", got)
	}
}

// Nodes are named with the runtime they report, since that is what the
// operator has to raise. The comparison reads the version numbers alone, so a
// build suffix is not a verdict, and a node reporting no runtime version is
// skipped.
func TestNodesWithoutNRIUser(t *testing.T) {
	got := nodesWithoutNRIUser([]string{
		"node-a\tcontainerd://2.2.7",
		"node-b\tcontainerd://2.3.3+azure",
		"node-c\tcontainerd://1.7.33",
		"node-d\tcontainerd://2.4.1",
		"node-e\tcri-o://1.33.0",
		"node-f\tcontainerd://2.3.0",
		"node-g\t",
		"",
	})
	want := []string{"node-a (containerd://2.2.7)", "node-c (containerd://1.7.33)", "node-e (cri-o://1.33.0)"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nodesWithoutNRIUser = %v, want %v", got, want)
	}
	if got := nodesWithoutNRIUser(nil); got != nil {
		t.Errorf("nodesWithoutNRIUser(nil) = %v, want none", got)
	}
}

func TestHostPortConflict(t *testing.T) {
	pod := func(ns, name, node string, port int32) corev1.Pod {
		return corev1.Pod{
			Namespace: ns, Name: name,
			Spec: corev1.PodSpec{
				NodeName:   node,
				Containers: []corev1.Container{{Name: "c", Ports: []corev1.ContainerPort{{HostPort: port}}}},
			},
		}
	}
	const ignoreNS = "c8s-system"

	for _, tc := range []struct {
		name        string
		pods        []corev1.Pod
		nodes       []string
		wantBlocked bool
		wantHolder  string // substring expected in holders, or "" for none
	}{
		{
			name:        "single node, ingress holds 443",
			pods:        []corev1.Pod{pod("kube-system", "ingress-nginx-controller-abc", "node-a", 443)},
			nodes:       []string{"node-a"},
			wantBlocked: true,
			wantHolder:  "kube-system/ingress-nginx-controller-abc",
		},
		{
			name: "two nodes, ingress on both",
			pods: []corev1.Pod{
				pod("kube-system", "ing-a", "node-a", 443),
				pod("kube-system", "ing-b", "node-b", 443),
			},
			nodes:       []string{"node-a", "node-b"},
			wantBlocked: true,
		},
		{
			name:        "two nodes, ingress on only one leaves a free node",
			pods:        []corev1.Pod{pod("kube-system", "ing-a", "node-a", 443)},
			nodes:       []string{"node-a", "node-b"},
			wantBlocked: false,
		},
		{
			name:        "holder only in ignored namespace",
			pods:        []corev1.Pod{pod(ignoreNS, "c8s-router", "node-a", 443)},
			nodes:       []string{"node-a"},
			wantBlocked: false,
		},
		{
			name:        "different port is not a conflict",
			pods:        []corev1.Pod{pod("kube-system", "ing-a", "node-a", 8080)},
			nodes:       []string{"node-a"},
			wantBlocked: false,
		},
		{
			name:        "unscheduled holder occupies no node",
			pods:        []corev1.Pod{pod("kube-system", "pending", "", 443)},
			nodes:       []string{"node-a"},
			wantBlocked: false,
			wantHolder:  "kube-system/pending",
		},
		{
			name:        "no nodes",
			pods:        []corev1.Pod{pod("kube-system", "ing-a", "node-a", 443)},
			nodes:       nil,
			wantBlocked: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocked, holders := hostPortConflict(tc.pods, tc.nodes, 443, ignoreNS)
			if blocked != tc.wantBlocked {
				t.Errorf("blocked = %v, want %v (holders=%v)", blocked, tc.wantBlocked, holders)
			}
			if tc.wantHolder != "" && !strings.Contains(strings.Join(holders, ","), tc.wantHolder) {
				t.Errorf("holders %v missing %q", holders, tc.wantHolder)
			}
		})
	}
}

// chartComponents reads the component set from the chart's c8s-lib table;
// this asserts the parse against the embedded chart so the install-time list
// cannot silently diverge from what the chart declares.
func TestChartComponentsFromEmbeddedChart(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	dir, err := helmchart.ExtractTemp()
	if err != nil {
		t.Fatalf("extract the chart: %v", err)
	}
	defer os.RemoveAll(dir)

	comps, err := chartComponents(context.Background(), filepath.Join(dir, helmchart.CloudChartFSPath))
	if err != nil {
		t.Fatalf("chartComponents: %v", err)
	}

	got := map[string]string{}
	for _, c := range comps {
		got[c.valuesPath] = c.repository
	}
	want := map[string]string{
		"image":                "ghcr.io/confidential-dot-ai/c8s-operator",
		"attestationApi.image": "ghcr.io/confidential-dot-ai/attestation-api",
		"armtlsMesh.image":     "ghcr.io/confidential-dot-ai/armtls-mesh",
		"nriImagePolicy.image": "ghcr.io/confidential-dot-ai/nri-image-policy",
		"volumed.image":        "ghcr.io/confidential-dot-ai/volumed",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chart components = %v, want %v", got, want)
	}
}

// effectiveValues must honor a -f values file, not just chart
// defaults and --set.
func TestEffectiveValuesHonorsValuesFile(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	dir, err := helmchart.ExtractTemp()
	if err != nil {
		t.Fatalf("extract the chart: %v", err)
	}
	defer os.RemoveAll(dir)
	chartPath := filepath.Join(dir, helmchart.CloudChartFSPath)

	vf := filepath.Join(t.TempDir(), "enable-volumed.yaml")
	if err := os.WriteFile(vf, []byte("volumed:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Default (no -f): volumed reads as disabled.
	tree, err := effectiveValues(context.Background(), chartPath, nil, nil)
	if err != nil {
		t.Fatalf("effectiveValues (defaults): %v", err)
	}
	if boolAtPath(tree, "volumed.enabled") {
		t.Fatal("volumed.enabled true with no -f; expected the chart default false")
	}

	// With the -f file: volumed reads as enabled.
	tree, err = effectiveValues(context.Background(), chartPath, []string{vf}, nil)
	if err != nil {
		t.Fatalf("effectiveValues (-f): %v", err)
	}
	if !boolAtPath(tree, "volumed.enabled") {
		t.Fatal("volumed.enabled false despite a -f file enabling it")
	}
}

// helmchart.MergeValues must deep-merge a -f overlay the way helm coalesces
// it: a nested map merges key-by-key (so enabling volumed via -f does not
// wipe its sibling image/hostPaths defaults), while a scalar replaces.
func TestMergeValuesDeepMergesOverlay(t *testing.T) {
	base := map[string]any{
		"volumed": map[string]any{
			"enabled": false,
			"image":   map[string]any{"repository": "ghcr.io/confidential-dot-ai/volumed", "tag": ""},
		},
		"router": map[string]any{"enabled": true},
	}
	overlay := map[string]any{
		"volumed": map[string]any{"enabled": true},
	}
	helmchart.MergeValues(base, overlay)

	if !boolAtPath(base, "volumed.enabled") {
		t.Error("volumed.enabled not flipped to true by the overlay")
	}
	// The sibling image map must survive the merge — a shallow replace would
	// drop it and break digest resolution.
	vol := base["volumed"].(map[string]any)
	img, ok := vol["image"].(map[string]any)
	if !ok || img["repository"] != "ghcr.io/confidential-dot-ai/volumed" {
		t.Errorf("overlay wiped volumed.image; got %v", vol["image"])
	}
	if !boolAtPath(base, "router.enabled") {
		t.Error("unrelated router.enabled was disturbed by the overlay")
	}
}

func assertArgsEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args = %v (len %d), want %v (len %d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; got %v", i, got[i], want[i], got)
		}
	}
}

func TestMaterializeStdinValues(t *testing.T) {
	t.Run("no dash passes files through untouched", func(t *testing.T) {
		got, cleanup, err := materializeStdinValues([]string{"a.yaml", "b.yaml"}, strings.NewReader("ignored"))
		if err != nil {
			t.Fatalf("materializeStdinValues: %v", err)
		}
		defer cleanup()
		if !reflect.DeepEqual(got, []string{"a.yaml", "b.yaml"}) {
			t.Errorf("got %v, want the input unchanged", got)
		}
	})

	t.Run("dash becomes a temp file holding the piped bytes, in order", func(t *testing.T) {
		payload := "router:\n  enabled: false\n"
		got, cleanup, err := materializeStdinValues([]string{"base.yaml", "-", "last.yaml"}, strings.NewReader(payload))
		if err != nil {
			t.Fatalf("materializeStdinValues: %v", err)
		}
		defer cleanup()
		if len(got) != 3 || got[0] != "base.yaml" || got[2] != "last.yaml" || got[1] == "-" {
			t.Fatalf("substitution broke ordering: %v", got)
		}
		data, err := os.ReadFile(got[1])
		if err != nil {
			t.Fatalf("read materialized file: %v", err)
		}
		if string(data) != payload {
			t.Errorf("materialized content = %q, want the piped %q", data, payload)
		}
	})

	t.Run("cleanup removes the temp files", func(t *testing.T) {
		got, cleanup, err := materializeStdinValues([]string{"-"}, strings.NewReader("a: 1\n"))
		if err != nil {
			t.Fatalf("materializeStdinValues: %v", err)
		}
		cleanup()
		if _, err := os.Stat(got[0]); !os.IsNotExist(err) {
			t.Errorf("temp file %s survives cleanup: %v", got[0], err)
		}
	})

	t.Run("a stdin read failure aborts", func(t *testing.T) {
		if _, _, err := materializeStdinValues([]string{"-"}, errReader{}); err == nil {
			t.Fatal("want the read error surfaced")
		}
	})

	t.Run("a temp-file write failure aborts", func(t *testing.T) {
		// RLIMIT_FSIZE=0 fails the payload write (Go swallows the SIGXFSZ),
		// but the limit is process-wide: the harness's own testlog appends
		// race the zeroed window and an unlucky buffer flush fails the whole
		// package with "can't write testlog.txt: file too large" while every
		// test is green. So the limit is zeroed in a re-exec'ed child (which
		// runs without a testlog) and the parent reads its verdict from
		// stdout — a pipe, which RLIMIT_FSIZE does not cover. The exit code
		// is deliberately not consulted: under -coverprofile the child may
		// fail writing its own coverage file inside the window.
		if os.Getenv("C8S_TEST_FSIZE_CHILD") == "1" {
			var lim syscall.Rlimit
			if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
				fmt.Println("CHILD_SKIP getrlimit:", err)
				return
			}
			lim.Cur = 0
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
				fmt.Println("CHILD_SKIP setrlimit:", err)
				return
			}
			if _, _, err := materializeStdinValues([]string{"-"}, strings.NewReader("a: 1\n")); err != nil {
				fmt.Println("CHILD_GOT_WRITE_ERROR")
			} else {
				fmt.Println("CHILD_NO_ERROR")
			}
			return
		}

		cmd := exec.Command(os.Args[0], "-test.run", "TestMaterializeStdinValues/a_temp-file_write_failure_aborts")
		cmd.Env = append(os.Environ(), "C8S_TEST_FSIZE_CHILD=1")
		out, _ := cmd.CombinedOutput()
		switch {
		case bytes.Contains(out, []byte("CHILD_GOT_WRITE_ERROR")):
		case bytes.Contains(out, []byte("CHILD_SKIP")):
			t.Skipf("child could not zero RLIMIT_FSIZE:\n%s", out)
		default:
			t.Fatalf("want the write error surfaced in the child; child output:\n%s", out)
		}
	})

	t.Run("an uncreatable temp dir aborts", func(t *testing.T) {
		t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
		if _, _, err := materializeStdinValues([]string{"-"}, strings.NewReader("a: 1\n")); err == nil {
			t.Fatal("want the temp-file error surfaced")
		}
	})
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// writeValuesFile writes a -f values file and returns its path.
func writeValuesFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write values: %v", err)
	}
	return p
}

// A -f file that writes nriImagePolicy.policy.exemptNamespaces owns it, empty
// list included: the computed values are helm's last -f, so a lane default
// injected over it would silently replace a deliberate choice.
func TestImageDigest(t *testing.T) {
	const digest = "sha256:ab12000000000000000000000000000000000000000000000000000000000000"
	for _, tc := range []struct {
		name string
		refs []string
		want string
	}{
		{"digested reference", []string{"docker.io/rancher/hardened-etcd@" + digest}, digest},
		{"bare digest imageID", []string{digest}, digest},
		{"docker-pullable prefix", []string{"docker-pullable://nginx@" + digest}, digest},
		{"imageID wins over the spec tag", []string{"nginx@" + digest, "nginx:1.27"}, digest},
		{"falls back to a pinned spec image", []string{"", "nginx@" + digest}, digest},
		{"tag only carries no digest", []string{"", "nginx:1.27"}, ""},
		{"nothing to read", []string{"", ""}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := imageDigest(tc.refs...); got != tc.want {
				t.Errorf("imageDigest(%q) = %q, want %q", tc.refs, got, tc.want)
			}
		})
	}
}

func TestAdmissibleDigests(t *testing.T) {
	const (
		componentDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		bootDigest      = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		workloadDigest  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		initDigest      = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	)
	values := map[string]any{
		"cds": map[string]any{"image": map[string]any{"digest": componentDigest}},
		"nriImagePolicy": map[string]any{"bootstrapAllowlist": map[string]any{
			"workloads": map[string]any{
				"etcd": map[string]any{"containers": []any{map[string]any{"digest": bootDigest}}},
				"infer": map[string]any{
					"initContainers": []any{map[string]any{"digest": initDigest}},
					"containers":     []any{map[string]any{"digest": workloadDigest}},
				},
			},
		}},
	}
	got := admissibleDigests(values, []c8sComponent{{valuesPath: "cds.image"}, {valuesPath: "volumed.image"}})
	want := map[string]bool{componentDigest: true, bootDigest: true, workloadDigest: true, initDigest: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("admissibleDigests = %v, want %v", got, want)
	}
}

// platformPod builders for the denial check.
func daemonSetPod(ns, name, image, imageID string) corev1.Pod {
	return corev1.Pod{
		Namespace:       ns,
		Name:            name,
		OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: "ds"}},
		Spec:            corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: image}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "main", Image: image, ImageID: imageID},
		}},
	}
}

func mirrorPod(ns, name, image, imageID string) corev1.Pod {
	p := daemonSetPod(ns, name, image, imageID)
	p.OwnerReferences = nil
	p.Annotations = map[string]string{corev1.MirrorPodAnnotationKey: "mirror"}
	return p
}

func deploymentPod(ns, name, image, imageID string) corev1.Pod {
	p := daemonSetPod(ns, name, image, imageID)
	p.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rs"}}
	return p
}

func statefulSetPod(ns, name, image, imageID string) corev1.Pod {
	p := daemonSetPod(ns, name, image, imageID)
	p.OwnerReferences = []metav1.OwnerReference{{Kind: "StatefulSet", Name: "sts"}}
	return p
}

func TestDeniedPlatformImages(t *testing.T) {
	const (
		etcd    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		cni     = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		tenant  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		pinned  = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
		release = "c8s-system"
	)
	pods := []corev1.Pod{
		mirrorPod("kube-system", "etcd-node-a", "index.docker.io/rancher/hardened-etcd:v3.6.12", "index.docker.io/rancher/hardened-etcd@"+etcd),
		daemonSetPod("calico-system", "calico-node-a", "calico/node:v3", "calico/node@"+cni),
		// The same DaemonSet on a second node must not be reported twice.
		daemonSetPod("calico-system", "calico-node-b", "calico/node:v3", "calico/node@"+cni),
		// A tenant Deployment is the operator's to allowlist, not a refusal.
		deploymentPod("tenant", "infer-abc", "example.test/vllm:v1", "example.test/vllm@"+tenant),
		// A platform image already in the floor is admitted.
		daemonSetPod("kube-system", "csi-node-a", "example.test/csi:v1", "example.test/csi@"+pinned),
		// The release's own components are torn up and replaced by this install.
		daemonSetPod(release, "c8s-armtls-mesh-a", "ghcr.io/confidential-dot-ai/armtls-mesh:main", "ghcr.io/confidential-dot-ai/armtls-mesh@"+tenant),
	}
	admitted := map[string]bool{pinned: true}

	got := deniedPlatformImages(pods, release, nil, admitted)
	want := []string{
		"calico-system/calico-node-a  docker.io/calico/node@" + cni,
		"kube-system/etcd-node-a  docker.io/rancher/hardened-etcd@" + etcd,
	}
	if !slices.Equal(got, want) {
		t.Errorf("deniedPlatformImages = %#v, want %#v", got, want)
	}

	// An exemption admits the repositories it names in the namespaces it names.
	exempt := nriimagepolicy.ExemptRepositories{
		"kube-system":   {"docker.io/rancher/"},
		"calico-system": {"docker.io/calico/"},
	}
	got = deniedPlatformImages(pods, release, exempt, admitted)
	if len(got) != 0 {
		t.Errorf("with both namespaces exempt, denied = %#v, want none", got)
	}
}

// A provider image pre-loaded on the node reports a bare image ID — the
// node-local config digest — and names its repository on the spec reference
// alone, which is what the exemption matches.
func TestDeniedPlatformImagesAdmitsAPreloadedProviderImage(t *testing.T) {
	const localID = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	pods := []corev1.Pod{daemonSetPod("kube-system", "kube-proxy-a", "gke.gcr.io/kube-proxy:v1.31.0-gke.1", localID)}
	exempt := nriimagepolicy.ExemptRepositories{"kube-system": {"gke.gcr.io/"}}
	if got := deniedPlatformImages(pods, "c8s-system", exempt, nil); len(got) != 0 {
		t.Errorf("denied = %#v, want none for a pre-loaded image the exemption names", got)
	}
	if got := deniedPlatformImages(pods, "c8s-system", nil, nil); len(got) != 1 {
		t.Errorf("denied = %#v, want the image reported without the exemption", got)
	}
}

// A container that has not pulled reports no digest, so there is nothing to
// evaluate — it must not be reported as denied on a guess.
func TestDeniedPlatformImagesSkipsUnpulledContainers(t *testing.T) {
	pod := daemonSetPod("kube-system", "kube-proxy-a", "kube-proxy:v1.31.0", "")
	if got := deniedPlatformImages([]corev1.Pod{pod}, "c8s-system", nil, nil); len(got) != 0 {
		t.Errorf("denied = %#v, want none for a container with no resolved imageID", got)
	}
}

// Init containers are admitted by the same policy as the main ones, so a
// denied init image wedges the pod just as hard.
func TestDeniedPlatformImagesCoversInitContainers(t *testing.T) {
	const digest = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	pod := daemonSetPod("kube-system", "cni-install-a", "main:v1", "")
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Image: "install-cni:v3", ImageID: "install-cni@" + digest}}
	got := deniedPlatformImages([]corev1.Pod{pod}, "c8s-system", nil, nil)
	want := []string{"kube-system/cni-install-a  docker.io/library/install-cni@" + digest}
	if !slices.Equal(got, want) {
		t.Errorf("denied = %#v, want %#v", got, want)
	}
}

// A denied container no platform pod runs — a provider add-on StatefulSet, a
// tenant Deployment — is stopped by the containerd restart and refused after
// it. The install reports those rather than refusing: the cluster survives
// without them, and a tenant workload is denied by design.
func TestDeniedWorkloadImages(t *testing.T) {
	const (
		metrics = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		vllm    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		proxy   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		mesh    = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
		exempt  = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
		release = "c8s-system"
	)
	pods := []corev1.Pod{
		statefulSetPod("gke-managed-cim", "kube-state-metrics-0", "gke.io/ksm:v2", "gke.io/ksm@"+metrics),
		deploymentPod("tenant", "infer-abc", "example.test/vllm:v1", "example.test/vllm@"+vllm),
		// A platform pod is the refusal's, not this list's.
		daemonSetPod("kube-system", "kube-proxy-a", "kube-proxy:v1.31.0", "kube-proxy@"+proxy),
		// The release's own pods are torn up and replaced by this install.
		deploymentPod(release, "c8s-router-abc", "ghcr.io/confidential-dot-ai/router:main", "ghcr.io/confidential-dot-ai/router@"+mesh),
		// An exempt namespace admits the repositories it names.
		deploymentPod("kube-system", "coredns-abc", "coredns:1.11", "coredns@"+exempt),
	}
	kubeSystem := nriimagepolicy.ExemptRepositories{"kube-system": {"docker.io/library/"}}
	got := deniedWorkloadImages(pods, release, kubeSystem, nil)
	want := []string{
		"gke-managed-cim/kube-state-metrics-0  gke.io/ksm@" + metrics,
		"tenant/infer-abc  example.test/vllm@" + vllm,
	}
	if !slices.Equal(got, want) {
		t.Errorf("deniedWorkloadImages = %#v, want %#v", got, want)
	}

	admitted := map[string]bool{metrics: true, vllm: true}
	if got := deniedWorkloadImages(pods, release, kubeSystem, admitted); len(got) != 0 {
		t.Errorf("with both digests admitted, denied = %#v, want none", got)
	}
}

// The report names what will be stopped and both ways to admit it, and prints
// nothing when the policy denies nothing.
func TestReportDeniedWorkloads(t *testing.T) {
	var buf bytes.Buffer
	reportDeniedWorkloads(&buf, []string{"gke-managed-cim/kube-state-metrics-0  gke.io/ksm@sha256:" + strings.Repeat("1", 64)})
	out := buf.String()
	for _, want := range []string{"gke-managed-cim/kube-state-metrics-0", "nriImagePolicy.bootstrapAllowlist.workloads", exemptNamespacesPath} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not mention %q:\n%s", want, out)
		}
	}

	buf.Reset()
	reportDeniedWorkloads(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("nothing denied must print nothing, got:\n%s", buf.String())
	}
}

// A pod the kubelet has finished with has no container left for the containerd
// restart to recreate, so its images are not the policy's to admit.
func TestDeniedPlatformImagesSkipsTerminalPods(t *testing.T) {
	const digest = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed} {
		pod := daemonSetPod("kube-system", "cni-migrate-a", "migrate:v1", "migrate@"+digest)
		pod.Status.Phase = phase
		if got := deniedPlatformImages([]corev1.Pod{pod}, "c8s-system", nil, nil); len(got) != 0 {
			t.Errorf("phase %s: denied = %#v, want none", phase, got)
		}
	}
}

// The repository is reported for pasting into the floor, so a status that
// carries the reference only on imageID must still name one.
func TestImageReferenceFallsBackToImageID(t *testing.T) {
	const digest = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	if got, want := imageReference("", "docker-pullable://calico/node@"+digest, digest), "docker.io/calico/node@"+digest; got != want {
		t.Errorf("imageReference = %q, want %q", got, want)
	}
	if got := imageReference("", "", digest); got != digest {
		t.Errorf("imageReference with nothing parseable = %q, want %q", got, digest)
	}
}

func TestRunningImagesNameABareDigestAlone(t *testing.T) {
	const digest = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
	pods := []corev1.Pod{daemonSetPod("kube-system", "fluentbit-a", digest, digest)}
	got := imageLines(runningImages(pods, func(corev1.Pod, runningImage) bool { return true }))
	want := []string{"kube-system/fluentbit-a  " + digest}
	if !slices.Equal(got, want) {
		t.Errorf("runningImages = %#v, want %#v", got, want)
	}
}

// Only the namespaces the policy exempts carry an exemption, whatever other
// namespace a prefix set names.
func TestExemptRepositories(t *testing.T) {
	values := map[string]any{"nriImagePolicy": map[string]any{"policy": map[string]any{
		"exemptNamespaces": []any{"kube-system"},
		"exemptRepositories": map[string]any{
			"kube-system": []any{"mcr.microsoft.com/oss/kubernetes/"},
			"gmp-system":  []any{"gke.gcr.io/"},
		},
	}}}
	exempt := exemptRepositories(values)
	if !exempt.Admits("kube-system", "mcr.microsoft.com/oss/kubernetes/kube-proxy:v1.31.0") {
		t.Errorf("exemptRepositories = %#v, want kube-system to admit its prefix", exempt)
	}
	if exempt.Admits("gmp-system", "gke.gcr.io/kube-proxy:v1.31.0") {
		t.Errorf("exemptRepositories = %#v, want no exemption for an unexempted namespace", exempt)
	}
}

// Every pod of the namespace, an exited init container included.
func TestExemptNamespaceImages(t *testing.T) {
	const (
		etcd   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		proxy  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		cns    = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
		dns    = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
		gke    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		vllm   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
		fluent = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	)
	cnsPod := daemonSetPod("kube-system", "azure-cns-a", "azure-cns:v1.6", "azure-cns@"+cns)
	// Exited before the plugin connected; the pod runs it again after a reboot.
	cnsPod.Spec.InitContainers = []corev1.Container{{Name: "init-cns", Image: "azure-cns-init:v1.6"}}
	cnsPod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name:    "init-cns",
		Image:   "azure-cns-init:v1.6",
		ImageID: "azure-cns-init@" + proxy,
		State:   corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}},
	}}
	pods := []corev1.Pod{
		mirrorPod("kube-system", "etcd-node-a", "rancher/hardened-etcd:v3.6.12", "rancher/hardened-etcd@"+etcd),
		cnsPod,
		// Same DaemonSet on a second node: one entry.
		daemonSetPod("kube-system", "azure-cns-b", "azure-cns:v1.6", "azure-cns@"+cns),
		deploymentPod("kube-system", "coredns-abc", "coredns:1.11", "coredns@"+dns),
		// In the exempt namespace, under no prefix.
		daemonSetPod("kube-system", "fluentbit-a", "example.test/fluentbit:v1", "example.test/fluentbit@"+fluent),
		// Outside the exempt set: not what this admits.
		daemonSetPod("gke-system", "gke-agent-a", "gke/agent:v1", "gke/agent@"+gke),
		deploymentPod("tenant", "infer-abc", "example.test/vllm:v1", "example.test/vllm@"+vllm),
	}
	exempt := nriimagepolicy.ExemptRepositories{"kube-system": {"docker.io/library/", "docker.io/rancher/"}}
	got := imageLines(exemptNamespaceImages(pods, exempt))
	want := []string{
		"kube-system/azure-cns-a  docker.io/library/azure-cns-init@" + proxy,
		"kube-system/azure-cns-a  docker.io/library/azure-cns@" + cns,
		"kube-system/coredns-abc  docker.io/library/coredns@" + dns,
		"kube-system/etcd-node-a  docker.io/rancher/hardened-etcd@" + etcd,
	}
	if !slices.Equal(got, want) {
		t.Errorf("exempt namespace images = %#v, want %#v", got, want)
	}

	if got := exemptNamespaceImages(pods, nil); len(got) != 0 {
		t.Errorf("with no exempt namespace, got %#v, want none", got)
	}

	denied := "kube-system/fluentbit-a  example.test/fluentbit@" + fluent
	if got := deniedPlatformImages(pods, "c8s-system", exempt, nil); !slices.Contains(got, denied) {
		t.Errorf("denied platform images = %#v, want %q among them", got, denied)
	}
}

// Every flag the hint names must be a flag of the command it names, and an
// install that stored no route manifest names the command that reads its
// digest.
func TestVerifyHintPrintsRunnableCommands(t *testing.T) {
	const (
		cdsURL = "https://cds.example:8443"
		cdsPin = "/run/c8s/cds-pin.json"
	)
	var buf bytes.Buffer
	printVerifyHint(&buf, cdsURL, cdsPin, "<operator-pub.pem>", "")

	verifyArgs := hintCommandArgs(t, buf.String(), "c8s verify")
	if slices.Contains(verifyArgs, cdsPin) {
		t.Errorf("the front-door check names the CDS pin, which carries no node measurement:\n%s", buf.String())
	}
	if !slices.Contains(verifyArgs, "--route-digest") {
		t.Errorf("the front-door check passes no --route-digest, which attest-lb requires:\n%s", buf.String())
	}
	if err := verify.NewCmd(verify.Defaults{}).ParseFlags(verifyArgs); err != nil {
		t.Errorf("c8s verify %s: %v", strings.Join(verifyArgs, " "), err)
	}

	anchorArgs := hintCommandArgs(t, buf.String(), "c8s cds ca")
	if err := cdsca.NewCmd().ParseFlags(anchorArgs); err != nil {
		t.Errorf("c8s cds ca %s: %v", strings.Join(anchorArgs, " "), err)
	}
	for _, want := range []string{cdsURL, cdsPin} {
		if !slices.Contains(anchorArgs, want) {
			t.Errorf("the anchor command omits %q, which this install named:\n%s", want, buf.String())
		}
	}

	show, _, err := routes.NewCmd().Find([]string{"show"})
	if err != nil {
		t.Fatal(err)
	}
	digestArgs := hintCommandArgs(t, buf.String(), "c8s routes show")
	if err := show.ParseFlags(digestArgs); err != nil {
		t.Errorf("c8s routes show %s: %v", strings.Join(digestArgs, " "), err)
	}
	if !slices.Contains(digestArgs, "--operator-keys") {
		t.Errorf("the digest the hint reads is not verified under the operator keys:\n%s", buf.String())
	}
}

// An install that stored a route manifest names its digest, so the check runs
// as printed.
func TestVerifyHintNamesTheStoredRouteDigest(t *testing.T) {
	const digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	var buf bytes.Buffer
	printVerifyHint(&buf, "https://cds.example:8443", "/run/c8s/cds-pin.json", "operator-pub.pem", digest)

	verifyArgs := hintCommandArgs(t, buf.String(), "c8s verify")
	i := slices.Index(verifyArgs, "--route-digest")
	if i < 0 || i+1 == len(verifyArgs) || verifyArgs[i+1] != digest {
		t.Errorf("the front-door check does not pass --route-digest %s:\n%s", digest, buf.String())
	}
	if strings.Contains(buf.String(), "c8s routes show") {
		t.Errorf("the hint names how to read a digest it printed itself:\n%s", buf.String())
	}
}

// hintCommandArgs is what the hint passes to the command named by prefix.
func hintCommandArgs(t *testing.T, hint, prefix string) []string {
	t.Helper()
	for line := range strings.SplitSeq(hint, "\n") {
		if i := strings.Index(line, prefix); i >= 0 {
			return strings.Fields(line[i+len(prefix):])
		}
	}
	t.Fatalf("the hint names no %q command:\n%s", prefix, hint)
	return nil
}

// The preflight reads each platform file's exemption through the value paths
// the chart renders a node's boot config from.
func TestEveryPlatformExemptionReachesThePreflight(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	dir, err := helmchart.ExtractTemp()
	if err != nil {
		t.Fatalf("extract the chart: %v", err)
	}
	defer os.RemoveAll(dir)
	chartPath := filepath.Join(dir, helmchart.CloudChartFSPath)

	for _, platform := range cloudPlatforms {
		t.Run(platform, func(t *testing.T) {
			values, err := effectiveValues(context.Background(), chartPath, orderedValuesFiles(chartPath, platform, nil), nil)
			if err != nil {
				t.Fatalf("read the platform's values: %v", err)
			}
			namespaces := stringsAtPath(values, exemptNamespacesPath)
			if len(namespaces) == 0 {
				t.Fatalf("%s exempts no namespace, so the install refuses the provider's own kube-system pods", platform)
			}
			exempt := exemptRepositories(values)
			for _, namespace := range namespaces {
				if len(exempt[namespace]) == 0 {
					t.Errorf("the preflight reads no %s for %s, so it judges an exemption no node has", exemptRepositoriesPath, namespace)
				}
			}
		})
	}
}

// The report is the audit surface: it must name the prefixes every node
// admits on, carry every image they admit (never a truncated list) and name
// the alternative posture.
func TestReportExemptedImages(t *testing.T) {
	images := make([]runningImage, 0, deniedImagesListed+5)
	for i := range cap(images) {
		digest := fmt.Sprintf("sha256:%064d", i)
		images = append(images, runningImage{
			namespace: "kube-system",
			pod:       fmt.Sprintf("pod-%02d", i),
			reference: fmt.Sprintf("example.test/img%02d@%s", i, digest),
			digest:    digest,
		})
	}
	var buf bytes.Buffer
	reportExemptedImages(&buf, nriimagepolicy.ExemptRepositories{"kube-system": {"example.test/"}}, images)
	out := buf.String()

	for _, image := range images {
		if !strings.Contains(out, image.line()) {
			t.Errorf("report omits %q — a truncated audit list is not one:\n%s", image.line(), out)
		}
	}
	for _, want := range []string{"kube-system", "example.test/", "nriImagePolicy.bootstrapAllowlist.workloads", exemptNamespacesPath} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not mention %q:\n%s", want, out)
		}
	}

	buf.Reset()
	reportExemptedImages(&buf, nil, nil)
	if buf.Len() != 0 {
		t.Errorf("nothing exempted must print nothing, got:\n%s", buf.String())
	}
}

func TestConfidentialNodeSelector(t *testing.T) {
	t.Run("labels become one sorted selector", func(t *testing.T) {
		values := map[string]any{"confidentialNodeSelector": map[string]any{
			"kubernetes.azure.com/security-type": "ConfidentialVM",
			"c8s.example/pool":                   "cvm",
		}}
		got, err := confidentialNodeSelector(values)
		if want := "c8s.example/pool=cvm,kubernetes.azure.com/security-type=ConfidentialVM"; err != nil || got != want {
			t.Fatalf("confidentialNodeSelector = (%q, %v), want (%q, nil)", got, err, want)
		}
	})

	t.Run("a value that is not a label map is refused", func(t *testing.T) {
		values := map[string]any{"confidentialNodeSelector": "ConfidentialVM"}
		if _, err := confidentialNodeSelector(values); err == nil {
			t.Fatal("want a refusal when the key holds no label map")
		}
	})
}
