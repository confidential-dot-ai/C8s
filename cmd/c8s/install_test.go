//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

var errTestResolve = errors.New("simulated resolve failure")

func TestOperatorKeysPreflight(t *testing.T) {
	// Keys provided → no gate, no warning.
	if warn, err := operatorKeysPreflight("operator.pub", nil, false); err != nil || warn != "" {
		t.Fatalf("keys provided: want no error/warn, got warn=%q err=%v", warn, err)
	}
	// Default path, no keys, no force → hard error (must acknowledge).
	if _, err := operatorKeysPreflight("", nil, false); err == nil {
		t.Fatal("no keys + no force: expected an error requiring --operator-keys or --force")
	}
	// Default path, no keys, --force → allowed, but warns.
	if warn, err := operatorKeysPreflight("", nil, true); err != nil || warn == "" {
		t.Fatalf("no keys + force: want warn and no error, got warn=%q err=%v", warn, err)
	}
	// -f supplied → operator owns cds.operatorKeys in their values file; no gate.
	if warn, err := operatorKeysPreflight("", []string{"custom.yaml"}, false); err != nil || warn != "" {
		t.Fatalf("-f supplied: want no error/warn, got warn=%q err=%v", warn, err)
	}
}

func TestDefaultInstallImageTag(t *testing.T) {
	tests := []struct {
		name         string
		buildVersion string
		want         string
	}{
		{name: "release tag used verbatim", buildVersion: "v0.1.0", want: "v0.1.0"},
		{name: "empty falls back", buildVersion: "", want: "main"},
		{name: "unstamped default falls back", buildVersion: "dev", want: "main"},
		{name: "git describe derivative falls back", buildVersion: "v0.1.0-5-gabc1234", want: "main"},
		{name: "dirty tree falls back", buildVersion: "v0.1.0-dirty", want: "main"},
		{name: "bare commit sha falls back", buildVersion: "abc1234", want: "main"},
		{name: "branch name falls back", buildVersion: "feat-phase5-chart-docs", want: "main"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultInstallImageTag(tt.buildVersion)
			if got != tt.want {
				t.Fatalf("defaultInstallImageTag(%q) = %q, want %q", tt.buildVersion, got, tt.want)
			}
		})
	}
}

func TestResolveImageTag(t *testing.T) {
	prev := installImageTag
	defer func() { installImageTag = prev }()

	// --image-tag set wins over the build-version default.
	installImageTag = "v9.9.9"
	if got := resolveImageTag(); got != "v9.9.9" {
		t.Errorf("with --image-tag set: got %q, want v9.9.9", got)
	}

	// Unset falls back to the build-version default. An unstamped test build is
	// not a release tag, so that default is the fallback tag.
	installImageTag = ""
	if got := resolveImageTag(); got != fallbackImageTag {
		t.Errorf("unset: got %q, want the fallback tag %q", got, fallbackImageTag)
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

func TestAppendInstallCRDArgsDisablesStatusMirrorWhenSkippingCRDs(t *testing.T) {
	// Emits the value only; helm's --skip-crds invocation flag is added at the
	// install call site, not here (these args become a values tree).
	got := appendInstallCRDArgs([]string{"--set", "image.tag=main"}, false)
	want := []string{"--set", "image.tag=main", "--set", "statusMirror.enabled=false"}
	if len(got) != len(want) {
		t.Fatalf("args length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; got %v", i, got[i], want[i], got)
		}
	}
}

func TestAppendInstallCRDArgsLeavesStatusMirrorEnabledWithCRDs(t *testing.T) {
	got := appendInstallCRDArgs([]string{"--set", "image.tag=main"}, true)
	want := []string{"--set", "image.tag=main"}
	if len(got) != len(want) {
		t.Fatalf("args length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; got %v", i, got[i], want[i], got)
		}
	}
}

// The helm argv ordering is load-bearing: operator -f files before the computed
// file (last -f wins, so computed values win on the keys they set), and
// --skip-crds present iff CRDs are skipped.
func TestBuildInstallHelmArgsOrdering(t *testing.T) {
	prevRel, prevNs := installRelease, installNamespace
	defer func() { installRelease, installNamespace = prevRel, prevNs }()
	installRelease, installNamespace = "c8s", "c8s-system"

	// CRDs installed, two operator -f files, wait on: computed file is LAST -f.
	assertArgsEqual(t, buildInstallHelmArgs("/chart", "/tmp/computed.yaml", []string{"a.yaml", "b.yaml"}, true, true), []string{
		"upgrade", "--install", "c8s", "/chart", "--namespace", "c8s-system",
		"-f", "a.yaml", "-f", "b.yaml", "-f", "/tmp/computed.yaml",
		"--wait", "--timeout=5m",
	})

	// CRDs skipped, no operator -f, wait off: --skip-crds present, computed file
	// still the last (only) -f, no --wait.
	assertArgsEqual(t, buildInstallHelmArgs("/chart", "/tmp/computed.yaml", nil, false, false), []string{
		"upgrade", "--install", "c8s", "/chart", "--namespace", "c8s-system",
		"--skip-crds", "-f", "/tmp/computed.yaml",
	})

}

// --cvm-mode is required: empty or unknown must error.
func TestValidateCvmModeRequiresKnownValue(t *testing.T) {
	if err := validateCvmMode(""); err == nil {
		t.Fatal("empty --cvm-mode: want error, got nil")
	}
	if err := validateCvmMode("bogus"); err == nil {
		t.Fatal("unknown --cvm-mode: want error, got nil")
	}
	for _, mode := range allowedCvmModes {
		if err := validateCvmMode(mode); err != nil {
			t.Errorf("mode %q: unexpected error: %v", mode, err)
		}
	}
}

func TestAppendSingleNodeInstallArgsDisabledIsNoOp(t *testing.T) {
	got := appendSingleNodeInstallArgs([]string{"upgrade"}, false)
	assertArgsEqual(t, got, []string{"upgrade"})
}

func TestAppendSingleNodeInstallArgsClearsCDSNodePinning(t *testing.T) {
	// --single-node must null both the selector (drops the role=cds pin and
	// collapses the installer split) and the tolerations (the dedicated-node
	// taint is meaningless without a dedicated node).
	got := appendSingleNodeInstallArgs([]string{"upgrade"}, true)
	assertArgsEqual(t, got, []string{
		"upgrade",
		"--set", "cds.node.selector=null",
		"--set", "cds.node.tolerations=null",
	})
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
		{name: "ref rejects release namespace", releaseNS: "c8s-system", refs: []string{"router=c8s-system/deployment/vllm"}, wait: true, wantErr: []string{"--workload-ref", "release namespace", "excluded"}},
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

// TestUpstreamAddress drives the derivation buildValueArgs uses to set
// router.upstream.address, so it guards the address the chart receives against
// divergence from the RunE's --upstream validation. The port comes from the
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
	want := []string{"ghcr.io/acme/init:v1", "ghcr.io/acme/router:v1"}
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
	if got, want := podTemplateImages(template), []string{"ghcr.io/acme/worker:v3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("crd images = %v, want %v", got, want)
	}
}

func TestBuildWorkloadImageArgsAddsNRIAllowlistDigests(t *testing.T) {
	resolve := func(ref string) (string, error) {
		switch ref {
		case "ghcr.io/acme/router:v1":
			return "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
		case "ghcr.io/acme/engine:v2":
			return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
		}
		t.Fatalf("unexpected ref resolved: %q", ref)
		return "", nil
	}
	got, err := buildWorkloadImageArgs([]string{"upgrade"}, []string{
		"ghcr.io/acme/router:v1",
		"ghcr.io/acme/engine:v2",
		"ghcr.io/acme/router:v1",
		"busybox@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}, resolve)
	if err != nil {
		t.Fatalf("buildWorkloadImageArgs: %v", err)
	}
	entry := func(name, digest, ref string) []string {
		p := "nriImagePolicy.bootstrapAllowlist.workloads." + name + "."
		return []string{
			"--set-string", p + "label=" + ref,
			"--set-string", p + "containers[0].digest=" + digest,
			"--set-string", p + "containers[0].image=" + ref,
			"--set-string", p + "containers[0].command.policy=any",
			"--set-string", p + "containers[0].args.policy=any",
		}
	}
	const (
		dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		dC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)
	want := []string{"upgrade"}
	want = append(want, entry("engine-aaaaaaaaaaaa", dA, "ghcr.io/acme/engine@"+dA)...)
	want = append(want, entry("router-bbbbbbbbbbbb", dB, "ghcr.io/acme/router@"+dB)...)
	want = append(want, entry("busybox-cccccccccccc", dC, "docker.io/library/busybox@"+dC)...)
	assertArgsEqual(t, got, want)
}

func TestBuildWorkloadImageArgsFailsClosedOnResolveError(t *testing.T) {
	_, err := buildWorkloadImageArgs(nil, []string{"ghcr.io/acme/router:v1"}, func(string) (string, error) {
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
	_, err := buildWorkloadImageArgs(nil, []string{sha512Image}, func(string) (string, error) {
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

func TestAppendDistroInstallArgsSetsNRI(t *testing.T) {
	for _, distro := range []string{"k8s", "rke2"} {
		t.Run(distro, func(t *testing.T) {
			got := appendDistroInstallArgs([]string{"upgrade"}, distro)
			assertArgsEqual(t, got, []string{
				"upgrade",
				"--set-string", "nriImagePolicy.distro=" + distro,
			})
		})
	}
}

// classifyDistroNodes splits "name\tkubeletVersion" lines by the "+rke2"
// build-metadata suffix RKE2's kubelet build carries. Anything else (vanilla
// upstream, k3s, future distros) lands in the "other" bucket — detection
// only owns the rke2 vs not-rke2 split.
func TestClassifyDistroNodesByKubeletVersionSuffix(t *testing.T) {
	lines := []string{
		"node-a\tv1.29.5+rke2r1",
		"node-b\tv1.29.5",        // vanilla upstream
		"node-c\tv1.30.1+rke2r2", // newer RKE2 build
		"node-d\tv1.30.0+k3s1",   // k3s lands in "other"
		"",                       // a trailing blank line from kubectl is ignored
		"malformed-no-tab",       // a line with no tab can't be classified, ignored
	}
	rke2, other := classifyDistroNodes(lines)
	wantRke2 := []string{"node-a", "node-c"}
	wantOther := []string{"node-b", "node-d"}
	if !reflect.DeepEqual(rke2, wantRke2) {
		t.Errorf("rke2 nodes = %v, want %v", rke2, wantRke2)
	}
	if !reflect.DeepEqual(other, wantOther) {
		t.Errorf("other nodes = %v, want %v", other, wantOther)
	}
}

// chooseDistro powers distro detection: the kubelet classification must map to
// the distro value the chart needs.
func TestChooseDistroHomogeneousClusters(t *testing.T) {
	got, err := chooseDistro([]string{"node-a", "node-b"}, nil)
	if err != nil || got != "rke2" {
		t.Errorf("all-RKE2 cluster: got (%q, %v), want (rke2, nil)", got, err)
	}
	got, err = chooseDistro(nil, []string{"node-a", "node-b"})
	if err != nil || got != "k8s" {
		t.Errorf("vanilla cluster: got (%q, %v), want (k8s, nil)", got, err)
	}
	// No classifiable nodes: fall back to the chart default rather than fail
	// an install on which nothing could schedule anyway.
	got, err = chooseDistro(nil, nil)
	if err != nil || got != "k8s" {
		t.Errorf("no classifiable nodes: got (%q, %v), want (k8s, nil)", got, err)
	}
}

// A mixed cluster has no single right distro — the installers patch a
// distro-specific containerd path on every selected node — so detection must
// demand explicit per-component values via -f instead of guessing.
func TestChooseDistroRejectsMixedClusters(t *testing.T) {
	_, err := chooseDistro([]string{"rke2-node"}, []string{"vanilla-node"})
	if err == nil {
		t.Fatal("mixed cluster: want error, got nil")
	}
	for _, want := range []string{"nriImagePolicy.distro", "rke2-node", "vanilla-node"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q (should name the fix and both node sets)", err.Error(), want)
		}
	}
}

// A -f file suppresses distro auto-detection only when it actually sets a
// distro; passing -f for any other value must leave detection in force (the
// bug: any -f used to silently drop the CLI to the chart's k8s default).
func TestValuesFilesSetDistro(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "values.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write values: %v", err)
		}
		return p
	}
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"nri distro set", "nriImagePolicy:\n  distro: rke2\n", true},
		{"unrelated value only", "router:\n  enabled: false\n", false},
		{"distro key absent under section", "nriImagePolicy:\n  enabled: true\n", false},
		{"empty distro string is not a choice", "nriImagePolicy:\n  distro: \"\"\n", false},
		{"empty file", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := valuesFilesSetDistro([]string{write(t, tc.body)})
			if err != nil {
				t.Fatalf("valuesFilesSetDistro: %v", err)
			}
			if got != tc.want {
				t.Errorf("valuesFilesSetDistro(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}

	t.Run("no files means detect", func(t *testing.T) {
		got, err := valuesFilesSetDistro(nil)
		if err != nil || got {
			t.Errorf("valuesFilesSetDistro(nil) = (%v, %v), want (false, nil)", got, err)
		}
	})

	t.Run("one of several files sets it", func(t *testing.T) {
		a := write(t, "router:\n  enabled: false\n")
		b := write(t, "nriImagePolicy:\n  distro: rke2\n")
		got, err := valuesFilesSetDistro([]string{a, b})
		if err != nil || !got {
			t.Errorf("valuesFilesSetDistro(two files) = (%v, %v), want (true, nil)", got, err)
		}
	})
}

func TestRouterHostPort(t *testing.T) {
	hp := func(https any) map[string]any {
		return map[string]any{"router": map[string]any{"hostPort": map[string]any{"https": https}}}
	}
	for _, tc := range []struct {
		name string
		tree map[string]any
		want int32
	}{
		{"empty string derives 443", hp(""), 443},
		{"no hostPort map", map[string]any{"router": map[string]any{}}, 443},
		{"string override", hp("8443"), 8443},
		{"int override", hp(9443), 9443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := routerHostPort(tc.tree)
			if err != nil || got != tc.want {
				t.Fatalf("routerHostPort = (%d, %v), want (%d, nil)", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		https any
	}{
		{"non-numeric string", "https"},
		{"string overflows int32", "4294967297"}, // 2^32 + 1 — would wrap to 1 on a bare int32 cast
		{"string above port range", "70000"},
		{"int above port range", 70000},
		{"zero is not a port", 0},
	} {
		t.Run(tc.name+" errors", func(t *testing.T) {
			if _, err := routerHostPort(hp(tc.https)); err == nil {
				t.Fatalf("want error for %v", tc.https)
			}
		})
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
			pods:        []corev1.Pod{pod("kube-system", "rke2-ingress-nginx-abc", "node-a", 443)},
			nodes:       []string{"node-a"},
			wantBlocked: true,
			wantHolder:  "kube-system/rke2-ingress-nginx-abc",
		},
		{
			name:        "single node, traefik holds 443 (rke2 v1.36+ default ingress)",
			pods:        []corev1.Pod{pod("kube-system", "rke2-traefik-abc", "node-a", 443)},
			nodes:       []string{"node-a"},
			wantBlocked: true,
			wantHolder:  "kube-system/rke2-traefik-abc",
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

func TestAppendCvmModeInstallArgsSetsAttestationApiValue(t *testing.T) {
	// The attestation sidecar is on by default; the arg-builder reads the
	// package flag, which cobra would set. Mirror that default here.
	prevAttest := installAttestEnabled
	installAttestEnabled = true
	t.Cleanup(func() { installAttestEnabled = prevAttest })

	// Two orthogonal axes:
	//  --cvm-mode: bare-metal (node-as-CVM) / gke (managed) / aks (vTPM)
	//  --hardware-platform: sev-snp (/dev/sev-guest) / tdx (/dev/tdx-guest)
	// node+gke all take either hardware-platform; aks always emits the vTPM
	// device and rides the Azure vTPM HCL report for both SNP (az-snp) and TDX
	// (az-tdx).
	build := func(mode, platform, sevGuest, tdxGuest, tpm string) []string {
		out := []string{
			"upgrade",
			"--set-string", "attestationApi.cvmMode=" + mode,
			"--set", "attestationApi.teeDevices.sevGuest=" + sevGuest,
			"--set", "attestationApi.teeDevices.tdxGuest=" + tdxGuest,
			"--set", "attestationApi.teeDevices.tpm=" + tpm,
		}
		// Any TDX shape — native (/dev/tdx-guest) or Azure vTPM (az-tdx) —
		// propagates the CPU TEE to CDS, which names its armTLS platform, or
		// CDS parses the TDX quote as an SNP report.
		if platform == "tdx" {
			out = append(out, "--set-string", "cds.armtlsPlatform=tdx")
		}
		// The attest sidecar's platform names the evidence shape the sidecar
		// requests from the attestation-api: az-snp/az-tdx under aks (Azure
		// vTPM HCL report — bare snp/tdx would probe guest devices AKS nodes
		// do not expose), bare tdx on native TDX. sev-snp outside aks keeps
		// the chart default (snp). Every override blanks the AMD-only
		// generation.
		switch {
		case mode == "aks" && platform == "tdx":
			out = append(out,
				"--set-string", "router.attest.platform=az-tdx",
				"--set-string", "router.attest.generation=",
			)
		case mode == "aks":
			out = append(out,
				"--set-string", "router.attest.platform=az-snp",
				"--set-string", "router.attest.generation=",
			)
		case platform == "tdx":
			out = append(out,
				"--set-string", "router.attest.platform=tdx",
				"--set-string", "router.attest.generation=",
			)
		}
		// node: the node image bakes attestation-api + nri-image-policy, so the
		// attestation-api copy is skipped and the NRI installer switches to its
		// baked form — the only path that reaches the baked plugin's CDS pins.
		if mode == "bare-metal" {
			out = append(out,
				"--set", "attestationApi.enabled=false",
				"--set", "nriImagePolicy.baked=true",
			)
		}
		return out
	}
	cases := map[string]struct {
		cvmMode          string
		hardwarePlatform string
		want             []string
	}{
		"gke + sev-snp":        {"gke", "sev-snp", build("gke", "sev-snp", "true", "false", "false")},
		"bare-metal + sev-snp": {"bare-metal", "sev-snp", build("bare-metal", "sev-snp", "true", "false", "false")},
		"gke + tdx":            {"gke", "tdx", build("gke", "tdx", "false", "true", "false")},
		"bare-metal + tdx":     {"bare-metal", "tdx", build("bare-metal", "tdx", "false", "true", "false")},
		"aks + sev-snp":        {"aks", "sev-snp", build("aks", "sev-snp", "false", "false", "true")},
		// az-tdx: Azure vTPM (tpm=true, no guest device) + TDX armTLS platform.
		"aks + tdx (az-tdx)": {"aks", "tdx", build("aks", "tdx", "false", "false", "true")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := appendCvmModeInstallArgs([]string{"upgrade"}, tc.cvmMode, tc.hardwarePlatform)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertArgsEqual(t, got, tc.want)
		})
	}
}

func TestAppendCvmModeInstallArgsRejectsUnknownMode(t *testing.T) {
	if _, err := appendCvmModeInstallArgs([]string{"upgrade"}, "bare-metal", ""); err == nil || !strings.Contains(err.Error(), "--hardware-platform is required") {
		t.Fatalf("empty --hardware-platform: err = %v, want required error", err)
	}
	if _, err := appendCvmModeInstallArgs([]string{"upgrade"}, "azure", "sev-snp"); err == nil {
		t.Fatal("appendCvmModeInstallArgs accepted an unknown --cvm-mode, want error")
	}
}

// --measurements fans each M into both mesh pin points, indexed, so the operator
// pins the internal mesh on the install itself. A blank entry (e.g. from a
// trailing comma) is dropped, not emitted as an empty index, and the emitted
// indices are contiguous over the validated list.
func TestAppendCvmModeInstallArgsMeasurements(t *testing.T) {
	prev := installMeasurements
	defer func() { installMeasurements = prev }()
	m0, m1 := strings.Repeat("aa", 48), strings.Repeat("bb", 48)
	installMeasurements = []string{m0, "", m1} // blank middle entry

	got, err := appendCvmModeInstallArgs([]string{"upgrade"}, "bare-metal", "tdx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"cds.measurements[0]=" + m0,
		"cds.measurements[1]=" + m1,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("args missing %q; got %v", want, got)
		}
	}
	// The blank must not produce an empty index-2 pin.
	if bad := "cds.measurements[2]="; slices.Contains(got, bad) {
		t.Errorf("blank entry leaked an empty pin %q; got %v", bad, got)
	}
}

func TestAppendCvmModeInstallArgsRejectsBadMeasurement(t *testing.T) {
	prev := installMeasurements
	defer func() { installMeasurements = prev }()
	installMeasurements = []string{"not-hex"}
	if _, err := appendCvmModeInstallArgs([]string{"upgrade"}, "bare-metal", "tdx"); err == nil {
		t.Fatal("appendCvmModeInstallArgs accepted a malformed measurement, want error")
	}
}

func TestAppendCvmModeInstallArgsRejectsUnknownHardwarePlatform(t *testing.T) {
	if _, err := appendCvmModeInstallArgs([]string{"upgrade"}, "bare-metal", "sgx"); err == nil {
		t.Fatal("appendCvmModeInstallArgs accepted an unknown --hardware-platform, want error")
	}
}

func TestAppendCvmModeInstallArgsAcceptsAksWithTdx(t *testing.T) {
	// aks + tdx is the Azure-vTPM TDX (az-tdx) shape: the node's vTPM HCL report
	// wraps a TD quote, so it needs the vTPM device (tpm=true, no guest device)
	// and the TDX armTLS platform on CDS/mesh — not a refusal.
	got, err := appendCvmModeInstallArgs([]string{"upgrade"}, "aks", "tdx")
	if err != nil {
		t.Fatalf("appendCvmModeInstallArgs(aks, tdx): unexpected error %v", err)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{
		"attestationApi.cvmMode=aks",
		"attestationApi.teeDevices.tpm=true",
		"attestationApi.teeDevices.tdxGuest=false",
		"cds.armtlsPlatform=tdx",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("aks+tdx args missing %q; got %v", want, got)
		}
	}
}

// testComponents mirrors the chart's c8sComponents for the resolver tests,
// which exercise buildDigestArgs without reading a real chart. The chart-read
// path (chartComponents) is covered separately by TestChartComponentsFromValues.
var testComponents = []c8sComponent{
	{valuePrefix: "image", repository: "ghcr.io/confidential-dot-ai/c8s-operator"},
	{valuePrefix: "attestationApi.image", repository: "ghcr.io/confidential-dot-ai/attestation-api", enabledPath: "attestationApi.enabled"},
	{valuePrefix: "cds.image", repository: "ghcr.io/confidential-dot-ai/cds"},
	{valuePrefix: "armtlsMesh.image", repository: "ghcr.io/confidential-dot-ai/armtls-mesh", enabledPath: "armtlsMesh.enabled"},
	{valuePrefix: "nriImagePolicy.image", repository: "ghcr.io/confidential-dot-ai/nri-image-policy", enabledPath: "nriImagePolicy.enabled"},
}

// allEnabled is the buildDigestArgs predicate for tests that resolve every
// component (the skip path is covered by TestBuildDigestArgsSkipsDisabledComponent).
func allEnabled(string) (bool, error) { return true, nil }

func TestBuildDigestArgsPinsEveryComponent(t *testing.T) {
	// Deterministic fake resolver: digest derived from the ref so each
	// component gets a distinct, predictable value.
	resolve := func(ref string) (string, error) {
		switch ref {
		case "ghcr.io/confidential-dot-ai/c8s-operator:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000aa", nil
		case "ghcr.io/confidential-dot-ai/attestation-api:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000bb", nil
		case "ghcr.io/confidential-dot-ai/cds:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000cc", nil
		case "ghcr.io/confidential-dot-ai/armtls-mesh:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000dd", nil
		case "ghcr.io/confidential-dot-ai/nri-image-policy:v1":
			return "sha256:00000000000000000000000000000000000000000000000000000000000000ee", nil
		}
		t.Fatalf("unexpected ref resolved: %q", ref)
		return "", nil
	}

	got, err := buildDigestArgs([]string{"upgrade"}, "v1", testComponents, resolve, allEnabled)
	if err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}
	assertArgsEqual(t, got, []string{
		"upgrade",
		// Each component pins both repository and digest so an -f repository
		// override cannot diverge from the digest resolved against it.
		"--set-string", "image.repository=ghcr.io/confidential-dot-ai/c8s-operator",
		"--set-string", "image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000aa",
		"--set-string", "attestationApi.image.repository=ghcr.io/confidential-dot-ai/attestation-api",
		"--set-string", "attestationApi.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000bb",
		"--set-string", "cds.image.repository=ghcr.io/confidential-dot-ai/cds",
		"--set-string", "cds.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000cc",
		"--set-string", "armtlsMesh.image.repository=ghcr.io/confidential-dot-ai/armtls-mesh",
		"--set-string", "armtlsMesh.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000dd",
		"--set-string", "nriImagePolicy.image.repository=ghcr.io/confidential-dot-ai/nri-image-policy",
		"--set-string", "nriImagePolicy.image.digest=sha256:00000000000000000000000000000000000000000000000000000000000000ee",
		// Resolving component digests enables their derivation into the NRI allowlist.
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
	})
}

// Each component repository is resolved at most once per install (no wasted
// registry round-trips).
func TestBuildDigestArgsResolvesEachComponentOnce(t *testing.T) {
	calls := map[string]int{}
	resolve := func(ref string) (string, error) {
		calls[ref]++
		return "sha256:1111111111111111111111111111111111111111111111111111111111111111", nil
	}
	if _, err := buildDigestArgs(nil, "v1", testComponents, resolve, allEnabled); err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}
	for ref, n := range calls {
		if n != 1 {
			t.Errorf("ref %q resolved %d times, want 1", ref, n)
		}
	}
}

// A component whose enabledPath resolves to false never renders, so its tag
// must not be resolved (that image may be unpublished at the install tag — e.g.
// attestationApi under --cvm-mode=bare-metal) and it must contribute no --set args.
// Enabled components still resolve and pin.
func TestBuildDigestArgsSkipsDisabledComponent(t *testing.T) {
	resolved := map[string]bool{}
	resolve := func(ref string) (string, error) {
		resolved[ref] = true
		return "sha256:3333333333333333333333333333333333333333333333333333333333333333", nil
	}
	disabled := map[string]bool{"attestationApi.enabled": true, "nriImagePolicy.enabled": true}
	enabled := func(path string) (bool, error) { return !disabled[path], nil }

	args, err := buildDigestArgs(nil, "v1", testComponents, resolve, enabled)
	if err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}
	for _, ref := range []string{
		"ghcr.io/confidential-dot-ai/attestation-api:v1",
		"ghcr.io/confidential-dot-ai/nri-image-policy:v1",
	} {
		if resolved[ref] {
			t.Errorf("disabled component %q was resolved, want skipped", ref)
		}
	}
	joined := strings.Join(args, " ")
	for _, prefix := range []string{"attestationApi.image", "nriImagePolicy.image"} {
		if strings.Contains(joined, prefix+".repository") || strings.Contains(joined, prefix+".digest") {
			t.Errorf("disabled component %q emitted --set args: %v", prefix, args)
		}
	}
	// Enabled components still pin both repository and digest.
	for _, want := range []string{
		"cds.image.repository=ghcr.io/confidential-dot-ai/cds",
		"armtlsMesh.image.repository=ghcr.io/confidential-dot-ai/armtls-mesh",
		"image.repository=ghcr.io/confidential-dot-ai/c8s-operator",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("enabled component arg %q missing from %v", want, args)
		}
	}
	if !resolved["ghcr.io/confidential-dot-ai/cds:v1"] {
		t.Error("enabled component cds was not resolved")
	}
}

// A predicate error (the effective-enabled read failed) must abort rather than
// silently resolve or skip the component.
func TestBuildDigestArgsFailsClosedOnEnabledError(t *testing.T) {
	resolve := func(string) (string, error) {
		return "sha256:4444444444444444444444444444444444444444444444444444444444444444", nil
	}
	enabled := func(string) (bool, error) { return false, errTestResolve }
	if _, err := buildDigestArgs(nil, "v1", testComponents, resolve, enabled); err == nil {
		t.Fatal("buildDigestArgs ignored an enabled-predicate error, want fail-closed")
	}
}

// A resolution failure for any component must abort: a partially pinned floor
// would pass the render guard while the served allowlist pointed at a wrong or
// missing digest.
func TestBuildDigestArgsFailsClosedOnResolveError(t *testing.T) {
	resolve := func(ref string) (string, error) {
		if ref == "ghcr.io/confidential-dot-ai/cds:v1" {
			return "", errTestResolve
		}
		return "sha256:2222222222222222222222222222222222222222222222222222222222222222", nil
	}
	if _, err := buildDigestArgs(nil, "v1", testComponents, resolve, allEnabled); err == nil {
		t.Fatal("buildDigestArgs ignored a resolver error, want fail-closed")
	}
}

// A missing tag (registry MANIFEST_UNKNOWN) must abort with the tag-coupling
// guidance explaining the lockstep publish model while preserving the cause.
func TestBuildDigestArgsExplainsTagCouplingOnMissingTag(t *testing.T) {
	notFound := errors.New(`crane digest "ghcr.io/confidential-dot-ai/c8s-operator:gpu-test": exit status 1: MANIFEST_UNKNOWN: manifest unknown`)
	resolve := func(string) (string, error) { return "", notFound }
	_, err := buildDigestArgs(nil, "gpu-test", testComponents, resolve, allEnabled)
	if err == nil {
		t.Fatal("buildDigestArgs accepted a missing tag, want fail-closed")
	}
	if !errors.Is(err, notFound) {
		t.Errorf("wrapped error must preserve the cause, got: %v", err)
	}
	// The hint must be self-contained (end users don't have the repo, so no
	// docs/ paths) and explain how to check the component tag.
	for _, want := range []string{"lockstep"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "docs/") {
		t.Errorf("user-facing hint must not reference in-repo docs paths, got: %v", err)
	}
}

// A component released on another repository's cadence has no image at a C8s
// release tag, so its chart-declared pinnedDigest must be used verbatim and the
// resolver must never be asked for it — asking is what aborted the whole
// install, since a C8s tag can only 404 against that repository.
func TestBuildDigestArgsUsesPinnedDigestWithoutResolving(t *testing.T) {
	const pinned = "sha256:00000000000000000000000000000000000000000000000000000000000000ff"
	comps := []c8sComponent{
		{valuePrefix: "cds.image", repository: "ghcr.io/confidential-dot-ai/cds"},
		{valuePrefix: "attestationApi.image", repository: "ghcr.io/confidential-dot-ai/attestation-api", pinnedDigest: pinned},
	}
	resolve := func(ref string) (string, error) {
		if strings.Contains(ref, "attestation-api") {
			return "", fmt.Errorf("resolver must not be called for a pinned component, got %q", ref)
		}
		return "sha256:1111111111111111111111111111111111111111111111111111111111111111", nil
	}
	got, err := buildDigestArgs(nil, "v0.1.15", comps, resolve, allEnabled)
	if err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}
	for _, want := range []string{
		"attestationApi.image.repository=ghcr.io/confidential-dot-ai/attestation-api",
		"attestationApi.image.digest=" + pinned,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("args missing %q; got %v", want, got)
		}
	}
}

// A pinned component that the effective config disables must not be pinned
// either: the enabled check has to run first, or the install would carry a
// floor entry for a DaemonSet it never renders.
func TestBuildDigestArgsSkipsDisabledPinnedComponent(t *testing.T) {
	comps := []c8sComponent{{
		valuePrefix:  "attestationApi.image",
		repository:   "ghcr.io/confidential-dot-ai/attestation-api",
		enabledPath:  "attestationApi.enabled",
		pinnedDigest: "sha256:00000000000000000000000000000000000000000000000000000000000000ff",
	}}
	resolve := func(string) (string, error) { return "", errTestResolve }
	got, err := buildDigestArgs(nil, "v0.1.15", comps, resolve, func(string) (bool, error) { return false, nil })
	if err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}
	for _, arg := range got {
		if strings.Contains(arg, "attestationApi.image") {
			t.Errorf("disabled pinned component was still pinned: %v", got)
		}
	}
}

// Auth/network resolve failures must pass through without the tag-coupling
// hint — advising a tag change for a 401 would send the operator down the
// wrong path.
func TestBuildDigestArgsLeavesOtherResolveErrorsUnhinted(t *testing.T) {
	resolve := func(string) (string, error) { return "", errTestResolve }
	_, err := buildDigestArgs(nil, "v1", testComponents, resolve, allEnabled)
	if err == nil {
		t.Fatal("buildDigestArgs ignored a resolver error, want fail-closed")
	}
	if strings.Contains(err.Error(), "lockstep") {
		t.Errorf("non-not-found error must not carry the tag-coupling hint: %v", err)
	}
}

// chartComponents reads the component set from the chart's values.yaml; this
// asserts the parse against the embedded chart so the install-time list cannot
// silently diverge from what the chart declares.
func TestChartComponentsFromValues(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}
	dir, err := extractChart()
	if err != nil {
		t.Fatalf("extractChart: %v", err)
	}
	defer os.RemoveAll(dir)

	comps, err := chartComponents(context.Background(), filepath.Join(dir, helmchart.ChartRoot))
	if err != nil {
		t.Fatalf("chartComponents: %v", err)
	}

	got := map[string]string{}
	for _, c := range comps {
		got[c.valuePrefix] = c.repository
	}
	want := map[string]string{
		"image":                "ghcr.io/confidential-dot-ai/c8s-operator",
		"attestationApi.image": "ghcr.io/confidential-dot-ai/attestation-api",
		"cds.image":            "ghcr.io/confidential-dot-ai/cds",
		"armtlsMesh.image":     "ghcr.io/confidential-dot-ai/armtls-mesh",
		"nriImagePolicy.image": "ghcr.io/confidential-dot-ai/nri-image-policy",
		"volumed.image":        "ghcr.io/confidential-dot-ai/volumed",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chart components = %v, want %v", got, want)
	}

	// Exactly the components released outside the C8s train may carry a
	// pinnedDigest. Pinning one that does publish at the install tag would
	// freeze it there silently, and unpinning attestation-api puts back the
	// abort that made `--image-tag <release>` uninstallable.
	pinned := map[string]string{}
	for _, c := range comps {
		if c.pinnedDigest != "" {
			pinned[c.valuePrefix] = c.pinnedDigest
		}
	}
	if len(pinned) != 1 || pinned["attestationApi.image"] == "" {
		t.Errorf("pinnedDigest components = %v, want only attestationApi.image", pinned)
	}
	if !strings.HasPrefix(pinned["attestationApi.image"], "sha256:") || len(pinned["attestationApi.image"]) != len("sha256:")+64 {
		t.Errorf("attestationApi pinnedDigest is not a sha256 digest: %q", pinned["attestationApi.image"])
	}
}

// componentEnabledPredicate must honor a -f values file, not just chart
// defaults and --set. volumed defaults to disabled; a -f file that enables it
// has to make the resolver see it as enabled, or its digest is never pinned and
// the render fails with no image ref.
func TestComponentEnabledPredicateHonorsValuesFile(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}
	dir, err := extractChart()
	if err != nil {
		t.Fatalf("extractChart: %v", err)
	}
	defer os.RemoveAll(dir)
	chartPath := filepath.Join(dir, helmchart.ChartRoot)

	vf := filepath.Join(t.TempDir(), "enable-volumed.yaml")
	if err := os.WriteFile(vf, []byte("volumed:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Default (no -f): volumed reads as disabled.
	installValues = nil
	pred, err := componentEnabledPredicate(context.Background(), chartPath, nil)
	if err != nil {
		t.Fatalf("predicate (defaults): %v", err)
	}
	if on, _ := pred("volumed.enabled"); on {
		t.Fatal("volumed.enabled true with no -f; expected the chart default false")
	}

	// With the -f file: volumed reads as enabled.
	installValues = []string{vf}
	defer func() { installValues = nil }()
	pred, err = componentEnabledPredicate(context.Background(), chartPath, nil)
	if err != nil {
		t.Fatalf("predicate (-f): %v", err)
	}
	if on, _ := pred("volumed.enabled"); !on {
		t.Fatal("volumed.enabled false despite a -f file enabling it; the resolver would skip pinning its digest")
	}
}

// helmchart.MergeValues must deep-merge a -f overlay the way helm coalesces
// it: a nested map merges key-by-key (so enabling volumed via -f does not
// wipe its sibling image/hostPaths defaults), while a scalar replaces. This
// is the fix for the resolver treating a -f-enabled, default-disabled
// component as still off.
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

func TestValuesFilesSetDistroErrorPaths(t *testing.T) {
	if _, err := valuesFilesSetDistro([]string{filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Fatal("want the read error surfaced")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := valuesFilesSetDistro([]string{bad}); err == nil {
		t.Fatal("want the parse error surfaced")
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
func TestValuesFilesSetExemptNamespaces(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"list set", "nriImagePolicy:\n  policy:\n    exemptNamespaces: [gatekeeper-system]\n", true},
		{"empty list is a choice", "nriImagePolicy:\n  policy:\n    exemptNamespaces: []\n", true},
		{"null is a choice", "nriImagePolicy:\n  policy:\n    exemptNamespaces:\n", true},
		{"sibling policy key only", "nriImagePolicy:\n  policy:\n    mode: audit\n", false},
		{"wrong nesting level", "nriImagePolicy:\n  exemptNamespaces: [kube-system]\n", false},
		{"unrelated value only", "router:\n  enabled: false\n", false},
		{"empty file", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := valuesFilesSetExemptNamespaces([]string{writeValuesFile(t, tc.body)})
			if err != nil {
				t.Fatalf("valuesFilesSetExemptNamespaces: %v", err)
			}
			if got != tc.want {
				t.Errorf("valuesFilesSetExemptNamespaces(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}

	t.Run("no files means default", func(t *testing.T) {
		got, err := valuesFilesSetExemptNamespaces(nil)
		if err != nil || got {
			t.Errorf("valuesFilesSetExemptNamespaces(nil) = (%v, %v), want (false, nil)", got, err)
		}
	})

	t.Run("one of several files sets it", func(t *testing.T) {
		a := writeValuesFile(t, "router:\n  enabled: false\n")
		b := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: [kube-system]\n")
		got, err := valuesFilesSetExemptNamespaces([]string{a, b})
		if err != nil || !got {
			t.Errorf("valuesFilesSetExemptNamespaces(two files) = (%v, %v), want (true, nil)", got, err)
		}
	})
}

func TestAppendExemptNamespacesInstallArgs(t *testing.T) {
	want := []string{"--set-string", "nriImagePolicy.policy.exemptNamespaces[0]=kube-system"}
	for _, mode := range hostedCvmModes {
		got, err := appendExemptNamespacesInstallArgs(nil, mode, nil)
		if err != nil {
			t.Fatalf("--cvm-mode=%s: %v", mode, err)
		}
		assertArgsEqual(t, got, want)
	}

	// node bakes the system digests into its own floor, so the chart's empty
	// default stands.
	got, err := appendExemptNamespacesInstallArgs(nil, "bare-metal", nil)
	if err != nil || got != nil {
		t.Errorf("--cvm-mode=bare-metal = (%v, %v), want (nil, nil)", got, err)
	}

	t.Run("a -f file that sets it wins", func(t *testing.T) {
		f := writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: [gatekeeper-system]\n")
		got, err := appendExemptNamespacesInstallArgs(nil, "aks", []string{f})
		if err != nil || got != nil {
			t.Errorf("with an exemptNamespaces -f = (%v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("an unrelated -f file does not suppress the default", func(t *testing.T) {
		f := writeValuesFile(t, "router:\n  enabled: false\n")
		got, err := appendExemptNamespacesInstallArgs(nil, "aks", []string{f})
		if err != nil {
			t.Fatalf("appendExemptNamespacesInstallArgs: %v", err)
		}
		assertArgsEqual(t, got, want)
	})

	t.Run("an unreadable -f file is an error, not a silent default", func(t *testing.T) {
		if _, err := appendExemptNamespacesInstallArgs(nil, "aks", []string{"/nonexistent/values.yaml"}); err == nil {
			t.Error("want an error for an unreadable values file")
		}
	})
}

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
	got := admissibleDigests(values, []c8sComponent{{valuePrefix: "cds.image"}, {valuePrefix: "volumed.image"}})
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
		Status:          corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Image: image, ImageID: imageID}}},
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

	// Exempting a namespace admits everything in it by captured digest.
	got = deniedPlatformImages(pods, release, []string{"kube-system", "calico-system"}, admitted)
	if len(got) != 0 {
		t.Errorf("with both namespaces exempt, denied = %#v, want none", got)
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
func TestImageRepositoryFallsBackToImageID(t *testing.T) {
	const digest = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	if got, want := imageRepository("", "docker-pullable://calico/node@"+digest), "docker.io/calico/node"; got != want {
		t.Errorf("imageRepository = %q, want %q", got, want)
	}
	if got := imageRepository("", ""); got != "" {
		t.Errorf("imageRepository with nothing parseable = %q, want empty", got)
	}
}

// The exemption admits by a digest set the plugin freezes per node under its
// own cache dir, so the install is the one place an operator can review it.
func TestExemptedPlatformImages(t *testing.T) {
	const (
		etcd  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		proxy = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		gke   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		vllm  = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	)
	pods := []corev1.Pod{
		mirrorPod("kube-system", "etcd-node-a", "rancher/hardened-etcd:v3.6.12", "rancher/hardened-etcd@"+etcd),
		daemonSetPod("kube-system", "kube-proxy-a", "kube-proxy:v1.31.0", "kube-proxy@"+proxy),
		// Same DaemonSet on a second node: one line, not two.
		daemonSetPod("kube-system", "kube-proxy-b", "kube-proxy:v1.31.0", "kube-proxy@"+proxy),
		// Outside the exempt set: not what this admits.
		daemonSetPod("gke-system", "gke-agent-a", "gke/agent:v1", "gke/agent@"+gke),
		deploymentPod("tenant", "infer-abc", "example.test/vllm:v1", "example.test/vllm@"+vllm),
	}
	got := exemptedPlatformImages(pods, []string{"kube-system"})
	want := []string{
		"kube-system/etcd-node-a  docker.io/rancher/hardened-etcd@" + etcd,
		"kube-system/kube-proxy-a  docker.io/library/kube-proxy@" + proxy,
	}
	if !slices.Equal(got, want) {
		t.Errorf("exemptedPlatformImages = %#v, want %#v", got, want)
	}

	if got := exemptedPlatformImages(pods, nil); len(got) != 0 {
		t.Errorf("with no exempt namespace, got %#v, want none", got)
	}
}

// The report is the audit surface: it must carry every digest (never a
// truncated list) and name the alternative posture.
func TestReportExemptedImages(t *testing.T) {
	images := make([]string, 0, deniedImagesListed+5)
	for i := range cap(images) {
		images = append(images, fmt.Sprintf("kube-system/pod-%02d  example.test/img%02d@sha256:%064d", i, i, i))
	}
	var buf bytes.Buffer
	reportExemptedImages(&buf, []string{"kube-system"}, images)
	out := buf.String()

	for _, image := range images {
		if !strings.Contains(out, image) {
			t.Errorf("report omits %q — a truncated audit list is not one:\n%s", image, out)
		}
	}
	for _, want := range []string{"kube-system", "nriImagePolicy.bootstrapAllowlist.workloads", exemptNamespacesPath} {
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

// --rtmrs completes the TDX pin: the entries fan into cds.rtmrs and
// armtlsMesh.rtmrs, normalized and in index order.
func TestAppendCvmModeInstallArgsRTMRs(t *testing.T) {
	prev := installRegisters
	defer func() { installRegisters = prev }()
	r1, r2 := strings.Repeat("11", 48), strings.Repeat("22", 48)
	installRegisters = []string{"2=" + r2, "1=" + r1} // out of order on purpose

	got, err := appendCvmModeInstallArgs([]string{"upgrade"}, "bare-metal", "tdx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"cds.rtmrs[0]=1=" + r1,
		"cds.rtmrs[1]=2=" + r2,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("args missing %q; got %v", want, got)
		}
	}

	installRegisters = []string{"0=" + r1}
	if _, err := appendCvmModeInstallArgs([]string{"upgrade"}, "bare-metal", "tdx"); err == nil {
		t.Fatal("RTMR[0] pin accepted; only RTMR[1] and RTMR[2] are supported")
	}
}

// A TDX install without RTMR pins warns that the measurement pin covers TDVF
// firmware only; SNP, pinned TDX, and values-file-pinned TDX stay quiet.
func TestTDXRTMRPinWarning(t *testing.T) {
	r1 := "1=" + strings.Repeat("11", 48)

	if warn, err := tdxRTMRPinWarning("sev-snp", nil, nil); err != nil || warn != "" {
		t.Fatalf("sev-snp: warn=%q err=%v, want quiet", warn, err)
	}
	if warn, err := tdxRTMRPinWarning("tdx", []string{r1}, nil); err != nil || warn != "" {
		t.Fatalf("pinned tdx: warn=%q err=%v, want quiet", warn, err)
	}
	warn, err := tdxRTMRPinWarning("tdx", nil, nil)
	if err != nil || warn == "" {
		t.Fatalf("unpinned tdx: warn=%q err=%v, want a warning", warn, err)
	}

	pinned := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(pinned, []byte("cds:\n  rtmrs:\n    - \""+r1+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if warn, err := tdxRTMRPinWarning("tdx", nil, []string{pinned}); err != nil || warn != "" {
		t.Fatalf("values-file pinned tdx: warn=%q err=%v, want quiet", warn, err)
	}

	empty := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(empty, []byte("cds:\n  rtmrs: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if warn, err := tdxRTMRPinWarning("tdx", nil, []string{empty}); err != nil || warn == "" {
		t.Fatalf("empty-list values file: warn=%q err=%v, want a warning", warn, err)
	}

	if _, err := tdxRTMRPinWarning("tdx", nil, []string{filepath.Join(t.TempDir(), "absent.yaml")}); err == nil {
		t.Fatal("an unreadable values file was silently treated as unpinned")
	}
}
