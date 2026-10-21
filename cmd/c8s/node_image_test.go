//go:build !c8s_node

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/distribution/reference"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

var (
	nodeImageTestCDSDigest    = "sha256:" + strings.Repeat("c", 64)
	nodeImageTestMeshDigest   = "sha256:" + strings.Repeat("d", 64)
	nodeImageTestRouterDigest = "sha256:" + strings.Repeat("e", 64)
)

func TestNodeImageRender(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	for _, platform := range []string{"tdx", "sev-snp"} {
		t.Run(platform, func(t *testing.T) {
			out := t.TempDir()
			cmd := newNodeImageCmd()
			args := []string{
				"render", "--hardware-platform", platform, "--kube-version", "v1.34.5",
				"--image-digest", testDigest, "--image-repository", "registry.example.com/c8s-operator",
				"--cds-image-digest", nodeImageTestCDSDigest, "--cds-image-repository", "registry.example.com/cds",
				"--armtls-mesh-image-digest", nodeImageTestMeshDigest, "--armtls-mesh-image-repository", "registry.example.com/armtls-mesh",
				"--output-dir", out,
			}
			if platform == "sev-snp" {
				args = append(args, "--chart-dir", filepath.Join("..", "..", "internal", "helmchart", "c8s"),
					"--router-image-digest", nodeImageTestRouterDigest, "--router-image-repository", "registry.example.com/nginx")
			}
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			var raw []byte
			for _, f := range []string{"c8s-integration.yaml", "c8s-cds-singleton.yaml", "c8s-cds-ha.yaml"} {
				part, err := os.ReadFile(filepath.Join(out, f))
				if err != nil {
					t.Fatal(err)
				}
				if f == "c8s-cds-ha.yaml" {
					for _, want := range []string{"name: GOMEMLIMIT", "memory: 4Gi", "sizeLimit: 2Gi", "--allowlist-max-bytes=2Gi"} {
						if !bytes.Contains(part, []byte(want)) {
							t.Fatalf("HA replicas render without %q", want)
						}
					}
					// Every cds node runs the CDS its own image carries: the
					// DaemonSet names it by the node-local tag, the airgap
					// import adds that name, and the floor pins the digest.
					cdsRef := "registry.example.com/cds@" + nodeImageTestCDSDigest
					if bytes.Contains(part, []byte("image: "+cdsRef)) || !bytes.Contains(part, []byte("image: registry.example.com/cds:c8s-node")) {
						t.Fatal("HA CDS DaemonSet does not name the node-local CDS image")
					}
					names, err := os.ReadFile(filepath.Join(out, "local-names.txt"))
					if err != nil || string(names) != cdsRef+" registry.example.com/cds:c8s-node\n" {
						t.Fatalf("local-names.txt: %q %v", names, err)
					}
					floor, err := os.ReadFile(filepath.Join(out, "cds-floor.json"))
					if err != nil || !bytes.Contains(floor, []byte(nodeImageTestCDSDigest)) {
						t.Fatal("the cds floor no longer pins the CDS digest")
					}
				}
				raw = append(raw, part...)
			}
			// The cds-role floor: the HA replica pinned to its exact argv, the
			// DaemonSets kept, and no other chart image (the operator image
			// carries the same c8s binary).
			floorRaw, err := os.ReadFile(filepath.Join(out, "cds-floor.json"))
			if err != nil {
				t.Fatal(err)
			}
			floor, err := pkgallowlist.ParseJSON(floorRaw)
			if err != nil {
				t.Fatal(err)
			}
			replica := floor.Workloads["cds-ha-replica"].Containers
			if len(replica) != 1 || replica[0].Args.Policy != pkgallowlist.PolicyExact || !slices.Contains(replica[0].Args.Argv, "--ha-config=/run/c8s-node/cds-ha.json") {
				t.Fatalf("cds floor does not pin the HA replica argv: %+v", replica)
			}
			for name, w := range floor.Workloads {
				for _, c := range w.Containers {
					if c.Digest.String() == testDigest {
						t.Fatalf("cds floor admits the operator image (%s)", name)
					}
				}
			}
			docs := nodeImageDocuments(t, raw)
			for _, key := range []string{
				"Namespace/c8s-system", "CustomResourceDefinition/confidentialworkloads.confidential.ai",
				"Deployment/c8s-operator", "Deployment/c8s-cds", "DaemonSet/c8s-cds-ha", "Deployment/c8s-router", "DaemonSet/c8s-armtls-mesh",
				"ConfigMap/c8s-cds-allowlist-seed", "MutatingWebhookConfiguration/c8s-pod-injector",
				"ValidatingAdmissionPolicy/c8s-cw-label-integrity", "ValidatingAdmissionPolicyBinding/c8s-cw-label-integrity",
				"ValidatingAdmissionPolicy/c8s-deny-host-namespaces", "ValidatingAdmissionPolicyBinding/c8s-deny-host-namespaces",
				"ValidatingAdmissionPolicy/c8s-deny-host-namespaces-ephemeral", "ValidatingAdmissionPolicyBinding/c8s-deny-host-namespaces-ephemeral",
				"ValidatingAdmissionPolicy/deny-armtls-mesh-uid", "ValidatingAdmissionPolicyBinding/deny-armtls-mesh-uid",
				"ValidatingAdmissionPolicy/deny-armtls-mesh-uid-ephemeral", "ValidatingAdmissionPolicyBinding/deny-armtls-mesh-uid-ephemeral",
				"NetworkPolicy/armtls-mesh-tcp-only-egress", "NetworkPolicy/c8s-operator-ingress",
			} {
				if docs[key] == nil {
					t.Errorf("missing %s", key)
				}
			}
			for _, name := range []string{"c8s-deny-host-namespaces", "c8s-deny-host-namespaces-ephemeral"} {
				if !bytes.Contains(docs["ValidatingAdmissionPolicy/"+name], []byte("AppArmor must not")) {
					t.Errorf("baked node image lost AppArmor admission in %s", name)
				}
			}
			for key, doc := range docs {
				var object struct {
					metav1.TypeMeta `json:",inline"`
					Metadata        metav1.ObjectMeta `json:"metadata"`
				}
				if err := yaml.Unmarshal(doc, &object); err != nil {
					t.Fatal(err)
				}
				switch object.Kind {
				case "Deployment", "DaemonSet", "ConfigMap", "ServiceAccount", "Role", "RoleBinding", "Service", "PersistentVolumeClaim", "PodDisruptionBudget", "NetworkPolicy":
					decrees := (object.Kind == "Role" || object.Kind == "RoleBinding") && object.Metadata.Namespace == nodeImageDecreeNamespace
					if object.Metadata.Namespace != nodeImageNamespace && !decrees {
						t.Errorf("%s namespace = %q", key, object.Metadata.Namespace)
					}
				default:
					if object.Metadata.Namespace != "" {
						t.Errorf("cluster resource %s has namespace %q", key, object.Metadata.Namespace)
					}
				}
				if strings.HasPrefix(key, "Pod/") || strings.HasPrefix(key, "HelmChart") {
					t.Errorf("unexpected runtime resource %s", key)
				}
			}
			for _, forbidden := range []string{"c8s-node.invalid", "c8s-node-runtime", "/run/confos/launch"} {
				if bytes.Contains(raw, []byte(forbidden)) {
					t.Errorf("baked manifests contain obsolete or private launch dependency %s", forbidden)
				}
			}
			var namespace corev1.Namespace
			if err := yaml.Unmarshal(docs["Namespace/c8s-system"], &namespace); err != nil {
				t.Fatal(err)
			}
			if namespace.Labels["confidential.ai/baked"] != "true" {
				t.Error("missing baked namespace marker")
			}
			for _, mode := range []string{"enforce", "warn", "audit"} {
				if namespace.Labels["pod-security.kubernetes.io/"+mode] != "privileged" {
					t.Errorf("namespace missing %s label", mode)
				}
			}
			imageList, err := os.ReadFile(filepath.Join(out, "images.txt"))
			if err != nil {
				t.Fatal(err)
			}
			images := strings.Fields(string(imageList))
			if len(images) != 4 || !slices.IsSorted(images) {
				t.Fatalf("image inventory must contain the four sorted core images, got %v", images)
			}
			for _, image := range []string{
				"registry.example.com/c8s-operator@" + testDigest,
				"registry.example.com/cds@" + nodeImageTestCDSDigest,
				"registry.example.com/armtls-mesh@" + nodeImageTestMeshDigest,
			} {
				if !slices.Contains(images, image) {
					t.Errorf("inventory missing overridden image %s", image)
				}
			}
			if platform == "sev-snp" && !slices.Contains(images, "registry.example.com/nginx@"+nodeImageTestRouterDigest) {
				t.Error("inventory lost the router image override")
			}
			for _, key := range []string{"Deployment/c8s-operator", "Deployment/c8s-cds", "Deployment/c8s-router", "DaemonSet/c8s-armtls-mesh"} {
				var workload appsv1.Deployment // Deployment and DaemonSet share spec.template.
				if err := yaml.Unmarshal(docs[key], &workload); err != nil {
					t.Fatal(err)
				}
				if workload.Namespace != nodeImageNamespace {
					t.Errorf("%s namespace = %q", key, workload.Namespace)
				}
				pod := workload.Spec.Template.Spec
				for _, c := range append(pod.InitContainers, pod.Containers...) {
					ref, err := reference.ParseDockerRef(c.Image)
					if err != nil {
						t.Fatal(err)
					}
					if !slices.Contains(images, ref.String()) || c.ImagePullPolicy != corev1.PullNever {
						t.Errorf("%s/%s must use a preloaded inventory image: image=%s pullPolicy=%s", key, c.Name, c.Image, c.ImagePullPolicy)
					}
				}
			}
			if docs["ConfigMap/c8s-router-nginx"] != nil {
				t.Error("integration manifests kept the router nginx ConfigMap")
			}
			// mkosi.sync installs every file in router-nginx/.
			entries, err := os.ReadDir(filepath.Join(out, "router-nginx"))
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if want := slices.Sorted(slices.Values(routerNginxFiles)); !slices.Equal(names, want) {
				t.Errorf("router-nginx/ holds %q, want %q", names, want)
			}
			nginxConf, err := os.ReadFile(filepath.Join(out, "router-nginx", "nginx.conf"))
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{"tls-cds.conf", "tls-acme.conf"} {
				if body, err := os.ReadFile(filepath.Join(out, "router-nginx", file)); err != nil || !strings.Contains(string(body), "ssl_certificate ") {
					t.Errorf("router-nginx/%s = %q, %v; want a certificate snippet", file, body, err)
				}
			}
			for _, directive := range []string{"listen 8443 ssl;", "server_name _;", "location = /allowlist", "limit_req zone=allowlist_write", "127.0.0.1:8801", "127.0.0.1:8800", "location /healthz", "include /run/c8s-node/router/upstream.conf;", "include /run/c8s-node/router/tls.conf;", "proxy_pass http://$c8s_upstream;", "listen 8080;"} {
				if !strings.Contains(string(nginxConf), directive) {
					t.Errorf("nginx missing %q", directive)
				}
			}
			if _, err := os.Stat(filepath.Join(out, "nginx.conf.in")); !os.IsNotExist(err) {
				t.Fatalf("unexpected standalone nginx configuration: %v", err)
			}
			seed, err := os.ReadFile(filepath.Join(out, "allowlist-seed.json"))
			if err != nil {
				t.Fatal(err)
			}
			if platform == "tdx" {
				testNodeImageBootstrap(t, seed)
			}
			allowlist, err := pkgallowlist.ParseJSON(seed)
			if err != nil {
				t.Fatal(err)
			}
			if len(allowlist.Workloads) != 6 {
				t.Errorf("seed has %d workloads, want four core images, the local-path helper and the router pod", len(allowlist.Workloads))
			}
			routerEntry := false
			for name := range allowlist.Workloads {
				routerEntry = routerEntry || strings.HasPrefix(name, "c8s-router-")
			}
			if !routerEntry {
				t.Error("router pod entry missing from the baked CDS seed")
			}
			var helperDigest string
			for _, workload := range allowlist.Workloads {
				for _, c := range workload.Containers {
					if strings.HasPrefix(c.Image, "busybox@") {
						helperDigest = c.Digest.String()
					}
				}
			}
			if helperDigest == "" {
				t.Fatal("local-path helper missing from the baked CDS seed")
			}
			index := allowlist.BuildIndex()
			for _, script := range []string{"/script/setup", "/script/teardown"} {
				if !index.AdmitsContainer(pkgallowlist.RunningContainer{
					Digest: helperDigest,
					Argv:   []string{"/bin/sh", script, "-p", "/opt/local-path-provisioner/pvc-123"},
				}) {
					t.Errorf("seed denies local-path helper %s", script)
				}
			}
			if index.AdmitsContainer(pkgallowlist.RunningContainer{
				Digest: helperDigest,
				Argv:   []string{"/bin/sh", "-c", "echo arbitrary command"},
			}) {
				t.Error("seed admits arbitrary busybox commands")
			}
		})
	}
}

func nodeImageDocuments(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	docs := map[string][]byte{}
	r := k8syaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	for {
		doc, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var object struct {
			metav1.TypeMeta `json:",inline"`
			Metadata        metav1.ObjectMeta `json:"metadata"`
		}
		if err := yaml.Unmarshal(doc, &object); err != nil {
			t.Fatal(err)
		}
		if object.Kind == "" {
			continue
		}
		key := object.Kind + "/" + object.Metadata.Name
		if docs[key] != nil {
			t.Fatalf("duplicate %s", key)
		}
		docs[key] = doc
	}
	return docs
}

func TestNodeImageRenderRejectsBadInputsBeforeHelm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*nodeImageRenderConfig)
	}{
		{"platform", func(c *nodeImageRenderConfig) { c.platform = "aks" }},
		{"missing Kubernetes version", func(c *nodeImageRenderConfig) { c.kubeVersion = "" }},
		{"invalid Kubernetes version", func(c *nodeImageRenderConfig) { c.kubeVersion = "latest" }},
		{"missing digest", func(c *nodeImageRenderConfig) { c.imageDigest = "" }},
		{"missing CDS digest", func(c *nodeImageRenderConfig) { c.cdsImageDigest = "" }},
		{"missing mesh digest", func(c *nodeImageRenderConfig) { c.armtlsMeshImageDigest = "" }},
		{"invalid router digest", func(c *nodeImageRenderConfig) { c.routerImageDigest = "latest" }},
		{"tagged CDS repository", func(c *nodeImageRenderConfig) { c.cdsImageRepository = "example.com/cds:main" }},
		{"invalid mesh repository", func(c *nodeImageRenderConfig) { c.armtlsMeshImageRepository = "invalid repo" }},
		{"digested router repository", func(c *nodeImageRenderConfig) { c.routerImageRepository = "example.com/nginx@" + testDigest }},
		{"tag as digest", func(c *nodeImageRenderConfig) { c.imageDigest = "main" }},
		{"tagged repository", func(c *nodeImageRenderConfig) { c.imageRepository += ":main" }},
		{"missing output", func(c *nodeImageRenderConfig) { c.outputDir = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBin(t)
			f.tool(t, "helm", "exit 99")
			cfg := nodeImageRenderConfig{platform: "tdx", kubeVersion: "v1.34.5", imageDigest: testDigest, cdsImageDigest: nodeImageTestCDSDigest, armtlsMeshImageDigest: nodeImageTestMeshDigest, imageRepository: "ghcr.io/confidential-dot-ai/c8s-operator", outputDir: t.TempDir()}
			tc.change(&cfg)
			if err := renderNodeImage(context.Background(), cfg); err == nil {
				t.Fatal("accepted invalid build inputs")
			}
			if calls := f.calls(t); len(calls) != 0 {
				t.Fatalf("called Helm before input validation: %v", calls)
			}
		})
	}
}

func TestNodeImageCollectRejectsIncompleteOrUnexpectedChart(t *testing.T) {
	for _, input := range []string{"", "kind: Deployment\nmetadata:\n  name: c8s-cds\n", "kind: DaemonSet\nmetadata:\n  name: armtls-mesh\n", "kind: HelmChart\nmetadata:\n  name: c8s\n"} {
		if _, err := collectNodeImageArtifacts([]byte(input)); err == nil {
			t.Errorf("accepted incomplete or unexpected render %q", input)
		}
	}
}

const nodeImageCollectFixtureTemplate = `
# Build-time chart resources.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-operator
spec:
  template:
    spec:
      containers:
        - name: operator
          image: registry.example.com/operator@CORE_DIGEST
          command: ["/app/c8s"]
      initContainers:
        - name: native-sidecar
          restartPolicy: Always
          image: registry.example.com/init@INIT_DIGEST
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-cds
spec:
  template:
    spec:
      containers:
        - name: cds
          image: registry.example.com/operator@CORE_DIGEST
          command: ["/app/c8s"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-router
spec:
  template:
    spec:
      containers:
        - name: router
          image: registry.example.com/operator@CORE_DIGEST
          command: ["/app/c8s"]
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: c8s-armtls-mesh
spec:
  template:
    spec:
      containers:
        - name: mesh
          image: registry.example.com/operator@CORE_DIGEST
          command: ["/app/c8s", "armtls-mesh"]
          args: ["--platform", "snp"]
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: confidentialworkloads.confidential.ai
spec:
  versions:
    - name: v1alpha1
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
          properties:
            counter:
              type: integer
              maximum: 9007199254740993
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: another-chart-policy
  annotations:
    description: "keep --- inside a scalar"
spec:
  failurePolicy: Fail
  validations:
    - expression: "object.metadata.name != 'forbidden'"
      message: |
        policy detail
        ---
        still one message
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: c8s-router-nginx
data:
  nginx.conf: |
    # a document-looking line remains nginx content
    ---
    events {}
  tls-cds.conf: ssl_certificate /tls/cert.pem;
  tls-acme.conf: ssl_certificate /etc/c8s-acme-tls/cert.pem;
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: c8s-cds-allowlist-seed
data:
  allowlist-seed.json: '{"schema":"c8s.allowlist/v1","workloads":{"core":{"containers":[{"digest":"CORE_DIGEST","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}]},"init":{"containers":[{"digest":"INIT_DIGEST","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}]}}}'
---
# An empty trailing document is harmless.
`

func nodeImageCollectFixture() string {
	return strings.NewReplacer("CORE_DIGEST", testDigest, "INIT_DIGEST", nodeImageTestCDSDigest).Replace(nodeImageCollectFixtureTemplate)
}

func TestNodeImageCollectPreservesCompleteResourcesAndConfigData(t *testing.T) {
	fixture := nodeImageCollectFixture()
	artifacts, err := collectNodeImageArtifacts([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	before, after := nodeImageDocuments(t, []byte(fixture)), nodeImageDocuments(t, slices.Concat(artifacts.integration, artifacts.cdsSingleton, artifacts.cdsHA))
	if after["ConfigMap/c8s-router-nginx"] != nil {
		t.Error("integration manifests kept the router nginx ConfigMap the image ships as files")
	}
	if got := artifacts.routerNginx["nginx.conf"]; got != "# a document-looking line remains nginx content\n---\nevents {}\n" {
		t.Errorf("router nginx.conf = %q, want the ConfigMap's content", got)
	}
	delete(before, "ConfigMap/c8s-router-nginx")
	for key, doc := range before {
		var want, got map[string]any
		if err := k8syaml.Unmarshal(doc, &want); err != nil {
			t.Fatal(err)
		}
		if err := k8syaml.Unmarshal(after[key], &got); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(key, "Deployment/") || strings.HasPrefix(key, "DaemonSet/") || strings.HasPrefix(key, "ConfigMap/") {
			want["metadata"].(map[string]any)["namespace"] = nodeImageNamespace
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("chart resource %s lost fields: got %#v, want %#v", key, got, want)
		}
	}
	if len(after) != len(before)+1 || after["Namespace/c8s-system"] == nil {
		t.Fatalf("unexpected integration resources: %v", after)
	}
	var cm corev1.ConfigMap
	if err := yaml.Unmarshal(after["ConfigMap/c8s-cds-allowlist-seed"], &cm); err != nil {
		t.Fatal(err)
	}
	if string(artifacts.seed) != cm.Data["allowlist-seed.json"] {
		t.Fatal("bootstrap seed differs from the complete manifest")
	}
	wantImages := []string{"registry.example.com/init@" + nodeImageTestCDSDigest, "registry.example.com/operator@" + testDigest}
	if !slices.Equal(artifacts.images, wantImages) {
		t.Fatalf("image inventory lost init image or duplicated common image: got %v, want %v", artifacts.images, wantImages)
	}
}

func TestNodeImageCollectRejectsExtraInvalidResources(t *testing.T) {
	for _, tc := range []struct{ name, resource string }{
		{"workload", "apiVersion: batch/v1\nkind: Job\nmetadata: {name: unexpected}\n"},
		{"duplicate operator", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: c8s-operator}\n"},
		{"duplicate nginx", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c8s-router-nginx}\ndata: {nginx.conf: duplicate}\n"},
		{"duplicate seed", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c8s-cds-allowlist-seed}\ndata: {allowlist-seed.json: duplicate}\n"},
		{"unnamed resource", "apiVersion: v1\nkind: Service\nmetadata: {}\n"},
		{"missing kind", "apiVersion: v1\nmetadata: {name: ignored-before}\n"},
		{"malformed document", "apiVersion: [\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := nodeImageCollectFixture() + "---\n" + tc.resource
			if _, err := collectNodeImageArtifacts([]byte(input)); err == nil {
				t.Fatal("accepted an invalid resource alongside otherwise complete chart artifacts")
			}
		})
	}
}

func TestNodeImageCollectRejectsIncompleteRouterNginx(t *testing.T) {
	for name, replacement := range map[string]string{
		"missing snippet": "",
		"empty snippet":   "  tls-acme.conf: \"\"\n",
		"extra key":       "  tls-acme.conf: ssl_certificate /etc/c8s-acme-tls/cert.pem;\n  extra.conf: x\n",
	} {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(nodeImageCollectFixture(), "  tls-acme.conf: ssl_certificate /etc/c8s-acme-tls/cert.pem;\n", replacement, 1)
			if _, err := collectNodeImageArtifacts([]byte(input)); err == nil {
				t.Fatal("accepted a router nginx ConfigMap that does not hold exactly routerNginxFiles")
			}
		})
	}
}

func TestNodeImageCollectRejectsUnpinnedOrUnseededImages(t *testing.T) {
	for _, tc := range []struct{ name, old, replacement string }{
		{"mutable container tag", "registry.example.com/operator@" + testDigest, "registry.example.com/operator:latest"},
		{"mutable init tag", "registry.example.com/init@" + nodeImageTestCDSDigest, "registry.example.com/init:latest"},
		{"unseeded container", "registry.example.com/operator@" + testDigest, "registry.example.com/operator@" + nodeImageTestMeshDigest},
		{"unseeded init", "registry.example.com/init@" + nodeImageTestCDSDigest, "registry.example.com/init@" + nodeImageTestMeshDigest},
		{"missing core workload", "name: c8s-cds", "name: other-cds"},
		{"restricted core bootstrap", `"command":{"policy":"any"}`, `"command":{"policy":"deny"}`},
		{"pinned args", `"args":{"policy":"any"},"mounts":{"policy":"any"}}]},"init"`, `"args":{"policy":"deny"},"mounts":{"policy":"any"}}]},"init"`},
		{"pinned executable other than the baked command", `"` + testDigest + `","command":{"policy":"any"}`, `"` + testDigest + `","command":{"policy":"exact","argv":["/other"]}`},
		{"unexpected namespace", "name: c8s-cds", "name: c8s-cds\n  namespace: outside"},
		{"cluster resource namespace", "name: confidentialworkloads.confidential.ai", "name: confidentialworkloads.confidential.ai\n  namespace: c8s-system"},
		{"invalid seed", `"schema":"c8s.allowlist/v1"`, `"schema":"invalid"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.ReplaceAll(nodeImageCollectFixture(), tc.old, tc.replacement)
			if _, err := collectNodeImageArtifacts([]byte(input)); err == nil {
				t.Fatal("accepted incomplete or unpinned measured workload inventory")
			}
		})
	}
}

func TestNodeImageCollectCanonicalizesPreloadReferences(t *testing.T) {
	for _, tc := range []struct{ image, canonical string }{
		{"busybox", "docker.io/library/busybox"},
		{"nginxinc/nginx-unprivileged", "docker.io/nginxinc/nginx-unprivileged"},
		{"nginxinc/nginx-unprivileged:tag", "docker.io/nginxinc/nginx-unprivileged"},
	} {
		t.Run(tc.image, func(t *testing.T) {
			input := strings.ReplaceAll(nodeImageCollectFixture(), "registry.example.com/operator", tc.image)
			artifacts, err := collectNodeImageArtifacts([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(artifacts.images, tc.canonical+"@"+testDigest) {
				t.Fatalf("preload name must match CRI's normalized image lookup: %v", artifacts.images)
			}
		})
	}
}

// Exercise the actual build-to-boot contract, including all system-floor and
// chart entries. Unit fixtures alone cannot catch collisions between the two.
func testNodeImageBootstrap(t *testing.T, seed []byte) {
	t.Helper()
	floor, err := os.ReadFile(filepath.Join("..", "..", "node-guest-image", "c8s", "image-policy.yaml.in"))
	if err != nil {
		t.Fatal(err)
	}
	floor = bytes.ReplaceAll(floor, []byte("@PLATFORM@"), []byte("tdx"))
	pins, err := refvalues.Load(filepath.Join("..", "..", "internal", "testdata", "node-identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	peers, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	pins.Images = pins.Images[:1]
	cds, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	components, err := pkgallowlist.ParseJSON(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent} {
		t.Run("bootstrap-"+string(role), func(t *testing.T) {
			root := t.TempDir()
			for name, data := range map[string][]byte{
				"usr/lib/c8s/image-policy.yaml":               floor,
				"usr/lib/c8s/allowlist-seed.json":             seed,
				filepath.Join(launchconfig.Dir, "peers.json"): peers,
				filepath.Join(launchconfig.Dir, "cds.json"):   cds,
			} {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			doc := &launchconfig.Document{
				Role:   role,
				Image:  launchconfig.Image{Platform: "tdx"},
				Server: launchconfig.ServerConfig{Address: "192.0.2.10", OperatorPublicKey: string(pins.Images[0].Anchor)},
				TLSSAN: "c8s.local",
			}
			if err := nodeservices.Prepare(root, doc); err != nil {
				t.Fatalf("actual chart seed and measured NRI floor cannot boot: %v", err)
			}
			prepared, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var policy struct {
				Allowlist struct {
					Base pkgallowlist.Allowlist `json:"base"`
				} `json:"allowlist"`
			}
			if err := yaml.Unmarshal(prepared, &policy); err != nil {
				t.Fatal(err)
			}
			if err := policy.Allowlist.Base.Normalize(); err != nil {
				t.Fatal(err)
			}
			for name, workload := range components.Workloads {
				got := policy.Allowlist.Base.Workloads[name]
				// YAML omits empty initContainers; treat nil and [] identically.
				if len(got.InitContainers) == 0 {
					got.InitContainers = nil
				}
				if len(workload.InitContainers) == 0 {
					workload.InitContainers = nil
				}
				if !reflect.DeepEqual(got, workload) {
					t.Errorf("bootstrap floor lost or changed chart workload %s: got %#v, want %#v", name, got, workload)
				}
			}
		})
	}
}

// A seed that pins a component's executable is accepted when the pin admits
// every command the baked manifests spell out for the image.
// The chart pins a component's args and mounts too; the seed must still admit
// every baked container, whether the manifest names the command or runs the
// image's entrypoint, with the mounts the manifest gives it.
func TestNodeImageCollectPinnedArgs(t *testing.T) {
	core := `{"digest":"` + testDigest + `","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}`
	mesh := `{"digest":"` + testDigest + `","command":{"policy":"exact","argv":["/app/c8s","armtls-mesh"]},"args":{"policy":"exact","argv":["--platform","snp"]}}`
	entrypoint := `{"digest":"` + testDigest + `","command":{"policy":"exact","argv":["/app/c8s"]},"args":{"policy":"deny"}}`
	const entrypointRouter = "        - name: router\n          image: registry.example.com/operator@" + testDigest
	const router = entrypointRouter + "\n          command: [\"/app/c8s\"]"
	urlArgs := `{"digest":"` + testDigest + `","command":{"policy":"exact","argv":["/app/c8s"]},"args":{"policy":"exact","argv":["--url=http://$(HOST_IP):8080"]}}`
	tmpRule := func(rule string) string {
		return `,{"digest":"` + testDigest + `","command":{"policy":"exact","argv":["/app/c8s"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","rules":[` + rule + `]}}`
	}
	hostTmp := router + "\n          volumeMounts: [{name: tmp, mountPath: /tmp, readOnly: true}]\n      volumes:\n        - name: tmp\n          hostPath: {path: /var/tmp}"
	placeholder := router + "\n          volumeMounts: [{name: c8s-volume-db, mountPath: /mnt/c8s-data/db}]\n      volumes:\n        - name: c8s-volume-db\n          emptyDir: {}"
	subPath := router + "\n          volumeMounts: [{name: cache, mountPath: /mnt/c8s-data/cache, subPath: cache}]\n      volumes:\n        - name: cache\n          emptyDir: {}"
	for _, tc := range []struct {
		name, seed, manifest string
		ok                   bool
	}{
		{"every invocation pinned", mesh + "," + entrypoint, "", true},
		{"image entrypoint under a pinned command", mesh + "," + entrypoint, entrypointRouter, false},
		{"image entrypoint and CMD under denied args", mesh + "," + entrypoint + `,{"digest":"` + testDigest + `","command":{"policy":"any"},"args":{"policy":"deny"}}`, entrypointRouter, false},
		{"image entrypoint under any command and args", mesh + "," + entrypoint + "," + core, entrypointRouter, true},
		{"entrypoint arguments not pinned", mesh + "," + entrypoint, router + "\n          args: [\"--other\"]", false},
		{"mount the manifest lacks", strings.Replace(mesh, `"args"`, `"mounts":{"policy":"exact","rules":[{"destination":"/tmp","kind":"emptyDir"}]},"args"`, 1) + "," + entrypoint, "", false},
		{"entrypoint under any command with pinned args", mesh + `,{"digest":"` + testDigest + `","command":{"policy":"any"},"args":{"policy":"deny"}}`, "", false},
		{"host mount pinned", mesh + "," + entrypoint + tmpRule(`{"destination":"/tmp","kind":"host","source":"/var/tmp","readOnly":true}`), hostTmp, true},
		{"host mount pinned as an emptyDir", mesh + "," + entrypoint + tmpRule(`{"destination":"/tmp","kind":"emptyDir"}`), hostTmp, false},
		{"host mount pinned writable", mesh + "," + entrypoint + tmpRule(`{"destination":"/tmp","kind":"host","source":"/var/tmp"}`), hostTmp, false},
		{"subpath pinned as data", mesh + "," + entrypoint + tmpRule(`{"destination":"/mnt/c8s-data/cache","kind":"data"}`), subPath, true},
		{"subpath pinned as an emptyDir", mesh + "," + entrypoint + tmpRule(`{"destination":"/mnt/c8s-data/cache","kind":"emptyDir"}`), subPath, false},
		{"volumed placeholder pinned as data", mesh + "," + entrypoint + tmpRule(`{"destination":"/mnt/c8s-data/db","kind":"data"}`), placeholder, true},
		{"volumed placeholder pinned as an emptyDir", mesh + "," + entrypoint + tmpRule(`{"destination":"/mnt/c8s-data/db","kind":"emptyDir"}`), placeholder, false},
		{"entrypoint under a denied command", mesh + `,{"digest":"` + testDigest + `","command":{"policy":"deny"},"args":{"policy":"any"}}`, "", false},
		{"env pinned", strings.Replace(mesh, `"args"`, `"env":{"policy":"deny"},"args"`, 1) + "," + entrypoint, "", false},
		{"escaped variable reference", mesh + "," + entrypoint + "," + urlArgs, router + "\n          args: [\"--url=http://$$(HOST_IP):8080\"]", true},
		{"escape not expanded", mesh + "," + entrypoint + "," + strings.Replace(urlArgs, "$(", "$$(", 1), router + "\n          args: [\"--url=http://$$(HOST_IP):8080\"]", false},
		{"defined variable reference", mesh + "," + entrypoint + "," + urlArgs, router + "\n          args: [\"--url=http://$(HOST_IP):8080\"]\n          env: [{name: HOST_IP, value: 10.0.0.1}]", false},
		{"service variable reference", mesh + "," + entrypoint + "," + urlArgs, router + "\n          args: [\"--url=http://$(HOST_IP):8080\"]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(nodeImageCollectFixture(), core, tc.seed, 1)
			if input == nodeImageCollectFixture() {
				t.Fatal("fixture seed did not change")
			}
			if tc.manifest != "" {
				input = strings.Replace(input, router, tc.manifest, 1)
			}
			_, err := collectNodeImageArtifacts([]byte(input))
			if (err == nil) != tc.ok {
				t.Fatalf("collectNodeImageArtifacts() error = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func TestNodeImageCollectAcceptsPinnedEntrypoint(t *testing.T) {
	input := strings.Replace(nodeImageCollectFixture(),
		`"`+testDigest+`","command":{"policy":"any"}`,
		`"`+testDigest+`","command":{"policy":"exact","argv":["/app/c8s"]}`, 1)
	if input == nodeImageCollectFixture() {
		t.Fatal("fixture did not change")
	}
	if _, err := collectNodeImageArtifacts([]byte(input)); err != nil {
		t.Fatalf("rejected a seed pinning the baked image to its entrypoint: %v", err)
	}
}

func TestKubeletArgv(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		err            bool
	}{
		{name: "plain", in: "--port=1", want: "--port=1"},
		{name: "escape", in: "$$(HOST_IP)", want: "$(HOST_IP)"},
		{name: "escaped dollar", in: "a$$b", want: "a$b"},
		{name: "undefined reference", in: "echo $(echo $$)", err: true},
		{name: "service variable", in: "--cds-url=https://$(C8S_CDS_SERVICE_HOST):8443", err: true},
		{name: "unclosed reference", in: "$(a $$", want: "$(a $"},
		{name: "trailing dollar", in: "a$", want: "a$"},
		{name: "lone dollar", in: "$x", want: "$x"},
		{name: "defined reference", in: "http://$(HOST_IP):1", err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kubeletArgv([]string{tc.in})
			if tc.err {
				if err == nil {
					t.Fatalf("kubeletArgv(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil || len(got) != 1 || got[0] != tc.want {
				t.Fatalf("kubeletArgv(%q) = %q, %v, want %q", tc.in, got, err, tc.want)
			}
		})
	}
}

// nodeImageEnvSeed is a seed whose core entries match the launch env: the
// runtime's variables plus extra, under any operator, CDS and router command
// and the mesh's pinned argv.
func nodeImageEnvSeed(t *testing.T, extra map[string]any) string {
	t.Helper()
	variables := map[string]any{
		"HOSTNAME":                      map[string]any{"present": true},
		"PATH":                          map[string]any{"exact": containerdDefaultPath},
		"KUBERNETES_SERVICE_HOST":       map[string]any{"present": true},
		"KUBERNETES_SERVICE_PORT":       map[string]any{"exact": "443"},
		"KUBERNETES_SERVICE_PORT_HTTPS": map[string]any{"exact": "443"},
		"KUBERNETES_PORT":               map[string]any{"present": true},
		"KUBERNETES_PORT_443_TCP":       map[string]any{"present": true},
		"KUBERNETES_PORT_443_TCP_ADDR":  map[string]any{"present": true},
		"KUBERNETES_PORT_443_TCP_PORT":  map[string]any{"exact": "443"},
		"KUBERNETES_PORT_443_TCP_PROTO": map[string]any{"exact": "tcp"},
	}
	component := map[string]any{"digest": testDigest, "command": map[string]any{"policy": "exact", "argv": []string{"/app/c8s"}}, "args": map[string]any{"policy": "deny"}, "env": map[string]any{"policy": "match", "variables": variables}}
	mesh := maps.Clone(variables)
	for name, matcher := range extra {
		mesh[name] = matcher
	}
	meshEntry := map[string]any{"digest": testDigest, "command": map[string]any{"policy": "exact", "argv": []string{"/app/c8s", "armtls-mesh"}}, "args": map[string]any{"policy": "exact", "argv": []string{"--platform", "snp"}}, "env": map[string]any{"policy": "match", "variables": mesh}}
	initEntry := map[string]any{"digest": nodeImageTestCDSDigest, "command": map[string]any{"policy": "any"}, "args": map[string]any{"policy": "any"}, "mounts": map[string]any{"policy": "any"}}
	seed, err := json.Marshal(map[string]any{"schema": "c8s.allowlist/v1", "workloads": map[string]any{
		"core": map[string]any{"containers": []any{component, meshEntry}},
		"init": map[string]any{"containers": []any{initEntry}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(seed)
}

const nodeImageFixtureMeshArgs = `          args: ["--platform", "snp"]`

// nodeImageEnvFixture is the collect fixture with service links off, the seed
// replaced, and env lines added to the mesh container.
func nodeImageEnvFixture(t *testing.T, seed, meshEnv string) string {
	t.Helper()
	fixture := strings.ReplaceAll(nodeImageCollectFixture(), "    spec:\n      containers:", "    spec:\n      enableServiceLinks: false\n      containers:")
	start := strings.Index(fixture, "allowlist-seed.json: '") + len("allowlist-seed.json: '")
	end := start + strings.Index(fixture[start:], "'")
	fixture = fixture[:start] + seed + fixture[end:]
	return strings.Replace(fixture, nodeImageFixtureMeshArgs, nodeImageFixtureMeshArgs+meshEnv, 1)
}

func TestNodeImageCollectMatchedEnv(t *testing.T) {
	const meshEnv = "\n          env: [{name: MODE, value: strict}, {name: POD, valueFrom: {fieldRef: {fieldPath: metadata.name}}}]"
	present, exact := map[string]any{"present": true}, func(v string) map[string]any { return map[string]any{"exact": v} }
	listed := map[string]any{"MODE": exact("strict"), "POD": present}
	with := func(name string, matcher any) map[string]any {
		out := maps.Clone(listed)
		if matcher == nil {
			delete(out, name)
		} else {
			out[name] = matcher
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		extra   map[string]any
		meshEnv string
		links   bool
		ok      bool
	}{
		{"every variable listed", listed, meshEnv, false, true},
		{"image variable pinned exact", with("LANG", exact("C.UTF-8")), meshEnv, false, true},
		{"literal pinned to another value", with("MODE", exact("lax")), meshEnv, false, false},
		{"reference pinned exact", with("POD", exact("mesh-0")), meshEnv, false, false},
		{"manifest variable not listed", with("POD", nil), meshEnv, false, false},
		{"listed variable nothing sets", with("EXTRA", present), meshEnv, false, false},
		{"kubelet-expanded literal pinned exact", with("MODE", exact("$(POD)")), "\n          env: [{name: MODE, value: $(POD)}, {name: POD, value: x}]", false, false},
		{"kubelet-expanded literal matched present", with("MODE", present), "\n          env: [{name: MODE, value: $(POD)}, {name: POD, value: x}]", false, true},
		{"runtime port pinned to another value", with("KUBERNETES_SERVICE_PORT", exact("6443")), meshEnv, false, false},
		{"envFrom", listed, meshEnv + "\n          envFrom: [{configMapRef: {name: extra}}]", false, false},
		{"optional key reference", with("POD", present), "\n          env: [{name: MODE, value: strict}, {name: POD, valueFrom: {secretKeyRef: {name: s, key: k, optional: true}}}]", false, false},
		{"service links on", listed, meshEnv, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := nodeImageEnvFixture(t, nodeImageEnvSeed(t, tc.extra), tc.meshEnv)
			if tc.links {
				input = strings.Replace(input, "enableServiceLinks: false\n      containers:\n        - name: mesh", "containers:\n        - name: mesh", 1)
			}
			_, err := collectNodeImageArtifacts([]byte(input))
			if (err == nil) != tc.ok {
				t.Fatalf("collectNodeImageArtifacts() error = %v, want ok %v", err, tc.ok)
			}
		})
	}
}
