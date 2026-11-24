//go:build !c8s_node

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	yamlv3 "gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/confidential-kubernetes/charts"
	workerprofile "github.com/confidential-dot-ai/confidential-kubernetes/images/node-guest/worker"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taconfig"
	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
)

var nodeImageTestMeshDigest = "sha256:" + strings.Repeat("d", 64)

var nodeImageTestVolumedDigest = "sha256:" + strings.Repeat("e", 64)

// floorTemplateFile is the worker image's floor template, as the image build
// reads it from the checkout.
const floorTemplateFile = "../../images/node-guest/worker/image-policy.yaml.in"

// The image build fills and bakes the template from the checkout while the
// release's render fills the one this binary embeds, so the two must be the
// same bytes.
func TestEmbeddedFloorTemplateIsTheImageBuildsFile(t *testing.T) {
	file, err := os.ReadFile(floorTemplateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(workerprofile.FloorTemplate, file) {
		t.Errorf("the embedded floor template differs from %s", floorTemplateFile)
	}
}

// nodeImageTestSetVersion is the release the stamped render publishes its
// component set under.
const nodeImageTestSetVersion = "0.43.0"

// node-image render writes what mkosi.sync installs or reads and nothing
// else: c8s-lib's nginx files and the worker chart's static pods byte for
// byte, the nginx image the cluster's router runs, a seed that boots with
// the measured floor and admits that router, and this release's component set.
func TestNodeImageRender(t *testing.T) {
	setCLIVersion(t, "v"+nodeImageTestSetVersion)
	for _, platform := range []string{"tdx", "sev-snp"} {
		t.Run(platform, func(t *testing.T) {
			out := t.TempDir()
			cmd := newNodeImageCmd()
			cmd.SetArgs([]string{
				"render", "--hardware-platform", platform, "--kube-version", "v1.36.6",
				"--image-digest", testDigest, "--image-repository", "registry.example.com/c8s-operator",
				"--armtls-mesh-image-digest", nodeImageTestMeshDigest, "--armtls-mesh-image-repository", "registry.example.com/armtls-mesh",
				"--volumed-image-digest", nodeImageTestVolumedDigest, "--volumed-image-repository", "registry.example.com/volumed",
				"--output-dir", out,
			})
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			want := map[string][]byte{}
			copied := map[string]string{
				"router-nginx": "lib/files/router-nginx",
				"static-pods":  "worker/files/static-pods",
			}
			for dir, chartDir := range copied {
				for name, body := range chartFiles(t, chartDir) {
					want[dir+"/"+name] = body
				}
			}
			got := outputFiles(t, out)
			for name, body := range want {
				if !bytes.Equal(got[name], body) {
					t.Errorf("%s differs from the chart's", name)
				}
			}
			names := slices.Sorted(maps.Keys(got))
			wantNames := slices.Sorted(maps.Keys(want))
			wantNames = append(wantNames, "allowlist-seed.json", "component-set.json", "router-image.txt")
			slices.Sort(wantNames)
			if !slices.Equal(names, wantNames) {
				t.Fatalf("node-image render wrote %v, want %v", names, wantNames)
			}

			cluster := renderTestWorkerCluster(t, platform)
			router := routerDeployment(t, cluster)
			nginx, _ := findPodContainer(router.Spec.Template.Spec.Containers, "nginx")
			routerImage := strings.TrimSpace(string(got["router-image.txt"]))
			if routerImage != nginx.Image {
				t.Errorf("router-image.txt = %q, the cluster's router runs %q", routerImage, nginx.Image)
			}

			seed := got["allowlist-seed.json"]
			testNodeImageBootstrap(t, seed, platform)
			allowlist, err := pkgallowlist.ParseJSON(seed)
			if err != nil {
				t.Fatal(err)
			}
			var labelled []string
			for name, workload := range allowlist.Workloads {
				// The router's and volumed's entries declare whole pods, which
				// carry no one image label.
				if !strings.HasPrefix(name, "c8s-router-") && !strings.HasPrefix(name, "c8s-volumed-") {
					labelled = append(labelled, workload.Label)
				}
			}
			slices.Sort(labelled)
			wantSeeded := []string{
				"registry.example.com/armtls-mesh@" + nodeImageTestMeshDigest,
				"registry.example.com/c8s-operator@" + testDigest,
				routerImage,
			}
			slices.Sort(wantSeeded)
			if !slices.Equal(labelled, wantSeeded) {
				t.Errorf("seeded images = %v, want %v", labelled, wantSeeded)
			}
			deployment, err := yaml.Marshal(cluster[routerDeploymentKey].Object)
			if err != nil {
				t.Fatal(err)
			}
			assertRouterDeclaresItsHostPorts(t, allowlist.Workloads[routerEntryName(t, cluster)], deployment)
			assertLocalPathDenied(t, allowlist)
			assertComponentSet(t, got["component-set.json"], routerEntryName(t, cluster), allowlist)
		})
	}
}

// assertComponentSet checks the set the render publishes: the release's
// version, the sidecars' images as this render pinned them, the router entry
// named name as the seed carries it, and volumed's as the node service.
func assertComponentSet(t *testing.T, file []byte, name string, seed *pkgallowlist.Allowlist) {
	t.Helper()
	doc, err := pkgallowlist.ParseJSON(file)
	if err != nil {
		t.Fatalf("component-set.json does not parse: %v", err)
	}
	set, published := doc.Components[nodeImageTestSetVersion]
	if !published || len(doc.Workloads) != 0 {
		t.Fatalf("component-set.json holds the sets %v and %d workload entries, want the release's set alone",
			slices.Sorted(maps.Keys(doc.Components)), len(doc.Workloads))
	}
	images := map[string]string{}
	for _, entry := range set.Entries {
		for _, c := range slices.Concat(entry.InitContainers, entry.Containers) {
			images[c.Digest.String()] = c.Image
		}
	}
	for digest, want := range map[string]string{
		testDigest:                 "registry.example.com/c8s-operator@" + testDigest,
		nodeImageTestMeshDigest:    "registry.example.com/armtls-mesh@" + nodeImageTestMeshDigest,
		nodeImageTestVolumedDigest: "registry.example.com/volumed@" + nodeImageTestVolumedDigest,
	} {
		if images[digest] != want {
			t.Errorf("the set labels %s %q, want %q", digest, images[digest], want)
		}
	}
	if router := seed.Workloads[name]; !reflect.DeepEqual(set.Entries[name], router) {
		t.Errorf("the set's %s entry =\n%+v\nwant the seed's\n%+v", name, set.Entries[name], router)
	}
	volumedName, volumed := seededEntry(t, seed, "c8s-volumed-")
	volumed.NodeService = true
	if !reflect.DeepEqual(set.Entries[volumedName], volumed) {
		t.Errorf("the set's %s entry =\n%+v\nwant the seed's as a node service\n%+v",
			volumedName, set.Entries[volumedName], volumed)
	}
}

// A build that is no release publishes no component set: a set is keyed by
// the release that built it. The seed is written either way.
func TestNodeImageRenderPublishesNoSetForADevBuild(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm CLI not found")
	}
	setCLIVersion(t, "dev")
	out := t.TempDir()
	cmd := newNodeImageCmd()
	var log bytes.Buffer
	cmd.SetErr(&log)
	cmd.SetArgs([]string{
		"render", "--hardware-platform", "tdx", "--kube-version", "v1.36.6",
		"--image-digest", testDigest, "--armtls-mesh-image-digest", nodeImageTestMeshDigest,
		"--volumed-image-digest", nodeImageTestVolumedDigest,
		"--output-dir", out,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "component-set.json")); !os.IsNotExist(err) {
		t.Errorf("stat component-set.json = %v, want it unwritten", err)
	}
	if _, err := os.Stat(filepath.Join(out, "allowlist-seed.json")); err != nil {
		t.Errorf("the render wrote no seed: %v", err)
	}
	if !strings.Contains(log.String(), `"dev" is no release tag`) {
		t.Errorf("the render said %q, want it name the version it refuses the set over", log.String())
	}
}

// A set is keyed by the release that built it, so every release tag keys one,
// a beta's included, and nothing else does.
func TestComponentSetVersion(t *testing.T) {
	for _, tc := range []struct {
		build, want string
	}{
		{"v0.43.0", "0.43.0"},
		{"v0.44.0-beta.1", "0.44.0-beta.1"},
		{"dev", ""},
		{"v0.43", ""},
		{"v0.43.0+2026", ""},
		{"0.43.0", ""},
	} {
		t.Run(tc.build, func(t *testing.T) {
			setCLIVersion(t, tc.build)
			got, err := componentSetVersion()
			if tc.want == "" {
				if err == nil {
					t.Fatalf("componentSetVersion = %q, want a refusal", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("componentSetVersion = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

// chartFiles are the files of a directory of the embedded charts, by name.
func chartFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := fs.ReadDir(charts.FS, dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, e := range entries {
		body, err := fs.ReadFile(charts.FS, path.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = body
	}
	return files
}

// outputFiles are the files under dir, by slash-separated relative path.
func outputFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = body
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// findPodContainer is the named container of a pod spec's list.
func findPodContainer(containers []corev1.Container, name string) (corev1.Container, bool) {
	i := slices.IndexFunc(containers, func(c corev1.Container) bool { return c.Name == name })
	if i < 0 {
		return corev1.Container{}, false
	}
	return containers[i], true
}

// The seeded router entry must declare what the baked router pod publishes.
func assertRouterDeclaresItsHostPorts(t *testing.T, entry pkgallowlist.Workload, deployment []byte) {
	t.Helper()
	var router appsv1.Deployment
	if err := yaml.Unmarshal(deployment, &router); err != nil {
		t.Fatal(err)
	}
	pod := router.Spec.Template.Spec
	var published []pkgallowlist.HostPort
	for _, c := range slices.Concat(pod.InitContainers, pod.Containers) {
		for _, p := range c.Ports {
			if p.HostPort == 0 {
				continue
			}
			// The pod spec's default, which the template writes out.
			protocol := string(corev1.ProtocolTCP)
			if p.Protocol != "" {
				protocol = string(p.Protocol)
			}
			published = append(published, pkgallowlist.HostPort{Protocol: protocol, HostPort: int(p.HostPort), ContainerPort: int(p.ContainerPort)})
		}
	}
	slices.SortFunc(published, func(a, b pkgallowlist.HostPort) int {
		return int(a.HostPort) - int(b.HostPort)
	})
	if declared := []pkgallowlist.HostPort(entry.HostPorts); !slices.Equal(declared, published) {
		t.Errorf("the baked router entry declares %+v, its pod publishes %+v", declared, published)
	}
}

// nodeImageDocumentKey is one rendered object's identity: a cluster-scoped
// object has no namespace, which leaves the leading separator.
func nodeImageDocumentKey(namespace, kind, name string) string {
	return namespace + "/" + kind + "/" + name
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
		// The identity Kubernetes gives an object, so one document rendered
		// into two namespaces is two entries (nodeImageDocumentKey).
		key := nodeImageDocumentKey(object.Metadata.Namespace, object.Kind, object.Metadata.Name)
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
		{"missing mesh digest", func(c *nodeImageRenderConfig) { c.armtlsMeshImageDigest = "" }},
		{"tagged mesh repository", func(c *nodeImageRenderConfig) { c.armtlsMeshImageRepository = "example.com/armtls-mesh:main" }},
		{"invalid mesh repository", func(c *nodeImageRenderConfig) { c.armtlsMeshImageRepository = "invalid repo" }},
		{"missing volumed digest", func(c *nodeImageRenderConfig) { c.volumedImageDigest = "" }},
		{"tagged volumed repository", func(c *nodeImageRenderConfig) { c.volumedImageRepository = "example.com/volumed:main" }},
		{"tag as digest", func(c *nodeImageRenderConfig) { c.imageDigest = "main" }},
		{"tagged repository", func(c *nodeImageRenderConfig) { c.imageRepository += ":main" }},
		{"missing output", func(c *nodeImageRenderConfig) { c.outputDir = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBin(t)
			f.tool(t, "helm", "exit 99")
			cfg := nodeImageRenderConfig{
				platform:              "tdx",
				kubeVersion:           "v1.34.5",
				imageDigest:           testDigest,
				imageRepository:       "ghcr.io/confidential-dot-ai/c8s-operator",
				armtlsMeshImageDigest: nodeImageTestMeshDigest,
				volumedImageDigest:    nodeImageTestVolumedDigest,
				outputDir:             t.TempDir(),
			}
			tc.change(&cfg)
			if err := renderNodeImage(context.Background(), cfg, io.Discard); err == nil {
				t.Fatal("accepted invalid build inputs")
			}
			if calls := f.calls(t); len(calls) != 0 {
				t.Fatalf("called Helm before input validation: %v", calls)
			}
		})
	}
}

// bootstrapTAPin is the pin `c8s ta config new` writes, built the way that
// command builds it: this cluster's Trust Authority configuration, bound to the launch
// digests of the image its VM boots.
func bootstrapTAPin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifest := filepath.Join(dir, "cds-manifest.json")
	body := fmt.Sprintf(`{"snp_variants":[{"smp":4,"measurement":{"algorithm":"sha384","snp_launch_digest":%q}}]}`,
		strings.Repeat("50", refvalues.DigestSize))
	if err := os.WriteFile(manifest, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	operatorKeys, err := operatorauth.ParseKeyBundle([]byte(testOperatorPublicKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	_, pin, err := taconfig.Build(taconfig.Inputs{
		ClusterID:     "bootstrap",
		OperatorKeys:  operatorKeys,
		ComponentSeed: []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`),
		Nodes: []byte(`{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":"` +
			strings.Repeat("ab", refvalues.DigestSize) + `"}]}`),
		NodeCIDRs:    []string{"192.0.2.0/24"},
		ClusterCIDRs: []string{"10.52.0.0/16", "10.53.0.0/16"},
		LeafDNSNames: []string{"c8s.local"},
		ManifestPath: manifest,
		Family:       teetypes.FamilySNP,
		VCPUs:        []int{4},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(pin)
}

// Exercise the actual build-to-boot contract, including all system-floor and
// chart entries. Unit fixtures alone cannot catch collisions between the two.
func testNodeImageBootstrap(t *testing.T, seed []byte, platform string) {
	t.Helper()
	floor, err := os.ReadFile(floorTemplateFile)
	if err != nil {
		t.Fatal(err)
	}
	// The placeholders mkosi.sync substitutes at image build.
	for placeholder, value := range map[string]string{
		"@PLATFORM@":        map[string]string{"tdx": "tdx", "sev-snp": "snp"}[platform],
		"@MESH_REPO@":       "ghcr.io/confidential-dot-ai/armtls-mesh",
		"@MESH_DIGEST@":     "sha256:" + strings.Repeat("1b", 32),
		"@OPERATOR_REPO@":   "ghcr.io/confidential-dot-ai/c8s-operator",
		"@OPERATOR_DIGEST@": "sha256:" + strings.Repeat("2c", 32),
		"@ROUTER_REPO@":     "docker.io/nginx/nginx-unprivileged",
		"@ROUTER_DIGEST@":   "sha256:" + strings.Repeat("3d", 32),
	} {
		floor = bytes.ReplaceAll(floor, []byte(placeholder), []byte(value))
	}
	components, err := pkgallowlist.ParseJSON(seed)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for name, data := range map[string][]byte{
		"usr/lib/c8s/image-policy.yaml":   floor,
		"usr/lib/c8s/allowlist-seed.json": seed,
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ta := cmdsutil.TA{Address: "192.0.2.50:8443", Measurements: bootstrapTAPin(t)}
	if err := nodeservices.Prepare(root, nodeservices.FloorInputs{TA: ta}); err != nil {
		t.Fatalf("actual chart seed and measured NRI floor cannot boot: %v", err)
	}
	prepared, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// Read as the plugin reads it: YAML-only fields (role, node,
	// serviceLinks) do not survive a JSON round trip.
	var policy struct {
		Allowlist struct {
			Base pkgallowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yamlv3.Unmarshal(prepared, &policy); err != nil {
		t.Fatal(err)
	}
	if err := policy.Allowlist.Base.Normalize(); err != nil {
		t.Fatal(err)
	}
	assertLocalPathDenied(t, &policy.Allowlist.Base)
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
	// The node exempts host binds only for a launch a base entry pins, so
	// every seed container that names a host mount must pin its whole launch.
	for name, workload := range components.Workloads {
		for _, c := range slices.Concat(workload.InitContainers, workload.Containers) {
			if slices.ContainsFunc(c.Mounts.Rules, func(r pkgallowlist.MountRule) bool { return r.Kind == pkgallowlist.MountHost }) && !c.LaunchPinned() {
				t.Errorf("seed workload %s holds a host mount without pinning its launch: %+v", name, c)
			}
		}
	}
}

func assertLocalPathDenied(t *testing.T, policy *pkgallowlist.Allowlist) {
	t.Helper()
	index := policy.BuildIndex()
	for _, tc := range []struct {
		digest string
		argv   []string
	}{
		{"sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d", []string{"/bin/sh", "/script/setup", "-p", "/arbitrary-host-root"}},
		{"sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d", []string{"/bin/sh", "/script/teardown", "-p", "/arbitrary-host-root"}},
		{"sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f", []string{"/bin/sh", "-c", "id"}},
	} {
		if index.AdmitsContainer(pkgallowlist.RunningContainer{Digest: tc.digest, Argv: tc.argv, Mounts: []pkgallowlist.ObservedMount{
			{Destination: "/script", Source: "/var/lib/kubelet/pods/controlled/volumes/kubernetes.io~configmap/script", Class: pkgallowlist.MountData, Storage: pkgallowlist.MountUnknown, ReadOnly: true},
			{Destination: "/arbitrary-host-root", Source: "/", Class: pkgallowlist.MountHost, Storage: pkgallowlist.MountUnknown},
		}}) {
			t.Errorf("policy admits removed local-path container %s: %v", tc.digest, tc.argv)
		}
	}
}
