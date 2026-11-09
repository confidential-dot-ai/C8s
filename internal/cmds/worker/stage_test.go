package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// bakedFloor is a worker image's NRI config: staging completes its mesh
// policy with the cluster ranges, resolver and credential role, and its
// static pod's argv with this worker's values.
const bakedFloor = `platform: sev-snp
workload_claims:
  socket_dir: /run/nri-image-policy
allowlist:
  node_tcb: true
  base:
    schema: c8s.allowlist/v1
    workloads:
      kube-proxy:
        initContainers:
          - digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            command: {policy: exact, argv: [wait-for-node]}
            args: {policy: exact, argv: ["--node=${NODE_NAME}"]}
            mounts: {policy: any}
        containers:
          - digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            command: {policy: exact, argv: [kube-proxy]}
            args:
              policy: exact
              argv:
                - --cluster-cidr=${POD_CIDR}
                - --hostname-override=${NODE_NAME}
                - --kubeconfig=/var/lib/kubelet/kubeconfig
            mounts: {policy: any}
      c8s-router-0123456789ab:
        hostPorts:
          - {protocol: TCP, hostPort: 443, containerPort: 8443}
        containers:
          - digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
            command: {policy: exact, argv: [/router]}
            args: {policy: exact, argv: [--operator-keys-file=/run/c8s-node/operator-pubkey]}
            mounts:
              policy: exact
              rules:
                - {destination: /run/c8s-node, kind: host, source: /run/c8s-node, readOnly: true}
            env: {policy: exact, values: {PATH: /bin}}
  pull:
    url: https://127.0.0.1:30808
    timeout: 30s
    attestation_api_url: http://127.0.0.1:8400
    measure_policies: true
policy:
  mode: fail-closed
  fatal_existing: true
  boot_marker_path: /run/nri-image-policy/registered
mesh:
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
worker: true
`

// kubeProxyTemplate is the static pod bakedFloor admits.
const kubeProxyTemplate = `apiVersion: v1
kind: Pod
metadata:
  name: kube-proxy
  namespace: kube-system
spec:
  hostNetwork: true
  initContainers:
    - name: wait
      image: docker.io/library/wait@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      command: [wait-for-node]
      args: ["--node=${NODE_NAME}"]
  containers:
    - name: kube-proxy
      image: registry.k8s.io/kube-proxy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      command: [kube-proxy]
      args:
        - --cluster-cidr=${POD_CIDR}
        - --hostname-override=${NODE_NAME}
        - --kubeconfig=/var/lib/kubelet/kubeconfig
`

// workerRoot is a worker's filesystem holding its marker and baked files.
func workerRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range map[string]string{
		"worker-image":                       "",
		"image-policy.yaml":                  bakedFloor,
		"allowlist-seed.json":                `{"schema":"c8s.allowlist/v1","workloads":{}}`,
		"worker/static-pods/kube-proxy.yaml": kubeProxyTemplate,
	} {
		path := filepath.Join(root, "/usr/lib/c8s", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stubPrimaryIPv4(t, "10.0.0.7")
	return root
}

// stubPrimaryIPv4 places the host on addr, the one seam over its routes.
func stubPrimaryIPv4(t *testing.T, addr string) {
	t.Helper()
	old := cmdsutil.PrimaryIPv4
	t.Cleanup(func() { cmdsutil.PrimaryIPv4 = old })
	cmdsutil.PrimaryIPv4 = func() (netip.Addr, error) { return netip.MustParseAddr(addr), nil }
}

// tokenFile is the bootstrap token beside the document on the launch disk.
func tokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(path, []byte(testToken+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	return path
}

// workerDocumentBytes is a worker document whose ranges are not the node
// image's.
func workerDocumentBytes(t *testing.T) []byte {
	t.Helper()
	doc := testDocument(t)
	doc.Kubernetes.PodCIDR = "10.100.0.0/16"
	doc.Kubernetes.ServiceCIDR = "10.200.0.0/16"
	doc.Kubernetes.ClusterDNS = "10.200.0.10"
	doc.CDS.Chain = "3:" + strings.Repeat("ab", 32)
	return marshalDocument(t, doc)
}

// stagedDocument is the launch file the initrd staged.
func stagedDocument(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "launch-file")
	if err := os.WriteFile(path, data, 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

// launchedWith serves an SEV-SNP attestation API whose verified self-report
// binds this worker's launch to launchFile.
func launchedWith(t *testing.T, launchFile []byte) string {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformSNP)
	verdict := mockapi.PassingVerdict("")
	hostData := sha256.Sum256(launchFile)
	verdict.Claims.InitData = hostData[:]
	stub.SetVerdict(verdict)
	return stub.URL()
}

// stagedOutputs is every file under root's outputs, by path, with its mode.
func stagedOutputs(t *testing.T, root string) map[string]string {
	t.Helper()
	outputs := map[string]string{}
	for _, dir := range []string{nodeservices.PublicDir, "/etc/nri", "/run/nri-image-policy", kubernetesDir} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || !entry.Type().IsRegular() {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			outputs[strings.TrimPrefix(path, root)] = info.Mode().Perm().String() + "\n" + string(data)
			return err
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	return outputs
}

type stagedRole struct {
	Name string `yaml:"name"`
	Port uint16 `yaml:"port"`
}

func TestStagePublishesTheDocumentsFloor(t *testing.T) {
	data := workerDocumentBytes(t)
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	root := workerRoot(t)
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data)); err != nil {
		t.Fatal(err)
	}

	policy, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var floor struct {
		Allowlist struct {
			Pull struct {
				URL   string `yaml:"url"`
				Chain string `yaml:"cds_chain"`
			} `yaml:"pull"`
		} `yaml:"allowlist"`
		Mesh struct {
			ClusterRanges []string     `yaml:"cluster_ranges"`
			Resolver      string       `yaml:"resolver"`
			Roles         []stagedRole `yaml:"roles"`
		} `yaml:"mesh"`
	}
	if err := yaml.Unmarshal(policy, &floor); err != nil {
		t.Fatal(err)
	}
	if got, want := floor.Mesh.ClusterRanges, []string{"10.100.0.0/16", "10.200.0.0/16"}; !slices.Equal(got, want) {
		t.Errorf("cluster_ranges = %v, want the document's %v", got, want)
	}
	if floor.Mesh.Resolver != doc.Kubernetes.ClusterDNS {
		t.Errorf("resolver = %q, want the document's cluster DNS %s", floor.Mesh.Resolver, doc.Kubernetes.ClusterDNS)
	}
	if got, err := os.ReadFile(filepath.Join(root, "run/nri-image-policy/node-ip")); err != nil || string(got) != "10.0.0.7\n" {
		t.Errorf("node-ip = %q, %v; want this host's primary address", got, err)
	}
	pull := floor.Allowlist.Pull
	if pull.URL != "https://cds.acme.example:8443" || pull.Chain != doc.CDS.Chain {
		t.Errorf("pull = %+v, want the document's CDS and chain pin %s", pull, doc.CDS.Chain)
	}
	roles := floor.Mesh.Roles
	if i := slices.IndexFunc(roles, func(r stagedRole) bool { return r.Name == nriimagepolicy.CredentialRole }); i < 0 || roles[i].Port != 8443 {
		t.Errorf("mesh roles = %+v, want the credential role on the document's CDS port", roles)
	}

	pins, err := refvalues.Parse([]byte(doc.CDS.Measurements))
	if err != nil {
		t.Fatal(err)
	}
	wantPin, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, nodeservices.PublicDir, "cds.json")); err != nil || string(got) != string(wantPin) {
		t.Errorf("cds.json = %s, %v; want the document's CDS pin", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, nodeservices.PublicDir, "router/hostnames")); err != nil || string(got) != "api.acme.example\n" {
		t.Errorf("router/hostnames = %q, %v; want the document's router hostname", got, err)
	}
	cds, err := doc.CDS.Parse()
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := cdsconfig.Parse(cds.LaunchFile)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, nodeservices.PublicDir, "operator-pubkey")); err != nil || !bytes.Equal(got, pinned.OperatorKeys.PEM()) {
		t.Errorf("operator-pubkey = %q, %v; want the pinned CDS configuration's operator keys", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, nodeservices.PublicDir, "tls-san")); err != nil || string(got) != doc.TLSSAN+"\n" {
		t.Errorf("tls-san = %q, %v; want the document's tlsSAN", got, err)
	}
	var published []string
	public := filepath.Join(root, nodeservices.PublicDir)
	if err := filepath.WalkDir(public, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			published = append(published, strings.TrimPrefix(path, public+"/"))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	names, err := stagedPublicNames()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := slices.Sorted(slices.Values(published)), slices.Sorted(slices.Values(names)); !slices.Equal(got, want) {
		t.Errorf("published %v, want the files stagedPublicNames lists, %v", got, want)
	}
}

func TestStageRerunIsIdempotent(t *testing.T) {
	data := workerDocumentBytes(t)
	root, path, api := workerRoot(t), stagedDocument(t, data), launchedWith(t, data)
	if err := stage(context.Background(), root, path, tokenFile(t), api); err != nil {
		t.Fatal(err)
	}
	first := stagedOutputs(t, root)
	if err := stage(context.Background(), root, path, tokenFile(t), api); err != nil {
		t.Fatal(err)
	}
	if second := stagedOutputs(t, root); len(first) == 0 || !maps.Equal(first, second) {
		t.Fatalf("rerun outputs = %v, want the first run's %v", second, first)
	}
}

// A document the launch did not bind, or one that does not parse, leaves no
// output behind, including those of an earlier run.
func TestStageFailsClosed(t *testing.T) {
	good := workerDocumentBytes(t)
	unparsable := []byte("schemaVersion: c8s-worker/v1\nunknown: field\n")
	for _, tc := range []struct {
		name     string
		staged   []byte
		launched []byte
		want     string
	}{
		{"bytes the launch did not bind", append(slices.Clone(good), "# swapped\n"...), good, "is not the document this worker launched with"},
		{"a bound document that does not parse", unparsable, unparsable, "worker document"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := workerRoot(t)
			if err := stage(context.Background(), root, stagedDocument(t, good), tokenFile(t), launchedWith(t, good)); err != nil {
				t.Fatal(err)
			}
			err := stage(context.Background(), root, stagedDocument(t, tc.staged), tokenFile(t), launchedWith(t, tc.launched))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stage = %v, want a refusal naming %q", err, tc.want)
			}
			if left := stagedOutputs(t, root); len(left) != 0 {
				t.Fatalf("a refused document left outputs behind: %v", slices.Sorted(maps.Keys(left)))
			}
		})
	}
}

// A preparation that fails after publishing some outputs takes them back.
func TestStageRemovesAFailedPreparationsOutputs(t *testing.T) {
	data := workerDocumentBytes(t)
	root := workerRoot(t)
	// A dangling conf.d fails the floor's write, after the public outputs.
	if err := os.MkdirAll(filepath.Join(root, "etc/nri"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(root, "etc/nri/conf.d")); err != nil {
		t.Fatal(err)
	}
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data)); err == nil {
		t.Fatal("staged a floor it could not write")
	}
	if left := stagedOutputs(t, root); len(left) != 0 {
		t.Fatalf("a failed preparation left outputs behind: %v", slices.Sorted(maps.Keys(left)))
	}
}

// A worker without a router block still publishes what the router reads: it
// fronts the cluster in the CDS's mode, under the document's tlsSAN.
func TestStagePublishesTheRoutersFilesWithoutARouterBlock(t *testing.T) {
	doc := testDocument(t)
	doc.Router = nil
	data := marshalDocument(t, doc)
	root := workerRoot(t)
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data)); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(root, nodeservices.PublicDir)
	for name, want := range map[string]string{"router/front-door-mode": "cds\n", "router/hostnames": "", "tls-san": "c8s.acme.example\n"} {
		if got, err := os.ReadFile(filepath.Join(public, name)); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if got, err := os.ReadFile(filepath.Join(public, "operator-pubkey")); err != nil || !strings.Contains(string(got), "PUBLIC KEY") {
		t.Errorf("operator-pubkey = %q, %v; want the pinned operator keys", got, err)
	}
}

// A floor the plugin would refuse, or run under a server's rules, stops the
// worker before the kubelet's inputs, and leaves no output behind.
func TestStageRefusesAFloorThePluginWouldNotRunAsAWorkers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through directory permissions")
	}
	data := workerDocumentBytes(t)
	for _, tc := range []struct {
		name, old, new, want string
	}{
		{"a misspelt worker key", "\nworker: true\n", "\nworkers: true\n", "field workers not found"},
		{"no worker key", "\nworker: true\n", "\n", "worker: true"},
		{"a mesh-exempt namespace", "\nmesh:\n", "\nmesh:\n  exempt_namespaces: [kube-system]\n", "mesh.exempt_namespaces"},
		{"no policy measurement", "    measure_policies: true\n", "", "allowlist.pull.measure_policies"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := workerRoot(t)
			floor := strings.Replace(bakedFloor, tc.old, tc.new, 1)
			if floor == bakedFloor {
				t.Fatalf("bakedFloor holds no %q", tc.old)
			}
			if err := os.WriteFile(filepath.Join(root, "usr/lib/c8s/image-policy.yaml"), []byte(floor), 0o644); err != nil {
				t.Fatal(err)
			}
			// /run/kubernetes cannot be made, so a refusal naming the floor
			// shows stage checked it before writing the kubelet's inputs.
			run := filepath.Join(root, "run")
			for _, dir := range []string{nodeservices.PublicDir, "/run/nri-image-policy"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(run, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(run, 0o755) })
			err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stage = %v, want the staged floor refused for %q", err, tc.want)
			}
			if left := stagedOutputs(t, root); len(left) != 0 {
				t.Fatalf("a refused floor left outputs behind: %v", slices.Sorted(maps.Keys(left)))
			}
		})
	}
}

// Off a worker image, staging refuses before it clears another role's
// outputs.
func TestStageTouchesNothingOffAWorkerImage(t *testing.T) {
	data := workerDocumentBytes(t)
	root := workerRoot(t)
	if err := os.Remove(filepath.Join(root, "usr/lib/c8s/worker-image")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{nodeservices.PublicDir + "/peers.json", nodeservices.PublicDir + "/operator-pubkey", "/etc/nri/conf.d/image-policy.yaml"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("a server's "+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := stagedOutputs(t, root)
	err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data))
	if err == nil || !strings.Contains(err.Error(), "only on a worker image") {
		t.Fatalf("stage = %v, want a refusal off a worker image", err)
	}
	if after := stagedOutputs(t, root); !maps.Equal(before, after) {
		t.Fatalf("outputs = %v, want them untouched: %v", after, before)
	}
}

// On TDX, a worker whose NRI plugin has since extended RTMR[3] with a policy
// in its journal stages again.
func TestStageReplaysTheMeasuredPolicyJournalOnTDX(t *testing.T) {
	data := workerDocumentBytes(t)
	root := workerRoot(t)
	policy := "sha256:" + strings.Repeat("1", 64)
	journal := filepath.Join(root, armtls.NodeJournal)
	if err := os.MkdirAll(filepath.Dir(journal), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, []byte(policy+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := runtimemeasure.LaunchFileDigest(teetypes.FamilyTDX, data)
	if err != nil {
		t.Fatal(err)
	}
	rtmr3 := runtimemeasure.FromDigestsSeeded(runtimemeasure.Extend(runtimemeasure.Zero, [runtimemeasure.Size]byte(digest)), []string{policy})
	stub := mockapi.New(t)
	stub.SetPlatform(teetypes.PlatformTDX)
	verdict := mockapi.PassingVerdict("")
	verdict.Claims.PlatformData = map[string]any{"rtmr_3": hex.EncodeToString(rtmr3[:])}
	stub.SetVerdict(verdict)
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), stub.URL()); err != nil {
		t.Fatal(err)
	}
}

// A journal staging cannot read is reported as such, not as another document.
func TestStageNamesAnUnreadableJournal(t *testing.T) {
	data := workerDocumentBytes(t)
	root := workerRoot(t)
	if err := os.MkdirAll(filepath.Join(root, armtls.NodeJournal), 0o755); err != nil {
		t.Fatal(err)
	}
	err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data))
	if err == nil || !strings.Contains(err.Error(), "read measured policies") || strings.Contains(err.Error(), "not the document") {
		t.Fatalf("stage = %v, want the journal read named as the failure", err)
	}
}

// An attestation API staging cannot reach is reported as unreachable, not as
// another document.
func TestStageNamesAnUnreachableAttestationAPI(t *testing.T) {
	data := workerDocumentBytes(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := stage(ctx, workerRoot(t), stagedDocument(t, data), tokenFile(t), "http://127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "not ready") || strings.Contains(err.Error(), "not the document") {
		t.Fatalf("stage = %v, want the attestation API reported unreachable", err)
	}
}

func TestStageWritesTheKubeletsInputs(t *testing.T) {
	data := workerDocumentBytes(t)
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	root := workerRoot(t)
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data)); err != nil {
		t.Fatal(err)
	}
	outputs := stagedOutputs(t, root)
	if got, want := outputs[kubeletEnvPath], "-rw-r--r--\nNODE_NAME=n-10-0-0-7\nNODE_IP=10.0.0.7\n"; got != want {
		t.Errorf("kubelet.env = %q, want %q", got, want)
	}
	mode, bootstrap, _ := strings.Cut(outputs[bootstrapKubeconfigPath], "\n")
	config, err := clientcmd.Load([]byte(bootstrap))
	if err != nil {
		t.Fatal(err)
	}
	cluster, user := config.Clusters["cluster"], config.AuthInfos["kubelet-bootstrap"]
	if mode != "-rw-------" || cluster == nil || user == nil || cluster.Server != "https://"+doc.Kubernetes.APIServer || string(cluster.CertificateAuthorityData) != doc.Kubernetes.CACertificate || user.Token != testToken {
		t.Errorf("bootstrap kubeconfig mode %s; want 0600, the document's API server and CA, and the token:\n%s", mode, bootstrap)
	}
	mode, kubelet, _ := strings.Cut(outputs[kubeletConfigPath], "\n")
	var got kubeletConfiguration
	if err := k8syaml.Unmarshal([]byte(kubelet), &got); err != nil {
		t.Fatal(err)
	}
	if mode != "-rw-r--r--" || !slices.Equal(got.ClusterDNS, []string{doc.Kubernetes.ClusterDNS}) {
		t.Errorf("kubelet config mode %s, clusterDNS %v; want 0644 and the document's %s", mode, got.ClusterDNS, doc.Kubernetes.ClusterDNS)
	}
}

func TestStageUsesTheNodeAddressConsistently(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		ip       string
		name     string
	}{
		{
			scenario: "first-address",
			ip:       "10.0.0.7",
			name:     "n-10-0-0-7",
		},
		{
			scenario: "second-address",
			ip:       "10.0.0.8",
			name:     "n-10-0-0-8",
		},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			root := workerRoot(t)
			stubPrimaryIPv4(t, tc.ip)
			data := workerDocumentBytes(t)
			if err := stage(
				context.Background(),
				root,
				stagedDocument(t, data),
				tokenFile(t),
				launchedWith(t, data),
			); err != nil {
				t.Fatal(err)
			}
			outputs := stagedOutputs(t, root)
			if got, want := outputs[kubeletEnvPath], "-rw-r--r--\nNODE_NAME="+tc.name+"\nNODE_IP="+tc.ip+"\n"; got != want {
				t.Errorf("kubelet.env = %q, want %q", got, want)
			}
			if floor := outputs["/etc/nri/conf.d/image-policy.yaml"]; !strings.Contains(floor, "--hostname-override="+tc.name) {
				t.Errorf("NRI floor does not use node name %s", tc.name)
			}
			if pod := outputs[staticPodPath+"/kube-proxy.yaml"]; !strings.Contains(pod, "--hostname-override="+tc.name) {
				t.Errorf("kube-proxy static pod does not use node name %s", tc.name)
			}
			if got := outputs["/run/nri-image-policy/node-ip"]; !strings.HasSuffix(got, "\n"+tc.ip+"\n") {
				t.Errorf("node-ip = %q, want %s", got, tc.ip)
			}
		})
	}
}

func TestStageResolvesTheAddressOnce(t *testing.T) {
	root := workerRoot(t)
	calls := 0
	cmdsutil.PrimaryIPv4 = func() (netip.Addr, error) {
		calls++
		if calls > 1 {
			return netip.Addr{}, errors.New("address selected more than once")
		}
		return netip.MustParseAddr("10.0.0.7"), nil
	}
	data := workerDocumentBytes(t)
	if err := stage(
		context.Background(),
		root,
		stagedDocument(t, data),
		tokenFile(t),
		launchedWith(t, data),
	); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("address lookups = %d, want 1", calls)
	}
	if got := stagedOutputs(t, root)[kubeletEnvPath]; !strings.Contains(got, "NODE_NAME=n-10-0-0-7\nNODE_IP=10.0.0.7\n") {
		t.Fatalf("kubelet.env = %q", got)
	}
}

func TestStageClearsOutputsWhenAddressSelectionFails(t *testing.T) {
	root := workerRoot(t)
	data := workerDocumentBytes(t)
	document, token, api := stagedDocument(t, data), tokenFile(t), launchedWith(t, data)
	if err := stage(context.Background(), root, document, token, api); err != nil {
		t.Fatal(err)
	}
	cmdsutil.PrimaryIPv4 = func() (netip.Addr, error) {
		return netip.Addr{}, errors.New("no address")
	}
	if err := stage(context.Background(), root, document, token, api); err == nil || !strings.Contains(err.Error(), "no address") {
		t.Fatalf("stage = %v, want address selection error", err)
	}
	if left := stagedOutputs(t, root); len(left) != 0 {
		t.Fatalf("failed address selection left outputs: %v", slices.Sorted(maps.Keys(left)))
	}
}

func TestStageRefusesInvalidSelectedAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr netip.Addr
	}{
		{
			name: "unset",
			addr: netip.Addr{},
		},
		{
			name: "ipv6",
			addr: netip.MustParseAddr("2001:db8::1"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := workerRoot(t)
			data := workerDocumentBytes(t)
			document, token, api := stagedDocument(t, data), tokenFile(t), launchedWith(t, data)
			if err := stage(context.Background(), root, document, token, api); err != nil {
				t.Fatal(err)
			}
			cmdsutil.PrimaryIPv4 = func() (netip.Addr, error) { return tc.addr, nil }
			if err := stage(context.Background(), root, document, token, api); err == nil {
				t.Fatal("stage accepted a non-IPv4 address")
			}
			if left := stagedOutputs(t, root); len(left) != 0 {
				t.Fatalf("invalid address left outputs: %v", slices.Sorted(maps.Keys(left)))
			}
		})
	}
}

// stagedBase is the measured base of the floor stage wrote under root.
func stagedBase(t *testing.T, root string) *allowlist.Index {
	t.Helper()
	return (&allowlist.Allowlist{Workloads: stagedWorkloads(t, root)}).BuildIndex()
}

// stagedWorkloads are the base entries of the floor stage wrote under root.
func stagedWorkloads(t *testing.T, root string) map[string]allowlist.Workload {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var floor struct {
		Allowlist struct {
			Base allowlist.Allowlist `yaml:"base"`
		} `yaml:"allowlist"`
	}
	if err := yaml.Unmarshal(data, &floor); err != nil {
		t.Fatal(err)
	}
	if err := floor.Allowlist.Base.Normalize(); err != nil {
		t.Fatal(err)
	}
	return floor.Allowlist.Base.Workloads
}

// launches are the digest and argv of every container of the rendered static
// pods, by pod file and container name.
func launches(t *testing.T, pods []fileutil.NewFile) map[string]allowlist.RunningContainer {
	t.Helper()
	running := map[string]allowlist.RunningContainer{}
	for _, file := range pods {
		var pod corev1.Pod
		if err := k8syaml.UnmarshalStrict(file.Data, &pod); err != nil {
			t.Fatal(err)
		}
		for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
			_, digest, _ := strings.Cut(c.Image, "@")
			running[file.Name+"/"+c.Name] = allowlist.RunningContainer{
				Digest: digest,
				Argv:   append(slices.Clone(c.Command), c.Args...),
				Mounts: []allowlist.ObservedMount{},
			}
		}
	}
	if len(running) == 0 {
		t.Fatal("the rendered static pods hold no container")
	}
	return running
}

// The floor a worker stages admits the static pods it renders, and only with
// this boot's values.
func TestStagedFloorAdmitsOnlyThisWorkersStaticPods(t *testing.T) {
	data := workerDocumentBytes(t)
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	root := workerRoot(t)
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data)); err != nil {
		t.Fatal(err)
	}
	floor := stagedBase(t, root)
	var rendered []fileutil.NewFile
	for path, output := range stagedOutputs(t, root) {
		if name, ok := strings.CutPrefix(path, staticPodPath+"/"); ok {
			_, pod, _ := strings.Cut(output, "\n")
			rendered = append(rendered, fileutil.NewFile{Name: name, Data: []byte(pod)})
		}
	}
	mine := launches(t, rendered)
	for name, launch := range mine {
		if !floor.AdmitsContainer(launch) {
			t.Errorf("the staged floor refuses static pod container %s, argv %q", name, launch.Argv)
		}
	}
	for what, values := range map[string]map[string]string{
		"another node name": {nodeservices.NodeNamePlaceholder: "n-0000000000000000", nodeservices.PodCIDRPlaceholder: doc.Kubernetes.PodCIDR},
		"another pod range": {nodeservices.NodeNamePlaceholder: "n-10-0-0-7", nodeservices.PodCIDRPlaceholder: "10.99.0.0/16"},
	} {
		other, err := staticPods(root, values)
		if err != nil {
			t.Fatal(err)
		}
		changed := 0
		for name, launch := range launches(t, other) {
			if slices.Equal(launch.Argv, mine[name].Argv) {
				continue
			}
			changed++
			if floor.AdmitsContainer(launch) {
				t.Errorf("the staged floor admits %s rendered with %s, argv %q", name, what, launch.Argv)
			}
		}
		if changed == 0 {
			t.Errorf("no static pod container names the value %s changes", what)
		}
	}
}

// Kubelet inputs that cannot be rendered or written leave no output behind,
// including those of an earlier run.
func TestStageRefusesUnrenderableKubeletInputs(t *testing.T) {
	data := workerDocumentBytes(t)
	writeTemplate := func(t *testing.T, root, name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, staticPodTemplates, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name    string
		breakIt func(t *testing.T, root, token string)
		want    string
	}{
		{"a malformed bootstrap token", func(t *testing.T, _, token string) {
			if err := os.WriteFile(token, []byte("not-a-token\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "does not hold a bootstrap token"},
		{"no static pod templates directory", func(t *testing.T, root, _ string) {
			if err := os.RemoveAll(filepath.Join(root, staticPodTemplates)); err != nil {
				t.Fatal(err)
			}
		}, "static pod templates: open"},
		{"a linked template", func(t *testing.T, root, _ string) {
			if err := os.Symlink("kube-proxy.yaml", filepath.Join(root, staticPodTemplates, "linked.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "linked.yaml is not a regular file"},
		{"a placeholder outside argv", func(t *testing.T, root, _ string) {
			writeTemplate(t, root, "kube-proxy.yaml", kubeProxyTemplate+"      env:\n        - {name: NODE, value: \"${NODE_NAME}\"}\n")
		}, "outside a container's"},
		{"a floor placeholder this worker does not fill", func(t *testing.T, root, _ string) {
			writeTemplate(t, root, "kube-proxy.yaml", kubeProxyTemplate+"      env:\n        - {name: ADDRESS, value: \"${NODE_ADVERTISE_ADDRESS}\"}\n")
		}, "outside a container's"},
		{"a template field a Pod does not have", func(t *testing.T, root, _ string) {
			writeTemplate(t, root, "extra.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: extra}\nspecc: {}\n")
		}, "extra.yaml"},
		{"a template that is not a Pod", func(t *testing.T, root, _ string) {
			writeTemplate(t, root, "config.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: config}\n")
		}, "not a named v1 Pod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, path, api := workerRoot(t), stagedDocument(t, data), launchedWith(t, data)
			token := filepath.Join(t.TempDir(), "bootstrap-token")
			if err := os.WriteFile(token, []byte(testToken), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := stage(context.Background(), root, path, token, api); err != nil {
				t.Fatal(err)
			}
			tc.breakIt(t, root, token)
			err := stage(context.Background(), root, path, token, api)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stage = %v, want a refusal naming %q", err, tc.want)
			}
			if left := stagedOutputs(t, root); len(left) != 0 {
				t.Fatalf("a refused input left outputs behind: %v", slices.Sorted(maps.Keys(left)))
			}
		})
	}
}

// An image without static pods stages a kubelet that runs none.
func TestStageWritesNoStaticPodsFromAnEmptyDirectory(t *testing.T) {
	data := workerDocumentBytes(t)
	root := workerRoot(t)
	if err := os.Remove(filepath.Join(root, staticPodTemplates, "kube-proxy.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data)); err != nil {
		t.Fatal(err)
	}
	pods, err := os.ReadDir(filepath.Join(root, staticPodPath))
	if err != nil || len(pods) != 0 {
		t.Fatalf("static pods = %v, %v; want an empty manifests directory", pods, err)
	}
}

// Kubelet inputs that fail to write, after the floor was published, take the
// floor back with them.
func TestStageRemovesTheFloorWhenTheKubeletsInputsFail(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through directory permissions")
	}
	data := workerDocumentBytes(t)
	root := workerRoot(t)
	run := filepath.Join(root, "run")
	for _, dir := range []string{nodeservices.PublicDir, "/run/nri-image-policy"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The other outputs' directories stay writable; /run/kubernetes cannot be made.
	if err := os.Chmod(run, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(run, 0o755) })
	err := stage(context.Background(), root, stagedDocument(t, data), tokenFile(t), launchedWith(t, data))
	if err == nil || !strings.Contains(err.Error(), kubernetesDir) {
		t.Fatalf("stage = %v, want the failed write of %s", err, kubernetesDir)
	}
	if left := stagedOutputs(t, root); len(left) != 0 {
		t.Fatalf("a failed kubelet write left outputs behind: %v", slices.Sorted(maps.Keys(left)))
	}
}
