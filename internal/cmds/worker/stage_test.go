package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// bakedFloor is a worker image's NRI config: staging completes its mesh
// policy with the cluster ranges and the credential role.
const bakedFloor = `platform: sev-snp
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      kube-proxy:
        containers:
          - digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            command: {policy: any}
            args: {policy: any}
  pull:
    url: https://127.0.0.1:30808
    timeout: 30s
policy:
  mode: fail-closed
mesh:
  exempt_namespaces: [kube-system]
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
`

// workerRoot is a worker's filesystem holding its image's marker, baked
// floor and component seed.
func workerRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	baked := filepath.Join(root, "usr/lib/c8s")
	if err := os.MkdirAll(baked, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"worker-image":        "",
		"image-policy.yaml":   bakedFloor,
		"allowlist-seed.json": `{"schema":"c8s.allowlist/v1","workloads":{}}`,
	} {
		if err := os.WriteFile(filepath.Join(baked, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// workerDocumentBytes is a worker document whose ranges are not the node
// image's.
func workerDocumentBytes(t *testing.T) []byte {
	t.Helper()
	doc := testDocument(t)
	doc.Kubernetes.PodCIDR = "10.100.0.0/16"
	doc.Kubernetes.ServiceCIDR = "10.200.0.0/16"
	doc.Kubernetes.ClusterDNS = "10.200.0.10"
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
	for _, dir := range []string{nodeservices.PublicDir, "/etc/nri"} {
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
	if err := stage(context.Background(), root, stagedDocument(t, data), launchedWith(t, data)); err != nil {
		t.Fatal(err)
	}

	policy, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var floor struct {
		Allowlist struct {
			Pull struct {
				URL      string `yaml:"url"`
				PinFloor uint64 `yaml:"cds_pin_floor"`
			} `yaml:"pull"`
		} `yaml:"allowlist"`
		Mesh struct {
			ClusterRanges []string     `yaml:"cluster_ranges"`
			Roles         []stagedRole `yaml:"roles"`
		} `yaml:"mesh"`
	}
	if err := yaml.Unmarshal(policy, &floor); err != nil {
		t.Fatal(err)
	}
	if got, want := floor.Mesh.ClusterRanges, []string{"10.100.0.0/16", "10.200.0.0/16"}; !slices.Equal(got, want) {
		t.Errorf("cluster_ranges = %v, want the document's %v", got, want)
	}
	pull := floor.Allowlist.Pull
	if pull.URL != "https://cds.acme.example:8443" || pull.PinFloor != doc.CDS.PinFloor {
		t.Errorf("pull = %+v, want the document's CDS and pin floor %d", pull, doc.CDS.PinFloor)
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
	for _, name := range []string{"peers.json", "operator-pubkey", "tls-san"} {
		if _, err := os.Stat(filepath.Join(root, nodeservices.PublicDir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("published %s, a server's or an agent's output: %v", name, err)
		}
	}
}

func TestStageRerunIsIdempotent(t *testing.T) {
	data := workerDocumentBytes(t)
	root, path, api := workerRoot(t), stagedDocument(t, data), launchedWith(t, data)
	if err := stage(context.Background(), root, path, api); err != nil {
		t.Fatal(err)
	}
	first := stagedOutputs(t, root)
	if err := stage(context.Background(), root, path, api); err != nil {
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
			if err := stage(context.Background(), root, stagedDocument(t, good), launchedWith(t, good)); err != nil {
				t.Fatal(err)
			}
			err := stage(context.Background(), root, stagedDocument(t, tc.staged), launchedWith(t, tc.launched))
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
	if err := stage(context.Background(), root, stagedDocument(t, data), launchedWith(t, data)); err == nil {
		t.Fatal("staged a floor it could not write")
	}
	if left := stagedOutputs(t, root); len(left) != 0 {
		t.Fatalf("a failed preparation left outputs behind: %v", slices.Sorted(maps.Keys(left)))
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
	err := stage(context.Background(), root, stagedDocument(t, data), launchedWith(t, data))
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
	if err := stage(context.Background(), root, stagedDocument(t, data), stub.URL()); err != nil {
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
	err := stage(context.Background(), root, stagedDocument(t, data), launchedWith(t, data))
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
	err := stage(ctx, workerRoot(t), stagedDocument(t, data), "http://127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "not ready") || strings.Contains(err.Error(), "not the document") {
		t.Fatalf("stage = %v, want the attestation API reported unreachable", err)
	}
}
