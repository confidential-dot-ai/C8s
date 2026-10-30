package cds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// The launch digests of two CDS images: the one the cluster runs, and the one
// an operator rolls it onto.
const (
	smp2Digest    = "e7df3a8f1dbe619607154ce994c1f4d7299c539b120b5560e137f7787e4ece304f270c1444b47c863fde54bc863291d7"
	smp4Digest    = "e0615da999afd20375d64ec9aaf0c480d6854198c01ed3e4157f881a96f635e532f7ad528ef69b408ef10319be5db106"
	rolledSMP2    = "a1b2c3d499afd20375d64ec9aaf0c480d6854198c01ed3e4157f881a96f635e532f7ad528ef69b408ef10319be5db106"
	rolledSMP4    = "b2c3d4e599afd20375d64ec9aaf0c480d6854198c01ed3e4157f881a96f635e532f7ad528ef69b408ef10319be5db106"
	targetMember  = "ahn7yq4qnkwftxo6ihoyu2bxpi"
	targetGenesis = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

// operatorCluster is one cluster the operator signs decrees for: the
// configuration its CDS VMs boot, the key file that configuration pins, and
// the pin document every replica read is verified against.
type operatorCluster struct {
	config      []byte
	clusterID   string
	configPath  string
	keyPath     string
	operatorPEM []byte
	cdsPinPath  string
}

func newOperatorCluster(t *testing.T) operatorCluster {
	t.Helper()
	key, operatorPEM := operatorKeyPair(t)
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	c := operatorCluster{
		config:      measuredDocument(t, cluster{operatorPEM: operatorPEM, workloads: map[string]string{"attestation-api": digestA}}),
		configPath:  filepath.Join(dir, "cds-config.yaml"),
		keyPath:     filepath.Join(dir, "operator.pem"),
		operatorPEM: operatorPEM,
		cdsPinPath:  filepath.Join(dir, "cds-pin.json"),
	}
	writeTestFile(t, c.configPath, c.config)
	writeTestFile(t, c.keyPath, keyPEM)
	writeTestFile(t, c.cdsPinPath, []byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(c.config))))
	parsed, err := cdsconfig.Parse(c.config)
	if err != nil {
		t.Fatal(err)
	}
	c.clusterID = parsed.ClusterID
	return c
}

// options are the flags every decree command shares.
func (c operatorCluster) options(t *testing.T) decreeOptions {
	t.Helper()
	return decreeOptions{
		config:      c.configPath,
		operatorKey: c.keyPath,
		out:         filepath.Join(t.TempDir(), "decree.json"),
		expiresIn:   defaultDecreeValidity,
		baseVersion: 4,
	}
}

// verifier reports the evidence of a CDS of this cluster: the image the pin
// document names, launched on this configuration.
func (c operatorCluster) verifier() cdsconn.PinVerifier {
	return testutil.VerifierStub(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		match := true
		result := &teetypes.VerificationResult{Platform: teetypes.PlatformSNP, SignatureValid: true, ReportDataMatch: &match}
		result.Claims.LaunchDigest = testutil.TestMeasurement
		binding := runtimemeasure.HostData(c.config)
		result.Claims.InitData = binding[:]
		return result, nil
	})
}

// replicaServing answers one replica's routes over armTLS: it reports what
// routes names, and holds every decree posted to it.
func (c operatorCluster) replicaServing(t *testing.T, routes map[string]any) replica {
	t.Helper()
	handler := http.NewServeMux()
	for path, answer := range routes {
		body, err := json.Marshal(answer)
		if err != nil {
			t.Fatal(err)
		}
		handler.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		})
	}
	handler.HandleFunc("POST "+decreesPath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxReplicaReport))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signed, err := cdsdecree.Parse(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answerFor(signed.Decree))
	})
	server := testutil.NewARMTLSServer(t, handler)
	return replica{
		address:  strings.TrimPrefix(server.URL, "https://"),
		cdsPin:   c.cdsPinPath,
		verifier: c.verifier(),
	}
}

// answerFor holds the kinds a replica acts on itself, and applies the rest.
func answerFor(d cdsdecree.Decree) cdsha.Delivered {
	switch d.Kind {
	case cdsdecree.Genesis, cdsdecree.Recover, cdsdecree.Admit:
		return cdsha.Delivered{Intent: d.IntentID, Held: true}
	}
	return cdsha.Delivered{Intent: d.IntentID, Version: d.BaseVersion + 1}
}

// pinDecree is a pin decree the cluster has applied, as a replica serves it.
func (c operatorCluster) pinDecree(t *testing.T, digests ...string) cdsdecree.Signed {
	t.Helper()
	pins, err := pinFlags{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, digests...)}}.document(c.config)
	if err != nil {
		t.Fatal(err)
	}
	key, err := certutil.LoadECPrivateKeyFile(c.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Sign(cdsdecree.Decree{
		ClusterID:   c.clusterID,
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.UpdateMeasurements,
		BaseVersion: 3,
		ExpiresAt:   time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		CDSPins:     pins,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// signed reads back the decree a command wrote, as the cluster checks it.
func (c operatorCluster) signed(t *testing.T, out string) cdsdecree.Signed {
	t.Helper()
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(c.operatorPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := cdsdecree.Verify(signed, keys, c.clusterID); err != nil {
		t.Fatalf("the cluster refuses the decree the operator would upload: %v", err)
	}
	return signed
}

// unjoined is what a replica of this cluster holding no cluster reports.
func (c operatorCluster) unjoined() cdsha.Status {
	return cdsha.Status{
		ClusterID: c.clusterID,
		ID:        targetMember,
		GenesisCA: targetGenesis,
	}
}

func snpManifest(t *testing.T, digests ...string) string {
	t.Helper()
	variants := make([]string, 0, len(digests))
	for i, digest := range digests {
		variants = append(variants, fmt.Sprintf(`{"smp":%d,"measurement":{"algorithm":"sha384","snp_launch_digest":%q}}`, 2*(i+1), digest))
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	writeTestFile(t, path, []byte(fmt.Sprintf(`{"version":3,"build":{"platform":"snp"},"snp_variants":[%s]}`, strings.Join(variants, ","))))
	return path
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// signing runs one decree command's own work, with a command that discards
// what it prints for the operator.
func signing(t *testing.T, run func(*cobra.Command) error) error {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return run(cmd)
}

// A pin decree names every image the cluster accepts, so an image roll signs
// the old and the new one in one decree. Each entry's name carries its launch
// digest, because two images of one cluster would otherwise take the same name.
func TestPinDecreeNamesEveryImageTheClusterAccepts(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	serving := c.replicaServing(t, nil)

	err := signing(t, func(cmd *cobra.Command) error {
		return pinsOptions{
			decreeOptions: o,
			pins: pinFlags{
				platform: "sev-snp",
				vcpus:    []int{2, 4},
				manifests: []string{
					snpManifest(t, smp2Digest, smp4Digest),
					snpManifest(t, rolledSMP2, rolledSMP4),
				},
			},
			to: serving,
		}.run(cmd)
	})
	if err != nil {
		t.Fatal(err)
	}
	decree := c.signed(t, o.out).Decree
	if decree.Kind != cdsdecree.UpdateMeasurements || decree.BaseVersion != o.baseVersion {
		t.Fatalf("decree = %+v", decree)
	}
	pins, err := decree.CDSPins.WithLaunchFile(c.config)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, image := range pins.Images {
		names[image.Name] = true
		if !strings.Contains(image.Name, "@") {
			t.Fatalf("entry %q does not name its launch digest", image.Name)
		}
	}
	if len(pins.Images) != 4 || len(names) != 4 {
		t.Fatalf("the decree pins %d images under %d names", len(pins.Images), len(names))
	}
}

// A decree applies at the version the operator saw, so the version is theirs
// to name rather than the CLI's to guess.
func TestPinDecreeNeedsTheVersionItAppliesOn(t *testing.T) {
	c := newOperatorCluster(t)
	cmd := newPinsCmd()
	cmd.SetArgs([]string{
		"--config", c.configPath,
		"--operator-key", c.keyPath,
		"--out", filepath.Join(t.TempDir(), "pins.json"),
		"--to", "cds-1.acme.example",
		"--cds-pin", c.cdsPinPath,
		"--platform", "sev-snp",
		"--vcpus", "2",
		"--image-manifest", snpManifest(t, smp2Digest),
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil {
		t.Fatal("a pin decree was signed without the version it applies on")
	}
}

// Only a key the configuration pins can sign for the cluster, so a key it does
// not pin fails here rather than on the board.
func TestSigningRefusesAKeyTheClusterDoesNotPin(t *testing.T) {
	c := newOperatorCluster(t)
	other, _ := operatorKeyPair(t)
	otherPEM, err := certutil.MarshalECKeyPEM(other)
	if err != nil {
		t.Fatal(err)
	}
	o := c.options(t)
	o.operatorKey = filepath.Join(t.TempDir(), "other.pem")
	writeTestFile(t, o.operatorKey, otherPEM)
	err = signing(t, func(cmd *cobra.Command) error {
		return pinsOptions{
			decreeOptions: o,
			pins:          pinFlags{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, smp2Digest)}},
		}.run(cmd)
	})
	if err == nil {
		t.Fatal("a decree was written for a key the configuration does not pin")
	}
	if _, statErr := os.Stat(o.out); statErr == nil {
		t.Fatal("the refused decree was written anyway")
	}
}

// A Genesis names the process it starts the cluster on, the address it was
// reached at, and the mesh CA that process would install.
func TestGenesisDecreeBindsTheTargetProcess(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	o.baseVersion = 0
	target := c.replicaServing(t, map[string]any{statusPath: c.unjoined()})
	err := signing(t, func(cmd *cobra.Command) error {
		return genesisOptions{
			decreeOptions: o,
			pins:          pinFlags{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, smp2Digest)}},
			target:        target,
			resumeVersion: 12,
		}.run(cmd)
	})
	if err != nil {
		t.Fatal(err)
	}
	decree := c.signed(t, o.out).Decree
	if decree.Kind != cdsdecree.Genesis || decree.TargetMember != targetMember || decree.GenesisCA != targetGenesis {
		t.Fatalf("decree = %+v", decree)
	}
	if decree.TargetAddress != target.address {
		t.Fatalf("target_address = %q, want the address dialled %q", decree.TargetAddress, target.address)
	}
	if decree.ResumeVersion != 12 || decree.IssuedAtMS == 0 {
		t.Fatalf("decree resumes above %d, issued at %d", decree.ResumeVersion, decree.IssuedAtMS)
	}
	nodes, err := decree.NodePins.Images()
	if err != nil {
		t.Fatal(err)
	}
	if nodes.Family != teetypes.FamilyTDX || len(nodes.Images) != 1 {
		t.Fatalf("the decree certifies %+v, want the configuration's nodes", nodes)
	}
}

func TestNodeImagesDecreeCarriesTheWholeSet(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	upgrading := filepath.Join(t.TempDir(), "nodes.json")
	writeTestFile(t, upgrading, []byte(upgradingNodesDocument))
	serving := c.replicaServing(t, nil)

	if err := signing(t, func(cmd *cobra.Command) error {
		return nodeImagesOptions{
			decreeOptions: o,
			nodes:         upgrading,
			to:            serving,
		}.run(cmd)
	}); err != nil {
		t.Fatal(err)
	}

	decree := c.signed(t, o.out).Decree
	if decree.Kind != cdsdecree.SetNodeImages || decree.BaseVersion != o.baseVersion {
		t.Fatalf("decree = %+v", decree)
	}
	if decree.CDSPins != nil {
		t.Fatal("a node-image decree carries the images a CDS of the cluster may run")
	}
	certified, err := decree.NodePins.Images()
	if err != nil {
		t.Fatal(err)
	}
	if certified.Family != teetypes.FamilyTDX || len(certified.Images) != 2 {
		t.Fatalf("the decree certifies %+v, want the image being replaced and the one replacing it", certified)
	}
}

func TestNodeImagesDecreeRefusesAFileThatPinsNothing(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	empty := filepath.Join(t.TempDir(), "nodes.json")
	writeTestFile(t, empty, []byte(`{"schema_version":"1","tee":"tdx","measurements":[]}`))

	err := signing(t, func(cmd *cobra.Command) error {
		return nodeImagesOptions{
			decreeOptions: o,
			nodes:         empty,
		}.run(cmd)
	})
	if err == nil {
		t.Fatal("a decree certifying no node image was signed")
	}
	if _, statErr := os.Stat(o.out); statErr == nil {
		t.Fatal("the refused decree was written anyway")
	}
}

// A Genesis starts a cluster that was never started, and a Recover carries on
// a voter's state, so each refuses a target in the other's state.
func TestOneShotDecreesRefuseTheWrongTarget(t *testing.T) {
	c := newOperatorCluster(t)
	joined := cdsha.Status{ClusterID: c.clusterID, ID: targetMember, Joined: true, Voters: []string{targetMember}}
	for _, tc := range []struct {
		name   string
		status cdsha.Status
		check  func(cdsha.Status, string) error
	}{
		{"a Genesis on a replica holding a cluster", joined, checkGenesisTarget},
		{
			"a Genesis on a replica of another cluster",
			cdsha.Status{
				ClusterID: "other",
				ID:        targetMember,
				GenesisCA: targetGenesis,
			},
			checkGenesisTarget,
		},
		{
			"a Genesis on a replica reporting no mesh CA",
			cdsha.Status{
				ClusterID: c.clusterID,
				ID:        targetMember,
			},
			checkGenesisTarget,
		},
		{"a Recover on a replica holding no cluster", c.unjoined(), checkRecoverTarget},
		{
			"a Recover on a replica holding no vote",
			cdsha.Status{
				ClusterID: c.clusterID,
				ID:        targetMember,
				Joined:    true,
			},
			checkRecoverTarget,
		},
		{"an Admit on a replica holding a cluster", joined, checkAdmitTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(tc.status, c.clusterID); err == nil {
				t.Fatal("the target was accepted")
			}
		})
	}
}

// An Admit lists the images the cluster already accepts, read from a serving
// replica as the decree it applied, so it cannot widen the set.
func TestAdmitDecreeTakesItsImagesFromTheAppliedPinDecree(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	o.baseVersion = 0
	applied := c.pinDecree(t, smp2Digest)
	target := c.replicaServing(t, map[string]any{statusPath: c.unjoined()})
	serving := c.replicaServing(t, map[string]any{pinDecreePath: applied})
	err := signing(t, func(cmd *cobra.Command) error {
		return admitOptions{decreeOptions: o, target: target, joined: serving.address}.run(cmd)
	})
	if err != nil {
		t.Fatal(err)
	}
	decree := c.signed(t, o.out).Decree
	if decree.Kind != cdsdecree.Admit || decree.TargetMember != targetMember {
		t.Fatalf("decree = %+v", decree)
	}
	admitted, err := decree.CDSPins.WithLaunchFile(c.config)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := applied.Decree.CDSPins.WithLaunchFile(c.config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(admitted, accepted) {
		t.Fatalf("the Admit pins %+v, want the images the cluster accepts %+v", admitted.Images, accepted.Images)
	}
}

// What a replica serves as the applied pin decree is still only its word
// until the operator keys check it, and it must pin an image.
func TestAdmitRefusesWhatTheServingReplicaCannotProve(t *testing.T) {
	c := newOperatorCluster(t)
	unsigned := c.pinDecree(t, smp2Digest)
	unsigned.Signature = ""
	keyOnly := c.pinDecree(t, smp2Digest)
	keyOnly.Decree.CDSPins = nil
	for _, tc := range []struct {
		name   string
		served cdsdecree.Signed
	}{
		{"an unsigned decree", unsigned},
		{"a decree pinning no image", keyOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := c.options(t)
			o.baseVersion = 0
			target := c.replicaServing(t, map[string]any{statusPath: c.unjoined()})
			serving := c.replicaServing(t, map[string]any{pinDecreePath: tc.served})
			err := signing(t, func(cmd *cobra.Command) error {
				return admitOptions{decreeOptions: o, target: target, joined: serving.address}.run(cmd)
			})
			if err == nil {
				t.Fatal("an Admit was signed for images the cluster did not prove")
			}
		})
	}
}

// A Recover resumes above the highest version the operator knows, which cannot
// be below the version it applies on.
func TestRecoverResumesAboveTheVersionItAppliesOn(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	err := signing(t, func(cmd *cobra.Command) error {
		return recoverOptions{decreeOptions: o, resumeVersion: o.baseVersion - 1, acknowledge: true}.run(cmd)
	})
	if err == nil {
		t.Fatal("a Recover resumed below the version it applies on")
	}
}

// The acknowledgement gates on its value: an operator who passes it as false
// has not accepted that a Recover drops writes.
func TestRecoverNeedsTheBreakGlassAcknowledgement(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	err := signing(t, func(cmd *cobra.Command) error {
		return recoverOptions{decreeOptions: o, resumeVersion: o.baseVersion}.run(cmd)
	})
	if err == nil {
		t.Fatal("a Recover was signed without the break-glass acknowledgement")
	}
	if _, statErr := os.Stat(o.out); statErr == nil {
		t.Fatal("the refused decree was written anyway")
	}
}

// A replica is named as an address, and the port every CDS serves the operator
// on is the default.
func TestAReplicaAddressNamesAHostAndAPort(t *testing.T) {
	for _, tc := range []struct {
		address string
		host    string
		port    uint16
	}{
		{"10.0.0.5", "10.0.0.5", replicaPort},
		{"cds-1.example.org", "cds-1.example.org", replicaPort},
		{"127.0.0.1:8441", "127.0.0.1", 8441},
	} {
		t.Run(tc.address, func(t *testing.T) {
			host, port, err := splitReplicaAddress(tc.address)
			if err != nil || host != tc.host || port != tc.port {
				t.Fatalf("host=%q port=%d error=%v", host, port, err)
			}
		})
	}
	for _, address := range []string{"10.0.0.5:http", "[::1", "a:b:c"} {
		if _, _, err := splitReplicaAddress(address); err == nil {
			t.Fatalf("%q named a replica", address)
		}
	}
	if _, err := resolveReplica(context.Background(), "127.0.0.1:8443"); err != nil {
		t.Fatalf("a replica at a literal address was refused: %v", err)
	}
}

// The voter seats are the cluster's, and a count no cluster keeps a majority
// at is refused where the operator signs.
func TestVotersDecreeNamesTheSeatsOfTheCluster(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	serving := c.replicaServing(t, nil)

	if err := signing(t, func(cmd *cobra.Command) error {
		return votersOptions{
			decreeOptions: o,
			voters:        5,
			to:            serving,
		}.run(cmd)
	}); err != nil {
		t.Fatal(err)
	}
	decree := c.signed(t, o.out).Decree
	if decree.Kind != cdsdecree.SetVoters || decree.Voters != 5 || decree.BaseVersion != o.baseVersion {
		t.Fatalf("decree = %+v", decree)
	}

	for _, seats := range []int{0, 2, cdsdecree.MaxVoterSeats + 2} {
		err := signing(t, func(cmd *cobra.Command) error {
			return votersOptions{
				decreeOptions: c.options(t),
				voters:        seats,
				to:            serving,
			}.run(cmd)
		})
		if err == nil {
			t.Fatalf("a decree naming %d voter seats was signed", seats)
		}
	}
}
