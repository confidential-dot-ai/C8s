package ta

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/taconn"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/localverify"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taconfig"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/tadecree"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/certutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
)

// The launch digests of two Trust Authority images: the one the cluster runs, and the one
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
// configuration its Trust Authority VMs boot, the key file that configuration pins, and
// the pin document every replica read is verified against.
type operatorCluster struct {
	config      []byte
	clusterID   string
	configPath  string
	keyPath     string
	operatorPEM []byte
	taPinPath   string
}

func newOperatorCluster(t *testing.T) operatorCluster {
	t.Helper()
	key, operatorPEM := operatorKeyPair(t)
	config := measuredDocument(t, cluster{operatorPEM: operatorPEM, workloads: map[string]string{"attestation-api": digestA}})
	return newOperatorClusterBooting(t, key, operatorPEM, config)
}

// newOperatorClusterBooting is a cluster whose Trust Authority boots config, which pins
// operatorPEM, the public key of key.
func newOperatorClusterBooting(
	t *testing.T,
	key *ecdsa.PrivateKey,
	operatorPEM []byte,
	config []byte,
) operatorCluster {
	t.Helper()
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	c := operatorCluster{
		config:      config,
		configPath:  filepath.Join(dir, "ta-config.yaml"),
		keyPath:     filepath.Join(dir, "operator.pem"),
		operatorPEM: operatorPEM,
		taPinPath:   filepath.Join(dir, "ta-pin.json"),
	}
	writeTestFile(t, c.configPath, c.config)
	writeTestFile(t, c.keyPath, keyPEM)
	writeTestFile(t, c.taPinPath, []byte(testutil.TAPinDocument(testutil.TestMeasurement, string(c.config))))
	parsed, err := taconfig.Parse(c.config)
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

// verifier reports the evidence of a Trust Authority of this cluster: the image the pin
// document names, launched on this configuration.
func (c operatorCluster) verifier() taconn.PinVerifier {
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
		signed, err := tadecree.Parse(body)
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
		taPin:    c.taPinPath,
		verifier: c.verifier(),
	}
}

// answerFor holds the kinds a replica acts on itself, and applies the rest.
func answerFor(d tadecree.Decree) taha.Delivered {
	switch d.Kind {
	case tadecree.Genesis, tadecree.Recover, tadecree.Admit:
		return taha.Delivered{Intent: d.IntentID, Held: true}
	}
	return taha.Delivered{Intent: d.IntentID, Version: d.BaseVersion + 1}
}

// pinDecree is a pin decree the cluster has applied, as a replica serves it.
func (c operatorCluster) pinDecree(t *testing.T, digests ...string) tadecree.Signed {
	t.Helper()
	pins, err := pinFlags{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, digests...)}}.document(c.config)
	if err != nil {
		t.Fatal(err)
	}
	key, err := certutil.LoadECPrivateKeyFile(c.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tadecree.Sign(tadecree.Decree{
		ClusterID:   c.clusterID,
		IntentID:    tadecree.NewIntentID(),
		Kind:        tadecree.UpdateMeasurements,
		BaseVersion: 3,
		ExpiresAt:   time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		TAPins:      pins,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// signed reads back the decree a command wrote, as the cluster checks it.
func (c operatorCluster) signed(t *testing.T, out string) tadecree.Signed {
	t.Helper()
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tadecree.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(c.operatorPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := tadecree.Verify(signed, keys, c.clusterID); err != nil {
		t.Fatalf("the cluster refuses the decree the operator would upload: %v", err)
	}
	return signed
}

// unjoined is what a replica of this cluster holding no cluster reports.
func (c operatorCluster) unjoined() taha.Status {
	return taha.Status{
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
	if decree.Kind != tadecree.UpdateMeasurements || decree.BaseVersion != o.baseVersion {
		t.Fatalf("decree = %+v", decree)
	}
	pins, err := decree.TAPins.WithLaunchFile(c.config)
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
		"--to", "ta-1.acme.example",
		"--ta-pin", c.taPinPath,
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

// The public half is the file an operator has at hand, and the flag takes the
// private one.
func TestSigningNamesAPublicKeyGivenAsTheOperatorKey(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	o.operatorKey = filepath.Join(t.TempDir(), "operator.pub")
	writeTestFile(t, o.operatorKey, c.operatorPEM)

	err := signing(t, func(cmd *cobra.Command) error {
		return pinsOptions{
			decreeOptions: o,
			pins: pinFlags{
				platform:  "sev-snp",
				vcpus:     []int{2},
				manifests: []string{snpManifest(t, smp2Digest)},
			},
		}.run(cmd)
	})
	if err == nil {
		t.Fatal("a decree was signed with the operator's public key")
	}
	for _, says := range []string{"--operator-key", "this is a public key", "c8s keys new --out"} {
		if !strings.Contains(err.Error(), says) {
			t.Errorf("signing with the public key = %q, want it to say %q", err, says)
		}
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
// A one-replica cluster's replica waits for a second replica to answer, so a
// Genesis it would hold forever is refused before it is signed.
func TestGenesisOfAOneReplicaClusterNeedsAlone(t *testing.T) {
	c := newReplicatedCluster(t)
	o := c.options(t)
	target := c.replicaServing(t, map[string]any{statusPath: c.unjoined()})
	genesis := func(alone bool) error {
		return signing(t, func(cmd *cobra.Command) error {
			return genesisOptions{
				decreeOptions: o,
				pins: pinFlags{
					platform:  "sev-snp",
					vcpus:     []int{2},
					manifests: []string{snpManifest(t, runningDigest)},
				},
				target: target,
				alone:  alone,
			}.run(cmd)
		})
	}

	err := genesis(false)
	if err == nil {
		t.Fatal("a Genesis the one replica would hold forever was signed")
	}
	if !strings.Contains(err.Error(), "--alone") {
		t.Errorf("the refusal is %q, want it to name --alone", err)
	}
	if err := genesis(true); err != nil {
		t.Fatalf("the same Genesis with --alone: %v", err)
	}
}

func TestGenesisDecreeBindsTheTargetProcess(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	o.baseVersion = 0
	target := c.replicaServing(t, map[string]any{statusPath: c.unjoined()})
	err := signing(t, func(cmd *cobra.Command) error {
		return genesisOptions{
			decreeOptions: o,
			pins:          pinFlags{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, runningDigest)}},
			target:        target,
			resumeVersion: 12,
		}.run(cmd)
	})
	if err != nil {
		t.Fatal(err)
	}
	decree := c.signed(t, o.out).Decree
	if decree.Kind != tadecree.Genesis || decree.TargetMember != targetMember || decree.GenesisCA != targetGenesis {
		t.Fatalf("decree = %+v", decree)
	}
	if decree.TargetAddress != target.address {
		t.Fatalf("target_address = %q, want the address dialled %q", decree.TargetAddress, target.address)
	}
	if decree.ResumeVersion != 12 || decree.IssuedAtMS == 0 {
		t.Fatalf("decree resumes above %d, issued at %d", decree.ResumeVersion, decree.IssuedAtMS)
	}
	// The configuration's nodes bind no launch, as a dev configuration's may.
	nodes, err := decree.NodePins.Images()
	if err != nil {
		t.Fatal(err)
	}
	if nodes.Family != teetypes.FamilyTDX || len(nodes.Images) != 1 || slices.ContainsFunc(nodes.Images, tadecree.EntryBindsLaunch) {
		t.Fatalf("the decree certifies %+v, want the configuration's nodes", nodes)
	}
}

// boundNodes is a node pin document with every entry bound to the launch file
// its nodes boot.
func boundNodes(t *testing.T, document string) []byte {
	t.Helper()
	nodes, err := refvalues.Parse([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	launched := sha512.Sum384([]byte("schemaVersion: c8s-worker/v1\n"))
	for i := range nodes.Images {
		nodes.Images[i].LaunchFileDigest = launched[:]
	}
	bound, err := refvalues.Format(nodes)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func TestNodeImagesDecreeCarriesTheWholeSet(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	upgrading := filepath.Join(t.TempDir(), "nodes.json")
	writeTestFile(t, upgrading, boundNodes(t, upgradingNodesDocument))
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
	if decree.Kind != tadecree.SetNodeImages || decree.BaseVersion != o.baseVersion {
		t.Fatalf("decree = %+v", decree)
	}
	if decree.TAPins != nil {
		t.Fatal("a node-image decree carries the images a Trust Authority of the cluster may run")
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

func TestNodeImagesDecreeRefusesAnEntryBindingNoLaunch(t *testing.T) {
	c := newOperatorCluster(t)
	o := c.options(t)
	unbound := filepath.Join(t.TempDir(), "nodes.json")
	writeTestFile(t, unbound, []byte(upgradingNodesDocument))

	err := signing(t, func(cmd *cobra.Command) error {
		return nodeImagesOptions{
			decreeOptions: o,
			nodes:         unbound,
		}.run(cmd)
	})
	if err == nil || !strings.Contains(err.Error(), "binds no launch") {
		t.Fatalf("got %v, want the entry binding no launch refused", err)
	}
	if _, statErr := os.Stat(o.out); statErr == nil {
		t.Fatal("the refused decree was written anyway")
	}
}

// A Genesis starts a cluster that was never started, and a Recover carries on
// a voter's state, so each refuses a target in the other's state.
func TestOneShotDecreesRefuseTheWrongTarget(t *testing.T) {
	c := newOperatorCluster(t)
	joined := taha.Status{ClusterID: c.clusterID, ID: targetMember, Joined: true, Voters: []string{targetMember}}
	for _, tc := range []struct {
		name   string
		status taha.Status
		check  func(taha.Status, string) error
	}{
		{"a Genesis on a replica holding a cluster", joined, checkGenesisTarget},
		{
			"a Genesis on a replica of another cluster",
			taha.Status{
				ClusterID: "other",
				ID:        targetMember,
				GenesisCA: targetGenesis,
			},
			checkGenesisTarget,
		},
		{
			"a Genesis on a replica reporting no mesh CA",
			taha.Status{
				ClusterID: c.clusterID,
				ID:        targetMember,
			},
			checkGenesisTarget,
		},
		{"a Recover on a replica holding no cluster", c.unjoined(), checkRecoverTarget},
		{
			"a Recover on a replica holding no vote",
			taha.Status{
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
	if decree.Kind != tadecree.Admit || decree.TargetMember != targetMember {
		t.Fatalf("decree = %+v", decree)
	}
	admitted, err := decree.TAPins.WithLaunchFile(c.config)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := applied.Decree.TAPins.WithLaunchFile(c.config)
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
	keyOnly.Decree.TAPins = nil
	for _, tc := range []struct {
		name   string
		served tadecree.Signed
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

// A replica is named as an address, and the port every Trust Authority serves the operator
// on is the default.
func TestAReplicaAddressNamesAHostAndAPort(t *testing.T) {
	for _, tc := range []struct {
		address string
		host    string
		port    uint16
	}{
		{"10.0.0.5", "10.0.0.5", replicaPort},
		{"ta-1.example.org", "ta-1.example.org", replicaPort},
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
	if decree.Kind != tadecree.SetVoters || decree.Voters != 5 || decree.BaseVersion != o.baseVersion {
		t.Fatalf("decree = %+v", decree)
	}

	for _, seats := range []int{0, 2, tadecree.MaxVoterSeats + 2} {
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

// --launch-file-field init_data pins guests whose launcher bound the launch
// file in MRCONFIGID: the decree names the field, and the pins a reader gets
// back read it there beside an RTMR[3] pinned untouched.
func TestPinFlagsPinGuestsThatReadMRCONFIGID(t *testing.T) {
	register := func(b string) string { return strings.Repeat(b, 48) }
	manifest := filepath.Join(t.TempDir(), "manifest.json")
	writeTestFile(t, manifest, []byte(fmt.Sprintf(`{"version":3,"build":{"platform":"tdx"},"tdx":{"mrtd":%q,"rtmr1":%q,"rtmr2":%q}}`,
		register("aa"), register("bb"), register("cc"))))
	launchFile := []byte("schemaVersion: c8s-ta/v1\nclusterID: lane\n")

	pins, err := pinFlags{platform: "tdx", manifests: []string{manifest}, launchFileField: "init_data"}.document(launchFile)
	if err != nil {
		t.Fatal(err)
	}
	if pins.LaunchFileField != "init_data" {
		t.Fatalf("launch_file_field = %q", pins.LaunchFileField)
	}
	bound, err := pins.WithLaunchFile(launchFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range bound.Images {
		if !image.LaunchFileInInitData || !bytes.Equal(image.Registers[3], make([]byte, 48)) {
			t.Errorf("entry %q: reads MRCONFIGID %v, RTMR[3] pin %x", image.Name, image.LaunchFileInInitData, image.Registers[3])
		}
	}

	plain, err := pinFlags{platform: "tdx", manifests: []string{manifest}}.document(launchFile)
	if err != nil {
		t.Fatal(err)
	}
	if plain.LaunchFileField != "" {
		t.Errorf("without the flag launch_file_field = %q", plain.LaunchFileField)
	}
	for _, refused := range []pinFlags{
		{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, strings.Repeat("ab", 48))}, launchFileField: "init_data"},
		{platform: "tdx", manifests: []string{manifest}, launchFileField: "host_data"},
	} {
		if _, err := refused.document(launchFile); err == nil || !strings.Contains(err.Error(), "--launch-file-field") {
			t.Errorf("%s with field %q: %v, want a refusal naming --launch-file-field", refused.platform, refused.launchFileField, err)
		}
	}
}

// A Genesis whose pins read another TDX field than the pin its replicas are
// verified with would commit and then admit none of them, so it is refused
// before anything is signed.

// A Genesis whose pins do not match the replica that forms the cluster would
// commit and then admit none of them, so the target is verified against the
// decree's pins as well as --ta-pin, and nothing is signed when it fails.
func TestGenesisRefusesPinsThatWouldNotAdmitItsTarget(t *testing.T) {
	c := newOperatorCluster(t)
	target := c.replicaServing(t, map[string]any{statusPath: c.unjoined()})
	for name, pins := range map[string]pinFlags{
		"another image":      {platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, smp2Digest)}},
		"another vCPU count": {platform: "sev-snp", vcpus: []int{4}, manifests: []string{snpManifest(t, runningDigest, smp4Digest)}},
	} {
		options := genesisOptions{decreeOptions: c.options(t), pins: pins, target: target}
		options.baseVersion = 0
		err := signing(t, options.run)
		if err == nil || !strings.Contains(err.Error(), "admits none of its replicas") {
			t.Errorf("%s: Genesis = %v, want a refusal", name, err)
		}
		if _, statErr := os.Stat(options.out); statErr == nil {
			t.Errorf("%s: a decree was written", name)
		}
	}
}

// runningDigest is the image the test replicas report: a Genesis is checked
// against its target, so its manifest names this one.
const runningDigest = testutil.TestMeasurement

// An image roll on TDX names two images of one firmware: MRTD is the same and
// the kernel registers differ, so the entries need names that differ too.
func TestPinFlagsNameTwoTDXImagesOfOneFirmwareApart(t *testing.T) {
	register := func(b string) string { return strings.Repeat(b, 48) }
	manifest := func(rtmr1 string) string {
		path := filepath.Join(t.TempDir(), "manifest.json")
		writeTestFile(t, path, []byte(fmt.Sprintf(`{"version":3,"build":{"platform":"tdx"},"tdx":{"mrtd":%q,"rtmr1":%q,"rtmr2":%q}}`,
			register("aa"), rtmr1, register("cc"))))
		return path
	}
	launchFile := []byte("schemaVersion: c8s-ta/v1\nclusterID: lane\n")
	for _, field := range []string{"", "init_data"} {
		flags := pinFlags{platform: "tdx", manifests: []string{manifest(register("bb")), manifest(register("dd"))}, launchFileField: field}
		pins, err := flags.document(launchFile)
		if err != nil {
			t.Fatalf("field %q: %v", field, err)
		}
		bound, err := pins.WithLaunchFile(launchFile)
		if err != nil {
			t.Fatalf("field %q: %v", field, err)
		}
		if len(bound.Images) != 2 || bound.Images[0].Name == bound.Images[1].Name {
			t.Fatalf("field %q: entries %+v, want two with distinct names", field, bound.Images)
		}
	}
}

// The connection the decree is written from must satisfy --ta-pin as well as
// the decree's pins: a guest that matches the decree's pins alone, wherever
// the host routes the second read, is refused.
func TestGenesisReadsItsTargetUnderBothPinSets(t *testing.T) {
	c := newOperatorCluster(t)
	target := c.replicaServing(t, map[string]any{statusPath: c.unjoined()})
	pins, err := pinFlags{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, runningDigest)}}.document(c.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitted(context.Background(), target, pins, c.config); err != nil {
		t.Fatalf("a target matching both pin sets: %v", err)
	}
	elsewhere := filepath.Join(t.TempDir(), "ta-pin.json")
	writeTestFile(t, elsewhere, []byte(testutil.TAPinDocument(smp2Digest, string(c.config))))
	target.taPin = elsewhere
	if _, err := admitted(context.Background(), target, pins, c.config); err == nil {
		t.Fatal("a target outside --ta-pin was read under the decree's pins alone")
	}
}
