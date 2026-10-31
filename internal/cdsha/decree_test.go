package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// A Genesis starts the cluster: the mesh CA the operator signed for, the
// image sets the decree carries, the voter seats this replica's configuration
// names, and the launch file its state belongs to.
func TestGenesisStartsTheCluster(t *testing.T) {
	r := newReplica(t)
	entry := r.entryFor(r.decree(cdsdecree.Genesis))
	if res := r.applyDecreeEntry(entry); res.Refused != "" || res.Version != 1 {
		t.Fatalf("genesis: %+v", res)
	}
	core := r.ClusterState()
	switch {
	case !core.Joined() || !bytes.Equal(core.MeshCACert, r.minted.Cert.Raw):
		t.Fatal("the cluster holds another mesh CA than its Genesis named")
	case r.CA() == nil || !r.CA().Key.Equal(r.minted.Key):
		t.Fatal("the replica cannot issue under the mesh CA")
	case core.PinsDecree == nil || core.PinsDecree.Decree.IntentID != entry.Decree.Decree.IntentID:
		t.Fatal("the cluster pins no CDS images")
	case core.NodeImages == nil:
		t.Fatal("the cluster certifies no node images")
	case core.Voters != r.cluster.launch.Voters:
		t.Fatalf("%d voter seats, want the configured %d", core.Voters, r.cluster.launch.Voters)
	case core.ConfigSHA256 != r.cluster.launch.ConfigSHA256:
		t.Fatal("the cluster's state does not name the launch file it was started on")
	case core.Format != baseFormat:
		t.Fatalf("a new cluster starts at format %d, want the base %d", core.Format, baseFormat)
	}
}

func TestSetNodeImagesReplacesTheWholeSet(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	started := r.ClusterState()
	if started.NodeImagesVersion != started.Version {
		t.Fatalf("the started cluster certifies the node images of version %d at version %d", started.NodeImagesVersion, started.Version)
	}

	upgrade := r.decree(cdsdecree.SetNodeImages)
	upgrade.NodePins = testNodeImages(t, 0x33, 0x44)
	upgraded := r.applyDecreeEntry(r.entryFor(upgrade))
	if upgraded.Refused != "" {
		t.Fatal(upgraded.Refused)
	}
	core := r.ClusterState()
	switch {
	case len(certifiedImages(t, core).Images) != 2:
		t.Fatalf("the cluster certifies %+v, want the image being replaced and the one replacing it", certifiedImages(t, core).Images)
	case core.NodeImagesVersion != upgraded.Version:
		t.Fatalf("the node image set is named by version %d, want the %d the decree reached", core.NodeImagesVersion, upgraded.Version)
	case core.PinsDecree.Decree.Kind != cdsdecree.Genesis:
		t.Fatal("a node image command changed the images a CDS of the cluster may run")
	}

	// The nodes are relaunched, and the next command retires the old image.
	retire := r.decree(cdsdecree.SetNodeImages)
	retire.NodePins = testNodeImages(t, 0x44)
	if res := r.applyDecreeEntry(r.entryFor(retire)); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	certified := certifiedImages(t, r.ClusterState())
	if len(certified.Images) != 1 || certified.Images[0].Name != "node-44" {
		t.Fatalf("the cluster certifies %+v, want the new node image alone", certified.Images)
	}
}

func certifiedImages(t *testing.T, core ClusterState) refvalues.ReferenceValues {
	t.Helper()
	if core.NodeImages == nil {
		t.Fatal("the cluster certifies no node images")
	}
	images, err := core.NodeImages.Images()
	if err != nil {
		t.Fatal(err)
	}
	return images
}

// A decree acts once, on the state its operator signed it for, under their
// own key, before it expires.
func TestADecreeAppliesOnceAndOnTheStateItNames(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	applied := r.decree(cdsdecree.UpdateMeasurements)
	if res := r.applyDecreeEntry(r.entryFor(applied)); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	version := r.ClusterState().Version

	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedByAStranger := r.decree(cdsdecree.UpdateMeasurements)
	strange, err := cdsdecree.Sign(signedByAStranger, stranger)
	if err != nil {
		t.Fatal(err)
	}

	expired := r.decree(cdsdecree.UpdateMeasurements)
	expired.ExpiresAt = time.Now().Add(-time.Minute)

	onAnotherVersion := r.decree(cdsdecree.UpdateMeasurements)
	onAnotherVersion.BaseVersion = version + 1

	anotherCluster := r.decree(cdsdecree.UpdateMeasurements)
	anotherCluster.ClusterID = "other"

	for name, refused := range map[string]DecreeEntry{
		"the same decree again": r.entryFor(applied),
		"a key the cluster does not know": {
			Decree: strange,
			AtMS:   time.Now().UnixMilli(),
		},
		"an expired decree": r.entryFor(expired),
		"another version":   r.entryFor(onAnotherVersion),
		"another cluster":   r.entryFor(anotherCluster),
	} {
		t.Run(name, func(t *testing.T) {
			res := r.applyDecreeEntry(refused)
			if res.Refused == "" {
				t.Fatal("applied")
			}
			if r.ClusterState().Version != version {
				t.Fatalf("a refused decree moved the cluster to version %d", r.ClusterState().Version)
			}
			if r.Stuck() != "" {
				t.Fatalf("a refused decree stopped the replica: %s", r.Stuck())
			}
		})
	}
}

// Every replica checks that a pin decree pins images of the launch file it
// boots itself: one for another file names a CDS of another cluster.
func TestPinsOfAnotherLaunchFileAreRefused(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	d := r.decree(cdsdecree.UpdateMeasurements)
	d.CDSPins.LaunchFileSHA256 = strings.Repeat("00", 32)
	res := r.applyDecreeEntry(r.entryFor(d))
	if !strings.Contains(res.Refused, "launch file") {
		t.Fatalf("refusal %q, want the launch file digests", res.Refused)
	}
	if r.ClusterState().PinsDecree.Decree.Kind != cdsdecree.Genesis {
		t.Fatal("the refused decree replaced the cluster's pins")
	}
}

// A Genesis entry carrying a mesh CA the decree does not name is refused: an
// admitted replica replaying a Genesis must not install a CA of its own.
func TestGenesisTakesOnlyTheMeshCATheDecreeNames(t *testing.T) {
	r := newReplica(t)
	entry := r.entryFor(r.decree(cdsdecree.Genesis))
	entry.MeshCACert, entry.MeshCAKey = caBytes(t, mintCA(t))
	if res := r.applyDecreeEntry(entry); !strings.Contains(res.Refused, "another mesh CA") {
		t.Fatalf("refusal %q", res.Refused)
	}
	if r.ClusterState().Joined() || r.CA() != nil {
		t.Fatal("a refused Genesis started the cluster")
	}
}

// A mesh CA is a certificate and the key that signed it.
func TestAMeshCAEntryCarriesAMatchingKey(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	held := r.CA()
	for name, edit := range map[string]func(*DecreeEntry){
		"no key":         func(de *DecreeEntry) { de.MeshCAKey = nil },
		"another key":    func(de *DecreeEntry) { _, de.MeshCAKey = caBytes(t, mintCA(t)) },
		"no certificate": func(de *DecreeEntry) { de.MeshCACert = []byte("not a certificate") },
	} {
		t.Run(name, func(t *testing.T) {
			entry := r.entryFor(r.decree(cdsdecree.RotateKey))
			edit(&entry)
			if res := r.applyDecreeEntry(entry); res.Refused == "" {
				t.Fatal("applied")
			}
			if r.CA() != held {
				t.Fatal("a refused rotation replaced the mesh CA")
			}
		})
	}
}

// RotateKey forks the mesh under a new key; the cluster's pins stay as they
// were, since the decree carries none.
func TestRotateKeyReplacesTheMeshCAOnly(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	pins := r.ClusterState().PinsDecree
	entry := r.entryFor(r.decree(cdsdecree.RotateKey))
	if res := r.applyDecreeEntry(entry); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if certutil.CertFingerprint(r.ClusterState().MeshCACert) != certutil.CertFingerprint(entry.MeshCACert) {
		t.Fatal("the cluster kept the retired mesh CA")
	}
	if r.ClusterState().PinsDecree != pins {
		t.Fatal("a key rotation changed the images the cluster pins")
	}
}

// A decree that carries a cluster on never starts one, an Admit is answered
// by the unjoined replica it names rather than applied, and a cluster is
// started once.
func TestAKindOutOfItsPlaceInTheClusterIsRefused(t *testing.T) {
	for _, kind := range []cdsdecree.Kind{cdsdecree.UpdateMeasurements, cdsdecree.RotateKey, cdsdecree.Recover} {
		t.Run(string(kind), func(t *testing.T) {
			r := newReplica(t)
			entry := r.entryFor(r.decree(kind))
			r.apply(Entry{
				Kind:   KindDecree,
				Decree: &entry,
			})
			if r.ClusterState().Joined() {
				t.Fatalf("a %s decree started a cluster", kind)
			}
		})
	}
	r := newReplica(t)
	r.genesis()
	if res := r.applyDecreeEntry(r.entryFor(r.decree(cdsdecree.Admit))); !strings.Contains(res.Refused, "Admit") {
		t.Fatalf("an Admit decree applied: %+v", res)
	}
	if res := r.applyDecreeEntry(r.entryFor(r.decree(cdsdecree.Genesis))); res.Refused == "" {
		t.Fatal("a second Genesis started the cluster again")
	}
}

// A cluster that starts again resumes above every version an earlier life of
// it reached, so a decree of that life never applies to this one.
func TestRecoverResumesAboveTheVersionTheOperatorNames(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	lost := r.decree(cdsdecree.UpdateMeasurements)

	carryOn := r.decree(cdsdecree.Recover)
	carryOn.ResumeVersion = r.ClusterState().Version + 40
	if res := r.applyDecreeEntry(r.entryFor(carryOn)); res.Refused != "" || res.Version != carryOn.ResumeVersion+1 {
		t.Fatalf("recover: %+v, want version %d", res, carryOn.ResumeVersion+1)
	}
	if res := r.applyDecreeEntry(r.entryFor(lost)); res.Refused == "" {
		t.Fatal("a decree signed for the cluster's earlier life applied")
	}
}

// A cluster that starts again names its start time, which is the later of the
// operator's signature and the leader's stamp.
func TestTheStartTimeIsTheLaterOfTheSignatureAndTheStamp(t *testing.T) {
	r := newReplica(t)
	signed := r.decree(cdsdecree.Genesis)
	signed.IssuedAtMS = time.Now().Add(10 * time.Minute).UnixMilli()
	entry := r.entryFor(signed)
	if res := r.applyDecreeEntry(entry); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if got := r.ClusterState().StartedAtMS; got != signed.IssuedAtMS {
		t.Fatalf("the cluster started at %d, want the operator's %d: a replica clock set back moved it", got, signed.IssuedAtMS)
	}

	later := newReplica(t)
	stamped := later.decree(cdsdecree.Genesis)
	stamped.IssuedAtMS = time.Now().Add(-10 * time.Minute).UnixMilli()
	entry = later.entryFor(stamped)
	if res := later.applyDecreeEntry(entry); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if got := later.ClusterState().StartedAtMS; got != entry.AtMS {
		t.Fatalf("the cluster started at %d, want the leader's stamp %d", got, entry.AtMS)
	}
}

// Node enforcers ignore an allowlist version below the one they hold, so a
// cluster that starts again raises the served version to its start time.
func TestAClusterThatStartsAgainRaisesTheAllowlistVersion(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	start := r.ClusterState().StartedAtMS
	version, err := r.al.Version()
	if err != nil {
		t.Fatal(err)
	}
	served, err := strconv.ParseInt(version, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if served != start {
		t.Fatalf("the allowlist serves version %d, want the cluster's start %d", served, start)
	}

	recovered := r.decree(cdsdecree.Recover)
	recovered.IssuedAtMS = start + time.Hour.Milliseconds()
	if res := r.applyDecreeEntry(r.entryFor(recovered)); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	version, err = r.al.Version()
	if err != nil {
		t.Fatal(err)
	}
	if version != strconv.FormatInt(recovered.IssuedAtMS, 10) {
		t.Fatalf("the allowlist serves version %s after a Recover at %d", version, recovered.IssuedAtMS)
	}
}
