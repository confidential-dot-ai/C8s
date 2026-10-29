package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	testCluster = "lane"
	// launchFile stands in for the measured configuration every replica of
	// the test cluster boots.
	launchFile = "schemaVersion: c8s-cds/v1\nclusterID: lane\n"
	// testMember is the member id a replica minted at its start.
	testMember = "ahn7yq4qnkwftxo6ihoyu2bxpi"
)

// cluster is what every replica of the test cluster shares: the values they
// booted with, the operator key whose decrees they obey, and the mesh CA the
// target of their Genesis minted.
type cluster struct {
	launch   Launch
	operator *ecdsa.PrivateKey
	minted   *issuer.CA
}

// replica is one state machine of that cluster, over stores of its own.
type replica struct {
	*FSM
	cluster
	// al is the allowlist store the state machine writes, as its builder
	// holds it.
	al    *allowlist.Store
	t     *testing.T
	index uint64
}

func newCluster(t *testing.T) cluster {
	t.Helper()
	operator, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(launchFile))
	return cluster{
		launch: Launch{
			ClusterID:    testCluster,
			OperatorKeys: []*ecdsa.PublicKey{&operator.PublicKey},
			ConfigSHA256: hex.EncodeToString(digest[:]),
			Voters:       3,
		},
		operator: operator,
		minted:   mintCA(t),
	}
}

// newReplica is a replica of a cluster of its own, over in-memory stores.
func newReplica(t *testing.T) *replica {
	t.Helper()
	return newCluster(t).replica(
		t,
		inMemoryAllowlist(t),
		secrets.NewMemoryStore(8, 4, 64),
		sandboxledger.New(time.Hour, 8),
	)
}

// replica is another replica of the cluster, over the stores given.
func (c cluster) replica(t *testing.T, al *allowlist.Store, sec *secrets.MemoryStore, led *sandboxledger.Ledger) *replica {
	t.Helper()
	return &replica{
		FSM:     NewFSM(c.launch, al, sec, led),
		cluster: c,
		al:      al,
		t:       t,
	}
}

func inMemoryAllowlist(t *testing.T) *allowlist.Store {
	t.Helper()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	return al
}

// mintCA mints a mesh CA, as a replica does before its Genesis.
func mintCA(t *testing.T) *issuer.CA {
	t.Helper()
	mesh, err := issuer.NewMeshCA("c8s-mesh-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return mesh.Current().CA
}

func (r *replica) apply(e Entry) Result {
	r.t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		r.t.Fatal(err)
	}
	return r.applyRaw(raw)
}

// applyRaw applies bytes as the next log entry, whatever they hold.
func (r *replica) applyRaw(raw []byte) Result {
	r.index++
	return r.Apply(r.index, raw)
}

func (r *replica) applyDecreeEntry(de DecreeEntry) DecreeResult {
	r.t.Helper()
	res := r.apply(Entry{
		Kind:   KindDecree,
		Decree: &de,
	})
	if res.Decree == nil {
		r.t.Fatalf("a decree entry answered no decree result: %+v", res)
	}
	return *res.Decree
}

// genesis starts the cluster, as the target of a Genesis decree does.
func (r *replica) genesis() DecreeResult {
	r.t.Helper()
	res := r.applyDecreeEntry(r.entryFor(r.decree(cdsdecree.Genesis)))
	if res.Refused != "" {
		r.t.Fatalf("genesis: %s", res.Refused)
	}
	return res
}

// decree is what the operator CLI signs for one kind: everything that kind
// must carry, against the cluster's current version.
func (r *replica) decree(kind cdsdecree.Kind) cdsdecree.Decree {
	r.t.Helper()
	version := r.ClusterState().Version
	d := cdsdecree.Decree{
		ClusterID: testCluster,
		IntentID:  cdsdecree.NewIntentID(),
		Kind:      kind,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	switch kind {
	case cdsdecree.Genesis:
		d.CDSPins = testPins(r.t, 0x11)
		d.NodePins = testNodeImages(r.t)
		d.TargetMember = testMember
		d.TargetAddress = "10.0.0.5:8444"
		d.IssuedAtMS = time.Now().UnixMilli()
		d.GenesisCA = certutil.CertFingerprint(r.minted.Cert.Raw)
	case cdsdecree.UpdateMeasurements:
		d.BaseVersion = version
		d.CDSPins = testPins(r.t, 0x22)
	case cdsdecree.RotateKey:
		d.BaseVersion = version
	case cdsdecree.Recover:
		d.BaseVersion = version
		d.TargetMember = testMember
		d.TargetAddress = "10.0.0.5:8444"
		d.IssuedAtMS = time.Now().UnixMilli()
		d.ResumeVersion = version
	case cdsdecree.DismissRecover:
		d.BaseVersion = version
	case cdsdecree.Admit:
		d.CDSPins = testPins(r.t, 0x11)
		d.TargetMember = testMember
	}
	return d
}

// entryFor is the entry a leader logs for a decree: its own clock, the policy
// a Genesis fixes, and the mesh CA the kinds that mint one carry.
func (r *replica) entryFor(d cdsdecree.Decree) DecreeEntry {
	r.t.Helper()
	de := DecreeEntry{
		Decree: r.sign(d),
		AtMS:   time.Now().UnixMilli(),
	}
	if d.Kind == cdsdecree.Genesis {
		de.Policy = r.LocalPolicy()
		de.MeshCACert, de.MeshCAKey = caBytes(r.t, r.minted)
	}
	if d.Kind == cdsdecree.RotateKey {
		de.MeshCACert, de.MeshCAKey = caBytes(r.t, mintCA(r.t))
	}
	return de
}

func (r *replica) sign(d cdsdecree.Decree) cdsdecree.Signed {
	r.t.Helper()
	signed, err := cdsdecree.Sign(d, r.operator)
	if err != nil {
		r.t.Fatal(err)
	}
	return signed
}

// caBytes is a mesh CA as an entry carries it: the certificate in DER and the
// key in PKCS#8.
func caBytes(t *testing.T, ca *issuer.CA) (cert, key []byte) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return ca.Cert.Raw, key
}

// testPins pins one CDS image to the launch file every replica boots.
func testPins(t *testing.T, digest byte) *cdsdecree.PinDocument {
	t.Helper()
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name:       "cds-smp4",
			Digest:     bytes.Repeat([]byte{digest}, refvalues.DigestSize),
			LaunchFile: []byte(launchFile),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pins, err := cdsdecree.NewPinDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

// testNodeImages pins one node image, which binds no launch file of its own.
func testNodeImages(t *testing.T) *cdsdecree.NodeImages {
	t.Helper()
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilyTDX,
		Images: []remote.ImagePin{{
			Name:   "node",
			Digest: bytes.Repeat([]byte{0x33}, refvalues.DigestSize),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	images, err := cdsdecree.NewNodeImages(document)
	if err != nil {
		t.Fatal(err)
	}
	return images
}
