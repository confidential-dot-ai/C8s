package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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
// booted with, the operator key whose decrees they obey, the key their
// backups seal to, and the mesh CA the target of their Genesis minted.
type cluster struct {
	launch   Launch
	operator *ecdsa.PrivateKey
	recovery *ecdsa.PrivateKey
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
	recovery, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		recovery: recovery,
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
		d.NodePins = testNodeImages(r.t, 0x33)
		d.TargetMember = testMember
		d.TargetAddress = "10.0.0.5:8444"
		d.IssuedAtMS = time.Now().UnixMilli()
		d.GenesisCA = certutil.CertFingerprint(r.minted.Cert.Raw)
	case cdsdecree.UpdateMeasurements:
		d.BaseVersion = version
		d.CDSPins = testPins(r.t, 0x22)
	case cdsdecree.SetNodeImages:
		d.BaseVersion = version
		d.NodePins = testNodeImages(r.t, 0x44)
	case cdsdecree.RotateKey:
		d.BaseVersion = version
	case cdsdecree.SetVoters:
		d.BaseVersion = version
		d.Voters = 1
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

// testPins pins CDS images to the launch file every replica boots.
func testPins(t *testing.T, digests ...byte) *cdsdecree.PinDocument {
	t.Helper()
	images := make([]remote.ImagePin, 0, len(digests))
	for _, digest := range digests {
		images = append(images, remote.ImagePin{
			Name:       fmt.Sprintf("cds-%02x", digest),
			Digest:     bytes.Repeat([]byte{digest}, refvalues.DigestSize),
			LaunchFile: []byte(launchFile),
		})
	}
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: images,
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

// The node images bind no launch file of their own.
func testNodeImages(t *testing.T, digests ...byte) *cdsdecree.NodeImages {
	t.Helper()
	images := make([]remote.ImagePin, 0, len(digests))
	for _, digest := range digests {
		images = append(images, remote.ImagePin{
			Name:   fmt.Sprintf("node-%02x", digest),
			Digest: bytes.Repeat([]byte{digest}, refvalues.DigestSize),
		})
	}
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilyTDX,
		Images: images,
	})
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := cdsdecree.NewNodeImages(document)
	if err != nil {
		t.Fatal(err)
	}
	return nodes
}

// The peer fixtures: this cluster's image and launch file, and another of each.
var (
	testLaunchFile  = []byte(launchFile)
	otherLaunchFile = []byte("schemaVersion: c8s-cds/v1\nclusterID: other\n")

	testImage  = strings.Repeat("a1", 48)
	otherImage = strings.Repeat("b2", 48)
	testRTMR1  = strings.Repeat("c3", 48)
	testRTMR2  = strings.Repeat("d4", 48)
	otherRTMR1 = strings.Repeat("e5", 48)
)

const testCallTimeout = 10 * time.Second

// snpVerdict is an SEV-SNP launch digest with HOSTDATA bound to file.
func snpVerdict(digest string, file []byte) mockapi.Verdict {
	verdict := mockapi.PassingVerdict(digest)
	bound := runtimemeasure.HostData(file)
	verdict.Claims.InitData = bound[:]
	return verdict
}

// tdxVerdict is snpVerdict for TDX: the MRTD, RTMR[1], RTMR[2], and RTMR[3] bound to file.
func tdxVerdict(mrtd, rtmr1, rtmr2 string, file []byte) mockapi.Verdict {
	verdict := mockapi.PassingVerdict(mrtd)
	bound := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(file), nil)
	verdict.Claims.PlatformData = map[string]any{
		"rtmr_1": rtmr1,
		"rtmr_2": rtmr2,
		"rtmr_3": hex.EncodeToString(bound[:]),
	}
	return verdict
}

// imagePin is one entry of an admission set, bound to file.
func imagePin(t *testing.T, digest string, file []byte) remote.ImagePin {
	t.Helper()
	raw, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatalf("image digest: %v", err)
	}
	return remote.ImagePin{Name: digest[:8], Digest: raw, LaunchFile: file}
}

// admittedImages is what a replica admits, changed while connections are live.
type admittedImages struct {
	mu     sync.Mutex
	pinned []remote.ImagePin
}

func (a *admittedImages) hold(images ...remote.ImagePin) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pinned = images
}

func (a *admittedImages) get() []remote.ImagePin {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.pinned)
}

// testReplica is one CDS VM: its attestation-api, identity and admission set.
type testReplica struct {
	stub     *mockapi.Stub
	attestor attestor
	identity peerIdentity
	member   string
	admits   *admittedImages
	mux      *mux
	answered chan peer
}

// newSNPReplica is a replica of the test image that admits its own image.
func newSNPReplica(t *testing.T, member string) *testReplica {
	t.Helper()
	return newPeerReplica(
		t,
		member,
		teetypes.PlatformSNP,
		snpVerdict(testImage, testLaunchFile),
		time.Now().Add(time.Hour),
	)
}

// newTDXReplica is newSNPReplica for a TDX guest.
func newTDXReplica(t *testing.T, member string, verdict mockapi.Verdict) *testReplica {
	t.Helper()
	return newPeerReplica(t, member, teetypes.PlatformTDX, verdict, time.Now().Add(time.Hour))
}

// newPeerReplica is a replica that peers under platform's verdict.
func newPeerReplica(
	t *testing.T,
	member string,
	platform teetypes.PlatformType,
	verdict mockapi.Verdict,
	notAfter time.Time,
) *testReplica {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetPlatform(platform)
	stub.SetVerdict(verdict)
	a, err := newAttestor(stub.URL(), testCallTimeout)
	if err != nil {
		t.Fatalf("attestation-api on %s: %v", stub.URL(), err)
	}
	identity, err := newPeerIdentity(a, testCluster, member, testLaunchFile, notAfter)
	if err != nil {
		t.Fatalf("mint %s identity: %v", member, err)
	}
	admits := &admittedImages{}
	admits.hold(identity.self)
	return &testReplica{
		stub:     stub,
		attestor: a,
		identity: identity,
		member:   member,
		admits:   admits,
		answered: make(chan peer, 8),
	}
}

// serve starts the replica's peer port on the loopback.
func (r *testReplica) serve(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	endpoint, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("listen address: %v", err)
	}
	r.mux = newMux(
		ln,
		raftAddr{endpoint: endpoint, member: r.member},
		r.certificate,
		r.verifier(),
		r.answer,
	)
	r.mux.serving()
	t.Cleanup(func() { r.mux.Close() })
}

func (r *testReplica) certificate() *tls.Certificate { return &r.identity.certificate }

func (r *testReplica) verifier() peerVerifier {
	return peerVerifier{clusterID: testCluster, attestor: r.attestor, admits: r.admits.get}
}

// judges makes this replica's attestation-api answer verdict from now on.
func (r *testReplica) judges(verdict mockapi.Verdict) { r.stub.SetVerdict(verdict) }

// refuses makes this replica's attestation-api verify nothing further.
func (r *testReplica) refuses(reply mockapi.ErrorReply) { r.stub.SetVerifyError(reply) }

// verdicts counts the verdicts this replica's attestation-api has given.
func (r *testReplica) verdicts() int { return len(r.stub.VerifyRequests()) }

// peerAddress is where this replica's peer port answers.
func (r *testReplica) peerAddress() netip.AddrPort { return r.mux.advert.endpoint }

func (r *testReplica) raftAddress() string { return r.mux.Addr().String() }

// answer reports which peer the control channel handed over, and names the
// member answering, as a replica of the cluster does.
func (r *testReplica) answer(from peer, _ controlRequest) controlAnswer {
	r.answered <- from
	return controlAnswer{Member: r.member}
}
