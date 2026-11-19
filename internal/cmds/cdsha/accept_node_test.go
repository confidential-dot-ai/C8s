//go:build !c8s_node

package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// nodeFixture is a one-replica chain whose accepted build pins a real CDS
// configuration, and a worker document that pins that build and the genesis.
type nodeFixture struct {
	chain    *verifiedChain
	state    *cdschain.State
	doc      worker.Document
	image    []byte
	launched remote.ImagePin
}

func newNodeFixture(t *testing.T) nodeFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := cdschain.PublicKeyPEM(&key.PublicKey)
	keys, err := operatorauth.ParseKeyBundle([]byte(pub))
	if err != nil {
		t.Fatal(err)
	}
	workloads, err := cdsconfig.MergeWorkloads([]byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	launched := remote.ImagePin{Name: "node", Digest: bytes.Repeat([]byte{0x11}, refvalues.DigestSize), Anchor: []byte(pub)}
	nodes := mustFormat(t, refvalues.ReferenceValues{Family: teetypes.FamilySNP, Images: []remote.ImagePin{launched}})
	config, err := cdsconfig.Format(cdsconfig.Document{
		ClusterID: "lane", OperatorKeys: keys, Workloads: workloads, Nodes: nodes,
		NodeCIDRs: []string{"192.168.0.0/16"}, LeafDNSNames: []string{"c8s.acme.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pin := mustFormat(t, refvalues.ReferenceValues{Family: teetypes.FamilySNP, Images: []remote.ImagePin{
		{Name: "cds", Digest: bytes.Repeat([]byte{0x50}, refvalues.DigestSize), LaunchFile: config},
	}})
	payload, _ := json.Marshal(cdschain.Genesis{Endpoints: []string{"a:1"}, Members: []string{pub}, OperatorKeys: pub, CAKey: pub,
		Accepted: []cdschain.Build{{Measurements: string(pin), Version: "v1.0.0"}}})
	genesis, err := cdschain.Sign(key, cdschain.Body{Cluster: "lane", Type: cdschain.TypeGenesis, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	state, err := cdschain.VerifyGenesis(genesis)
	if err != nil {
		t.Fatal(err)
	}
	return nodeFixture{
		chain: &verifiedChain{Genesis: genesis, Hashes: []cdschain.Hash{genesis.Hash()}, state: state},
		state: state,
		doc: worker.Document{
			SchemaVersion: worker.SchemaVersion,
			CDS:           cmdsutil.CDS{Address: "cds.acme.example:8443", Measurements: string(pin), Chain: "0:" + genesis.Hash().String()},
			TLSSAN:        "c8s.acme.example",
			Kubernetes: worker.Kubernetes{
				APIServer:     "acme.k8s.example:443",
				CACertificate: testCA(t),
				PodCIDR:       "10.52.0.0/16",
				ServiceCIDR:   "10.53.0.0/16",
				ClusterDNS:    "10.53.0.10",
			},
		},
		image:    mustFormat(t, refvalues.ReferenceValues{Family: teetypes.FamilySNP, Images: []remote.ImagePin{{Name: "worker", Digest: bytes.Repeat([]byte{0x77}, refvalues.DigestSize)}}}),
		launched: launched,
	}
}

func mustFormat(t *testing.T, values refvalues.ReferenceValues) []byte {
	t.Helper()
	data, err := refvalues.Format(values)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kubernetes"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func marshal(t *testing.T, doc worker.Document) []byte {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A worker document that pins this chain and an accepted build is admitted
// onto the set the chain certifies (the launch file's before a nodes entry,
// the newest entry's after one), the worker image bound to its digest; the
// chain takes the result.
func TestAcceptNodeExtendsTheSetTheChainCertifies(t *testing.T) {
	f := newNodeFixture(t)
	document := marshal(t, f.doc)
	a, err := admitOnChain(f.chain, f.state, document, f.image)
	if err != nil {
		t.Fatal(err)
	}
	set, err := refvalues.Parse(a.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(document)
	if len(set.Images) != 2 || set.Images[0].Name != f.launched.Name || !bytes.Equal(set.Images[1].LaunchFileDigest, digest[:]) {
		t.Fatalf("admitted set = %+v, want the launch file's node and the worker bound to the document", set.Images)
	}
	if err := cdschain.CheckNodes(a.Nodes); err != nil {
		t.Fatal(err)
	}

	// After a nodes entry, a second document extends that entry's set.
	f.state.Nodes = string(a.Nodes)
	second := f.doc
	second.TLSSAN = "c8s.acme.example"
	second.Kubernetes.CACertificate = testCA(t)
	b, err := admitOnChain(f.chain, f.state, marshal(t, second), f.image)
	if err != nil {
		t.Fatal(err)
	}
	if set, _ := refvalues.Parse(b.Nodes); len(set.Images) != 3 {
		t.Fatalf("second admission = %d images, want the entry's two and one more", len(set.Images))
	}
}

// Each row must refuse.
func TestAcceptNodeRefusesADocumentForAnotherSet(t *testing.T) {
	f := newNodeFixture(t)
	other := mustFormat(t, refvalues.ReferenceValues{Family: teetypes.FamilySNP, Images: []remote.ImagePin{
		{Name: "cds", Digest: bytes.Repeat([]byte{0x51}, refvalues.DigestSize), LaunchFile: f.state.Pins().Images[0].LaunchFile},
	}})
	for name, edit := range map[string]func(*worker.Document){
		"no chain pin":          func(d *worker.Document) { d.CDS.Chain = "" },
		"another chain's entry": func(d *worker.Document) { d.CDS.Chain = "0:" + strings.Repeat("ab", 32) },
		"an entry past the head": func(d *worker.Document) {
			d.CDS.Chain = "1:" + f.chain.Hashes[0].String()
		},
		"a CDS build the chain does not accept": func(d *worker.Document) { d.CDS.Measurements = string(other) },
	} {
		doc := f.doc
		edit(&doc)
		if _, err := admitOnChain(f.chain, f.state, marshal(t, doc), f.image); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	if _, err := admitOnChain(f.chain, f.state, marshal(t, f.doc), f.image); err != nil {
		t.Fatalf("negative control: %v", err)
	}
}
