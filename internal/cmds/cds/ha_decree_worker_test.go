package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
)

// workerAdmission is a node-images decree for c that also certifies the
// workers launched with a worker document pinning cdsPin.
type workerAdmission struct {
	o        nodeImagesOptions
	document []byte
}

func newWorkerAdmission(t *testing.T, c operatorCluster, cdsPin []byte) workerAdmission {
	t.Helper()
	dir := t.TempDir()
	document := workerDocument(t, cdsPin)
	image, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilyTDX, Images: []remote.ImagePin{{
		Name:      "worker",
		Digest:    bytes.Repeat([]byte{0x77}, refvalues.DigestSize),
		Registers: map[int][]byte{1: bytes.Repeat([]byte{0x71}, refvalues.DigestSize), 2: bytes.Repeat([]byte{0x72}, refvalues.DigestSize)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string][]byte{"worker.yaml": document, "worker-image.json": image, "nodes.json": boundNodes(t, upgradingNodesDocument)}
	for name, data := range paths {
		writeTestFile(t, filepath.Join(dir, name), data)
	}
	return workerAdmission{
		o: nodeImagesOptions{
			decreeOptions:  c.options(t),
			nodes:          filepath.Join(dir, "nodes.json"),
			workerDocument: filepath.Join(dir, "worker.yaml"),
			workerImage:    filepath.Join(dir, "worker-image.json"),
			to:             c.replicaServing(t, nil),
		},
		document: document,
	}
}

// pinOf is c's CDS pin document.
func pinOf(t *testing.T, c operatorCluster) []byte {
	t.Helper()
	data, err := os.ReadFile(c.cdsPinPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// workerDocument is a worker document pinning the CDS cdsPin pins.
func workerDocument(t *testing.T, cdsPin []byte) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kubernetes"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(worker.Document{
		SchemaVersion: worker.SchemaVersion,
		CDS:           cmdsutil.CDS{Address: "cds.acme.example:8443", Measurements: string(cdsPin), PinFloor: 1},
		TLSSAN:        "c8s-router.c8s-router.svc",
		Kubernetes: worker.Kubernetes{
			APIServer:     "acme.k8s.example:443",
			CACertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			PodCIDR:       "10.52.0.0/16",
			ServiceCIDR:   "10.53.0.0/16",
			ClusterDNS:    "10.53.0.10",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// run runs the decree with answer on stdin, and returns what it printed and
// prompted.
func (w workerAdmission) run(t *testing.T, answer string) (stdout, stderr string, err error) {
	t.Helper()
	var out, prompt strings.Builder
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	cmd.SetIn(strings.NewReader(answer))
	cmd.SetOut(&out)
	cmd.SetErr(&prompt)
	err = w.o.run(cmd)
	return out.String(), prompt.String(), err
}

func TestNodeImagesDecreeCertifiesAConfirmedWorkerDocument(t *testing.T) {
	c := newOperatorCluster(t)
	w := newWorkerAdmission(t, c, pinOf(t, c))
	_, stderr, err := w.run(t, "y\n")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(w.document)
	name := "worker-" + hex.EncodeToString(digest[:6])
	facts := strings.Index(stderr, "API server        acme.k8s.example:443\n")
	set := strings.Index(stderr, "  "+name+"  bound to this document")
	prompt := strings.Index(stderr, "[y/N]")
	if facts < 0 || set < facts || prompt < set {
		t.Fatalf("the facts and the set were not shown before the prompt:\n%s", stderr)
	}
	certified, err := c.signed(t, w.o.out).Decree.NodePins.Images()
	if err != nil {
		t.Fatal(err)
	}
	bound := slices.IndexFunc(certified.Images, func(pin remote.ImagePin) bool {
		return bytes.Equal(pin.LaunchFileDigest, digest[:])
	})
	if len(certified.Images) != 3 || bound < 0 || certified.Images[bound].Name != name {
		t.Fatalf("the decree certifies %+v, want --nodes and the worker image bound to the document", certified.Images)
	}
}

func TestNodeImagesDecreeSignsNothingUnconfirmed(t *testing.T) {
	for _, answer := range []string{"n\n", "\n", ""} {
		c := newOperatorCluster(t)
		w := newWorkerAdmission(t, c, pinOf(t, c))
		if _, _, err := w.run(t, answer); err == nil || !strings.Contains(err.Error(), "not signed") {
			t.Fatalf("answer %q: got %v, want the decree left unsigned", answer, err)
		}
		if _, err := os.Stat(w.o.out); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("answer %q: the unconfirmed decree was written: %v", answer, err)
		}
	}
}

func TestNodeImagesDecreeRefusesAWorkerDocumentPinningAnotherCDS(t *testing.T) {
	c := newOperatorCluster(t)
	other := newOperatorCluster(t)
	w := newWorkerAdmission(t, c, pinOf(t, other))
	stdout, stderr, err := w.run(t, "y\n")
	if err == nil || !strings.Contains(err.Error(), "pins another CDS than --cds-pin") {
		t.Fatalf("got %v, want the document refused", err)
	}
	if stdout != "" || stderr != "" {
		t.Fatalf("a refused document was reported or prompted for:\n%s\n%s", stdout, stderr)
	}
	if _, err := os.Stat(w.o.out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the refused decree was written: %v", err)
	}
}

func TestNodeImagesDecreeTakesAWorkerDocumentOnlyWithItsImage(t *testing.T) {
	c := newOperatorCluster(t)
	for _, tc := range []struct{ document, image string }{{"worker.yaml", ""}, {"", "worker-image.json"}} {
		w := newWorkerAdmission(t, c, pinOf(t, c))
		w.o.workerDocument, w.o.workerImage = tc.document, tc.image
		if _, _, err := w.run(t, "y\n"); err == nil || !strings.Contains(err.Error(), "go together") {
			t.Fatalf("document %q, image %q: got %v, want the pair refused", tc.document, tc.image, err)
		}
		if _, err := os.Stat(w.o.out); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("document %q, image %q: the decree was written: %v", tc.document, tc.image, err)
		}
	}
}
