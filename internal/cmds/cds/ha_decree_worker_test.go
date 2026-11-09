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
	"io"
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
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
)

// workerFiles are a worker document pinning a cluster's CDS, the worker image
// it launches, and a set in force whose every entry binds a launch.
type workerFiles struct {
	flags    workerFlags
	nodes    string
	document []byte
}

func newWorkerFiles(t *testing.T, cdsPin []byte) workerFiles {
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
	return workerFiles{
		flags: workerFlags{
			document: filepath.Join(dir, "worker.yaml"),
			image:    filepath.Join(dir, "worker-image.json"),
		},
		nodes:    filepath.Join(dir, "nodes.json"),
		document: document,
	}
}

// workerAdmission is a node-images decree for c that also certifies the
// workers launched with a worker document pinning cdsPin.
type workerAdmission struct {
	o        nodeImagesOptions
	document []byte
}

func newWorkerAdmission(t *testing.T, c operatorCluster, cdsPin []byte) workerAdmission {
	t.Helper()
	files := newWorkerFiles(t, cdsPin)
	return workerAdmission{
		o: nodeImagesOptions{
			decreeOptions: c.options(t),
			nodes:         files.nodes,
			worker:        files.flags,
			to:            c.replicaServing(t, nil),
		},
		document: files.document,
	}
}

// newWorkersCluster is a replica set whose launch file names no nodes, as a
// cluster of workers boots before its first worker.
func newWorkersCluster(t *testing.T) operatorCluster {
	t.Helper()
	key, operatorPEM := operatorKeyPair(t)
	var document map[string]any
	if err := yaml.Unmarshal(replicatedDocument(t, operatorPEM), &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "nodes")
	config, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return newOperatorClusterBooting(t, key, operatorPEM, config)
}

// workerGenesis is a Genesis decree for c's unjoined replica that admits the
// worker document worker names.
func workerGenesis(t *testing.T, c operatorCluster, worker workerFlags) genesisOptions {
	t.Helper()
	o := c.options(t)
	o.baseVersion = 0
	return genesisOptions{
		decreeOptions: o,
		pins:          pinFlags{platform: "sev-snp", vcpus: []int{2}, manifests: []string{snpManifest(t, smp2Digest)}},
		worker:        worker,
		target:        c.replicaServing(t, map[string]any{statusPath: c.unjoined()}),
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
		CDS: cmdsutil.CDS{
			Address:      "cds.acme.example:8443",
			Measurements: string(cdsPin),
			PinFloor:     1,
		},
		TLSSAN: "c8s-router.c8s-router.svc",
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

// runAnswering runs a decree command with answer on stdin, and returns what it
// printed and prompted.
func runAnswering(t *testing.T, answer string, run func(*cobra.Command) error) (stdout, stderr string, err error) {
	t.Helper()
	var out, prompt strings.Builder
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	cmd.SetIn(strings.NewReader(answer))
	cmd.SetOut(&out)
	cmd.SetErr(&prompt)
	err = run(cmd)
	return out.String(), prompt.String(), err
}

func TestNodeImagesDecreeCertifiesAConfirmedWorkerDocument(t *testing.T) {
	c := newOperatorCluster(t)
	w := newWorkerAdmission(t, c, pinOf(t, c))
	_, stderr, err := runAnswering(t, "y\n", w.o.run)
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
		if _, _, err := runAnswering(t, answer, w.o.run); err == nil || !strings.Contains(err.Error(), "not signed") {
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
	stdout, stderr, err := runAnswering(t, "y\n", w.o.run)
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

// Cobra refuses a worker image without its document, and the reverse, before
// any decree is built; a Genesis starts from --nodes or a worker document.
func TestWorkerDecreesRefuseFlagsThatDoNotGoTogether(t *testing.T) {
	nodeImages := []string{"--config", "c", "--operator-key", "k", "--base-version", "1", "--to", "r", "--cds-pin", "p", "--nodes", "n"}
	genesis := []string{"--config", "c", "--operator-key", "k", "--target", "r", "--cds-pin", "p", "--platform", "tdx", "--image-manifest", "m", "--resume-version", "0"}
	for _, tc := range []struct {
		cmd  *cobra.Command
		args []string
		want string
	}{
		{newNodeImagesCmd(), append(nodeImages, "--worker-document", "w"), "[worker-document worker-image]"},
		{newNodeImagesCmd(), append(nodeImages, "--worker-image", "i"), "[worker-document worker-image]"},
		{newGenesisCmd(), append(genesis, "--worker-document", "w"), "[worker-document worker-image]"},
		{newGenesisCmd(), append(genesis, "--worker-image", "i"), "[worker-document worker-image]"},
		{newGenesisCmd(), append(genesis, "--nodes", "n", "--worker-document", "w", "--worker-image", "i"), "[nodes worker-document]"},
	} {
		tc.cmd.SetArgs(tc.args)
		tc.cmd.SetOut(io.Discard)
		tc.cmd.SetErr(io.Discard)
		if err := tc.cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s %q: got %v, want the flags %s refused", tc.cmd.Name(), tc.args, err, tc.want)
		}
	}
}

// A cluster of workers starts out certifying its first worker document.
func TestGenesisDecreeCertifiesAConfirmedFirstWorkerDocument(t *testing.T) {
	c := newWorkersCluster(t)
	files := newWorkerFiles(t, pinOf(t, c))
	o := workerGenesis(t, c, files.flags)
	_, stderr, err := runAnswering(t, "y\n", o.run)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "[y/N]") {
		t.Fatalf("the Genesis was signed without a prompt:\n%s", stderr)
	}
	decree := c.signed(t, o.out).Decree
	certified, err := decree.NodePins.Images()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(files.document)
	if decree.Kind != cdsdecree.Genesis || len(certified.Images) != 1 || !bytes.Equal(certified.Images[0].LaunchFileDigest, digest[:]) {
		t.Fatalf("the %s decree certifies %+v, want the worker image bound to the document alone", decree.Kind, certified.Images)
	}
}

func TestGenesisDecreeSignsNoWorkerDocumentUnconfirmed(t *testing.T) {
	c := newWorkersCluster(t)
	o := workerGenesis(t, c, newWorkerFiles(t, pinOf(t, c)).flags)
	if _, _, err := runAnswering(t, "n\n", o.run); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("got %v, want the Genesis left unsigned", err)
	}
	if _, err := os.Stat(o.out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the unconfirmed Genesis was written: %v", err)
	}
}

// A worker document starts only a cluster whose configuration names no nodes,
// rather than replacing the ones it names.
func TestGenesisDecreeStartsFromAWorkerDocumentOnlyWithoutConfiguredNodes(t *testing.T) {
	c := newOperatorCluster(t)
	o := workerGenesis(t, c, newWorkerFiles(t, pinOf(t, c)).flags)
	if _, _, err := runAnswering(t, "y\n", o.run); err == nil || !strings.Contains(err.Error(), "the configuration names nodes") {
		t.Fatalf("got %v, want the worker document refused beside configured nodes", err)
	}
	if _, err := os.Stat(o.out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the refused Genesis was written: %v", err)
	}
}

func TestGenesisDecreeRefusesToCertifyNoNode(t *testing.T) {
	c := newWorkersCluster(t)
	o := workerGenesis(t, c, workerFlags{})
	if _, _, err := runAnswering(t, "y\n", o.run); err == nil || !strings.Contains(err.Error(), "--worker-document") {
		t.Fatalf("got %v, want a Genesis certifying no node refused", err)
	}
	if _, err := os.Stat(o.out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a Genesis certifying no node was written: %v", err)
	}
}
