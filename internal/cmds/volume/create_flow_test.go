package volume

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	intsecrets "github.com/confidential-dot-ai/c8s/internal/secrets"
)

// flowFixture is a source directory, an output path, and an escrow path.
type flowFixture struct {
	dir, src, out, escrow string
}

func newFlowFixture(t *testing.T) flowFixture {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	return flowFixture{dir: dir, src: src, out: filepath.Join(dir, "vol.img"), escrow: filepath.Join(dir, "escrow.json")}
}

func (f flowFixture) config(fake *fakeTools) createConfig {
	return createConfig{
		name:      "weights",
		source:    f.src,
		out:       f.out,
		path:      "/tenant-a/volumes/weights",
		escrowOut: f.escrow,
		run:       fake.run,
	}
}

func captureCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(context.Background())
	return cmd, &out
}

// operatorKeyFile writes a fresh operator private key and returns its path.
func operatorKeyFile(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(dir, "operator.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// A dry run builds the image and writes escrow but never reaches CDS, so an
// operator can produce an artifact offline.
func TestRunCreateDryRunBuildsAndEscrowsWithoutCDS(t *testing.T) {
	f := newFlowFixture(t)
	fake := newFake()
	cfg := f.config(fake)
	cfg.dryRun = true

	cmd, out := captureCmd()
	if err := runCreate(cmd, &options{}, cfg); err != nil {
		t.Fatalf("create: %v", err)
	}

	img, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatalf("image not written: %v", err)
	}
	if len(img) != fake.dataBytes+fake.treeBytes {
		t.Errorf("image is %d bytes, want %d", len(img), fake.dataBytes+fake.treeBytes)
	}
	raw, err := os.ReadFile(f.escrow)
	if err != nil {
		t.Fatalf("escrow not written: %v", err)
	}
	blob, err := DecodeBlob(raw)
	if err != nil {
		t.Fatalf("escrow is not a key blob: %v", err)
	}

	// The escrowed key must be the one the image was encrypted with, or the
	// escrow file recovers nothing.
	key, err := blob.DecodeKey()
	if err != nil {
		t.Fatalf("escrow key: %v", err)
	}
	var plain bytes.Buffer
	if err := decrypt(&plain, bytes.NewReader(img), key); err != nil {
		t.Fatalf("decrypt with escrowed key: %v", err)
	}
	want := append(bytes.Repeat([]byte{0xA5}, fake.dataBytes), bytes.Repeat([]byte{0x5A}, fake.treeBytes)...)
	if !bytes.Equal(plain.Bytes(), want) {
		t.Fatal("escrowed key does not decrypt the image it was written alongside")
	}
	if !strings.Contains(out.String(), "CDS not called") {
		t.Errorf("dry run did not say CDS was skipped: %s", out.String())
	}
}

func TestRunCreateStoresBlobAndPrintsGuidance(t *testing.T) {
	f := newFlowFixture(t)
	fake := newFake()

	var gotPath string
	var gotReq intsecrets.PutRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotReq)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	o := &options{Options: cdsconn.Options{
		URL:         srv.URL,
		Insecure:    true,
		OperatorKey: operatorKeyFile(t, f.dir)}}
	cfg := f.config(fake)
	cfg.node = "node-1"

	cmd, out := captureCmd()
	if err := runCreate(cmd, o, cfg); err != nil {
		t.Fatalf("create: %v", err)
	}

	if gotPath != "/secrets/tenant-a/volumes/weights" {
		t.Errorf("cds path = %q", gotPath)
	}
	if gotReq.Overwrite {
		t.Error("create asked to overwrite")
	}
	raw, err := base64.StdEncoding.DecodeString(gotReq.Value)
	if err != nil {
		t.Fatalf("stored value is not base64: %v", err)
	}
	stored, err := DecodeBlob(raw)
	if err != nil {
		t.Fatalf("stored value is not a key blob: %v", err)
	}

	// What CDS holds and what escrow holds have to be the same key, or a
	// restart recovers a volume nobody can open.
	escrowRaw, err := os.ReadFile(f.escrow)
	if err != nil {
		t.Fatalf("escrow: %v", err)
	}
	escrowed, err := DecodeBlob(escrowRaw)
	if err != nil {
		t.Fatalf("escrow blob: %v", err)
	}
	if stored.Key != escrowed.Key ||
		(stored.Verity == nil) != (escrowed.Verity == nil) ||
		(stored.Verity != nil && *stored.Verity != *escrowed.Verity) {
		t.Fatal("the blob stored in CDS differs from the escrowed one")
	}

	got := out.String()
	for _, want := range []string{"c8s-vol-weights", "kubernetes.io/hostname: node-1", `"read": ["/tenant-a/volumes/weights"]`} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// A CDS refusal must not leave a half-finished volume looking successful.
func TestRunCreateSurfacesCDSRefusal(t *testing.T) {
	f := newFlowFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	o := &options{Options: cdsconn.Options{
		URL: srv.URL, Insecure: true, OperatorKey: operatorKeyFile(t, f.dir)}}
	cmd, _ := captureCmd()
	err := runCreate(cmd, o, f.config(newFake()))
	if err == nil || !strings.Contains(err.Error(), "not replaceable") {
		t.Fatalf("got %v, want a refusal naming the occupied path", err)
	}
	// Escrow is written before CDS, so the key survives a failed store — the
	// image on disk is openable once the path question is resolved.
	if _, statErr := os.Stat(f.escrow); statErr != nil {
		t.Errorf("escrow missing after a CDS refusal: %v", statErr)
	}
}

func TestRunCreateRejectsBadFlagsBeforeBuilding(t *testing.T) {
	f := newFlowFixture(t)
	cfg := f.config(newFake())
	cfg.name = ""
	cmd, _ := captureCmd()
	if err := runCreate(cmd, &options{}, cfg); err == nil {
		t.Fatal("accepted an empty --name")
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Error("an image was built despite invalid flags")
	}
}

func TestExecRunnerPinsEnvAndWrapsFailure(t *testing.T) {
	out, err := execRunner(context.Background(), "sh", "-c", "echo $SOURCE_DATE_EPOCH,$TZ")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "0,UTC" {
		t.Errorf("env = %q, want SOURCE_DATE_EPOCH and TZ pinned", got)
	}
	if _, err := execRunner(context.Background(), "sh", "-c", "echo boom >&2; exit 3"); err == nil {
		t.Fatal("a failing tool reported success")
	} else if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error drops the tool's output: %v", err)
	}
}

// A mutable dry run builds the ext4 image, escrows a key-only blob, and never
// reaches CDS — the same escrow-then-store ordering the immutable path holds.
func TestRunCreateMutableDryRunBuildsAndEscrows(t *testing.T) {
	f := newFlowFixture(t)
	fake := newFake()
	cfg := f.config(fake)
	cfg.dryRun = true
	cfg.mutable = true
	cfg.sizeBytes = 20 << 20

	cmd, out := captureCmd()
	if err := runCreate(cmd, &options{}, cfg); err != nil {
		t.Fatalf("create: %v", err)
	}

	img, err := os.ReadFile(f.out)
	if err != nil {
		t.Fatalf("image not written: %v", err)
	}
	if len(img) != 20<<20 {
		t.Errorf("image is %d bytes, want %d", len(img), 20<<20)
	}
	raw, err := os.ReadFile(f.escrow)
	if err != nil {
		t.Fatalf("escrow not written: %v", err)
	}
	blob, err := DecodeBlob(raw)
	if err != nil {
		t.Fatalf("escrow is not a key blob: %v", err)
	}
	if !blob.Mutable || blob.Verity != nil {
		t.Fatalf("escrow blob = %+v, want mutable with no verity", blob)
	}

	// The escrowed key must decrypt the image, or the escrow recovers nothing.
	key, err := blob.DecodeKey()
	if err != nil {
		t.Fatalf("escrow key: %v", err)
	}
	var plain bytes.Buffer
	if err := decrypt(&plain, bytes.NewReader(img), key); err != nil {
		t.Fatalf("decrypt with escrowed key: %v", err)
	}
	if !bytes.Equal(plain.Bytes(), make([]byte, 20<<20)) {
		t.Fatal("escrowed key does not decrypt the image it was written alongside")
	}
	if !strings.Contains(out.String(), "mutable") {
		t.Errorf("output does not name the volume mutable: %s", out.String())
	}
}

// The mutable path must warn on the artifact itself: the operator is giving up
// tamper detection by choosing it.
func TestPrintResultWarnsThatMutableHasNoIntegrity(t *testing.T) {
	var out bytes.Buffer
	printResult(&out, createConfig{
		name: "scratch", out: "/tmp/vol.img", escrowOut: "/tmp/escrow.json", mutable: true,
	}, "/tenant-a/volumes/scratch", 50<<30, Verity{})
	got := out.String()
	for _, want := range []string{"50Gi", "no integrity protection"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}
