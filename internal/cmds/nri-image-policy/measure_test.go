package nriimagepolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

type fakeRegister struct {
	value [runtimemeasure.Size]byte
	fail  error
}

func (r *fakeRegister) Extend(event []byte) error {
	if r.fail != nil {
		return r.fail
	}
	r.value = runtimemeasure.Extend(r.value, [runtimemeasure.Size]byte(event))
	return nil
}

func (r *fakeRegister) Extension() ([]byte, error) { return r.value[:], nil }

const testDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func measureFixture(t *testing.T, reg *fakeRegister) measureConfig {
	t.Helper()
	dir := t.TempDir()
	pub := filepath.Join(dir, "pubkey")
	if err := os.WriteFile(pub, []byte("launch key"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := openRegister
	t.Cleanup(func() { openRegister = old })
	openRegister = func(teetypes.PlatformType) (runtimemeasure.Register, error) { return reg, nil }
	return measureConfig{RTMR3: true, JournalPath: filepath.Join(dir, "journal"), LaunchPubkey: pub}
}

func TestOpenMeasurerGating(t *testing.T) {
	if m, err := openMeasurer(measureConfig{}, "tdx"); m != nil || err != nil {
		t.Fatalf("disabled: %v %v", m, err)
	}
	if _, err := openMeasurer(measureConfig{RTMR3: true}, "tdx"); err == nil {
		t.Fatal("enabled without paths")
	}
	// The register holds only the launch-key seed: reconciles.
	reg := &fakeRegister{value: runtimemeasure.Seed([]byte("launch key"))}
	cfg := measureFixture(t, reg)
	if m, err := openMeasurer(cfg, "tdx"); err != nil || m == nil {
		t.Fatalf("seeded register: %v", err)
	}
	// An unexplained extend: refuse to start.
	reg2 := &fakeRegister{value: runtimemeasure.Seed([]byte("other key"))}
	cfg = measureFixture(t, reg2)
	if _, err := openMeasurer(cfg, "tdx"); err == nil || !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("diverged register: %v", err)
	}
}

func TestMeasureStartedExtendsAndDeniesOnFailure(t *testing.T) {
	reg := &fakeRegister{value: runtimemeasure.Seed([]byte("launch key"))}
	m, err := openMeasurer(measureFixture(t, reg), "tdx")
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{measurer: m, containerd: &fakeContainerd{}}
	if err := p.measureStarted(context.Background(), "busybox@"+testDigest); err != nil {
		t.Fatal(err)
	}
	if reg.value != runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed([]byte("launch key")), []string{testDigest}) {
		t.Fatal("register does not hold seed + digest")
	}
	reg.fail = errors.New("tsm write failed")
	other := "sha256:" + strings.Repeat("c", 64)
	if err := p.measureStarted(context.Background(), other); err == nil {
		t.Fatal("extend failure admitted the container")
	}
	p = &plugin{measurer: m, containerd: &fakeContainerd{resolve: func(context.Context, string) (string, error) {
		return "", errors.New("no such image")
	}}}
	if err := p.measureStarted(context.Background(), "busybox:latest"); err == nil {
		t.Fatal("unresolvable digest admitted the container")
	}
	if err := (&plugin{}).measureStarted(context.Background(), "busybox:latest"); err != nil {
		t.Fatal("disabled measurement must be a no-op")
	}
}
