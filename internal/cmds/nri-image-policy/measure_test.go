package nriimagepolicy

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
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
	oldReg, oldKey := openRegister, readOperatorKey
	t.Cleanup(func() { openRegister, readOperatorKey = oldReg, oldKey })
	openRegister = func(teetypes.PlatformType) (runtimemeasure.Register, error) { return reg, nil }
	readOperatorKey = func() ([]byte, error) { return []byte("launch key"), nil }
	return measureConfig{RTMR3: true, JournalPath: filepath.Join(t.TempDir(), "journal")}
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
	// No staged operator key: nothing to seed from, refuse to start.
	cfg = measureFixture(t, &fakeRegister{})
	readOperatorKey = func() ([]byte, error) { return nil, credrelease.ErrNoOperatorKey }
	if _, err := openMeasurer(cfg, "tdx"); !errors.Is(err, credrelease.ErrNoOperatorKey) {
		t.Fatalf("missing operator key: %v", err)
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

// A tag resolves once per start: the digest measured is the one admitted,
// even if the tag moves between the checks and the measurement.
func TestStartContainerMeasuresTheAdmittedDigest(t *testing.T) {
	reg := &fakeRegister{value: runtimemeasure.Seed([]byte("launch key"))}
	m, err := openMeasurer(measureFixture(t, reg), "tdx")
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "base"})}})
	p.SetReady()
	p.measurer = m
	answers := []string{pushDigestA, pushDigestB}
	p.containerd = &fakeContainerd{resolve: func(context.Context, string) (string, error) {
		if len(answers) == 0 {
			t.Fatal("tag resolved more than twice")
		}
		d := answers[0]
		answers = answers[1:]
		return d, nil
	}}
	pod := makePod("default", "pod")
	if err := p.StartContainer(context.Background(), pod, makeCtrWithImage(pod.Id, "ctr", "registry/repo:latest")); err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 {
		t.Fatalf("resolved the tag %d times in one start, want 1", 2-len(answers))
	}
	if reg.value != runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed([]byte("launch key")), []string{pushDigestA}) {
		t.Fatal("measured a digest other than the admitted one")
	}
}
