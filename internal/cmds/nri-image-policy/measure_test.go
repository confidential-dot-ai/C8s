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
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
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

var launchSeed = runtimemeasure.Seed([]byte("launch key"))

// measureFixture is a pod-role config over reg: the staged launch key is
// "launch key" and the journal directory is a fresh temp dir.
func measureFixture(t *testing.T, reg *fakeRegister) *config {
	t.Helper()
	origKey, origOpen := readOperatorKey, openRegister
	t.Cleanup(func() { readOperatorKey, openRegister = origKey, origOpen })
	readOperatorKey = func() ([]byte, error) { return []byte("launch key"), nil }
	openRegister = func(teetypes.PlatformType) (runtimemeasure.Register, error) { return reg, nil }
	return &config{
		Platform:       "tdx",
		Measure:        measureConfig{RTMR3: true},
		WorkloadClaims: workloadClaimsConfig{SocketDir: t.TempDir()},
	}
}

func journalPath(cfg *config) string {
	return filepath.Join(cfg.WorkloadClaims.SocketDir, armtls.MeasuredPoliciesJournal)
}

func TestOpenMeasurerGating(t *testing.T) {
	reg := &fakeRegister{value: launchSeed}
	cfg := measureFixture(t, reg)
	cfg.Measure.RTMR3 = false
	if m, err := openMeasurer(cfg, discardLogger()); m != nil || err != nil {
		t.Fatalf("disabled: %v %v", m, err)
	}
	cfg.Measure.RTMR3 = true
	cfg.Platform = "snp"
	if m, err := openMeasurer(cfg, discardLogger()); m != nil || err != nil {
		t.Fatalf("no runtime register: %v %v", m, err)
	}
	cfg.Platform = "tdx"
	// The register holds only the launch-key seed: reconciles, and the
	// journal is readable to the non-root readers before the first measure.
	m, err := openMeasurer(cfg, discardLogger())
	if err != nil || m == nil {
		t.Fatalf("seeded register: %v", err)
	}
	if info, err := os.Stat(journalPath(cfg)); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("journal = %v, %v; want an empty 0644 file", info, err)
	}
	// The runtime directory may not exist yet on the first start of a boot:
	// opening creates it rather than failing the plugin.
	cfg.WorkloadClaims.SocketDir = filepath.Join(cfg.WorkloadClaims.SocketDir, "not-yet", "nri-image-policy")
	if _, err := openMeasurer(cfg, discardLogger()); err != nil {
		t.Fatalf("missing runtime directory: %v", err)
	}
	if info, err := os.Stat(journalPath(cfg)); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("journal in a created directory = %v, %v; want 0644", info, err)
	}
	// No staged launch key: nothing to seed from.
	readOperatorKey = func() ([]byte, error) { return nil, errors.New("no key") }
	if _, err := openMeasurer(cfg, discardLogger()); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Fatalf("missing anchor: %v", err)
	}
	// An unexplained extend: refuse to start.
	cfg = measureFixture(t, &fakeRegister{value: runtimemeasure.Seed([]byte("other key"))})
	if _, err := openMeasurer(cfg, discardLogger()); err == nil || !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("diverged register: %v", err)
	}
}

// A journal that recorded a digest the register never received is an extend
// the plugin was killed in the middle of: opening finishes it, and the digest
// is not measured twice.
func TestPodRoleJournalReconcilesAfterInterruptedExtend(t *testing.T) {
	d1, d2 := testDigest, "sha256:"+strings.Repeat("c", 64)
	reg := &fakeRegister{value: runtimemeasure.FromDigestsSeeded(launchSeed, []string{d1})}
	cfg := measureFixture(t, reg)
	if err := os.WriteFile(journalPath(cfg), []byte(d1+"\n"+d2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := openMeasurer(cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	want := runtimemeasure.FromDigestsSeeded(launchSeed, []string{d1, d2})
	if reg.value != want {
		t.Fatal("opening did not finish the interrupted extend")
	}
	if extended, err := m.MeasureOnce(d2); err != nil || extended {
		t.Fatalf("MeasureOnce(d2) = %v, %v; want already measured", extended, err)
	}
	if reg.value != want {
		t.Fatal("measured d2 twice")
	}
	if info, err := os.Stat(journalPath(cfg)); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("journal = %v, %v; want 0644", info, err)
	}
}

func TestMeasureStartedExtendsAndDeniesOnFailure(t *testing.T) {
	reg := &fakeRegister{value: launchSeed}
	m, err := openMeasurer(measureFixture(t, reg), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{measurer: m, containerd: &fakeContainerd{}}
	if err := p.measureStarted(context.Background(), "busybox@"+testDigest); err != nil {
		t.Fatal(err)
	}
	if reg.value != runtimemeasure.FromDigestsSeeded(launchSeed, []string{testDigest}) {
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

// Certificates carry at most armtls.MaxRuntimeExtensions digests: the guest
// refuses the workload that would push the list past that, and still admits
// an image it already measured.
func TestMeasureOnceRefusesBeyondTheCertificateCap(t *testing.T) {
	reg := &fakeRegister{value: launchSeed}
	m, err := openMeasurer(measureFixture(t, reg), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	digests := make([]string, armtls.MaxRuntimeExtensions)
	for i := range digests {
		digests[i] = "sha256:" + strings.Repeat("0", 56) + string([]byte{hexDigit(i >> 12), hexDigit(i >> 8), hexDigit(i >> 4), hexDigit(i)}) + "0000"
		if _, err := m.MeasureOnce(digests[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.MeasureOnce(testDigest); err == nil || !strings.Contains(err.Error(), "most its certificates can carry") {
		t.Fatalf("over the cap: %v", err)
	}
	if extended, err := m.MeasureOnce(digests[0]); err != nil || extended {
		t.Fatalf("already measured at the cap: %v, %v", extended, err)
	}
}

func hexDigit(v int) byte { return "0123456789abcdef"[v&0xf] }

// A tag resolves once per start: the digest measured is the one admitted,
// even if the tag moves between the checks and the measurement.
func TestStartContainerMeasuresTheAdmittedDigest(t *testing.T) {
	reg := &fakeRegister{value: launchSeed}
	m, err := openMeasurer(measureFixture(t, reg), discardLogger())
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
	if reg.value != runtimemeasure.FromDigestsSeeded(launchSeed, []string{pushDigestA}) {
		t.Fatal("measured a digest other than the admitted one")
	}
}
