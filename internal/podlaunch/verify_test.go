package podlaunch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/launchbinding"
)

type imageWithoutDigests struct{ runtimemeasure.ImageIdentity }

func (imageWithoutDigests) LaunchDigests() []runtimemeasure.LaunchVariant { return nil }

func loadIdentity(t *testing.T, measured launchbinding.MeasuredIdentity, err error) {
	t.Helper()
	old := loadMeasuredIdentity
	t.Cleanup(func() { loadMeasuredIdentity = old })
	loadMeasuredIdentity = func(context.Context, string, string, string) (launchbinding.MeasuredIdentity, error) {
		return measured, err
	}
}

// Every refusal of Verify, one row per check. None stages anything.
func TestVerifyFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) Config
		want  string
	}{
		{"unknown platform", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			cfg.Platform = "sgx"
			return cfg
		}, "platform must be tdx or snp"},
		{"no signature path", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			cfg.SignaturePath = ""
			return cfg
		}, "both --config and --signature"},
		{"missing document", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			cfg.DocumentPath = filepath.Join(t.TempDir(), "absent.yaml")
			return cfg
		}, "absent.yaml"},
		{"empty signature", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			cfg.SignaturePath = writeFile(t, "launch.yaml.sig", "")
			return cfg
		}, "must be a regular file"},
		{"self-report failure", func(t *testing.T) Config {
			doc, key, _ := testPodDocument(t, "tdx")
			loadIdentity(t, launchbinding.MeasuredIdentity{}, errors.New("attestation-api down"))
			return testConfig(t, doc, key)
		}, "verify this boot's identity: attestation-api down"},
		{"keyless boot", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			measured := testMeasuredIdentity(t, doc, pub)
			measured.OperatorKey, measured.OperatorKeyErr = nil, launchbinding.ErrNoOperatorKey
			loadIdentity(t, measured, nil)
			return testConfig(t, doc, key)
		}, "requires a measured launch key"},
		{"measured key is not a public key", func(t *testing.T) Config {
			doc, key, _ := testPodDocument(t, "tdx")
			testLoader(t, doc, "not a key")
			return testConfig(t, doc, key)
		}, "measured launch key"},
		{"signed by another key", func(t *testing.T) Config {
			doc, _, pub := testPodDocument(t, "tdx")
			other, _ := testKey(t)
			testLoader(t, doc, pub)
			return testConfig(t, doc, other)
		}, "launch configuration signature"},
		{"signed but invalid document", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			testLoader(t, doc, pub)
			doc.ClusterID = "Cluster_One"
			return testConfig(t, doc, key)
		}, "clusterID"},
		{"another platform than this boot", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			testLoader(t, doc, pub)
			cfg := testConfig(t, doc, key)
			cfg.Platform = "snp"
			return cfg
		}, "launch image platform does not match"},
		{"no image identity", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			measured := testMeasuredIdentity(t, doc, pub)
			measured.Image = nil
			loadIdentity(t, measured, nil)
			return testConfig(t, doc, key)
		}, "no image identity"},
		{"no launch digests", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			measured := testMeasuredIdentity(t, doc, pub)
			measured.Image = imageWithoutDigests{measured.Image}
			loadIdentity(t, measured, nil)
			return testConfig(t, doc, key)
		}, "no launch digests"},
		{"another measurement", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			booted := doc
			booted.Image.Measurement = strings.Repeat("aa", 48)
			testLoader(t, booted, pub)
			return testConfig(t, doc, key)
		}, "launch image measurement does not match"},
		{"another RTMR[2]", func(t *testing.T) Config {
			doc, key, pub := testPodDocument(t, "tdx")
			booted := doc
			booted.Image.RTMRs = map[int]string{1: doc.Image.RTMRs[1], 2: strings.Repeat("aa", 48)}
			testLoader(t, booted, pub)
			return testConfig(t, doc, key)
		}, "RTMR[2] does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.setup(t)
			if err := Stage(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			requireAbsent(t, cfg.path(PodMarker))
			requireAbsent(t, cfg.path(DefaultStagedPath))
		})
	}
}

// The stage command reports a refused document.
func TestStageCmdRefuses(t *testing.T) {
	doc, _, pub := testPodDocument(t, "tdx")
	testLoader(t, doc, pub)
	other, _ := testKey(t)
	bad := testConfig(t, doc, other)
	err := runBundleCmd(t, "stage", "--platform", "tdx", "--config", bad.DocumentPath, "--signature", bad.SignaturePath)
	if err == nil || !strings.Contains(err.Error(), "launch configuration signature") {
		t.Fatalf("got %v, want a signature refusal", err)
	}
}

// A stale output Stage cannot remove refuses the stage before verification.
func TestStageRefusesUnremovableOutput(t *testing.T) {
	doc, key, pub := testPodDocument(t, "tdx")
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := os.MkdirAll(filepath.Join(cfg.path(PodMarker), "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Stage(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "remove stale "+PodMarker) {
		t.Fatalf("got %v, want the stale marker named", err)
	}
	requireAbsent(t, cfg.path(DefaultStagedPath))
}

// A failed write never publishes the marker.
func TestStageVerifiedWriteFailures(t *testing.T) {
	doc, _, pub := testPodDocument(t, "tdx")
	verified := &Verified{document: doc, operatorPub: []byte(pub)}
	for _, tc := range []struct {
		name  string
		block func(cfg Config) error
		want  string
	}{
		{"output parent is a file", func(cfg Config) error {
			return os.WriteFile(cfg.path("/run"), nil, 0o600)
		}, "create output parent"},
		{"output is a non-empty directory", func(cfg Config) error {
			return os.MkdirAll(filepath.Join(cfg.path(Dir+"/operator-pubkey"), "child"), 0o700)
		}, "stage " + Dir + "/operator-pubkey"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{RootDir: t.TempDir()}
			if err := tc.block(cfg); err != nil {
				t.Fatal(err)
			}
			if err := stageVerified(cfg, verified); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(cfg.path(PodMarker)); err == nil {
				t.Fatal("a failed stage published the marker")
			}
		})
	}
}

func TestConfigPathWithoutRoot(t *testing.T) {
	if got := (Config{}).path(PodMarker); got != PodMarker {
		t.Fatalf("path = %q, want %q", got, PodMarker)
	}
}
