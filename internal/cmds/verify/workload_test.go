package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// testHeldAllowlist is a minimal one-entry policy document; its Canonical()
// bytes are what a client would hold after GET /allowlist.
func testHeldAllowlist(t *testing.T) ([]byte, []byte) {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(`{
		"schema": "c8s.allowlist/v1",
		"workloads": {
			"api": {
				"initContainers": [],
				"containers": [{
					"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"command": {"policy": "any"},
					"args": {"policy": "any"}
				}]
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := al.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	return canonical, digest
}

// caSignedWorkloadLeaf mints a leaf carrying the matched-workload stamp and
// signed by a fresh CA, returning the leaf and CA bundle path — the shape CDS
// produces.
func caSignedWorkloadLeaf(t *testing.T, matched *armtls.MatchedWorkload) (*x509.Certificate, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mesh-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var exts []pkix.Extension
	if matched != nil {
		ext, err := armtls.MarshalMatchedWorkloadExtension(matched)
		if err != nil {
			t.Fatal(err)
		}
		exts = append(exts, ext)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certutil.EncodeCertPEM(caDER), 0o600); err != nil {
		t.Fatal(err)
	}
	return leaf, path
}

// Both workload-policy flags are usage errors without --mesh-ca, exactly like
// --sandbox-id: the stamp is CA-vouched, and pinning without the chain check
// would pin a string the presenter chose.
func TestBuildPolicyWorkloadFlagsRequireMeshCA(t *testing.T) {
	if _, err := buildPolicy(config{workload: "api"}); err == nil {
		t.Fatal("--workload accepted without --mesh-ca")
	}
	if _, err := buildPolicy(config{allowlistFile: "whatever.json"}); err == nil {
		t.Fatal("--allowlist accepted without --mesh-ca")
	}
	// The name checks need a loadable CA: a missing --mesh-ca file errors
	// first and would mask them.
	meshCA := writeMeshCAFile(t)
	if _, err := buildPolicy(config{workload: "not/a/name", meshCA: meshCA}); err == nil || !strings.Contains(err.Error(), "--workload") {
		t.Fatalf("err = %v, want the invalid-entry-name refusal", err)
	}
	if _, err := buildPolicy(config{workload: strings.Repeat("a", 64), meshCA: meshCA}); err == nil || !strings.Contains(err.Error(), "--workload") {
		t.Fatalf("err = %v, want the over-long-name refusal", err)
	}
	if _, err := buildPolicy(config{workload: "api", meshCA: meshCA}); err != nil {
		t.Fatalf("a valid name with a loadable CA must build: %v", err)
	}
}

func TestApplyWorkloadPolicyReportsProvenance(t *testing.T) {
	_, digest := testHeldAllowlist(t)
	matched := &armtls.MatchedWorkload{Name: "api", AllowlistVersion: "4", AllowlistDigest: digest}
	leaf, _ := caSignedWorkloadLeaf(t, matched)
	ev := &evidence{leaf: leaf, workload: matched}

	oc := Outcome{Verified: true}
	applyWorkloadPolicy(&oc, config{}, ev, nil)
	if oc.Workload != "api" || oc.WorkloadAllowlistVersion != "4" {
		t.Fatalf("workload = %q v%q, want api v4", oc.Workload, oc.WorkloadAllowlistVersion)
	}
	if !strings.Contains(oc.WorkloadNote, "not verified") {
		t.Fatalf("note = %q, want it to say the name is unverified without --mesh-ca", oc.WorkloadNote)
	}

	// A failed hardware verdict must not surface an "attested-looking" name.
	failed := Outcome{Verified: false}
	applyWorkloadPolicy(&failed, config{}, ev, nil)
	if failed.Workload != "" {
		t.Fatalf("Workload = %q on a failed verdict, want empty", failed.Workload)
	}
}

// A malformed matched-workload extension fails the verdict rather than being
// ignored — damage never reads as absence.
func TestApplyWorkloadPolicyUnparseableFailsClosed(t *testing.T) {
	oc := Outcome{Verified: true}
	applyWorkloadPolicy(&oc, config{}, &evidence{workloadErr: errSandboxTest}, nil)
	if oc.Verified {
		t.Fatal("unparseable matched-workload extension did not fail the verdict")
	}
	if !strings.Contains(oc.Error, "workload_malformed") {
		t.Fatalf("error = %q, want workload_malformed", oc.Error)
	}
}

// The full pin matrix against a chain-valid leaf: pass, name mismatch, absent
// stamp, digest mismatch, unresolved name.
func TestApplyWorkloadPolicyPins(t *testing.T) {
	canonical, digest := testHeldAllowlist(t)
	matched := &armtls.MatchedWorkload{Name: "api", AllowlistVersion: "4", AllowlistDigest: digest}
	leaf, caPath := caSignedWorkloadLeaf(t, matched)
	unstamped, _ := caSignedWorkloadLeaf(t, nil)

	allowlistPath := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(allowlistPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(cfg config, ev *evidence) Outcome {
		t.Helper()
		held, err := loadHeldAllowlist(cfg.allowlistFile)
		if err != nil {
			t.Fatalf("loadHeldAllowlist: %v", err)
		}
		oc := Outcome{Verified: true}
		applySandboxPolicy(&oc, cfg, ev, operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
		applyWorkloadPolicy(&oc, cfg, ev, held)
		return oc
	}

	t.Run("name pin passes", func(t *testing.T) {
		oc := run(config{workload: "api", meshCA: caPath}, &evidence{leaf: leaf, workload: matched})
		if !oc.Verified {
			t.Fatalf("verdict failed: %s", oc.Error)
		}
		if !strings.Contains(oc.WorkloadNote, "workload_verified") {
			t.Fatalf("note = %q, want workload_verified", oc.WorkloadNote)
		}
	})
	t.Run("name pin mismatch", func(t *testing.T) {
		oc := run(config{workload: "other", meshCA: caPath}, &evidence{leaf: leaf, workload: matched})
		if oc.Verified || !strings.Contains(oc.Error, "workload_name_mismatch") {
			t.Fatalf("verdict = %v %q, want workload_name_mismatch", oc.Verified, oc.Error)
		}
	})
	t.Run("absent stamp", func(t *testing.T) {
		oc := Outcome{Verified: true}
		applyWorkloadPolicy(&oc, config{workload: "api", meshCA: caPath}, &evidence{leaf: unstamped}, nil)
		if oc.Verified || !strings.Contains(oc.Error, "workload_absent") {
			t.Fatalf("verdict = %v %q, want workload_absent", oc.Verified, oc.Error)
		}
	})
	t.Run("allowlist pin passes and resolves", func(t *testing.T) {
		oc := run(config{allowlistFile: allowlistPath, meshCA: caPath}, &evidence{leaf: leaf, workload: matched})
		if !oc.Verified {
			t.Fatalf("verdict failed: %s", oc.Error)
		}
	})
	t.Run("allowlist digest mismatch", func(t *testing.T) {
		otherPath := filepath.Join(t.TempDir(), "other.json")
		mutated := bytes.Replace(canonical, []byte("api"), []byte("ape"), 1)
		if err := os.WriteFile(otherPath, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		oc := run(config{allowlistFile: otherPath, meshCA: caPath}, &evidence{leaf: leaf, workload: matched})
		if oc.Verified || !strings.Contains(oc.Error, "allowlist_digest_mismatch") {
			t.Fatalf("verdict = %v %q, want allowlist_digest_mismatch", oc.Verified, oc.Error)
		}
	})
	t.Run("stamped name unresolved in held document", func(t *testing.T) {
		ghost := &armtls.MatchedWorkload{Name: "ghost", AllowlistVersion: "4", AllowlistDigest: digest}
		ghostLeaf, ghostCA := caSignedWorkloadLeaf(t, ghost)
		oc := run(config{allowlistFile: allowlistPath, meshCA: ghostCA}, &evidence{leaf: ghostLeaf, workload: ghost})
		if oc.Verified || !strings.Contains(oc.Error, "workload_unresolved") {
			t.Fatalf("verdict = %v %q, want workload_unresolved", oc.Verified, oc.Error)
		}
	})
	t.Run("pin needs a leaf", func(t *testing.T) {
		oc := Outcome{Verified: true}
		applyWorkloadPolicy(&oc, config{workload: "api", meshCA: caPath}, &evidence{}, nil)
		if oc.Verified {
			t.Fatal("pin passed with no leaf certificate")
		}
	})
	t.Run("self-signed leaf fails the chain before the pin", func(t *testing.T) {
		// A leaf signed by a DIFFERENT CA than the supplied bundle.
		otherLeaf, _ := caSignedWorkloadLeaf(t, matched)
		oc := run(config{workload: "api", meshCA: caPath}, &evidence{leaf: otherLeaf, workload: matched})
		if oc.Verified {
			t.Fatal("a leaf not chaining to --mesh-ca satisfied the workload pin")
		}
	})
}

// The --allowlist file is read exactly once. Two reads would let the verdict
// validate one version of the file and hash another; the digest comparison must
// be against the bytes that were parsed.
func TestHeldAllowlistIsReadOnce(t *testing.T) {
	canonical, digest := testHeldAllowlist(t)
	matched := &armtls.MatchedWorkload{Name: "api", AllowlistVersion: "4", AllowlistDigest: digest}
	leaf, caPath := caSignedWorkloadLeaf(t, matched)

	path := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(path, canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := loadHeldAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}

	// Swap the file underneath for something that would fail every check.
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config{allowlistFile: path, meshCA: caPath}
	ev := &evidence{leaf: leaf, workload: matched}
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, cfg, ev, operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
	applyWorkloadPolicy(&oc, cfg, ev, held)
	if !oc.Verified {
		t.Fatalf("verdict re-read the file instead of using the loaded bytes: %s", oc.Error)
	}
}

func TestLoadHeldAllowlist(t *testing.T) {
	if held, err := loadHeldAllowlist(""); held != nil || err != nil {
		t.Fatalf("unset --allowlist = %v, %v; want nil, nil", held, err)
	}
	if _, err := loadHeldAllowlist(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing --allowlist file accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHeldAllowlist(bad); err == nil {
		t.Fatal("unparseable --allowlist file accepted")
	}
}
