package verify

import (
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

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// attestedCert builds a self-signed cert carrying a (fake) SNP attestation
// extension, optionally with a sandbox-ID extension.
func attestedCert(t *testing.T, sandboxID string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: make([]byte, armtls.SNPReportSize)}
	der, err := armtls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sandboxID != "" {
		der = reissueWithSandboxID(t, key, sandboxID)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// reissueWithSandboxID mints a self-signed leaf carrying both the attestation
// and sandbox-ID extensions — the shape CDS produces, minus the CA signature.
func reissueWithSandboxID(t *testing.T, key *ecdsa.PrivateKey, sandboxID string) []byte {
	t.Helper()
	att := &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: make([]byte, armtls.SNPReportSize)}
	attExt, err := armtls.MarshalExtension(att)
	if err != nil {
		t.Fatal(err)
	}
	sandboxExt, err := armtls.MarshalSandboxIDExtension(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(7),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtKeyUsage:     armtlsPurposes,
		ExtraExtensions: []pkix.Extension{attExt, sandboxExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestEvidenceFromCertReadsSandboxID(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	ev, err := evidenceFromCert(attestedCert(t, id), "test", leafTrust{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.sandboxID != id {
		t.Fatalf("sandboxID = %q, want %q", ev.sandboxID, id)
	}
	if ev.sandboxErr != nil {
		t.Fatalf("sandboxErr = %v", ev.sandboxErr)
	}
	if ev.leaf == nil {
		t.Fatal("leaf not retained; --mesh-ca could not check what CDS signed")
	}

	// A claims-free cert keeps the plain key anchor.
	want, err := armtls.ReportDataForKey(ev.leaf.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(ev.erd) != string(want[:48]) {
		t.Fatalf("erd = %x, want the plain key anchor %x", ev.erd, want[:48])
	}
}

// The reported ID is always qualified by what authenticates it: unqualified it
// would read as attested, which it is not.
func TestApplySandboxPolicyReportsProvenance(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	ev, err := evidenceFromCert(attestedCert(t, id), "test", leafTrust{})
	if err != nil {
		t.Fatal(err)
	}

	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{}, ev, operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
	if oc.SandboxID != id {
		t.Fatalf("SandboxID = %q, want %q", oc.SandboxID, id)
	}
	if !strings.Contains(oc.SandboxIDNote, "not verified") {
		t.Fatalf("note = %q, want it to say the ID is unverified without --mesh-ca", oc.SandboxIDNote)
	}

	// A failed hardware verdict must not surface an "attested-looking" ID.
	failed := Outcome{Verified: false}
	applySandboxPolicy(&failed, config{}, ev, operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
	if failed.SandboxID != "" {
		t.Fatalf("SandboxID = %q on a failed verdict, want empty", failed.SandboxID)
	}
}

// A self-signed leaf cannot satisfy --sandbox-id: it does not chain to the mesh
// CA, and CDS's signature is the only thing that vouches for the ID.
func TestApplySandboxPolicySelfSignedFailsMeshCA(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	cert := attestedCert(t, id)
	ev, err := evidenceFromCert(cert, "test", leafTrust{})
	if err != nil {
		t.Fatal(err)
	}

	// A CA bundle that did not sign this leaf.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certutil.EncodeCertPEM(caDER), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config{sandboxID: id, meshCA: caPath}
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, cfg, ev, operatorKeysReport{}, mustPlan(t, cfg), measurementsReport{})
	if oc.Verified {
		t.Fatal("self-signed leaf claiming the pinned sandbox ID passed --mesh-ca")
	}
	if !strings.Contains(oc.Error, "mesh-ca") {
		t.Fatalf("error = %q, want it to name the CA check", oc.Error)
	}
}

// A malformed sandbox-ID extension fails the verdict rather than being ignored.
func TestApplySandboxPolicyUnparseableIDFailsClosed(t *testing.T) {
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{}, &evidence{sandboxErr: errSandboxTest}, operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
	if oc.Verified {
		t.Fatal("unparseable sandbox-ID extension did not fail the verdict")
	}
}

var errSandboxTest = &sandboxTestError{}

type sandboxTestError struct{}

func (*sandboxTestError) Error() string { return "bad sandbox extension" }

// serverAuthOnly is the TLS purpose a CDS-issued serving leaf carries.
var serverAuthOnly = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

// armtlsPurposes is what armtls.CreateAttestedCert stamps on an attested leaf.
var armtlsPurposes = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

// caSignedLeaf mints a leaf carrying sandboxID and the given TLS purpose,
// signed by a fresh CA, returning the leaf and the CA bundle path — the shape
// CDS produces.
func caSignedLeaf(t *testing.T, sandboxID string, usages []x509.ExtKeyUsage) (*x509.Certificate, string) {
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
	ext, err := armtls.MarshalSandboxIDExtension(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtKeyUsage:     usages,
		ExtraExtensions: []pkix.Extension{ext},
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

// With a mesh CA the leaf chains to, the pin holds and the note says the ID was
// actually verified rather than merely reported.
func TestApplySandboxPolicyVerifiedAgainstMeshCA(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	leaf, caPath := caSignedLeaf(t, id, serverAuthOnly)
	ev := &evidence{leaf: leaf, sandboxID: id}

	cfg := config{sandboxID: id, meshCA: caPath}
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, cfg, ev, operatorKeysReport{}, mustPlan(t, cfg), measurementsReport{})
	if !oc.Verified {
		t.Fatalf("verdict failed: %s", oc.Error)
	}
	if !strings.Contains(oc.SandboxIDNote, "verified: the leaf chains") {
		t.Fatalf("note = %q, want it to record the chain check", oc.SandboxIDNote)
	}
	if !strings.Contains(oc.SandboxIDNote, "--sandbox-id") {
		t.Fatalf("note = %q, want it to record that the pin was exercised", oc.SandboxIDNote)
	}

	// The same leaf without the pin reports only the chain check, so the two
	// runs cannot be confused for one another.
	unpinnedCfg := config{meshCA: caPath}
	unpinned := Outcome{Verified: true}
	applySandboxPolicy(&unpinned, unpinnedCfg, ev, operatorKeysReport{}, mustPlan(t, unpinnedCfg), measurementsReport{})
	if strings.Contains(unpinned.SandboxIDNote, "--sandbox-id") {
		t.Fatalf("note = %q, want no pin claim when --sandbox-id was not supplied", unpinned.SandboxIDNote)
	}

	// A different expected ID on the same chain-valid leaf must still fail.
	mismatchCfg := config{sandboxID: "someother", meshCA: caPath}
	mismatch := Outcome{Verified: true}
	applySandboxPolicy(&mismatch, mismatchCfg, ev, operatorKeysReport{}, mustPlan(t, mismatchCfg), measurementsReport{})
	if mismatch.Verified {
		t.Fatal("a mismatched --sandbox-id passed on a chain-valid leaf")
	}
}

// --mesh-ca authenticates a leaf the CA issued for serving TLS: the same CA
// over a clientAuth-only leaf fails the chain check.
func TestApplySandboxPolicyMeshCARequiresServerAuth(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	leaf, caPath := caSignedLeaf(t, id, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	cfg := config{sandboxID: id, meshCA: caPath}
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, cfg, &evidence{leaf: leaf, sandboxID: id},
		operatorKeysReport{}, mustPlan(t, cfg), measurementsReport{})
	if oc.Verified {
		t.Fatal("a leaf the CA did not issue for serving TLS passed --mesh-ca")
	}
	if !strings.Contains(oc.Error, "mesh-ca") {
		t.Fatalf("error = %q, want it to name the CA check", oc.Error)
	}
}

// --mesh-ca asks a question; with no leaf to ask it of, that is an error rather
// than a silently skipped check reported as success.
func TestApplySandboxPolicyMeshCANeedsALeaf(t *testing.T) {
	_, caPath := caSignedLeaf(t, "abc", serverAuthOnly)
	cfg := config{meshCA: caPath}
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, cfg, &evidence{}, operatorKeysReport{}, mustPlan(t, cfg), measurementsReport{})
	if oc.Verified {
		t.Fatal("--mesh-ca silently passed with no leaf to check")
	}
}

// --sandbox-id needs a leaf to read the ID from; evidence without one (a
// discovery target) must fail the pin rather than skip it.
func TestApplySandboxPolicyPinNeedsALeaf(t *testing.T) {
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{sandboxID: "8d9f6c2b1a0e"}, &evidence{}, operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
	if oc.Verified {
		t.Fatal("--sandbox-id silently passed with no leaf to check")
	}
	if !strings.Contains(oc.Error, "--sandbox-id needs the target's leaf certificate") {
		t.Fatalf("Error = %q, want the leafless refusal", oc.Error)
	}
}

// --operator-keys compares against the list the attested target serves. Each
// way that can fail must demote the verdict, and an unfetched list must say so
// rather than compare against nothing.
func TestApplySandboxPolicyOperatorKeys(t *testing.T) {
	pubPEM, _ := operatorPubPEM(t)
	keysPath := filepath.Join(t.TempDir(), "op.pub")
	if err := os.WriteFile(keysPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{operatorKeys: keysPath}
	expected, err := expectedOperatorKeysDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		report   operatorKeysReport
		want     bool
		wantNote string
	}{
		{"served set matches", operatorKeysReport{digest: expected}, true, "matched: the set served over the attested cert equals --operator-keys"},
		{"served set differs", operatorKeysReport{digest: []byte("different")}, false, ""},
		{"fetch failed", operatorKeysReport{fetchErr: errSandboxTest}, false, ""},
		{"never fetched", operatorKeysReport{note: "kind is not cds"}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oc := Outcome{Verified: true}
			applySandboxPolicy(&oc, cfg, &evidence{}, tc.report, mustPlan(t, cfg), measurementsReport{})
			if oc.Verified != tc.want {
				t.Fatalf("Verified = %v, want %v (error: %s)", oc.Verified, tc.want, oc.Error)
			}
			if oc.OperatorKeysNote != tc.wantNote {
				t.Fatalf("OperatorKeysNote = %q, want %q", oc.OperatorKeysNote, tc.wantNote)
			}
		})
	}

	// A gather that never reached the endpoint carries no note of its own on a
	// --from-file target; the failure must still name a cause.
	t.Run("never fetched with no gather note", func(t *testing.T) {
		oc := Outcome{Verified: true}
		applySandboxPolicy(&oc, cfg, &evidence{}, operatorKeysReport{}, mustPlan(t, cfg), measurementsReport{})
		if oc.Verified || strings.HasSuffix(oc.Error, ": ") {
			t.Fatalf("Error = %q, want a failure naming why the check could not run", oc.Error)
		}
	})
}

// The operator-keys section is otherwise byte-identical whether or not
// --operator-keys was supplied, so a mistyped flag name leaves a run that
// compared nothing looking exactly like one that compared and matched.
func TestApplySandboxPolicyOperatorKeysVerdictDistinguishesPinning(t *testing.T) {
	pubPEM, fp := operatorPubPEM(t)
	keysPath := filepath.Join(t.TempDir(), "op.pub")
	if err := os.WriteFile(keysPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{operatorKeys: keysPath}
	served, err := expectedOperatorKeysDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := operatorKeysReport{fingerprints: []string{fp}, digest: served}

	pinned := Outcome{Verified: true}
	applySandboxPolicy(&pinned, cfg, &evidence{}, report, mustPlan(t, cfg), measurementsReport{})
	unpinned := Outcome{Verified: true}
	applySandboxPolicy(&unpinned, config{}, &evidence{}, report, mustPlan(t, config{}), measurementsReport{})

	if !pinned.Verified || !unpinned.Verified {
		t.Fatalf("both runs should pass: pinned error %q, unpinned error %q", pinned.Error, unpinned.Error)
	}
	if pinned.OperatorKeysNote == unpinned.OperatorKeysNote {
		t.Fatalf("pinned and unpinned runs report identically: %q", pinned.OperatorKeysNote)
	}
	if !strings.Contains(pinned.OperatorKeysNote, "matched") {
		t.Errorf("pinned note = %q, want it to state the comparison passed", pinned.OperatorKeysNote)
	}
	if !strings.Contains(unpinned.OperatorKeysNote, "not pinned") || strings.Contains(unpinned.OperatorKeysNote, "matched") {
		t.Errorf("unpinned note = %q, want it to say the set was compared against nothing", unpinned.OperatorKeysNote)
	}
}

// Without keys to list there is nothing for an unpinned run to qualify: the
// gather's own note (a 404, a skipped kind) already says why the set is absent.
func TestApplySandboxPolicyOperatorKeysUnpinnedNeedsKeys(t *testing.T) {
	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, config{}, &evidence{}, operatorKeysReport{digest: []byte("empty-set")}, &verifyPlan{}, measurementsReport{})
	if oc.OperatorKeysNote != "" {
		t.Fatalf("OperatorKeysNote = %q, want no verdict when no keys were listed", oc.OperatorKeysNote)
	}
}

// The --operator-keys bundle is read exactly once, in the plan. A second read
// would compare the served set against a file the plan never validated, so a
// bundle swapped mid-run would be judged in the verdict and not in the plan.
func TestOperatorKeysAreReadOnce(t *testing.T) {
	pubPEM, _ := operatorPubPEM(t)
	keysPath := filepath.Join(t.TempDir(), "op.pub")
	if err := os.WriteFile(keysPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{operatorKeys: keysPath}
	planned, err := expectedOperatorKeysDigest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan := mustPlan(t, cfg)

	// Swap the bundle underneath for another key set.
	otherPEM, _ := operatorPubPEM(t)
	if err := os.WriteFile(keysPath, otherPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, cfg, &evidence{}, operatorKeysReport{digest: planned}, plan, measurementsReport{})
	if !oc.Verified {
		t.Fatalf("verdict re-read the bundle instead of comparing against the planned digest: %s", oc.Error)
	}
	if oc.OperatorKeysNote != operatorKeysMatchedNote {
		t.Fatalf("note = %q, want %q", oc.OperatorKeysNote, operatorKeysMatchedNote)
	}
}

// An unreadable or empty --mesh-ca bundle is a usage error rather than
// "no CA supplied", which would silently downgrade the check.
func TestMeshCABundleErrors(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.pem")
	if _, err := buildPolicy(config{meshCA: missing}); err == nil {
		t.Fatal("buildPolicy accepted a missing --mesh-ca file")
	}

	notPEM := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildPolicy(config{meshCA: notPEM}); err == nil {
		t.Fatal("buildPolicy accepted a --mesh-ca file with no certificates")
	}
}

// The --mesh-ca bundle is read exactly once, in the plan. A second read would
// check the leaf's chain against an anchor the plan never saw.
func TestMeshCABundleIsReadOnce(t *testing.T) {
	const id = "8d9f6c2b1a0e"
	leaf, caPath := caSignedLeaf(t, id, serverAuthOnly)
	cfg := config{sandboxID: id, meshCA: caPath}
	plan := mustPlan(t, cfg)

	// Swap the bundle underneath for a CA that signed nothing here.
	_, otherCA := caSignedLeaf(t, id, serverAuthOnly)
	other, err := os.ReadFile(otherCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, other, 0o600); err != nil {
		t.Fatal(err)
	}

	oc := Outcome{Verified: true}
	applySandboxPolicy(&oc, cfg, &evidence{leaf: leaf, sandboxID: id}, operatorKeysReport{}, plan, measurementsReport{})
	if !oc.Verified {
		t.Fatalf("verdict re-read the bundle instead of using the planned anchor: %s", oc.Error)
	}
	if !strings.Contains(oc.SandboxIDNote, "verified: the leaf chains") {
		t.Fatalf("note = %q, want the chain check recorded", oc.SandboxIDNote)
	}
}
