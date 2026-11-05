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

// caSignedLeafAssignedTo mints a mesh-CA-signed serving leaf carrying a sandbox
// ID and, when assigned is set, an assigned workload ID: the shape CDS issues
// to a pod CVM.
func caSignedLeafAssignedTo(t *testing.T, assigned string) (*x509.Certificate, string) {
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
	sandbox, err := armtls.MarshalSandboxIDExtension("8d9f6c2b1a0e")
	if err != nil {
		t.Fatal(err)
	}
	exts := []pkix.Extension{sandbox}
	if assigned != "" {
		ext, err := armtls.MarshalAssignedWorkloadIDExtension(assigned)
		if err != nil {
			t.Fatal(err)
		}
		exts = append(exts, ext)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "workload"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtKeyUsage:     serverAuthOnly,
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

// Two tenants may run one workload, so only the assigned workload ID tells
// their leaves apart: the pin passes on the expected tenant and fails on
// another tenant's leaf and on a leaf that names none.
func TestApplySandboxPolicyAssignedWorkloadPin(t *testing.T) {
	const tenant = "tenant-a.web"
	for _, tc := range []struct {
		name     string
		assigned string
		want     bool
	}{
		{"expected tenant", tenant, true},
		{"another tenant", "tenant-b.web", false},
		{"no assigned workload", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, caPath := caSignedLeafAssignedTo(t, tc.assigned)
			oc := Outcome{Verified: true}
			applySandboxPolicy(&oc, config{assignedWorkloadID: tenant, meshCA: caPath}, &evidence{leaf: leaf, sandboxID: "8d9f6c2b1a0e"},
				operatorKeysReport{}, &verifyPlan{}, measurementsReport{})
			if oc.Verified != tc.want {
				t.Fatalf("verified = %v (%s), want %v", oc.Verified, oc.Error, tc.want)
			}
			if tc.want && oc.AssignedWorkloadID != tenant {
				t.Fatalf("assigned workload ID = %q, want %q", oc.AssignedWorkloadID, tenant)
			}
			if !tc.want && oc.AssignedWorkloadID != "" {
				t.Fatalf("assigned workload ID = %q reported on a failed pin", oc.AssignedWorkloadID)
			}
		})
	}
}

// The ID is vouched for by CDS's signature on the leaf, so the pin is refused
// without the mesh CA that checks it, refused with a value outside the
// workload-name grammar, and refused against a CDS target.
func TestBuildPolicyAssignedWorkloadFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config
		want string
	}{
		{"without mesh CA", config{assignedWorkloadID: "tenant-a.web"}, "requires --mesh-ca"},
		{"invalid ID", config{assignedWorkloadID: "-bad"}, "--assigned-workload-id: "},
		{"CDS target", config{kind: "cds", assignedWorkloadID: "tenant-a.web", meshCA: "ca.pem"}, "--assigned-workload-id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildPolicy(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("buildPolicy = %v, want an error naming %q", err, tc.want)
			}
		})
	}
}
