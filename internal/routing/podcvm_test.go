package routing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// podLeaf mints a leaf the way CDS issues one to a pod CVM: no subject or
// SANs, the pcvm- instance identity, the assigned workload ID, and the
// matched-workload stamp only when the whole observation set matched.
func podLeaf(t testing.TB, ca *issuer.CA, workload, assigned string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	params := issuer.SignCSRParams{CSR: csr, TTL: 30 * time.Minute, SandboxID: "pcvm-" + strings.Repeat("ab", 32), AssignedWorkloadID: assigned}
	if workload != "" {
		params.MatchedWorkload = &armtls.MatchedWorkload{Name: workload, AllowlistVersion: "1", AllowlistDigest: testDigest}
	}
	certPEM, _, _, err := ca.SignCSR(params)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// A named route reaches a pod CVM whose leaf CDS stamped with the route's
// workload; a membership-only pod leaf names nothing and is refused (B1).
func TestB1PodCVMBackend(t *testing.T) {
	f := newFixture(t)
	for i, tc := range []struct {
		name string
		leaf tls.Certificate
		want int
	}{
		{"named pod leaf", podLeaf(t, f.mesh, "web", "user-alice"), http.StatusOK},
		{"named pod leaf without an assigned ID", podLeaf(t, f.mesh, "web", ""), http.StatusOK},
		{"pod leaf named for another workload", podLeaf(t, f.mesh, "admin", "user-alice"), http.StatusBadGateway},
		{"membership-only pod leaf", podLeaf(t, f.mesh, "", "user-alice"), http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := startBackend(t, "web", tc.leaf)
			f.apply(t, simpleManifest(uint64(i+1), b.addr()))
			if got := f.get("/").Code; got != tc.want {
				t.Fatalf("GET / = %d, want %d", got, tc.want)
			}
		})
	}
}

// A route that pins an assigned workload ID reaches only the pod CVM whose
// leaf carries exactly that ID, besides the workload name; another user's
// pod and a leaf without the ID are refused before any request is written.
func TestB1PodCVMAssignedWorkloadPin(t *testing.T) {
	f := newFixture(t)
	for i, tc := range []struct {
		name string
		leaf tls.Certificate
		want int
	}{
		{"match", podLeaf(t, f.mesh, "web", "user-alice"), http.StatusOK},
		{"mismatch", podLeaf(t, f.mesh, "web", "user-bob"), http.StatusBadGateway},
		{"missing", podLeaf(t, f.mesh, "web", ""), http.StatusBadGateway},
		{"match but another workload", podLeaf(t, f.mesh, "admin", "user-alice"), http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := startBackend(t, "web", tc.leaf)
			r := workloadRoute("/", "prefix", b.addr(), "web")
			r.backend["assignedWorkloadID"] = "user-alice"
			f.apply(t, manifestSpec{revision: uint64(i + 1), hosts: map[string][]route{testHost: {r}}})
			if got := f.get("/").Code; got != tc.want {
				t.Fatalf("GET / = %d, want %d", got, tc.want)
			}
			if tc.want != http.StatusOK && b.hits.Load() != 0 {
				t.Fatalf("backend saw %d requests after a refused pin, want 0", b.hits.Load())
			}
		})
	}
}
