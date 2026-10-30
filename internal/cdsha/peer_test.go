package cdsha

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// A replica of the same image on the same launch file is a peer of this
// cluster, and its member id comes from the certificate its attested key
// signed.
func TestAnotherReplicaOfTheSameImageIsAdmitted(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")

	admitted, err := admitting.verifier().admit(joining.identity.certificate.Leaf.Raw)
	if err != nil {
		t.Fatalf("peer refused: %v", err)
	}
	if admitted.member != "member-b" {
		t.Fatalf("admitted member %q, want member-b", admitted.member)
	}
}

// The evidence must bind the cluster, the certificate key and the expiry, so
// a recorded certificate is no use in another cluster or past its date. The
// attestation-api is the one that compares, so what matters is the binding it
// is asked for.
func TestAdmissionAsksTheServiceForThePeerBinding(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")
	leaf := joining.identity.certificate.Leaf

	before := admitting.verdicts()
	if _, err := admitting.verifier().admit(leaf.Raw); err != nil {
		t.Fatalf("peer refused: %v", err)
	}
	requests := admitting.stub.VerifyRequests()
	if len(requests) != before+1 {
		t.Fatalf("the service was asked %d times, want one verdict", len(requests)-before)
	}
	want := peerBindingOf(t, leaf, testCluster, "member-b", leaf.NotAfter)
	if got := requests[len(requests)-1].Params.ExpectedReportData; !slices.Equal(got, want[:]) {
		t.Fatalf("the service was asked to check %x, want the peer binding %x", got, want)
	}
	for _, other := range []struct {
		name    string
		binding [48]byte
	}{
		{
			"another cluster",
			peerBindingOf(t, leaf, "another-cluster", "member-b", leaf.NotAfter),
		},
		{
			"another member",
			peerBindingOf(t, leaf, testCluster, "member-c", leaf.NotAfter),
		},
		{
			"another expiry",
			peerBindingOf(t, leaf, testCluster, "member-b", leaf.NotAfter.Add(time.Second)),
		},
	} {
		if other.binding == want {
			t.Fatalf("the peer binding does not separate %s", other.name)
		}
	}
}

// peerBindingOf is the report data cert's key and the context given bind.
func peerBindingOf(t *testing.T, cert *x509.Certificate, clusterID, member string, notAfter time.Time) [48]byte {
	t.Helper()
	binding, err := peerReportData(cert.PublicKey, peerContext(clusterID, member, notAfter))
	if err != nil {
		t.Fatalf("peer binding: %v", err)
	}
	return binding
}

// A service that does not confirm the binding leaves the certificate key
// unproven, so the peer is refused. A service that ignores the request field
// answers the same way.
func TestPeerWithAnUnconfirmedBindingIsRefused(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")

	unbound := snpVerdict(testImage, testLaunchFile)
	unbound.ReportDataMatch = nil
	admitting.judges(unbound)

	_, err := admitting.verifier().admit(joining.identity.certificate.Leaf.Raw)
	if !errors.Is(err, armtls.ErrKeyBinding) {
		t.Fatalf("admitted a peer whose binding was not confirmed: %v", err)
	}
}

// Evidence the hardware did not sign says nothing, and the verdict is read
// before any claim is.
func TestPeerWithUnsignedEvidenceIsRefused(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")

	admitting.refuses(mockapi.VerificationFailed("signature does not verify"))

	if _, err := admitting.verifier().admit(joining.identity.certificate.Leaf.Raw); err == nil {
		t.Fatal("admitted a peer whose evidence did not verify")
	}
}

// An image the admission set does not list is refused, which is what a CDS
// image roll rests on.
func TestPeerOutsideTheAdmissionSetIsRefused(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")
	admitting.admits.hold(imagePin(t, otherImage, testLaunchFile))

	_, err := admitting.verifier().admit(joining.identity.certificate.Leaf.Raw)
	if !errors.Is(err, armtls.ErrPolicyViolation) {
		t.Fatalf("admitted an image this replica does not pin: %v", err)
	}
}

// The same image launched on another configuration is another cluster's CDS,
// so every pin binds the launch file this replica booted.
func TestPeerOnAnotherLaunchFileIsRefused(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")
	admitting.admits.hold(imagePin(t, testImage, otherLaunchFile))

	_, err := admitting.verifier().admit(joining.identity.certificate.Leaf.Raw)
	if !errors.Is(err, armtls.ErrPolicyViolation) {
		t.Fatalf("admitted a replica of another cluster: %v", err)
	}
}

// A replica that pins no image knows no peer of its cluster.
func TestEmptyAdmissionSetAdmitsNobody(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")
	admitting.admits.hold()

	_, err := admitting.verifier().admit(joining.identity.certificate.Leaf.Raw)
	if !errors.Is(err, armtls.ErrUnpinned) {
		t.Fatalf("an empty admission set admitted a peer: %v", err)
	}
	recheck := verdict{verifiedPlatform: teetypes.PlatformSNP}.admittedBy(nil)
	if !errors.Is(recheck, remote.ErrMeasurementNotAllowed) {
		t.Fatalf("an empty admission set admitted a live connection's peer: %v", recheck)
	}
}

// An expired certificate is an old key, and the body is authenticated before
// the evidence costs an attestation-api call.
func TestExpiredPeerCertificateIsRefusedBeforeVerification(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	expired := newPeerReplica(
		t,
		"member-b",
		teetypes.PlatformSNP,
		snpVerdict(testImage, testLaunchFile),
		time.Now().Add(-time.Minute),
	)

	before := admitting.verdicts()
	_, err := admitting.verifier().admit(expired.identity.certificate.Leaf.Raw)
	if err == nil {
		t.Fatal("admitted an expired peer certificate")
	}
	if got := admitting.verdicts(); got != before {
		t.Fatalf("the service was asked for %d verdicts on an expired certificate, want none", got-before)
	}
}

// The evidence binds the key alone, so every other field of the certificate —
// the member id included — is authenticated by the signature that key made.
func TestAlteredPeerCertificateIsRefused(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")

	altered := slices.Clone(joining.identity.certificate.Leaf.Raw)
	altered[len(altered)-1] ^= 0xff

	before := admitting.verdicts()
	if _, err := admitting.verifier().admit(altered); err == nil {
		t.Fatal("admitted a certificate body its own key did not sign")
	}
	if got := admitting.verdicts(); got != before {
		t.Fatalf("the service was asked for %d verdicts on an altered certificate, want none", got-before)
	}
}

// A certificate carries both the member id and the evidence; one without the
// other identifies nobody.
func TestPeerCertificateMustCarryMemberAndEvidence(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")
	evidence, err := agarmtls.ExtractAttestation(joining.identity.certificate.Leaf, oidPeerEvidence)
	if err != nil {
		t.Fatalf("read the evidence back: %v", err)
	}
	evidenceExtension, err := evidence.MarshalExtension(oidPeerEvidence)
	if err != nil {
		t.Fatalf("evidence extension: %v", err)
	}
	memberExtension, err := newMemberExtension("member-b")
	if err != nil {
		t.Fatalf("member extension: %v", err)
	}

	for _, tc := range []struct {
		name       string
		extensions []pkix.Extension
	}{
		{"evidence without a member", []pkix.Extension{evidenceExtension}},
		{"a member without evidence", []pkix.Extension{memberExtension}},
		{"two members", []pkix.Extension{evidenceExtension, memberExtension, memberExtension}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := admitting.verifier().admit(selfSigned(t, tc.extensions)); err == nil {
				t.Fatal("admitted a certificate that names no attested member")
			}
		})
	}
}

// Evidence belongs to the key its binding names. Copied onto another key, it
// is judged against that key's binding, which no CVM attested.
func TestCopiedEvidenceIsJudgedAgainstTheKeyPresentingIt(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	joining := newSNPReplica(t, "member-b")
	evidence, err := agarmtls.ExtractAttestation(joining.identity.certificate.Leaf, oidPeerEvidence)
	if err != nil {
		t.Fatalf("read the evidence back: %v", err)
	}
	evidenceExtension, err := evidence.MarshalExtension(oidPeerEvidence)
	if err != nil {
		t.Fatalf("evidence extension: %v", err)
	}
	member, err := newMemberExtension("member-b")
	if err != nil {
		t.Fatalf("member extension: %v", err)
	}

	copied, err := x509.ParseCertificate(selfSigned(t, []pkix.Extension{evidenceExtension, member}))
	if err != nil {
		t.Fatalf("parse the copy: %v", err)
	}
	if _, err := admitting.verifier().admit(copied.Raw); err != nil {
		t.Fatalf("the stub confirms whatever binding it is asked for: %v", err)
	}

	asked := admitting.stub.VerifyRequests()
	want := peerBindingOf(t, copied, testCluster, "member-b", copied.NotAfter)
	if got := asked[len(asked)-1].Params.ExpectedReportData; !slices.Equal(got, want[:]) {
		t.Fatalf("the service was asked to check %x, want the presenting key's binding %x", got, want)
	}
	leaf := joining.identity.certificate.Leaf
	if want == peerBindingOf(t, leaf, testCluster, "member-b", leaf.NotAfter) {
		t.Fatal("the binding does not separate the key the evidence was made for")
	}
}

// A certificate someone else vouches for is not a peer certificate: nothing
// here verifies a chain, so the body would be unauthenticated.
func TestCAVouchedPeerCertificateIsRefused(t *testing.T) {
	admitting := newSNPReplica(t, "member-a")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: peerCommonName},
		Issuer:       pkix.Name{CommonName: "a certificate authority"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	issuer := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "a certificate authority"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = admitting.verifier().admit(der)
	if err == nil {
		t.Fatal("admitted a peer certificate vouched for by a certificate authority")
	}
}

// The self pin is the launch identity the replica's own verdict reports: on
// SEV-SNP the launch digest, bound to the launch file it booted.
func TestSelfPinIsTheLaunchIdentityOfThisReplica(t *testing.T) {
	replica := newSNPReplica(t, "member-a")

	self := replica.identity.self
	if got := hex.EncodeToString(self.Digest); got != testImage {
		t.Fatalf("self pin digest %s, want %s", got, testImage)
	}
	if len(self.Registers) != 0 {
		t.Fatalf("self pin carries %d registers, and an SEV-SNP image has none", len(self.Registers))
	}
	if !slices.Equal(self.LaunchFile, testLaunchFile) {
		t.Fatal("the self pin does not bind the launch file this replica booted")
	}
}

// On Intel TDX the MRTD covers the firmware, so the image's identity is the
// MRTD together with the registers the guest measures.
func TestSelfPinOnTDXCoversTheGuestRegisters(t *testing.T) {
	admitting := newTDXReplica(t, "member-a", tdxVerdict(testImage, testRTMR1, testRTMR2, testLaunchFile))
	same := newTDXReplica(t, "member-b", tdxVerdict(testImage, testRTMR1, testRTMR2, testLaunchFile))
	otherGuest := newTDXReplica(t, "member-c", tdxVerdict(testImage, otherRTMR1, testRTMR2, testLaunchFile))

	self := admitting.identity.self
	if len(self.Registers) != 2 {
		t.Fatalf("self pin carries %d registers, want RTMR[1] and RTMR[2]", len(self.Registers))
	}
	if _, err := admitting.verifier().admit(same.identity.certificate.Leaf.Raw); err != nil {
		t.Fatalf("a replica of the same TDX image was refused: %v", err)
	}

	admitting.judges(tdxVerdict(testImage, otherRTMR1, testRTMR2, testLaunchFile))
	_, err := admitting.verifier().admit(otherGuest.identity.certificate.Leaf.Raw)
	if !errors.Is(err, armtls.ErrPolicyViolation) {
		t.Fatalf("admitted a guest under the same MRTD: %v", err)
	}
}

// A platform whose evidence names no image identity admits nothing.
func TestPlatformWithoutAnImageIdentityHasNoSelfPin(t *testing.T) {
	_, err := verdict{verifiedPlatform: teetypes.PlatformType("mystery")}.imagePin(testLaunchFile)
	if err == nil {
		t.Fatal("a platform with no image identity produced a self pin")
	}
}

// The platform that chooses the checks comes from what the service verified,
// never from the envelope a peer presents, so a verdict without one is no
// verdict at all.
func TestVerdictWithoutAVerifiedPlatformIsRefused(t *testing.T) {
	response := remote.VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true}}
	_, err := newVerdict(response)
	if err == nil {
		t.Fatal("a response naming no platform produced a verdict")
	}
}

// The attestation-api that judges a peer is this VM's own: a service the host
// could answer for would admit whoever it liked.
func TestAttestationAPIOffThisVMIsRefused(t *testing.T) {
	for _, address := range []string{
		"http://attestation.example.org:8400",
		"http://10.1.0.4:8400",
		"not a url",
	} {
		if _, err := newAttestor(address, testCallTimeout); err == nil {
			t.Fatalf("accepted an attestation-api at %s", address)
		}
	}
	if _, err := newAttestor("http://127.0.0.1:8400", testCallTimeout); err != nil {
		t.Fatalf("refused the loopback attestation-api: %v", err)
	}
	if _, err := newAttestor("unix:///run/attestation/attest.sock", testCallTimeout); err != nil {
		t.Fatalf("refused the attestation-api unix socket: %v", err)
	}
}

// The member id travels in one length byte, and the certificate reader holds
// to the same bound as the Raft frame.
func TestMemberIDIsBounded(t *testing.T) {
	replica := newSNPReplica(t, "member-a")
	long := string(make([]byte, maxMemberID+1))

	hour := time.Now().Add(time.Hour)
	if _, err := newPeerIdentity(replica.attestor, testCluster, long, testLaunchFile, hour); err == nil {
		t.Fatal("minted an identity for a member id no frame carries")
	}
	if _, err := newPeerIdentity(replica.attestor, testCluster, "", testLaunchFile, hour); err == nil {
		t.Fatal("minted an identity for no member")
	}
}

// selfSigned self-signs a fresh key into a certificate carrying extensions.
func selfSigned(t *testing.T, extensions []pkix.Extension) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{CommonName: peerCommonName},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
