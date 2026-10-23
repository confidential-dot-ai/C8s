package cdsha

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// fakeAttestationAPI emulates /attest and /verify for one TDX "node": the
// evidence it issues carries the report_data verbatim, and /verify echoes it
// back in the claims. It only checks that the Verify request carries the same
// evidence, so the test exercises the client wiring and claim mapping.
type fakeAttestationAPI struct {
	rtmr   [4]string
	mrtd   string
	broken bool // report an invalid signature
}

func (f *fakeAttestationAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /attest", func(w http.ResponseWriter, r *http.Request) {
		var req remote.AttestRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		ev, _ := json.Marshal(map[string]string{"quote": hex.EncodeToString(req.ReportData)})
		_ = json.NewEncoder(w).Encode(remote.AttestResponse{Platform: teetypes.PlatformTDX, Evidence: ev})
	})
	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		var req remote.VerifyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		var ev struct{ Quote string }
		_ = json.Unmarshal(req.Evidence, &ev)
		rd, _ := hex.DecodeString(ev.Quote)
		rd = append(rd, make([]byte, 64-len(rd))...)
		res := teetypes.VerificationResult{
			SignatureValid: !f.broken,
			Platform:       teetypes.PlatformTDX,
			Claims: teetypes.Claims{
				LaunchDigest: f.mrtd,
				ReportData:   rd,
				PlatformData: map[string]any{"rtmr_0": f.rtmr[0], "rtmr_1": f.rtmr[1], "rtmr_2": f.rtmr[2], "rtmr_3": f.rtmr[3]},
			},
		}
		_ = json.NewEncoder(w).Encode(remote.VerifyResponse{Result: res})
	})
	return mux
}

func TestNodeAttestorRoundTrip(t *testing.T) {
	f := &fakeAttestationAPI{mrtd: digest(1), rtmr: [4]string{digest(0xa0), digest(2), digest(3), digest(0x33)}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	att := NewNodeAttestor(srv.URL, 2*time.Second)

	rd := PeerBinding("tenant-a", []byte("spki"), time.Unix(1, 0))
	ev, err := att.Evidence(rd)
	if err != nil {
		t.Fatal(err)
	}
	c, err := att.Verify(ev)
	if err != nil {
		t.Fatal(err)
	}
	if c.ReportData != rd {
		t.Fatal("report_data not carried through")
	}
	// Measurement excludes RTMR0 (VM shape); anchor is RTMR3.
	if want := strings.Join([]string{digest(1), digest(2), digest(3)}, ":"); c.Measurement != want {
		t.Fatalf("measurement %s", c.Measurement)
	}
	if c.Anchor != digest(0x33) {
		t.Fatalf("anchor %s", c.Anchor)
	}
	// A verdict with an invalid signature is refused before any claim is read.
	f.broken = true
	if _, err := att.Verify(ev); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if _, err := att.Verify([]byte("{")); err == nil {
		t.Fatal("evidence that is not JSON verified")
	}
}

func tdxClaims(rd []byte) teetypes.Claims {
	return teetypes.Claims{LaunchDigest: digest(1), ReportData: rd,
		PlatformData: map[string]any{"rtmr_1": digest(2), "rtmr_2": digest(3), "rtmr_3": digest(4)}}
}

// nodeClaims maps a verified result to the image pin and the launch-key
// anchor, and refuses anything incomplete.
func TestNodeClaims(t *testing.T) {
	tdxRes := func(c teetypes.Claims) teetypes.VerificationResult {
		return teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX, Claims: c}
	}
	rd := make([]byte, 64)
	rd[0] = 7
	c, err := nodeClaims(tdxRes(tdxClaims(rd)))
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := ImagePin("tdx", digest(1), map[int]string{1: digest(2), 2: digest(3)})
	if c.Measurement != pin || c.Anchor != digest(4) || c.ReportData[0] != 7 {
		t.Fatalf("claims %+v, want measurement %s", c, pin)
	}
	// RTMR3 is the anchor, not part of the measurement.
	other := tdxClaims(rd)
	other.PlatformData["rtmr_3"] = digest(9)
	if c2, _ := nodeClaims(tdxRes(other)); c2.Measurement != c.Measurement || c2.Anchor == c.Anchor {
		t.Fatal("RTMR3 must change the anchor only")
	}
	snp := teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformSNP,
		Claims: teetypes.Claims{LaunchDigest: digest(5), InitData: []byte{0xab, 0xcd}, ReportData: rd}}
	if c, err := nodeClaims(snp); err != nil || c.Anchor != "abcd" || c.Measurement != digest(5) {
		t.Fatalf("snp claims %+v: %v", c, err)
	}
	tail := make([]byte, 64)
	tail[60] = 1
	unknown := snp
	unknown.Platform = "other"
	regs := func(drop string) teetypes.Claims {
		c := tdxClaims(rd)
		c.PlatformData = maps.Clone(c.PlatformData)
		delete(c.PlatformData, drop)
		return c
	}
	for name, res := range map[string]teetypes.VerificationResult{
		"short report_data": tdxRes(tdxClaims(make([]byte, 20))),
		"non-zero tail":     tdxRes(tdxClaims(tail)),
		"no launch digest":  tdxRes(teetypes.Claims{ReportData: rd, PlatformData: tdxClaims(nil).PlatformData}),
		"no RTMR1":          tdxRes(regs("rtmr_1")),
		"no RTMR2":          tdxRes(regs("rtmr_2")),
		"no RTMR3":          tdxRes(regs("rtmr_3")),
		"unknown platform":  unknown,
	} {
		if _, err := nodeClaims(res); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestImagePin(t *testing.T) {
	m := strings.ToUpper(digest(1))
	pin, err := ImagePin("tdx", m, map[int]string{1: digest(2), 2: digest(3)})
	if err != nil || pin != strings.Join([]string{digest(1), digest(2), digest(3)}, ":") {
		t.Fatalf("tdx pin %q: %v", pin, err)
	}
	if _, err := ImagePin("tdx", m, map[int]string{1: digest(2)}); err == nil {
		t.Fatal("tdx pin without RTMR2")
	}
	if pin, err := ImagePin("snp", m, nil); err != nil || pin != digest(1) {
		t.Fatalf("snp pin %q: %v", pin, err)
	}
	// A decree image's pin is the replica's ImagePin, in lowercase only.
	img := testImage(1)
	if pin, err := img.Pin(); err != nil || pin != img.MRTD+":"+img.RTMR1+":"+img.RTMR2 {
		t.Fatalf("decree image pin %q: %v", pin, err)
	}
	img.RTMR1 = strings.Repeat("AB", 48)
	if _, err := img.Pin(); err == nil {
		t.Fatal("uppercase register accepted")
	}
	if _, err := ImagePin("nope", m, nil); err == nil {
		t.Fatal("unknown platform pinned")
	}
}

type failingAttestor struct{}

func (failingAttestor) Evidence([48]byte) ([]byte, error) { return nil, errors.New("no TEE") }
func (failingAttestor) Verify([]byte) (Claims, error)     { return Claims{}, errors.New("no TEE") }

// peerVerifier refuses every peer that is not a replica of this cluster.
func TestPeerVerifier(t *testing.T) {
	v := peerVerifier{clusterID: testCluster, att: MockAttestor{}, pins: func() []string { return []string{"m1"} }}
	m1 := MockAttestor{Measurement: "m1"}
	day := time.Now().Add(24 * time.Hour)
	good, err := newPeerCert(testCluster, m1, day)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.claims(good.Certificate[0]); err != nil {
		t.Fatal(err)
	}
	unpinned, _ := newPeerCert(testCluster, MockAttestor{Measurement: "m9"}, day)
	otherCluster, _ := newPeerCert("tenant-b", m1, day)
	expired, _ := newPeerCert(testCluster, m1, time.Now().Add(-time.Hour))
	plain := mustCA(t).Cert.Raw // no evidence extension
	// A leaked key re-signs the expired certificate, evidence and all, with
	// a later NotAfter.
	gc, _ := x509.ParseCertificate(expired.Certificate[0])
	gc.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	gc.ExtraExtensions = gc.Extensions
	key := expired.PrivateKey.(*ecdsa.PrivateKey)
	extended, err := x509.CreateCertificate(rand.Reader, gc, gc, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{
		"expired":              expired.Certificate[0],
		"re-signed later":      extended,
		"unpinned measurement": unpinned.Certificate[0],
		"other cluster":        otherCluster.Certificate[0],
		"no evidence":          plain,
		"not a certificate":    []byte("junk"),
	} {
		if _, err := v.claims(der); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	other := v
	other.anchor = "another-launch-key"
	if _, err := other.claims(good.Certificate[0]); err == nil {
		t.Error("peer with another launch-key anchor accepted")
	}
	cold := v
	cold.pins = func() []string { return nil }
	if _, err := cold.claims(unpinned.Certificate[0]); err != nil {
		t.Errorf("a cold replica must defer the pin check to the offered chain: %v", err)
	}
}
