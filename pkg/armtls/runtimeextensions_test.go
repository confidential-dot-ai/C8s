package armtls

import (
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

func TestReadRuntimeExtensions(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		journal string // "" leaves no file
		want    []string
		wantErr bool
	}{
		{name: "missing"},
		{name: "within the cap", journal: p + "\n", want: []string{p}},
		{name: "over the cap", journal: distinctJournal(MaxRuntimeExtensions + 1), wantErr: true},
	} {
		path := filepath.Join(dir, tc.name)
		if tc.journal != "" {
			if err := os.WriteFile(path, []byte(tc.journal), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got, err := ReadRuntimeExtensions(path)
		if (err != nil) != tc.wantErr || !slices.Equal(got, tc.want) {
			t.Errorf("%s: ReadRuntimeExtensions = %d entries, %v; want %d entries, error %v", tc.name, len(got), err, len(tc.want), tc.wantErr)
		}
	}
}

func TestWithRuntimeExtensions(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	empty := filepath.Join(dir, "empty")
	journal := filepath.Join(dir, "measured-policies")
	if err := os.WriteFile(journal, []byte(p+"\n"+q+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tdxReport, err := json.Marshal(teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{"quote":"AA=="}`)})
	if err != nil {
		t.Fatal(err)
	}
	tdx := Attestation{Family: TEETypeTDX, Report: tdxReport}
	own := tdx
	own.RuntimeExtensions = []string{q}
	snp := Attestation{Family: TEETypeSEVSNP, Report: fakeSNPReport([64]byte{})}

	for _, tc := range []struct {
		name    string
		att     Attestation
		journal *Journal
		want    []string
	}{
		{name: "TDX carries the journal", att: tdx, journal: NewJournal(journal), want: []string{p, q}},
		{name: "TDX with an empty journal", att: tdx, journal: NewJournal(empty)},
		{name: "TDX with a missing journal", att: tdx, journal: NewJournal(missing)},
		{name: "TDX without a journal", att: tdx, journal: NewJournal("")},
		{name: "TDX keeps its own list", att: own, journal: NewJournal(journal), want: []string{q}},
		{name: "SEV-SNP never", att: snp, journal: NewJournal(journal)},
	} {
		ext, err := MarshalExtension(WithRuntimeExtensions(&tc.att, tc.journal))
		if err != nil {
			t.Fatalf("%s: MarshalExtension: %v", tc.name, err)
		}
		got, err := UnmarshalExtension(ext.Value)
		if err != nil {
			t.Fatalf("%s: UnmarshalExtension: %v", tc.name, err)
		}
		if !slices.Equal(got.RuntimeExtensions, tc.want) {
			t.Errorf("%s: RuntimeExtensions = %v, want %v", tc.name, got.RuntimeExtensions, tc.want)
		}
	}
	if tdx.RuntimeExtensions != nil {
		t.Errorf("WithRuntimeExtensions set RuntimeExtensions on its argument: %v", tdx.RuntimeExtensions)
	}
}

// tdxClaims are the claims of a TDX node launched for anchor that extended
// RTMR[3] with extended.
func tdxClaims(mrtd, anchor []byte, extended ...string) teetypes.Claims {
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(anchor), extended)
	return teetypes.Claims{
		LaunchDigest: hex.EncodeToString(mrtd),
		PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg[:])},
	}
}

func TestEnforceImagesRuntimeExtensions(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	mrtd := bytes.Repeat([]byte{0x42}, sha512.Size384)
	anchor := []byte("operator key")
	pins := []remote.ImagePin{{Name: "node", Digest: mrtd, Anchor: anchor}}
	tooMany := make([]string, 257)
	for i := range tooMany {
		tooMany[i] = p
	}
	for _, tc := range []struct {
		name    string
		claims  teetypes.Claims
		claimed []string
		wantErr bool
	}{
		{name: "bare seed, no list", claims: tdxClaims(mrtd, anchor)},
		{name: "bare seed, list ahead of the quote", claims: tdxClaims(mrtd, anchor), claimed: []string{p}},
		{name: "replaying prefix", claims: tdxClaims(mrtd, anchor, p), claimed: []string{p, q}},
		{name: "whole list", claims: tdxClaims(mrtd, anchor, p, q), claimed: []string{p, q}},
		{name: "extended, no list", claims: tdxClaims(mrtd, anchor, p), wantErr: true},
		{name: "list does not replay", claims: tdxClaims(mrtd, anchor, q), claimed: []string{p}, wantErr: true},
		{name: "wrong anchor", claims: tdxClaims(mrtd, []byte("other key"), p), claimed: []string{p}, wantErr: true},
		{name: "list too long", claims: tdxClaims(mrtd, anchor), claimed: tooMany, wantErr: true},
	} {
		resp := remote.VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX, Claims: tc.claims}}
		err := EnforceImages(resp, pins, teetypes.PlatformTDX, tc.claimed)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: EnforceImages = %v, want error %v", tc.name, err, tc.wantErr)
		}
	}
	if pins[0].AcceptExtension != nil {
		t.Error("EnforceImages set AcceptExtension on the caller's pin")
	}
}

func TestPinsEnforceWithRuntimeLogPreservesExtensionDenial(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	mrtd := bytes.Repeat([]byte{0x42}, sha512.Size384)
	anchor := []byte("operator key")
	denied := errors.New("runtime extension denied")
	pins := Pins{
		Images: []remote.ImagePin{
			{
				Name:   "node",
				Digest: mrtd,
				Anchor: anchor,
				AcceptExtension: func(string) error {
					return denied
				},
			},
		},
	}
	resp := remote.VerifyResponse{
		Result: teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformTDX,
			Claims:         tdxClaims(mrtd, anchor, p),
		},
	}
	evidence := teetypes.AttestationEvidence{
		Platform: teetypes.PlatformTDX,
		Evidence: json.RawMessage(`{"quote":"fake"}`),
	}
	if err := pins.EnforceWithRuntimeLog(resp, evidence, []string{p}); !errors.Is(err, denied) {
		t.Fatalf("EnforceWithRuntimeLog = %v, want extension denial", err)
	}
	if err := EnforceImages(resp, pins.Images, evidence.Platform, []string{p}); !errors.Is(err, denied) {
		t.Fatalf("EnforceImages = %v, want extension denial", err)
	}
}

// A peer's certificate carries its list to VerifyCert, which replays it
// against an anchored pin.
func TestVerifyCertReplaysRuntimeExtensions(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	mrtd := bytes.Repeat([]byte{0x42}, sha512.Size384)
	anchor := []byte("operator key")
	stub := mockapi.New(t)
	verdict := mockapi.PassingVerdict("")
	verdict.Claims = tdxClaims(mrtd, anchor, p)
	stub.SetVerdict(verdict)
	policy := Pins{Images: []remote.ImagePin{{Name: "node", Digest: mrtd, Anchor: anchor}}}.VerifyPolicy(stub.URL())

	report, err := json.Marshal(teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{"quote":"fake"}`)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		list    []string
		wantErr bool
	}{
		{name: "replaying list", list: []string{p}},
		{name: "no list", wantErr: true},
	} {
		key, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		der, err := CreateAttestedCert(key, &Attestation{Family: TEETypeTDX, Report: report, RuntimeExtensions: tc.list}, nil)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCert(cert, policy, nil); (err != nil) != tc.wantErr {
			t.Errorf("%s: VerifyCert = %v, want error %v", tc.name, err, tc.wantErr)
		}
	}
}

// A journal that cannot be read, or that outgrew the per-boot cap, yields no
// list rather than failing the producer, and each distinct failure is logged
// once: a verifier that needs the list still fails closed.
func TestJournalOmitsUnusableList(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	dir := t.TempDir()
	path := filepath.Join(dir, "measured-policies")
	var logs bytes.Buffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))

	j := NewJournal(path)
	for _, tc := range []struct {
		name     string
		contents string // "" makes path a directory, which cannot be read
		want     []string
		wantLogs int
	}{
		{name: "unreadable", wantLogs: 1},
		{name: "still unreadable", wantLogs: 1},
		{name: "readable", contents: p + "\n", want: []string{p}, wantLogs: 1},
		{name: "over the cap", contents: distinctJournal(MaxRuntimeExtensions + 1), wantLogs: 2},
		{name: "still over the cap", contents: distinctJournal(MaxRuntimeExtensions + 1), wantLogs: 2},
	} {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		var err error
		if tc.contents == "" {
			err = os.Mkdir(path, 0o700)
		} else {
			err = os.WriteFile(path, []byte(tc.contents), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := j.Policies(); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Policies() = %d entries, want %v", tc.name, len(got), tc.want)
		}
		if got := strings.Count(logs.String(), "omits the measured policies"); got != tc.wantLogs {
			t.Errorf("%s: %d warnings logged, want %d", tc.name, got, tc.wantLogs)
		}
		tdx := &Attestation{Family: TEETypeTDX, Report: []byte("{}")}
		if _, err := MarshalExtension(WithRuntimeExtensions(tdx, j)); err != nil {
			t.Errorf("%s: MarshalExtension(WithRuntimeExtensions) = %v, want nil", tc.name, err)
		}
	}
}

// A missing journal is logged once, naming the path, so a wrong mount shows.
func TestJournalLogsMissingOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "measured-policies")
	var logs bytes.Buffer
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))

	j := NewJournal(path)
	for range 2 {
		if got := j.Policies(); got != nil {
			t.Fatalf("Policies() = %v, want nil", got)
		}
	}
	if got := strings.Count(logs.String(), "no measured-policy journal"); got != 1 {
		t.Errorf("%d missing-journal lines logged, want 1:\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), path) {
		t.Errorf("log does not name %s:\n%s", path, logs.String())
	}
}

// distinctJournal is a journal of n distinct digests.
func distinctJournal(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "sha256:%064x\n", i)
	}
	return b.String()
}
