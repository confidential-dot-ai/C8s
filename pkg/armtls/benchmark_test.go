package armtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func BenchmarkGenerateKeyPair(b *testing.B) {
	for b.Loop() {
		_, _, _ = GenerateKeyPair()
	}
}

func BenchmarkReportDataForKey(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b.ResetTimer()
	for b.Loop() {
		_, _ = ReportDataForKey(&key.PublicKey, nil)
	}
}

func BenchmarkReportDataForKeyWithNonce(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce := []byte("benchmark-nonce-32-bytes-random!")
	b.ResetTimer()
	for b.Loop() {
		_, _ = ReportDataForKey(&key.PublicKey, nonce)
	}
}

func BenchmarkCreateAttestedCert(b *testing.B) {
	key, reportData, _ := GenerateKeyPair()
	att := &Attestation{
		Family: TEETypeSEVSNP,
		Report: fakeSNPReport(reportData),
	}
	opts := &CertOptions{
		TTL:      1 * time.Hour,
		DNSNames: []string{"bench.local"},
	}
	b.ResetTimer()
	for b.Loop() {
		_, _ = CreateAttestedCert(key, att, opts)
	}
}

func BenchmarkMarshalExtension(b *testing.B) {
	reportData := [64]byte{1, 2, 3, 4}
	att := &Attestation{
		Family:    TEETypeSEVSNP,
		Report:    fakeSNPReport(reportData),
		CertChain: []byte("fake-cert-chain-data"),
	}
	b.ResetTimer()
	for b.Loop() {
		_, _ = MarshalExtension(att)
	}
}

func BenchmarkUnmarshalExtension(b *testing.B) {
	reportData := [64]byte{1, 2, 3, 4}
	att := &Attestation{
		Family:    TEETypeSEVSNP,
		Report:    fakeSNPReport(reportData),
		CertChain: []byte("fake-cert-chain-data"),
	}
	ext, _ := MarshalExtension(att)
	b.ResetTimer()
	for b.Loop() {
		_, _ = UnmarshalExtension(ext.Value)
	}
}
