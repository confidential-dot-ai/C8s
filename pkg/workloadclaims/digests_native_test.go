package workloadclaims

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestNativeInventoryLimitPreservesTLSStateAndNativePeerVerification(t *testing.T) {
	key, binding, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := make([]byte, armtls.SNPReportSize)
	report[0] = 2
	copy(report[0x50:0x90], binding[:])
	report[0x1f0], report[0x1f6], report[0x1f7] = 255, 255, 255
	der, err := armtls.CreateAttestedCert(key, &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: report}, nil)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	var verified atomic.Int64
	native, err := armtls.NewNativeVerifierWithEngine(teetypes.SnpTcb{Bootloader: 12, Snp: 28, Microcode: 28}, func(_ context.Context, _ teetypes.AttestationEvidence, params teetypes.VerifyParams, options teeverify.Options) (*teetypes.VerificationResult, error) {
		verified.Add(1)
		if !options.SNP.CheckRevocations || !bytes.Equal(params.ExpectedReportData, binding[:48]) {
			return nil, errors.New("native inventory lost peer binding or collateral policy")
		}
		return &teetypes.VerificationResult{
			Platform: teetypes.PlatformSNP, SignatureValid: true, CollateralVerified: true,
			ReportDataMatch: teetypes.Ptr(true),
			Claims:          teetypes.Claims{LaunchDigest: hex.EncodeToString(testPins().Current().Images[0].Digest), PlatformData: map[string]any{"policy": map[string]any{"migrate_ma": false}}},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert}
	armtls.FollowNativeClientPins(serverTLS, testPins(), native)
	listener, err := listenDigests("127.0.0.1:0", serverTLS, true)
	if err != nil {
		t.Fatal(err)
	}
	sawTLS := make(chan bool, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		sawTLS <- request.TLS != nil && len(request.TLS.PeerCertificates) == 1
		w.WriteHeader(http.StatusNoContent)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) != 1 || !bytes.Equal(raw[0], der) {
				return errors.New("test inventory certificate changed")
			}
			return nil
		},
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if !<-sawTLS || verified.Load() != 1 {
		t.Fatalf("bounded inventory listener lost TLS state or native peer verification: native calls=%d", verified.Load())
	}
}
