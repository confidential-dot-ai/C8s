package attestclient

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestObtainCertificateRejectsInvalidCSRBeforeEvidence(t *testing.T) {
	block, _ := pem.Decode([]byte(testCSRPEM(t)))
	if block == nil {
		t.Fatal("fixture is not PEM")
	}
	block.Bytes[len(block.Bytes)-1] ^= 1
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("invalid-signature fixture must still parse: %v", err)
	}
	if err := request.CheckSignature(); err == nil {
		t.Fatal("fixture signature is valid")
	}

	profile := IssuanceProfile{
		ReportData: func(crypto.PublicKey, []byte) ([]byte, error) {
			t.Fatal("invalid CSR reached report-data generation")
			return nil, errors.New("unexpected report-data generation")
		},
		Request: func(teetypes.PlatformType, *types.AttestRequestBody) error {
			t.Fatal("invalid CSR reached request preparation")
			return errors.New("unexpected request preparation")
		},
	}
	client := NewClient(unreachableURL)
	result, err := client.ObtainCertificateWithProfileContext(
		context.Background(),
		unreachableURL,
		string(pem.EncodeToMemory(block)),
		"dGVzdC1jaGFsbGVuZ2U=",
		profile,
	)
	if result.Certificate != "" || err == nil || !strings.HasPrefix(err.Error(), "CSR signature invalid:") {
		t.Fatalf("issuance = %v, %v; want an empty certificate and a signature refusal", result, err)
	}
}
