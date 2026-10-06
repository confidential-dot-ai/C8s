//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

func TestMakeAttestFunc_ReportDataSize(t *testing.T) {
	// Simulate the data flow: ReportDataForKey returns a 64-byte array
	// (48-byte SHA-384 hash + 16 zero bytes). makeAttestFunc must send
	// only the 48-byte hash to the attestation-api, NOT the full
	// 64-byte padded array. Sending 64 bytes causes TPM_RC_SIZE on vTPMs.
	stub := mockapi.New(t)
	attestFunc := makeAttestFunc(attestclient.NewClient(""), stub.URL())

	// Build a 64-byte hex string (like SelfSignedProvider.Provision does).
	var reportData [64]byte
	hash := sha512.Sum384([]byte("test-public-key"))
	copy(reportData[:], hash[:])
	customData := fmt.Sprintf("%x", reportData[:])

	if _, err := attestFunc(context.Background(), customData); err != nil {
		t.Fatalf("attestFunc failed: %v", err)
	}

	reqs := stub.AttestRequests()
	if len(reqs) != 1 {
		t.Fatalf("/attest calls = %d, want 1", len(reqs))
	}
	if got := len(reqs[0].ReportData); got != sha512.Size384 {
		t.Errorf("attestation-api received %d bytes, want %d (SHA-384 hash only, no zero padding)", got, sha512.Size384)
	}
}

func TestMakeAttestFunc_ReportDataNotZeroPadded(t *testing.T) {
	// Regression test: even when the SHA-384 hash contains trailing bytes
	// that happen to be non-zero, the sent data must be exactly sha512.Size384
	// bytes, no more and no less.
	stub := mockapi.New(t)
	attestFunc := makeAttestFunc(attestclient.NewClient(""), stub.URL())

	// Create report data where the hash fills all 48 bytes.
	var reportData [64]byte
	for i := range 48 {
		reportData[i] = byte(i + 1)
	}
	customData := hex.EncodeToString(reportData[:])

	if _, err := attestFunc(context.Background(), customData); err != nil {
		t.Fatalf("attestFunc failed: %v", err)
	}

	reqs := stub.AttestRequests()
	if len(reqs) != 1 {
		t.Fatalf("/attest calls = %d, want 1", len(reqs))
	}
	receivedBytes := reqs[0].ReportData
	if len(receivedBytes) != sha512.Size384 {
		t.Fatalf("received %d bytes, want %d", len(receivedBytes), sha512.Size384)
	}
	for i := range 48 {
		if receivedBytes[i] != byte(i+1) {
			t.Errorf("byte %d: got %d, want %d", i, receivedBytes[i], i+1)
		}
	}
}
