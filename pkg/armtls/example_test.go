package armtls_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func ExampleNewServerTLSConfig() {
	tlsCfg, _, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform: "sev-snp",
		AttestFunc: func(ctx context.Context, customData string) (string, error) {
			// In production: call your TEE attestation infrastructure
			// to generate an SNP report with customData as REPORTDATA.
			return "", fmt.Errorf("not running in a TEE")
		},
		DNSNames: []string{"app.internal"},
	})
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{TLSConfig: tlsCfg}
	// server.ListenAndServeTLS("", "") — cert is provisioned lazily, in memory
	_ = server
	fmt.Println("server configured")
	// Output: server configured
}

func ExampleNewClientTLSConfig() {
	tlsCfg, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{
		Policy: &armtls.VerifyPolicy{
			// In production: set acceptable launch measurements.
			// Empty means accept any measurement (UNSAFE — dev only).
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	_ = client
	fmt.Println("client configured")
	// Output: client configured
}

func ExampleNewServerTLSConfig_mutualTLS() {
	tlsCfg, _, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform: "sev-snp",
		AttestFunc: func(ctx context.Context, customData string) (string, error) {
			return "", fmt.Errorf("not running in a TEE")
		},
		DNSNames:     []string{"app.internal"},
		ClientPolicy: &armtls.VerifyPolicy{
			// Require clients to present armTLS certificates.
			// Measurements: acceptable client launch measurements.
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = tlsCfg
	fmt.Println("mTLS server configured")
	// Output: mTLS server configured
}

func ExampleNewClientTLSConfig_mutualTLS() {
	tlsCfg, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{
		Policy: &armtls.VerifyPolicy{},
		// Present own armTLS certificate to the server.
		Platform: "sev-snp",
		AttestFunc: func(ctx context.Context, customData string) (string, error) {
			return "", fmt.Errorf("not running in a TEE")
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = tlsCfg
	fmt.Println("mTLS client configured")
	// Output: mTLS client configured
}

func ExampleGenerateKeyPair() {
	key, reportData, err := armtls.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("key curve: %s\n", key.Curve.Params().Name)
	fmt.Printf("reportData length: %d bytes\n", len(reportData))
	// Output:
	// key curve: P-256
	// reportData length: 64 bytes
}
