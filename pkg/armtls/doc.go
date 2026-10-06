// Package armtls implements attestation-rooted TLS (ARmTLS) for C8s.
// Peers authenticate through key-bound TEE evidence or a configured mesh CA.
// CDS verifies attestation before issuing mesh certificates.
//
// This package provides certificate issuance and lifecycle, TLS configurations,
// CDS provisioning, and policy verification through the C8s attestation-api.
// The evidence extension format and key binding live in attestation-go/armtls.
package armtls
