// Package ratls binds a TLS key to a TEE with an X.509 certificate extension:
// the attestation report's REPORTDATA is hash(publicKey), so a verified report
// proves the key was generated inside the TEE. The extension itself — wire
// format, parsing, the key binding — lives in attestation-go/ratls; this
// package is the C8s side of it: certificate issuance and lifecycle, the TLS
// server and client configs, the CDS provisioning client, and the policy
// verification that runs over the C8s attestation-api.
package ratls
