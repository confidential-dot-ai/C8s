package types

import "encoding/json"

// DiscoveryDocument is the /v1/discovery preflight document the router serves
// (written by get-cert): the CDS-issued serving certificate plus the attestation
// evidence captured at issuance. It is the wire contract shared between the
// producer (get-cert) and consumers (c8s verify, c8s-verify-js).
type DiscoveryDocument struct {
	Version     string               `json:"version"`
	GeneratedAt string               `json:"generated_at"`
	PublicTLS   PublicTLSDiscovery   `json:"public_tls"`
	CDSTLS      CDSTLSDiscovery      `json:"cds_tls"`
	Attestation AttestationDiscovery `json:"attestation"`
}

// PublicTLSDiscovery describes the public-facing TLS identity (hostname + mode).
type PublicTLSDiscovery struct {
	Hostname string `json:"hostname"`
	Mode     string `json:"mode"`
}

// CDSTLSDiscovery carries the CDS-issued serving certificate and where it (and
// the mesh CA) are served.
type CDSTLSDiscovery struct {
	CertificatePEM    string `json:"certificate_pem"`
	CertificateSHA256 string `json:"certificate_sha256"`
	CertificateURL    string `json:"certificate_url,omitempty"`
	MeshCAURL         string `json:"mesh_ca_url,omitempty"`
}

// AttestationDiscovery carries the issuance challenge plus the platform-specific
// attestation evidence object, kept raw so it is forwarded verbatim to
// verification (SEV-SNP, TDX, …).
type AttestationDiscovery struct {
	Challenge string          `json:"challenge"`
	Platform  string          `json:"platform"`
	Evidence  json.RawMessage `json:"evidence"`

	// RuntimeExtensions is the TDX RTMR[3] runtime extension list sent with
	// the evidence, unauthenticated until replayed against the quote.
	RuntimeExtensions []string `json:"runtime_extensions,omitempty"`
}
