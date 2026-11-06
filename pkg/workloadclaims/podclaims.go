package workloadclaims

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	PodClaimsVersion  = 1
	MaxPodClaimsBytes = 1 << 20
)

// PodClaims is a guest-owned admission snapshot, authenticated by fresh TDX
// evidence rather than by the TLS private key exported to the mesh container.
// RuntimeExtensions is the complete ordered image journal for this boot;
// Containers lists the image digest of every distinct admission, including
// exited init jobs. The claims carry image digests only: no argument,
// environment, mount or role observation. AssignedPodUID is the signed
// assignment; RuntimePodUID is kubelet's actual static-Pod UID. Neither is
// substituted for the guest-generated BootID.
type PodClaims struct {
	Version           int            `json:"version"`
	BootID            string         `json:"boot_id"`
	AssignedPodUID    string         `json:"assigned_pod_uid"`
	RuntimePodUID     string         `json:"runtime_pod_uid"`
	SandboxID         string         `json:"sandbox_id"`
	Revision          uint64         `json:"revision"`
	RuntimeExtensions []string       `json:"runtime_extensions"`
	Containers        []PodContainer `json:"containers"`
}

// PodContainer is one admitted container of a pod CVM: its image digest.
type PodContainer struct {
	Digest string `json:"digest"`
}

// InstanceID names one guest boot and runtime sandbox. Its framing is JSON,
// so different UID/sandbox boundaries cannot produce the same hash input.
func (p PodClaims) InstanceID() string {
	b, _ := json.Marshal([]string{p.BootID, p.RuntimePodUID, p.SandboxID})
	h := sha256.Sum256(b)
	return "pcvm-" + hex.EncodeToString(h[:])
}

// Canonical returns the sole Pod claims wire encoding: encoding/json's compact
// struct encoding with stable field order. Containers are sorted by digest;
// the log stays ordered. Invalid or incomplete image history is never
// repaired by normalization.
func (p PodClaims) Canonical() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	containers := slices.Clone(p.Containers)
	slices.SortFunc(containers, func(a, b PodContainer) int { return strings.Compare(a.Digest, b.Digest) })
	p.Containers = containers
	b, err := json.Marshal(p)
	if err != nil || len(b) > MaxPodClaimsBytes {
		return nil, fmt.Errorf("invalid or oversized Pod claims")
	}
	return b, nil
}

// DecodePodClaims rejects alternate encodings, unknown fields, duplicate keys
// and noncanonical nulls before hashing the submitted bytes.
func DecodePodClaims(raw []byte) (PodClaims, error) {
	var p PodClaims
	if len(raw) > MaxPodClaimsBytes || strictjson.Validate(raw) != nil {
		return p, fmt.Errorf("invalid Pod claims JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return PodClaims{}, fmt.Errorf("invalid Pod claims fields")
	}
	canonical, err := p.Canonical()
	if err != nil {
		return PodClaims{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return PodClaims{}, fmt.Errorf("pod claims are not canonically encoded")
	}
	return p, nil
}

func (p PodClaims) validate() error {
	boot, err := hex.DecodeString(p.BootID)
	if p.Version != PodClaimsVersion || err != nil || len(boot) != 32 || hex.EncodeToString(boot) != p.BootID || p.Revision == 0 {
		return fmt.Errorf("invalid Pod claims version or boot identity")
	}
	for _, id := range []string{p.AssignedPodUID, p.RuntimePodUID, p.SandboxID} {
		if armtls.ValidateSandboxID(id) != nil {
			return fmt.Errorf("invalid Pod claims identity")
		}
	}
	if len(p.RuntimeExtensions) == 0 || len(p.RuntimeExtensions) > armtls.MaxRuntimeExtensions || len(p.Containers) == 0 {
		return fmt.Errorf("pod claims require bounded, nonempty admission history")
	}
	measured := map[string]bool{}
	for _, d := range p.RuntimeExtensions {
		if !types.IsCanonicalDigest(d) || measured[d] {
			return fmt.Errorf("invalid or duplicate Pod runtime extension")
		}
		measured[d] = true
	}
	observed := map[string]bool{}
	for _, c := range p.Containers {
		if !types.IsCanonicalDigest(c.Digest) {
			return fmt.Errorf("invalid Pod container digest")
		}
		observed[c.Digest] = true
	}
	if !maps.Equal(measured, observed) {
		return fmt.Errorf("pod observations disagree with complete measurement journal")
	}
	return nil
}

// PodReportData binds a fresh quote to one CSR and one complete canonical
// snapshot. Domain separation keeps node CSRs and public status quotes from
// being interpreted as authenticated Pod observations. All hash inputs after
// the domain are fixed width: SPKI SHA-384, nonce32, claims SHA-384.
func PodReportData(pub crypto.PublicKey, nonce, canonical []byte) ([]byte, error) {
	if len(nonce) != 32 {
		return nil, fmt.Errorf("pod attestation requires a 32-byte challenge")
	}
	if _, err := DecodePodClaims(canonical); err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("invalid Pod CSR key")
	}
	keyHash := sha512.Sum384(spki)
	claimsHash := sha512.Sum384(canonical)
	h := sha512.New384()
	_, _ = h.Write([]byte("c8s-pod-attestation/v1\x00"))
	_, _ = h.Write(keyHash[:])
	_, _ = h.Write(nonce)
	_, _ = h.Write(claimsHash[:])
	return h.Sum(nil), nil
}
