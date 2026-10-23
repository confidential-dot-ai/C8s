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
	"unicode/utf8"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const (
	PodClaimsVersion  = 1
	MaxPodClaimsBytes = 1 << 20
)

// PodClaims is a guest-owned admission snapshot, authenticated by fresh TDX
// evidence rather than by the TLS private key exported to the mesh container.
// RuntimeExtensions is the complete ordered image journal for this boot;
// Containers retains every distinct admission, including exited init jobs.
// AssignedPodUID is the signed assignment; RuntimePodUID is kubelet's actual
// static-Pod UID. Neither is substituted for the guest-generated BootID.
type PodClaims struct {
	Version           int                `json:"version"`
	BootID            string             `json:"boot_id"`
	AssignedPodUID    string             `json:"assigned_pod_uid"`
	RuntimePodUID     string             `json:"runtime_pod_uid"`
	SandboxID         string             `json:"sandbox_id"`
	Revision          uint64             `json:"revision"`
	RuntimeExtensions []string           `json:"runtime_extensions"`
	Containers        []SandboxContainer `json:"containers"`
}

// The Pod-only adapter preserves named source volumes, which the legacy node
// callback omits. Host source paths are never serialized. Embedding retains
// the existing observation field names; the explicit mounts member overrides
// SandboxContainer.Mounts without emitting duplicate JSON keys.
type podContainerWire struct {
	SandboxContainer
	Mounts []podMountWire `json:"mounts"`
}
type podMountWire struct {
	allowlist.ObservedMount
	Volume string `json:"volume,omitempty"`
}
type podClaimsWire struct {
	Version           int                `json:"version"`
	BootID            string             `json:"boot_id"`
	AssignedPodUID    string             `json:"assigned_pod_uid"`
	RuntimePodUID     string             `json:"runtime_pod_uid"`
	SandboxID         string             `json:"sandbox_id"`
	Revision          uint64             `json:"revision"`
	RuntimeExtensions []string           `json:"runtime_extensions"`
	Containers        []podContainerWire `json:"containers"`
}

func podWire(p PodClaims) podClaimsWire {
	w := podClaimsWire{Version: p.Version, BootID: p.BootID, AssignedPodUID: p.AssignedPodUID, RuntimePodUID: p.RuntimePodUID, SandboxID: p.SandboxID, Revision: p.Revision, RuntimeExtensions: p.RuntimeExtensions}
	for _, c := range p.Containers {
		mounts := make([]podMountWire, len(c.Mounts))
		for i, m := range c.Mounts {
			mounts[i] = podMountWire{ObservedMount: m, Volume: m.Volume}
		}
		w.Containers = append(w.Containers, podContainerWire{SandboxContainer: c, Mounts: mounts})
	}
	return w
}

func (w podClaimsWire) claims() PodClaims {
	p := PodClaims{Version: w.Version, BootID: w.BootID, AssignedPodUID: w.AssignedPodUID, RuntimePodUID: w.RuntimePodUID, SandboxID: w.SandboxID, Revision: w.Revision, RuntimeExtensions: w.RuntimeExtensions}
	for _, c := range w.Containers {
		var mounts []allowlist.ObservedMount
		if c.Mounts != nil {
			mounts = make([]allowlist.ObservedMount, len(c.Mounts))
		}
		for i, m := range c.Mounts {
			mounts[i] = m.ObservedMount
			mounts[i].Volume = m.Volume
		}
		c.SandboxContainer.Mounts = mounts
		p.Containers = append(p.Containers, c.SandboxContainer)
	}
	return p
}

// InstanceID names one guest boot and runtime sandbox. Its framing is JSON,
// so different UID/sandbox boundaries cannot produce the same hash input.
func (p PodClaims) InstanceID() string {
	b, _ := json.Marshal([]string{p.BootID, p.RuntimePodUID, p.SandboxID})
	h := sha256.Sum256(b)
	return "pcvm-" + hex.EncodeToString(h[:])
}

// Canonical returns the sole Pod claims wire encoding: encoding/json's compact
// struct encoding, with stable field order and lexically ordered map keys.
// Admissions are sorted bytewise by their compact JSON; the log stays ordered.
// Invalid or incomplete image history is never repaired by normalization.
func (p PodClaims) Canonical() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	wire := podWire(p)
	slices.SortFunc(wire.Containers, func(a, b podContainerWire) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return bytes.Compare(x, y)
	})
	b, err := json.Marshal(wire)
	if err != nil || len(b) > MaxPodClaimsBytes {
		return nil, fmt.Errorf("invalid or oversized Pod claims")
	}
	return b, nil
}

// DecodePodClaims rejects alternate encodings, unknown fields, duplicate keys,
// noncanonical nulls and lossy Unicode before hashing the submitted bytes.
// Env.VariableDigests may be null to report unavailable per-variable evidence.
func DecodePodClaims(raw []byte) (PodClaims, error) {
	var p PodClaims
	if len(raw) > MaxPodClaimsBytes || strictjson.Validate(raw) != nil {
		return p, fmt.Errorf("invalid Pod claims JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var wire podClaimsWire
	if err := dec.Decode(&wire); err != nil {
		return PodClaims{}, fmt.Errorf("invalid Pod claims fields")
	}
	p = wire.claims()
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
		canonical, err := runtimemeasure.CanonicalDigest(d)
		if err != nil || canonical != d || measured[d] {
			return fmt.Errorf("invalid or duplicate Pod runtime extension")
		}
		measured[d] = true
	}
	observed, admissions := map[string]bool{}, map[string]bool{}
	for _, c := range p.Containers {
		canonical, err := runtimemeasure.CanonicalDigest(c.Digest)
		if err != nil || canonical != c.Digest || len(c.Argv) == 0 || !c.Env.Valid() || c.Mounts == nil {
			return fmt.Errorf("incomplete Pod container observation")
		}
		if !validPodStrings(c.Role) || !validPodStrings(c.Argv...) {
			return fmt.Errorf("invalid Pod observation text")
		}
		for _, m := range c.Mounts {
			if !validPodStrings(m.Destination, m.Volume, string(m.Class), string(m.Storage), m.HostSourceDigest, m.Provenance) {
				return fmt.Errorf("invalid Pod mount observation text")
			}
		}
		if admissions[c.Key()] {
			return fmt.Errorf("duplicate Pod admission")
		}
		admissions[c.Key()], observed[c.Digest] = true, true
	}
	if !maps.Equal(measured, observed) {
		return fmt.Errorf("pod observations disagree with complete measurement journal")
	}
	return nil
}

func validPodStrings(values ...string) bool {
	for _, value := range values {
		if !utf8.ValidString(value) {
			return false
		}
	}
	return true
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
	keyHash, claimsHash := sha512.Sum384(spki), sha512.Sum384(canonical)
	h := sha512.New384()
	_, _ = h.Write([]byte("c8s-pod-attestation/v1\x00"))
	_, _ = h.Write(keyHash[:])
	_, _ = h.Write(nonce)
	_, _ = h.Write(claimsHash[:])
	return h.Sum(nil), nil
}
