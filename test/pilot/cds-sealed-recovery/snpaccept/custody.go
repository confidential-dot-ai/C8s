//go:build linux

package snpaccept

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/google/go-sev-guest/abi"
)

// This channel delegates the acceptance authority to a separate, exact-launch
// SNP guest. It does not carry the raw hardware root or introduce a production
// release API. The existing WALAuthority still approves every CDS key grant.
type CustodyRequest struct {
	Nonce     []byte `json:"nonce"`
	PublicKey []byte `json:"public_key"`
	Report    []byte `json:"report"`
}

type CustodyGrant struct {
	RequestHash []byte         `json:"request_hash"`
	KEM         []byte         `json:"kem"`
	Record      overenc.Record `json:"record"`
	Signature   []byte         `json:"signature"`
}

type custodyMaterial struct {
	Seed []byte `json:"seed"`
	Wrap []byte `json:"wrap"`
}

// CustodyRecipient is owned by one phase goroutine and consumed once.
type CustodyRecipient struct {
	request CustodyRequest
	key     *overenc.ClientKey
	used    bool
}

func custodyBinding(q CustodyRequest) [64]byte {
	q.Report = nil
	b, _ := json.Marshal(q)
	return sha512.Sum512(append([]byte("c8s/cds-snp-acceptance/custody-recipient/v1\x00"), b...))
}

func custodyHash(q CustodyRequest) []byte {
	b, _ := json.Marshal(q)
	h := sha512.Sum384(b)
	return h[:]
}

func newCustodyRecipient() (*CustodyRecipient, error) {
	key, err := overenc.GenerateClientKey()
	if err != nil {
		return nil, err
	}
	nonce, err := overenc.GenerateSessionID()
	if err != nil {
		return nil, err
	}
	return &CustodyRecipient{request: CustodyRequest{Nonce: nonce, PublicKey: bytes.Clone(key.EncapsulationKey())}, key: key}, nil
}

func NewCustodyRecipient(ctx context.Context, h *Hardware) (*CustodyRecipient, CustodyRequest, error) {
	r, err := newCustodyRecipient()
	if err != nil {
		return nil, CustodyRequest{}, err
	}
	r.request.Report, err = h.Report(ctx, custodyBinding(r.request))
	return r, r.request, err
}

func custodyTranscript(g CustodyGrant) []byte {
	h := sha512.New384()
	h.Write([]byte("c8s/cds-snp-acceptance/custody-channel/v1\x00"))
	h.Write(g.RequestHash)
	h.Write(g.KEM)
	return h.Sum(nil)
}

func custodySigned(g CustodyGrant) []byte {
	g.Signature = nil
	b, _ := json.Marshal(g)
	return append([]byte("c8s/cds-snp-acceptance/custody-grant/v1\x00"), b...)
}

func sealCustody(q CustodyRequest, signer ed25519.PrivateKey, wrap []byte) (*CustodyGrant, error) {
	ct, shared, err := overenc.Encapsulate(q.PublicKey)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	g := CustodyGrant{RequestHash: custodyHash(q), KEM: ct}
	channel, err := overenc.NewServerChannel(shared, custodyTranscript(g), q.Nonce)
	if err != nil {
		return nil, err
	}
	seed := signer.Seed()
	defer clear(seed)
	plain, err := json.Marshal(custodyMaterial{seed, wrap})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	g.Record, err = channel.SealResponse(plain, 1)
	if err != nil {
		return nil, err
	}
	g.Signature = ed25519.Sign(signer, custodySigned(g))
	return &g, nil
}

func checkCustodyRequest(q *CustodyRequest) error {
	if q == nil || len(q.Nonce) != overenc.SessionIDBytes || len(q.PublicKey) != overenc.XWingEKBytes || len(q.Report) != abi.ReportSize {
		return errors.New("bounded attested custody recipient required")
	}
	return nil
}

func (h *Hardware) Delegate(ctx context.Context, p Parameters, q *CustodyRequest, collateral Collateral) (*CustodyGrant, error) {
	if err := checkCustodyRequest(q); err != nil {
		return nil, err
	}
	signer, wrap, err := h.material(ctx, p)
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	defer clear(wrap)
	return h.delegateMaterial(ctx, signer, wrap, q, collateral)
}

func (h *Hardware) delegateMaterial(ctx context.Context, signer ed25519.PrivateKey, wrap []byte, q *CustodyRequest, collateral Collateral) (*CustodyGrant, error) {
	// The operator supplies neither the approved launch nor a recipient policy.
	// Both are computed from this custodian's unchanged measured template.
	launch, err := h.cdsLaunch(signer.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	config := sha256.Sum256(launch)
	binding := custodyBinding(*q)
	_, err = snp.VerifyReportContext(ctx, q.Report, nil, teetypes.VerifyParams{
		ExpectedReportData: binding[:], ExpectedInitDataHash: config[:], ExpectedLaunchDigest: h.ReportInfo.Measurement,
	}, teetypes.PlatformSNP, snp.MinReportVersion, snp.Options{CheckRevocations: true, Getter: collateral})
	if err != nil {
		return nil, err
	}
	r, err := abi.ReportToProto(q.Report)
	if err != nil {
		return nil, err
	}
	policy, err := abi.ParseSnpPolicy(r.Policy)
	if err != nil || policy.Debug || policy.MigrateMA || r.Vmpl != 0 {
		return nil, errors.New("custody recipient debug/migration/VMPL policy refused")
	}
	return sealCustody(*q, signer, wrap)
}

func (r *CustodyRecipient) Open(g CustodyGrant, authority ed25519.PublicKey) (ed25519.PrivateKey, []byte, error) {
	if r.used {
		return nil, nil, errors.New("custody recipient already consumed")
	}
	r.used = true
	if len(authority) != ed25519.PublicKeySize || len(g.KEM) != overenc.XWingCTBytes || len(g.Record.CT) > 1024 || g.Record.Seq != 1 ||
		!bytes.Equal(g.RequestHash, custodyHash(r.request)) || !ed25519.Verify(authority, custodySigned(g), g.Signature) {
		return nil, nil, errors.New("custody grant signature or recipient mismatch")
	}
	shared, err := r.key.Decapsulate(g.KEM)
	r.key = nil
	if err != nil {
		return nil, nil, err
	}
	defer clear(shared)
	channel, err := overenc.NewClientChannel(shared, custodyTranscript(g), r.request.Nonce)
	if err != nil {
		return nil, nil, err
	}
	plain, err := channel.OpenResponse(g.Record, 1)
	if err != nil {
		return nil, nil, err
	}
	defer clear(plain)
	var material custodyMaterial
	if err := json.Unmarshal(plain, &material); err != nil {
		return nil, nil, err
	}
	defer clear(material.Seed)
	if len(material.Seed) != ed25519.SeedSize || len(material.Wrap) != 32 {
		clear(material.Wrap)
		return nil, nil, errors.New("invalid sealed custody material")
	}
	signer := ed25519.NewKeyFromSeed(material.Seed)
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), authority) {
		clear(signer)
		clear(material.Wrap)
		return nil, nil, errors.New("recovered authority differs from measured CDS launch")
	}
	return signer, material.Wrap, nil
}
