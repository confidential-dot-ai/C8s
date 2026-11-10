package objectstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

const (
	RequestPath = "/object-state/recovery/request"
	GrantPath   = "/object-state/recovery/grant"
)

var (
	ErrRecipientUsed         = errors.New("object state recovery: recipient already consumed")
	ErrRecoveryPolicyChanged = errors.New("object state recovery: current policy changed")
)

// RecoveryIdentity is selected by custody policy, never by the provisioning
// relay. StorageSHA256 binds the complete storage authority and object address.
type RecoveryIdentity struct {
	ClusterID     string `json:"cluster_id"`
	StorageSHA256 string `json:"storage_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
}

func (i RecoveryIdentity) check() error {
	if i.ClusterID == "" || len(i.ClusterID) > 256 || !utf8.ValidString(i.ClusterID) {
		return errors.New("object state recovery: invalid cluster identity")
	}
	for _, value := range []string{
		i.StorageSHA256,
		i.ConfigSHA256,
	} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
			return errors.New("object state recovery: canonical SHA-256 bindings required")
		}
	}
	return nil
}

type RecoveryRequest struct {
	Version   int              `json:"version"`
	Identity  RecoveryIdentity `json:"identity"`
	Nonce     []byte           `json:"nonce"`
	PublicKey []byte           `json:"public_key"`
}

func (r RecoveryRequest) Check() error {
	if r.Version != 1 || len(r.Nonce) != overenc.SessionIDBytes || len(r.PublicKey) != overenc.XWingEKBytes {
		return errors.New("object state recovery: malformed recipient")
	}
	return r.Identity.check()
}

// Digest binds a grant to one recipient incarnation obtained over attested TLS.
func (r RecoveryRequest) Digest() []byte {
	body, _ := json.Marshal(r)
	hash := sha512.Sum384(append(
		[]byte("c8s/object-state/v1/recovery-request\x00"),
		body...,
	))
	return hash[:]
}

// RecoveryMaterial is plaintext only inside the custodian and approved CDS.
// It can recover existing state but carries no initialization authority.
type RecoveryMaterial struct {
	Key []byte `json:"key"`
}

type RecoveryGrant struct {
	RequestHash []byte         `json:"request_hash"`
	KEM         []byte         `json:"kem"`
	Record      overenc.Record `json:"record"`
	Signature   []byte         `json:"signature"`
}

func (g RecoveryGrant) Check() error {
	if len(g.RequestHash) != sha512.Size384 || len(g.KEM) != overenc.XWingCTBytes ||
		g.Record.Seq != 1 || len(g.Record.CT) < 16 || len(g.Record.CT) > 256 ||
		len(g.Signature) != ed25519.SignatureSize {
		return errors.New("object state recovery: malformed grant")
	}
	return nil
}

// Recipient belongs to one process incarnation. Its public request and private
// key are immutable; exactly one successful Open may return recovered material.
type Recipient struct {
	request RecoveryRequest
	key     *overenc.ClientKey
	used    atomic.Bool
}

func NewRecipient(identity RecoveryIdentity) (*Recipient, error) {
	if err := identity.check(); err != nil {
		return nil, err
	}
	key, err := overenc.GenerateClientKey()
	if err != nil {
		return nil, err
	}
	nonce, err := overenc.GenerateSessionID()
	if err != nil {
		return nil, err
	}
	return &Recipient{
		request: RecoveryRequest{
			Version:   1,
			Identity:  identity,
			Nonce:     nonce,
			PublicKey: bytes.Clone(key.EncapsulationKey()),
		},
		key: key,
	}, nil
}

func (r *Recipient) Request() RecoveryRequest {
	request := r.request
	request.Nonce = bytes.Clone(request.Nonce)
	request.PublicKey = bytes.Clone(request.PublicKey)
	return request
}

func (r *Recipient) Open(
	grant RecoveryGrant,
	authority ed25519.PublicKey,
) (RecoveryMaterial, error) {
	if r.used.Load() {
		return RecoveryMaterial{}, ErrRecipientUsed
	}
	if err := grant.Check(); err != nil {
		return RecoveryMaterial{}, err
	}
	if len(authority) != ed25519.PublicKeySize ||
		!bytes.Equal(
			grant.RequestHash,
			r.request.Digest(),
		) ||
		!ed25519.Verify(
			authority,
			recoverySignedBytes(grant),
			grant.Signature,
		) {
		return RecoveryMaterial{}, errors.New("object state recovery: wrong recipient or authority")
	}
	shared, err := r.key.Decapsulate(grant.KEM)
	if err != nil {
		return RecoveryMaterial{}, err
	}
	defer clear(shared)
	channel, err := overenc.NewClientChannel(
		shared,
		recoveryTranscript(grant),
		r.request.Nonce,
	)
	if err != nil {
		return RecoveryMaterial{}, err
	}
	plaintext, err := channel.OpenResponse(
		grant.Record,
		1,
	)
	if err != nil {
		return RecoveryMaterial{}, errors.New("object state recovery: invalid sealed material")
	}
	defer clear(plaintext)
	var material RecoveryMaterial
	if err := decodeRecovery(
		plaintext,
		&material,
	); err != nil || len(material.Key) != 32 {
		clear(material.Key)
		return RecoveryMaterial{}, errors.New("object state recovery: invalid recovered key")
	}
	if !r.used.CompareAndSwap(
		false,
		true,
	) {
		clear(material.Key)
		return RecoveryMaterial{}, ErrRecipientUsed
	}
	return material, nil
}

func recoveryTranscript(grant RecoveryGrant) []byte {
	hash := sha512.New384()
	hash.Write([]byte("c8s/object-state/v1/recovery-channel\x00"))
	hash.Write(grant.RequestHash)
	hash.Write(grant.KEM)
	return hash.Sum(nil)
}

func recoverySignedBytes(grant RecoveryGrant) []byte {
	grant.Signature = nil
	body, _ := json.Marshal(grant)
	return append(
		[]byte("c8s/object-state/v1/recovery-grant\x00"),
		body...,
	)
}

func sealRecovery(
	request RecoveryRequest,
	material RecoveryMaterial,
	signer ed25519.PrivateKey,
) (*RecoveryGrant, error) {
	if err := request.Check(); err != nil {
		return nil, err
	}
	if err := checkRecoveryMaterial(
		material,
		signer,
	); err != nil {
		return nil, err
	}
	kem, shared, err := overenc.Encapsulate(request.PublicKey)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	grant := RecoveryGrant{
		RequestHash: request.Digest(),
		KEM:         kem,
	}
	channel, err := overenc.NewServerChannel(
		shared,
		recoveryTranscript(grant),
		request.Nonce,
	)
	if err != nil {
		return nil, err
	}
	plaintext, _ := json.Marshal(material)
	defer clear(plaintext)
	grant.Record, err = channel.SealResponse(
		plaintext,
		1,
	)
	if err != nil {
		return nil, err
	}
	grant.Signature = ed25519.Sign(
		signer,
		recoverySignedBytes(grant),
	)
	return &grant, nil
}

func checkRecoveryMaterial(
	material RecoveryMaterial,
	signer ed25519.PrivateKey,
) error {
	if len(material.Key) != 32 {
		return errors.New("object state recovery: invalid custody material")
	}
	return checkRecoverySigner(signer)
}

func checkRecoverySigner(signer ed25519.PrivateKey) error {
	if len(signer) != ed25519.PrivateKeySize {
		return errors.New("object state recovery: invalid signing key")
	}
	canonical := ed25519.NewKeyFromSeed(signer[:ed25519.SeedSize])
	defer clear(canonical)
	if !bytes.Equal(
		canonical,
		signer,
	) {
		return errors.New("object state recovery: inconsistent signing key")
	}
	return nil
}

// RecoveryPolicy is selected by the independently controlled custodian. The
// verifier is local to that trusted runtime, not supplied by a recovery relay.
type RecoveryPolicy struct {
	Revision       string
	Images         []remote.ImagePin
	AttestationURL string
	Native         *armtls.NativeVerifier
}

// RecoveryPolicySource freshly authenticates the same current object CDS serves.
// Owner-approved image policy comes from measured custody configuration or that
// authenticated state. Missing state is always an error. Each result is owned
// by the caller. This interface does not supply custody deployment, a hardware
// key root or rollback protection.
type RecoveryPolicySource interface {
	Current(context.Context) (RecoveryPolicy, error)
}

// Release authenticates the recipient itself, then rereads current policy
// before sealing. The final read orders release against revocation; revocation
// after it cannot recall an already authorized grant. Keys must already be
// protected inside the custodian; this helper does not create hardware custody.
func Release(
	ctx context.Context,
	expected RecoveryIdentity,
	origin string,
	source RecoveryPolicySource,
	material RecoveryMaterial,
	signer ed25519.PrivateKey,
) (*RecoveryGrant, error) {
	return releaseRecovery(
		ctx,
		expected,
		origin,
		source,
		material,
		signer,
		fetchRecoveryRecipient,
	)
}

func releaseRecovery(
	ctx context.Context,
	expected RecoveryIdentity,
	origin string,
	source RecoveryPolicySource,
	material RecoveryMaterial,
	signer ed25519.PrivateKey,
	fetch recoveryRecipientFetcher,
) (*RecoveryGrant, error) {
	if err := checkRecoveryMaterial(
		material,
		signer,
	); err != nil {
		return nil, err
	}
	request, err := authorizeRecoveryRecipient(
		ctx,
		expected,
		origin,
		source,
		fetch,
	)
	if err != nil {
		return nil, err
	}
	return sealRecovery(
		request,
		material,
		signer,
	)
}

type recoveryRecipientFetcher func(
	context.Context,
	RecoveryIdentity,
	string,
	RecoveryPolicy,
) (RecoveryRequest, error)

func authorizeRecoveryRecipient(
	ctx context.Context,
	expected RecoveryIdentity,
	origin string,
	source RecoveryPolicySource,
	fetch recoveryRecipientFetcher,
) (RecoveryRequest, error) {
	if err := expected.check(); err != nil {
		return RecoveryRequest{}, err
	}
	u, err := url.Parse(origin)
	if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || source == nil {
		return RecoveryRequest{}, errors.New("object state recovery: HTTPS origin and current policy required")
	}
	ctx, cancel := context.WithTimeout(
		ctx,
		10*time.Second,
	)
	defer cancel()
	policy, err := source.Current(ctx)
	if err != nil {
		return RecoveryRequest{}, err
	}
	if err := policy.Check(expected); err != nil {
		return RecoveryRequest{}, err
	}
	request, err := fetch(
		ctx,
		expected,
		origin,
		policy,
	)
	if err != nil {
		return RecoveryRequest{}, err
	}
	if request.Identity != expected {
		return RecoveryRequest{}, errors.New("object state recovery: recipient identity mismatch")
	}
	if err := request.Check(); err != nil {
		return RecoveryRequest{}, err
	}
	finalPolicy, err := source.Current(ctx)
	if err != nil {
		return RecoveryRequest{}, err
	}
	if !reflect.DeepEqual(
		policy,
		finalPolicy,
	) {
		return RecoveryRequest{}, ErrRecoveryPolicyChanged
	}
	if err := ctx.Err(); err != nil {
		return RecoveryRequest{}, err
	}
	return request, nil
}

// Check requires bounded image pins for the exact measured launch and a
// verifier local to the trusted custodian. It does not authenticate the policy.
func (policy RecoveryPolicy) Check(expected RecoveryIdentity) error {
	if policy.Native == nil {
		return errors.New("object state recovery: native verifier required")
	}
	if policy.Revision == "" || len(policy.Revision) > 1024 ||
		len(policy.Images) == 0 || len(policy.Images) > 64 {
		return errors.New("object state recovery: bounded current image policy required")
	}
	local, err := url.Parse(policy.AttestationURL)
	if err != nil {
		return errors.New("object state recovery: invalid verifier")
	}
	ip, _ := netip.ParseAddr(local.Hostname())
	unix := local.Scheme == "unix" && local.Host == "" && local.Path != ""
	loopback := (local.Scheme == "http" || local.Scheme == "https") && ip.IsLoopback() &&
		(local.Path == "" || local.Path == "/")
	if (!unix && !loopback) || local.User != nil || local.RawQuery != "" || local.ForceQuery || local.Fragment != "" {
		return errors.New("object state recovery: verifier must be local to the custodian")
	}
	for _, image := range policy.Images {
		hash := sha256.Sum256(image.LaunchFile)
		if len(image.Digest) != 48 || len(image.LaunchFile) == 0 || len(image.LaunchFile) > 1<<20 ||
			hex.EncodeToString(hash[:]) != expected.ConfigSHA256 ||
			image.Anchor != nil || image.LaunchFileDigest != nil || image.AcceptExtension != nil {
			return errors.New("object state recovery: images must pin the exact measured launch")
		}
		for index, register := range image.Registers {
			if index < 0 || index > 3 || len(register) != 48 {
				return errors.New("object state recovery: invalid image register")
			}
		}
	}
	return nil
}

func fetchRecoveryRecipient(
	ctx context.Context,
	expected RecoveryIdentity,
	origin string,
	policy RecoveryPolicy,
) (RecoveryRequest, error) {
	if policy.Native == nil {
		return RecoveryRequest{}, errors.New("object state recovery: native recipient verifier required")
	}
	verification := armtls.Pins{Images: policy.Images}.VerifyPolicy(policy.AttestationURL)
	verification.RequireNonMigratable = true
	verification.Native = policy.Native
	tlsConfig, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{Policy: verification})
	if err != nil {
		return RecoveryRequest{}, err
	}
	client := armtls.HTTPClient(tlsConfig)
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(
		*http.Request,
		[]*http.Request,
	) error {
		return http.ErrUseLastResponse
	}
	u, _ := url.Parse(origin)
	u.Path = RequestPath
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		u.String(),
		nil,
	)
	if err != nil {
		return RecoveryRequest{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return RecoveryRequest{}, errors.New("object state recovery: attested recipient connection failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return RecoveryRequest{}, errors.New("object state recovery: recipient request refused")
	}
	body, err := readutil.ReadAll(
		response.Body,
		8<<10,
	)
	if err != nil {
		return RecoveryRequest{}, errors.New("object state recovery: malformed recipient response")
	}
	var recipient RecoveryRequest
	if err := decodeRecovery(
		body,
		&recipient,
	); err != nil || recipient.Identity != expected {
		return RecoveryRequest{}, errors.New("object state recovery: recipient identity mismatch")
	}
	if err := recipient.Check(); err != nil {
		return RecoveryRequest{}, err
	}
	return recipient, nil
}

func decodeRecovery(
	body []byte,
	destination any,
) error {
	if err := strictjson.Validate(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}
