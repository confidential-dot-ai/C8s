package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// objectImage is one complete committed state. A format change must first
// ship readers that understand both formats, before any writer adopts it.
type objectImage struct {
	Version         int                        `json:"version"`
	Revision        uint64                     `json:"revision"`
	Launch          [32]byte                   `json:"launch"`
	StartedMS       int64                      `json:"started_ms"`
	CACert          []byte                     `json:"ca_cert"`
	CAKey           []byte                     `json:"ca_key"`
	Allowlist       []byte                     `json:"allowlist"`
	AllowlistDigest [32]byte                   `json:"allowlist_digest"`
	Secrets         []secrets.SnapshotEntry    `json:"secrets"`
	Bindings        []sandboxledger.Binding    `json:"bindings"`
	Issuance        map[string]objectChallenge `json:"issuance"`
	Release         map[string]objectChallenge `json:"release"`
}

type objectChallenge struct {
	IssuedMS  int64 `json:"issued_ms"`
	ExpiresMS int64 `json:"expires_ms"`
}

// Each view belongs to exactly one request worker. No live handler shares a
// mutable store or cache with another request.
type objectView struct {
	handles
	challengePools
	state            objectImage
	stores           stores
	ca               issuer.CurrentCA
	nodes            armtls.PinSource
	initialAllowlist [32]byte
	initialSecrets   [32]byte
	initialBindings  [32]byte
	changed          bool
}

func initialObjectView(cfg config) (*objectView, error) {
	db, err := allowlist.OpenInMemory()
	if err != nil {
		return nil, err
	}
	st := stores{
		allowlist: db,
		secrets:   newSecretsStore(cfg),
		bindings: sandboxledger.New(
			issuer.CapTTL(
				cfg.certTTL,
				issuer.MaxLeafTTL,
			),
			cfg.sandboxLedgerMax,
		),
	}
	st.allowlist.SetNodeDelay(cfg.allowlistNodeDelay)
	if err := seedWorkloads(
		st.allowlist.Local(),
		cfg.measured.Workloads,
	); err != nil {
		st.close()
		return nil, err
	}
	if err := st.allowlist.Local().StartJournal(); err != nil {
		st.close()
		return nil, err
	}
	mesh, err := issuer.NewMeshCA(
		cfg.caCommonName,
		cfg.caCertValidity,
	)
	if err != nil {
		st.close()
		return nil, err
	}
	ca := mesh.Current()
	key, err := x509.MarshalPKCS8PrivateKey(ca.CA.Key)
	if err != nil {
		st.close()
		return nil, err
	}
	return bindObjectView(
		cfg,
		objectImage{
			Version:   1,
			Launch:    sha256.Sum256(cfg.measuredFile),
			StartedMS: time.Now().UnixMilli(),
			CACert:    ca.CA.Cert.Raw,
			CAKey:     key,
			Issuance:  make(map[string]objectChallenge),
			Release:   make(map[string]objectChallenge),
		},
		st,
		ca,
	), nil
}

func readObjectView(
	cfg config,
	plain []byte,
) (*objectView, error) {
	if err := strictjson.Validate(plain); err != nil {
		return nil, errors.New("object state: invalid state encoding")
	}
	var state objectImage
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if err := d.Decode(&state); err != nil {
		return nil, errors.New("object state: unsupported state encoding")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("object state: trailing state data")
	}
	if state.Version != 1 || state.Revision == 0 || state.StartedMS <= 0 ||
		state.Launch != sha256.Sum256(cfg.measuredFile) ||
		state.Issuance == nil || state.Release == nil {
		return nil, errors.New("object state: incompatible state or launch configuration")
	}
	if len(state.Secrets) > cfg.secretsMaxPaths || len(state.Bindings) > cfg.sandboxLedgerMax ||
		len(state.Issuance) > objectChallengeLimit || len(state.Release) > objectChallengeLimit {
		return nil, objectstate.ErrTooLarge
	}
	cert, err := x509.ParseCertificate(state.CACert)
	if err != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("object state: invalid CA certificate")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(state.CAKey)
	if err != nil {
		return nil, errors.New("object state: invalid CA key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("object state: CA certificate and key disagree")
	}
	db, err := allowlist.OpenInMemory()
	if err != nil {
		return nil, err
	}
	if err := db.Restore(
		state.Allowlist,
		state.AllowlistDigest,
	); err != nil {
		db.Close()
		return nil, errors.New("object state: invalid allowlist image")
	}
	db.SetNodeDelay(cfg.allowlistNodeDelay)
	st := stores{
		allowlist: db,
		secrets:   newSecretsStore(cfg),
		bindings: sandboxledger.New(
			issuer.CapTTL(
				cfg.certTTL,
				issuer.MaxLeafTTL,
			),
			cfg.sandboxLedgerMax,
		),
	}
	st.secrets.Restore(state.Secrets)
	st.bindings.Restore(state.Bindings)
	return bindObjectView(
		cfg,
		state,
		st,
		issuer.CurrentCA{
			CA: &issuer.CA{
				Cert: cert,
				Key:  key,
			},
			CertPEM: certutil.EncodeCertPEM(cert.Raw),
		},
	), nil
}

func bindObjectView(
	cfg config,
	state objectImage,
	st stores,
	ca issuer.CurrentCA,
) *objectView {
	v := &objectView{
		handles: handles{
			allowlist: st.allowlist.Local(),
			secrets:   st.secrets.Local(),
			bindings:  st.bindings.Local(),
		},
		state:            state,
		stores:           st,
		ca:               ca,
		nodes:            armtls.FixedPins(cfg.measured.Nodes),
		initialAllowlist: st.allowlist.Digest(),
		initialSecrets:   st.secrets.Digest(),
		initialBindings:  st.bindings.Digest(),
	}
	v.challengePools = challengePools{
		issuance: &objectChallenges{
			entries: state.Issuance,
			ttl:     cfg.challengeTTL,
			changed: &v.changed,
		},
		secrets: &objectChallenges{
			entries: state.Release,
			ttl:     cfg.challengeTTL,
			changed: &v.changed,
		},
	}
	return v
}

func (v *objectView) dirty() bool {
	return v.changed || v.stores.allowlist.Digest() != v.initialAllowlist ||
		v.stores.secrets.Digest() != v.initialSecrets || v.stores.bindings.Digest() != v.initialBindings
}

func (v *objectView) encode() ([]byte, error) {
	if v.state.Revision == math.MaxUint64 {
		return nil, errors.New("object state: revision exhausted")
	}
	// InEffect needs older documents until their activation delay has passed.
	depth, err := v.stores.allowlist.InEffectDepth(time.Now())
	if err != nil {
		return nil, err
	}
	result := v.stores.allowlist.Apply(allowlist.Command{
		Op:   allowlist.OpPruneHistory,
		AtMS: time.Now().UnixMilli(),
		Keep: max(
			32,
			depth,
		),
	})
	if result.Kind != "" {
		return nil, errors.New("object state: cannot bound policy history")
	}
	image, err := v.stores.allowlist.Dump()
	if err != nil {
		return nil, err
	}
	v.state.Revision++
	v.state.Allowlist = image
	v.state.AllowlistDigest = v.stores.allowlist.Digest()
	v.state.Secrets = v.stores.secrets.Dump()
	v.state.Bindings = v.stores.bindings.Dump()
	slices.SortFunc(
		v.state.Secrets,
		func(a, b secrets.SnapshotEntry) int {
			return bytes.Compare(
				[]byte(a.Path),
				[]byte(b.Path),
			)
		},
	)
	slices.SortFunc(
		v.state.Bindings,
		func(a, b sandboxledger.Binding) int {
			return bytes.Compare(
				[]byte(a.SandboxID),
				[]byte(b.SandboxID),
			)
		},
	)
	return json.Marshal(v.state)
}

func (v *objectView) renewCA(validity time.Duration) error {
	if !pastHalfLife(
		v.ca.CA.Cert,
		time.Now(),
	) {
		return nil
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return err
	}
	template := certutil.NewCATemplate(
		serial,
		v.ca.CA.Cert.Subject.CommonName,
		time.Now().Add(validity),
	)
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&v.ca.CA.Key.PublicKey,
		v.ca.CA.Key,
	)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(
		cert.RawSubject,
		v.ca.CA.Cert.RawSubject,
	) ||
		!bytes.Equal(
			cert.SubjectKeyId,
			v.ca.CA.Cert.SubjectKeyId,
		) {
		return errors.New("object state: CA renewal changed identity")
	}
	v.ca = issuer.CurrentCA{
		CA: &issuer.CA{
			Cert: cert,
			Key:  v.ca.CA.Key,
		},
		CertPEM: certutil.EncodeCertPEM(der),
	}
	v.state.CACert = der
	v.changed = true
	return nil
}

func (v *objectView) MeshCA() meshCA                             { return fixedObjectCA{v.ca} }
func (v *objectView) NodeImages() armtls.PinSource               { return v.nodes }
func (v *objectView) TokenFloor() time.Time                      { return time.UnixMilli(v.state.StartedMS) }
func (v *objectView) Ready() bool                                { return true }
func (v *objectView) ClusterRoutes() map[string]http.HandlerFunc { return nil }
func (v *objectView) Gate(next http.Handler) http.Handler        { return next }
func (v *objectView) KeepMeshCA(
	context.Context,
	*armtls.CertManager,
) {
}
func (v *objectView) Stop() {
	v.stores.close()
	clear(v.state.CAKey)
	clear(v.state.Allowlist)
	for _, entry := range v.state.Secrets {
		clear(entry.Value)
	}
}

type fixedObjectCA struct{ ca issuer.CurrentCA }

func (c fixedObjectCA) Current() (issuer.CurrentCA, bool) { return c.ca, true }

const objectChallengeLimit = 8192

// Issued random nonces live in the object until consumed or expired. Removal
// is permanent even if a host subsequently moves its clock backwards.
type objectChallenges struct {
	entries map[string]objectChallenge
	ttl     time.Duration
	changed *bool
}

func (c *objectChallenges) Create() ([32]byte, error) {
	var nonce [32]byte
	now := time.Now()
	for key, entry := range c.entries {
		if entry.ExpiresMS <= now.UnixMilli() {
			delete(
				c.entries,
				key,
			)
			*c.changed = true
		}
	}
	if len(c.entries) >= objectChallengeLimit {
		return nonce, errors.New("object state: challenge capacity reached")
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}
	c.entries[base64.RawStdEncoding.EncodeToString(nonce[:])] = objectChallenge{
		IssuedMS:  now.UnixMilli(),
		ExpiresMS: now.Add(c.ttl).UnixMilli(),
	}
	*c.changed = true
	return nonce, nil
}

func (c *objectChallenges) Consume(nonce []byte) bool {
	if len(nonce) != 32 {
		return false
	}
	key := base64.RawStdEncoding.EncodeToString(nonce)
	entry, ok := c.entries[key]
	if !ok {
		return false
	}
	delete(
		c.entries,
		key,
	)
	*c.changed = true
	now := time.Now().UnixMilli()
	return now >= entry.IssuedMS-30_000 && now < entry.ExpiresMS
}
