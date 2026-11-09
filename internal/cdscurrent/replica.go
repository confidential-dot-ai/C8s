// Package cdscurrent exercises CDS handlers over encrypted current state.
// It is an experimental adapter, not a production CDS backend or a custodian.
package cdscurrent

import (
	"context"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

var (
	ErrUninitialized = errors.New("current CDS: enrolled state is missing")
	ErrBusy          = errors.New("current CDS: admission limit reached")
	ErrCapacity      = errors.New("current CDS: state exceeds the pilot bound")
	ErrChallenge     = errors.New("current CDS: invalid or consumed challenge")
)

const (
	maxStateBytes  = 8 << 20
	maxChallenges  = 1024
	maxBindings    = 4096
	requestTimeout = 10 * time.Second
)

// Register must finish a majority acceptance before returning a value, including
// for reads. After possible acceptance it returns uncertainty without retrying.
// Successful Update returns its exact accepted candidate in caller-owned memory.
// Update must finish any active transform before returning and never invoke it
// afterward. Callers may release captured input and output buffers on return.
// An aborted transform must wrap casregister.ErrUnavailable with its cause.
type Register interface {
	Read(context.Context) ([]byte, error)
	Update(
		context.Context,
		func([]byte) ([]byte, error),
	) ([]byte, error)
}

type Config struct {
	ClusterID string
	// Key is provisioned by the caller. Local tests do not establish key custody.
	Key                 []byte
	OperatorKeys        []*ecdsa.PublicKey
	ClockSkew           time.Duration
	MaxPaths            int
	MaxPerHolder        int
	MaxSecretValueBytes int
	QueueSize           int
	ChallengeTTL        time.Duration
	LedgerTTL           time.Duration
	NodeDelay           time.Duration
}

type parameters struct {
	ClusterID                                   string
	OperatorKeys                                string
	ClockSkew                                   time.Duration
	MaxPaths, MaxPerHolder, MaxSecretValueBytes int
	ChallengeTTL, LedgerTTL, NodeDelay          time.Duration
}

type Replica struct {
	register Register
	policy   parameters
	verifier operatorauth.Verifier
	aead     cipher.AEAD
	domain   []byte
	active   chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
}

func New(
	register Register,
	cfg Config,
) (*Replica, error) {
	if register == nil || cfg.ClusterID == "" || len(cfg.ClusterID) > 256 || len(cfg.Key) != chacha20poly1305.KeySize {
		return nil, errors.New("current CDS: register, cluster identity and 32-byte key required")
	}
	if cfg.MaxPaths == 0 {
		cfg.MaxPaths = 1024
	}
	if cfg.MaxPerHolder == 0 {
		cfg.MaxPerHolder = 128
	}
	if cfg.MaxSecretValueBytes == 0 {
		cfg.MaxSecretValueBytes = 64 << 10
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 8
	}
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = time.Minute
	}
	if cfg.LedgerTTL == 0 {
		cfg.LedgerTTL = time.Hour
	}
	if cfg.MaxPaths < 1 || cfg.MaxPaths > 65536 ||
		cfg.MaxPerHolder < 1 ||
		cfg.MaxSecretValueBytes < 1 || cfg.MaxSecretValueBytes > 1<<20 ||
		cfg.QueueSize < 1 || cfg.QueueSize > 128 ||
		cfg.ChallengeTTL < time.Second || cfg.ChallengeTTL > 5*time.Minute ||
		cfg.LedgerTTL <= 0 || cfg.LedgerTTL > 24*time.Hour ||
		cfg.ClockSkew < 0 || cfg.ClockSkew > time.Minute ||
		cfg.NodeDelay < 0 || cfg.NodeDelay > time.Hour {
		return nil, errors.New("current CDS: invalid admission or state limits")
	}
	keys := make(
		[]*ecdsa.PublicKey,
		len(cfg.OperatorKeys),
	)
	for i, key := range cfg.OperatorKeys {
		if key == nil {
			return nil, errors.New("current CDS: nil operator key")
		}
		encoded, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		if err != nil {
			return nil, err
		}
		keys[i] = parsed.(*ecdsa.PublicKey)
	}
	keySet, err := operatorauth.KeySetHash(keys)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(cfg.Key)
	if err != nil {
		return nil, err
	}
	p := parameters{
		ClusterID:           cfg.ClusterID,
		OperatorKeys:        keySet,
		ClockSkew:           cfg.ClockSkew,
		MaxPaths:            cfg.MaxPaths,
		MaxPerHolder:        cfg.MaxPerHolder,
		MaxSecretValueBytes: cfg.MaxSecretValueBytes,
		ChallengeTTL:        cfg.ChallengeTTL,
		LedgerTTL:           cfg.LedgerTTL,
		NodeDelay:           cfg.NodeDelay,
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	ctx, cancel := context.WithCancel(context.Background())
	return &Replica{
		register: register,
		policy:   p,
		verifier: operatorauth.Verifier{
			Keys:      keys,
			ClockSkew: cfg.ClockSkew,
		},
		aead: aead,
		domain: append(
			[]byte("cdscurrent/v1/"),
			digest[:]...,
		),
		active: make(
			chan struct{},
			cfg.QueueSize,
		),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (r *Replica) Close() { r.cancel() }

func (r *Replica) begin(ctx context.Context) (context.Context, func(), error) {
	if err := r.ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	select {
	case r.active <- struct{}{}:
	default:
		return nil, nil, ErrBusy
	}
	ctx, cancel := context.WithTimeout(
		ctx,
		requestTimeout,
	)
	stop := context.AfterFunc(
		r.ctx,
		cancel,
	)
	return ctx, func() { stop(); cancel(); <-r.active }, nil
}

// Bootstrap is an explicit local enrollment operation. Recovery never calls it.
func (r *Replica) Bootstrap(ctx context.Context) error {
	ctx, done, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	mesh, err := issuer.NewMeshCA(
		issuer.DefaultCACommonName,
		issuer.DefaultCAValidity,
	)
	if err != nil {
		return err
	}
	ca := mesh.Current().CA
	key, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return err
	}
	defer clear(key)
	al, err := r.emptyPolicy()
	if err != nil {
		return err
	}
	defer al.Close()
	if err := al.Local().StartJournal(); err != nil {
		return err
	}
	image, err := al.Dump()
	if err != nil {
		return err
	}
	defer clear(image)
	candidate, err := r.seal(snapshot{
		Format:       1,
		CACert:       ca.Cert.Raw,
		CAKey:        key,
		Policy:       image,
		PolicyDigest: al.Digest(),
		Challenges:   map[string]int64{},
	})
	if err != nil {
		return err
	}
	exists := false
	_, err = r.register.Update(
		ctx,
		func(current []byte) ([]byte, error) {
			exists = len(current) != 0
			if exists {
				return current, nil
			}
			return candidate, nil
		},
	)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("current CDS: cluster already enrolled")
	}
	return nil
}

func (r *Replica) CA(ctx context.Context) (*issuer.CA, error) {
	ctx, done, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	v, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	defer v.close()
	return v.ca, nil
}

func (r *Replica) Bind(
	ctx context.Context,
	sandboxID string,
	host string,
) error {
	if sandboxID == "" || host == "" || len(sandboxID) > 256 || len(host) > 256 {
		return errors.New("current CDS: invalid sandbox binding")
	}
	ctx, done, err := r.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	held := false
	_, err = r.update(
		ctx,
		func(v *view) error {
			held = v.ledger.Local().Record(
				sandboxID,
				host,
			)
			return nil
		},
	)
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("current CDS: sandbox binding refused")
	}
	return nil
}
