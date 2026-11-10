package cds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	"github.com/confidential-dot-ai/c8s/internal/server"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func runObjectCDS(
	ctx context.Context,
	cfg config,
) error {
	if cfg.allowlistPersistent {
		return errors.New("object state: --allowlist-persistent is incompatible with encrypted object state")
	}
	o := cfg.measured.ObjectState
	credentials := objectstate.NewCredentialProvider(time.Now)
	store, err := objectstate.NewS3(
		objectstate.S3Config{
			Region:        o.Region,
			Bucket:        o.Bucket,
			Key:           o.Key,
			Endpoint:      o.Endpoint,
			ExpectedOwner: o.ExpectedBucketOwner,
			MaxBytes:      o.MaxBytes,
			Timeout:       10 * time.Second,
		},
		credentials,
	)
	if err != nil {
		return err
	}
	recipient, err := objectstate.NewRecipient(objectRecoveryIdentity(cfg))
	if err != nil {
		return err
	}
	limits, err := issuer.NewIPRateLimiter(
		rate.Limit(cfg.rateLimit),
		cfg.rateBurst,
		cfg.rateLimiterMax,
	)
	if err != nil {
		return err
	}
	challenges, err := issuer.NewIPRateLimiter(
		rate.Limit(cfg.rateLimit),
		cfg.rateBurst,
		cfg.rateLimiterMax,
	)
	if err != nil {
		return err
	}
	checker := readiness.NewChecker(
		armtls.NewAttestationClient(cfg.attestationApiURL),
		cfg.readinessInterval,
	)
	app, err := newApplication(
		ctx,
		cfg,
		&objectView{nodes: armtls.FixedPins(cfg.measured.Nodes)},
		&checker,
		limits,
		challenges,
	)
	if err != nil {
		return err
	}
	tlsCfg, peers, err := armtls.NewServerTLSConfig(servingConfig(
		cfg,
		nil,
	))
	if err != nil {
		return err
	}
	warm, cancel := context.WithTimeout(
		ctx,
		30*time.Second,
	)
	err = peers.WarmUp(warm)
	cancel()
	if err != nil {
		return err
	}
	bootstrap := newObjectBootstrap(
		ctx,
		cfg,
		store,
		recipient,
		credentials,
		app.dependencies,
		peers.UpdateClientCA,
	)
	defer bootstrap.Stop()
	go peers.RunRotation(ctx)
	go checker.Run(ctx)
	go limits.EvictionLoop(
		ctx,
		cfg.rateLimiterEvictInterval,
		cfg.rateLimiterIdleTimeout,
	)
	go challenges.EvictionLoop(
		ctx,
		cfg.rateLimiterEvictInterval,
		cfg.rateLimiterIdleTimeout,
	)
	srv := newHTTPServer(
		clientAddress(cfg),
		server.RequestLogger(bootstrap),
		cfg,
	)
	srv.TLSConfig = tlsCfg
	go cmdsutil.ShutdownOnDone(
		ctx,
		srv,
		5*time.Second,
	)
	slog.Info(
		"CDS awaiting an attested object-state recovery grant",
		"cluster_id",
		cfg.measured.ClusterID,
	)
	if err := srv.ListenAndServeTLS(
		"",
		"",
	); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func objectRecoveryIdentity(cfg config) objectstate.RecoveryIdentity {
	storage := cfg.measured.ObjectState.StorageDigest()
	launch := sha256.Sum256(cfg.measuredFile)
	return objectstate.RecoveryIdentity{
		ClusterID:     cfg.measured.ClusterID,
		StorageSHA256: hex.EncodeToString(storage[:]),
		ConfigSHA256:  hex.EncodeToString(launch[:]),
	}
}

func objectCipher(
	cfg config,
	key []byte,
) (*objectstate.Cipher, error) {
	storage := cfg.measured.ObjectState.StorageDigest()
	domain := []byte("c8s/cds-object-state/v1\x00" + cfg.measured.ClusterID + "\x00")
	domain = append(
		domain,
		storage[:]...,
	)
	return objectstate.NewCipher(
		key,
		domain,
		int(cfg.measured.ObjectState.MaxBytes),
	)
}

type objectGrantMessage struct {
	ctx         context.Context
	state       *objectstate.RecoveryGrant
	credentials *objectstate.CredentialGrant
	answer      chan error
}

// One control actor owns recovery. Request workers are published only after
// encrypted state has been recovered or explicitly initialized.
type objectBootstrap struct {
	cfg         config
	store       objectstate.Store
	recipient   *objectstate.Recipient
	credentials *objectstate.CredentialProvider
	build       func(backend) (dependencies, error)
	onCA        func(*x509.Certificate)
	ctx         context.Context
	cancel      context.CancelFunc
	grants      chan objectGrantMessage
	grantSlots  chan struct{}
	done        chan struct{}
	active      atomic.Pointer[objectServer]
	metrics     atomic.Pointer[objectMetricsHandler]
	// Retain an accepted state-key grant across transient recovery failures.
	accepted            [32]byte
	acceptedCredentials [32]byte
	sealed              *objectstate.Cipher
}

type objectMetricsHandler struct{ http.Handler }

func newObjectBootstrap(
	ctx context.Context,
	cfg config,
	store objectstate.Store,
	recipient *objectstate.Recipient,
	credentials *objectstate.CredentialProvider,
	build func(backend) (dependencies, error),
	onCA func(*x509.Certificate),
) *objectBootstrap {
	ctx, cancel := context.WithCancel(ctx)
	b := &objectBootstrap{
		cfg:         cfg,
		store:       store,
		recipient:   recipient,
		credentials: credentials,
		build:       build,
		onCA:        onCA,
		ctx:         ctx,
		cancel:      cancel,
		grants: make(
			chan objectGrantMessage,
			1,
		),
		grantSlots: make(
			chan struct{},
			2,
		),
		done: make(chan struct{}),
	}
	go b.control()
	return b
}

func (b *objectBootstrap) Stop() {
	b.cancel()
	<-b.done
	if active := b.active.Load(); active != nil {
		active.Stop()
	}
}

func (b *objectBootstrap) control() {
	defer close(b.done)
	for {
		select {
		case <-b.ctx.Done():
			return
		case message := <-b.grants:
			var err error
			switch {
			case b.ctx.Err() != nil:
				err = b.ctx.Err()
			case message.ctx.Err() != nil:
				err = message.ctx.Err()
			case message.state != nil && message.credentials == nil:
				err = b.activate(
					message.ctx,
					*message.state,
				)
			case message.credentials != nil && message.state == nil:
				err = b.refreshCredentials(
					message.ctx,
					*message.credentials,
				)
			default:
				err = errors.New("object state: invalid control message")
			}
			message.answer <- err
		}
	}
}

func (b *objectBootstrap) activate(
	ctx context.Context,
	grant objectstate.RecoveryGrant,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	if b.sealed == nil {
		material, err := b.recipient.Open(
			grant,
			b.cfg.measured.ObjectState.RecoveryAuthority,
		)
		if err != nil {
			return err
		}
		defer clear(material.Key)
		b.sealed, err = objectCipher(
			b.cfg,
			material.Key,
		)
		if err != nil {
			return err
		}
		b.accepted = digest
	} else if b.accepted != digest {
		return errors.New("object state: another grant was already accepted")
	}
	return b.resumeRecovery(ctx)
}

func (b *objectBootstrap) refreshCredentials(
	ctx context.Context,
	grant objectstate.CredentialGrant,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	if digest != b.acceptedCredentials {
		credentials, err := b.recipient.OpenCredentials(
			grant,
			b.cfg.measured.ObjectState.RecoveryAuthority,
		)
		if err != nil {
			return err
		}
		if err := b.credentials.Install(credentials); err != nil {
			return err
		}
		b.acceptedCredentials = digest
	}
	if b.sealed == nil {
		return nil
	}
	return b.resumeRecovery(ctx)
}

func (b *objectBootstrap) resumeRecovery(ctx context.Context) error {
	if b.active.Load() != nil {
		return nil
	}
	view, err := recoverObjectView(
		ctx,
		b.cfg,
		b.store,
		b.sealed,
	)
	if err != nil {
		return err
	}
	defer view.Stop()
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if b.onCA != nil {
		b.onCA(view.ca.CA.Cert)
	}
	active := newObjectServer(
		b.ctx,
		b.cfg,
		b.store,
		b.sealed,
		b.build,
		b.onCA,
	)
	registry := prometheus.NewRegistry()
	if err := registry.Register(active); err != nil {
		active.Stop()
		return err
	}
	b.metrics.Store(&objectMetricsHandler{promhttp.HandlerFor(
		prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		},
		promhttp.HandlerOpts{},
	)})
	b.active.Store(active)
	active.startMaintenance()
	slog.Info(
		"CDS object state recovered",
		"cluster_id",
		b.cfg.measured.ClusterID,
		"revision",
		view.state.Revision,
		"key_id",
		caKeyID(view.ca.CA.Cert),
	)
	return nil
}

func recoverObjectView(
	ctx context.Context,
	cfg config,
	store objectstate.Store,
	sealed *objectstate.Cipher,
) (*objectView, error) {
	object, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	plain, err := sealed.Open(object.Data)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return readObjectView(
		cfg,
		plain,
	)
}

func (b *objectBootstrap) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set(
		"Cache-Control",
		"no-store",
	)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/healthz":
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		if metrics := b.metrics.Load(); metrics != nil {
			metrics.ServeHTTP(
				w,
				r,
			)
		} else {
			promhttp.Handler().ServeHTTP(
				w,
				r,
			)
		}
	case r.Method == http.MethodGet && r.URL.Path == objectstate.RequestPath:
		w.Header().Set(
			"Content-Type",
			"application/json",
		)
		_ = json.NewEncoder(w).Encode(b.recipient.Request())
	case r.Method == http.MethodPost && (r.URL.Path == objectstate.GrantPath || r.URL.Path == objectstate.CredentialsPath):
		b.acceptGrant(
			w,
			r,
		)
	default:
		if active := b.active.Load(); active != nil {
			active.ServeHTTP(
				w,
				r,
			)
		} else {
			http.Error(
				w,
				"CDS requires an attested recovery grant",
				http.StatusServiceUnavailable,
			)
		}
	}
}

func (b *objectBootstrap) acceptGrant(
	w http.ResponseWriter,
	r *http.Request,
) {
	if b.ctx.Err() != nil || r.Context().Err() != nil {
		http.Error(
			w,
			"recovery unavailable",
			http.StatusServiceUnavailable,
		)
		return
	}
	select {
	case b.grantSlots <- struct{}{}:
		defer func() { <-b.grantSlots }()
	default:
		http.Error(
			w,
			"recovery request capacity reached",
			http.StatusServiceUnavailable,
		)
		return
	}
	ctx, cancel := context.WithTimeout(
		r.Context(),
		objectRequestTimeout,
	)
	defer cancel()
	stop := context.AfterFunc(
		b.ctx,
		cancel,
	)
	defer stop()
	readStopped := make(chan struct{})
	stopRead := context.AfterFunc(
		ctx,
		func() {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now())
			_ = r.Body.Close()
			close(readStopped)
		},
	)
	defer func() {
		if !stopRead() {
			<-readStopped
		}
	}()
	message := objectGrantMessage{
		ctx: ctx,
		answer: make(
			chan error,
			1,
		),
	}
	var grant interface{ Check() error }
	limit := int64(16 << 10)
	if r.URL.Path == objectstate.CredentialsPath {
		message.credentials = new(objectstate.CredentialGrant)
		grant = message.credentials
		limit = objectstate.MaxCredentialGrantBytes
	} else {
		message.state = new(objectstate.RecoveryGrant)
		grant = message.state
	}
	raw, err := io.ReadAll(http.MaxBytesReader(
		w,
		r.Body,
		limit,
	))
	if err != nil || strictjson.Validate(raw) != nil {
		http.Error(
			w,
			"invalid recovery grant",
			http.StatusBadRequest,
		)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(grant); err != nil || grant.Check() != nil {
		http.Error(
			w,
			"invalid recovery grant",
			http.StatusBadRequest,
		)
		return
	}
	if ctx.Err() != nil {
		http.Error(
			w,
			"recovery request canceled",
			http.StatusServiceUnavailable,
		)
		return
	}
	select {
	case b.grants <- message:
	default:
		http.Error(
			w,
			"recovery request capacity reached",
			http.StatusServiceUnavailable,
		)
		return
	}
	select {
	case err := <-message.answer:
		if err != nil {
			http.Error(
				w,
				"recovery refused or current state unavailable",
				http.StatusServiceUnavailable,
			)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case <-ctx.Done():
		http.Error(
			w,
			"recovery outcome unknown",
			http.StatusServiceUnavailable,
		)
	}
}
