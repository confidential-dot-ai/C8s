package cds

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

type credentialReadPause struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type credentialGatedStore struct {
	base        *acceptanceObjectStore
	credentials *objectstate.CredentialProvider
	failReads   atomic.Bool
	creates     atomic.Int64
	pause       atomic.Pointer[credentialReadPause]
}

func (s *credentialGatedStore) Load(ctx context.Context) (objectstate.Object, error) {
	if _, err := s.credentials.Retrieve(ctx); err != nil {
		return objectstate.Object{}, err
	}
	if s.failReads.Load() {
		return objectstate.Object{}, errors.New("synthetic read outage")
	}
	if pause := s.pause.Load(); pause != nil {
		pause.once.Do(func() { close(pause.entered) })
		select {
		case <-pause.release:
		case <-ctx.Done():
			return objectstate.Object{}, ctx.Err()
		}
	}
	return s.base.Load(ctx)
}

func (s *credentialGatedStore) Create(
	ctx context.Context,
	data []byte,
) (string, error) {
	s.creates.Add(1)
	if _, err := s.credentials.Retrieve(ctx); err != nil {
		return "", err
	}
	return s.base.Create(
		ctx,
		data,
	)
}

func (s *credentialGatedStore) CompareAndSwap(
	ctx context.Context,
	expected string,
	data []byte,
) (string, error) {
	if _, err := s.credentials.Retrieve(ctx); err != nil {
		return "", err
	}
	return s.base.CompareAndSwap(
		ctx,
		expected,
		data,
	)
}

type credentialBootstrapFixture struct {
	bootstrap *objectBootstrap
	store     *credentialGatedStore
	key       []byte
	signer    ed25519.PrivateKey
	start     time.Time
	clock     atomic.Int64
}

func newCredentialBootstrapFixture(t *testing.T) *credentialBootstrapFixture {
	t.Helper()
	h := newObjectAcceptance(t)
	h.stop()
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := yaml.Unmarshal(
		h.cfg.measuredFile,
		&wire,
	); err != nil {
		t.Fatal(err)
	}
	wire["objectState"].(map[string]any)["recoveryAuthority"] = base64.StdEncoding.EncodeToString(public)
	h.cfg.measuredFile, err = yaml.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.measured, err = cdsconfig.Parse(h.cfg.measuredFile)
	if err != nil {
		t.Fatal(err)
	}
	f := &credentialBootstrapFixture{
		key: make(
			[]byte,
			32,
		),
		signer: signer,
		start:  time.Now().UTC(),
	}
	if _, err := rand.Read(f.key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(f.key); clear(f.signer) })
	f.clock.Store(f.start.UnixNano())
	provider := objectstate.NewCredentialProvider(func() time.Time {
		return time.Unix(
			0,
			f.clock.Load(),
		)
	})
	f.store = &credentialGatedStore{
		base:        &acceptanceObjectStore{},
		credentials: provider,
	}
	cipher, err := objectCipher(
		h.cfg,
		f.key,
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := initializeObjectState(
		t.Context(),
		h.cfg,
		f.store.base,
		cipher,
	)
	if err != nil {
		t.Fatal(err)
	}
	view.Stop()
	recipient, err := objectstate.NewRecipient(objectRecoveryIdentity(h.cfg))
	if err != nil {
		t.Fatal(err)
	}
	application := h.newServer(t)
	application.Stop()
	f.bootstrap = newObjectBootstrap(
		t.Context(),
		h.cfg,
		f.store,
		recipient,
		provider,
		application.dependencies,
		nil,
	)
	t.Cleanup(f.bootstrap.Stop)
	return f
}

func (f *credentialBootstrapFixture) stateGrant(t *testing.T) objectstate.RecoveryGrant {
	t.Helper()
	return sealBootstrapGrant(
		t,
		f.bootstrap.recipient.Request(),
		objectstate.RecoveryMaterial{
			Key: f.key,
		},
		"recovery",
		f.signer,
	)
}

func (f *credentialBootstrapFixture) credentialGrant(
	t *testing.T,
	sequence int,
) objectstate.CredentialGrant {
	t.Helper()
	credentials := objectstate.TemporaryCredentials{
		AccessKeyID:     "synthetic-access-key",
		SecretAccessKey: "synthetic-secret-key",
		SessionToken:    "synthetic-session-token",
		ExpiresAt:       f.start.Add(time.Duration(sequence) * 10 * time.Minute),
	}
	return objectstate.CredentialGrant(sealBootstrapGrant(
		t,
		f.bootstrap.recipient.Request(),
		credentials,
		"credential",
		f.signer,
	))
}

// This constructs real encrypted wire grants; inventory and storage remain synthetic.
func sealBootstrapGrant(
	t *testing.T,
	request objectstate.RecoveryRequest,
	material any,
	domain string,
	signer ed25519.PrivateKey,
) objectstate.RecoveryGrant {
	t.Helper()
	kem, shared, err := overenc.Encapsulate(request.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(shared)
	grant := objectstate.RecoveryGrant{
		RequestHash: request.Digest(),
		KEM:         kem,
	}
	transcript := sha512.New384()
	transcript.Write([]byte("c8s/object-state/v1/" + domain + "-channel\x00"))
	transcript.Write(grant.RequestHash)
	transcript.Write(grant.KEM)
	channel, err := overenc.NewServerChannel(
		shared,
		transcript.Sum(nil),
		request.Nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	grant.Record, err = channel.SealResponse(
		plaintext,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	grant.Signature = ed25519.Sign(
		signer,
		append(
			[]byte("c8s/object-state/v1/"+domain+"-grant\x00"),
			unsigned...,
		),
	)
	return grant
}

func postBootstrapGrant(
	t *testing.T,
	bootstrap *objectBootstrap,
	grant any,
) *httptest.ResponseRecorder {
	t.Helper()
	path := objectstate.GrantPath
	if _, credentials := grant.(objectstate.CredentialGrant); credentials {
		path = objectstate.CredentialsPath
	}
	body, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	return objectCall(
		bootstrap,
		http.MethodPost,
		path,
		body,
		"",
	)
}

func TestObjectCredentialsResealedSessionResumesRecovery(t *testing.T) {
	f := newCredentialBootstrapFixture(t)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			f.credentialGrant(
				t,
				1,
			),
		),
		http.StatusNoContent,
	)
	f.store.failReads.Store(true)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			f.stateGrant(t),
		),
		http.StatusServiceUnavailable,
	)
	if f.store.creates.Load() != 0 || f.bootstrap.active.Load() != nil {
		t.Fatal("failed recovery created state or published a server")
	}
	f.store.failReads.Store(false)
	// A restarted custodian seals the current session again with fresh KEM material.
	for range 2 {
		objectWantStatus(
			t,
			postBootstrapGrant(
				t,
				f.bootstrap,
				f.credentialGrant(
					t,
					1,
				),
			),
			http.StatusNoContent,
		)
	}
	if f.store.creates.Load() != 0 || f.bootstrap.active.Load() == nil {
		t.Fatal("re-sealed session failed to recover existing state without creation")
	}
	credentials, err := f.store.credentials.Retrieve(t.Context())
	if err != nil || !credentials.Expires.Equal(f.start.Add(10*time.Minute)) {
		t.Fatal("re-sealed session changed its expiration")
	}
}

func TestObjectCredentialsRenewalPreservesRecoveredIdentity(t *testing.T) {
	t.Setenv(
		"AWS_ACCESS_KEY_ID",
		"untrusted-host-access-key",
	)
	t.Setenv(
		"AWS_SECRET_ACCESS_KEY",
		"untrusted-host-secret-key",
	)
	f := newCredentialBootstrapFixture(t)
	state := f.stateGrant(t)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			state,
		),
		http.StatusServiceUnavailable,
	)
	view, err := recoverObjectView(
		t.Context(),
		f.bootstrap.cfg,
		f.store.base,
		f.bootstrap.sealed,
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedCA := bytes.Clone(view.ca.CA.Cert.Raw)
	view.Stop()
	if f.store.creates.Load() != 0 || f.bootstrap.active.Load() != nil {
		t.Fatal("state-key grant without credentials created state or served requests")
	}
	f.store.failReads.Store(true)
	first := f.credentialGrant(
		t,
		1,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			first,
		),
		http.StatusServiceUnavailable,
	)
	f.clock.Store(f.start.Add(10*time.Minute + time.Second).UnixNano())
	if _, err := f.store.credentials.Retrieve(t.Context()); !errors.Is(
		err,
		objectstate.ErrCredentialsUnavailable,
	) {
		t.Fatal("expired credentials fell back to the host identity")
	}
	second := f.credentialGrant(
		t,
		2,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			second,
		),
		http.StatusServiceUnavailable,
	)
	if f.store.creates.Load() != 0 || f.bootstrap.active.Load() != nil {
		t.Fatal("renewal during a read outage created state or published a server")
	}
	f.store.failReads.Store(false)
	second = f.credentialGrant(
		t,
		2,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			second,
		),
		http.StatusNoContent,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			state,
		),
		http.StatusNoContent,
	)
	objectWantStatus(
		t,
		objectCall(
			f.bootstrap,
			http.MethodGet,
			"/ca",
			nil,
			"",
		),
		http.StatusOK,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			first,
		),
		http.StatusServiceUnavailable,
	)
	f.clock.Store(f.start.Add(20*time.Minute + time.Second).UnixNano())
	objectWantStatus(
		t,
		objectCall(
			f.bootstrap,
			http.MethodGet,
			"/ca",
			nil,
			"",
		),
		http.StatusServiceUnavailable,
	)
	// Acknowledging the latest grant again does not extend its expired session.
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			second,
		),
		http.StatusNoContent,
	)
	objectWantStatus(
		t,
		objectCall(
			f.bootstrap,
			http.MethodGet,
			"/ca",
			nil,
			"",
		),
		http.StatusServiceUnavailable,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			f.credentialGrant(
				t,
				3,
			),
		),
		http.StatusNoContent,
	)
	objectWantStatus(
		t,
		objectCall(
			f.bootstrap,
			http.MethodGet,
			"/ca",
			nil,
			"",
		),
		http.StatusOK,
	)
	recovered, err := recoverObjectView(
		t.Context(),
		f.bootstrap.cfg,
		f.store,
		f.bootstrap.sealed,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Stop()
	if !bytes.Equal(
		expectedCA,
		recovered.ca.CA.Cert.Raw,
	) {
		t.Fatal("credential renewal changed the committed CA")
	}
	if f.store.creates.Load() != 0 {
		t.Fatal("credential renewal attempted to create state")
	}
}

func TestObjectCredentialsNeverCreateMissingState(t *testing.T) {
	f := newCredentialBootstrapFixture(t)
	f.store.base.mu.Lock()
	f.store.base.data = nil
	f.store.base.mu.Unlock()
	state := f.stateGrant(t)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			f.credentialGrant(
				t,
				1,
			),
		),
		http.StatusNoContent,
	)
	for range 2 {
		objectWantStatus(
			t,
			postBootstrapGrant(
				t,
				f.bootstrap,
				state,
			),
			http.StatusServiceUnavailable,
		)
	}
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			f.credentialGrant(
				t,
				2,
			),
		),
		http.StatusServiceUnavailable,
	)
	if f.store.creates.Load() != 0 || f.bootstrap.active.Load() != nil {
		t.Fatal("missing state was created or served by ordinary recovery")
	}
	if _, err := f.store.base.Load(t.Context()); !errors.Is(
		err,
		objectstate.ErrNotFound,
	) {
		t.Fatal("ordinary recovery replaced the missing current object")
	}
}

func TestObjectCredentialsRejectCrossPurposeAndMalformedGrants(t *testing.T) {
	f := newCredentialBootstrapFixture(t)
	state := f.stateGrant(t)
	credentials := f.credentialGrant(
		t,
		1,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			objectstate.CredentialGrant(state),
		),
		http.StatusServiceUnavailable,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			objectstate.RecoveryGrant(credentials),
		),
		http.StatusServiceUnavailable,
	)
	wrong := newCredentialBootstrapFixture(t)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			wrong.bootstrap,
			credentials,
		),
		http.StatusServiceUnavailable,
	)
	for _, body := range [][]byte{
		[]byte(`{"signature":null,"signature":null}`),
		bytes.Repeat(
			[]byte("x"),
			objectstate.MaxCredentialGrantBytes+1,
		),
	} {
		objectWantStatus(
			t,
			objectCall(
				f.bootstrap,
				http.MethodPost,
				objectstate.CredentialsPath,
				body,
				"",
			),
			http.StatusBadRequest,
		)
	}
	if _, err := f.store.credentials.Retrieve(t.Context()); !errors.Is(
		err,
		objectstate.ErrCredentialsUnavailable,
	) {
		t.Fatal("rejected grant installed credentials")
	}
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			credentials,
		),
		http.StatusNoContent,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			state,
		),
		http.StatusNoContent,
	)
}

func TestObjectRecoveryRejectsInitializationField(t *testing.T) {
	f := newCredentialBootstrapFixture(t)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			f.credentialGrant(
				t,
				1,
			),
		),
		http.StatusNoContent,
	)
	for _, allowed := range []bool{false, true} {
		grant := sealBootstrapGrant(
			t,
			f.bootstrap.recipient.Request(),
			map[string]any{
				"key":              f.key,
				"allow_initialize": allowed,
			},
			"recovery",
			f.signer,
		)
		objectWantStatus(
			t,
			postBootstrapGrant(
				t,
				f.bootstrap,
				grant,
			),
			http.StatusServiceUnavailable,
		)
	}
	if f.bootstrap.active.Load() != nil || f.store.creates.Load() != 0 {
		t.Fatal("removed initialization field authorized a recovery or creation")
	}
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			f.stateGrant(t),
		),
		http.StatusNoContent,
	)
}

func TestObjectCredentialsControlQueueBackpressureAndShutdown(t *testing.T) {
	f := newCredentialBootstrapFixture(t)
	first := f.credentialGrant(
		t,
		1,
	)
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			first,
		),
		http.StatusNoContent,
	)
	pause := &credentialReadPause{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	f.store.pause.Store(pause)
	state := f.stateGrant(t)
	stateDone := make(
		chan *httptest.ResponseRecorder,
		1,
	)
	go func() {
		stateDone <- postBootstrapGrant(
			t,
			f.bootstrap,
			state,
		)
	}()
	select {
	case <-pause.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not reach the blocked read")
	}
	second := f.credentialGrant(
		t,
		2,
	)
	encoded, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request := httptest.NewRequest(
		http.MethodPost,
		objectstate.CredentialsPath,
		bytes.NewReader(encoded),
	).WithContext(ctx)
	credentialDone := make(
		chan *httptest.ResponseRecorder,
		1,
	)
	go func() {
		response := httptest.NewRecorder()
		f.bootstrap.ServeHTTP(
			response,
			request,
		)
		credentialDone <- response
	}()
	deadline := time.After(5 * time.Second)
	for len(f.bootstrap.grants) != 1 {
		select {
		case <-deadline:
			t.Fatal("credential refresh did not enter the shared queue")
		case <-time.After(time.Millisecond):
		}
	}
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			f.credentialGrant(
				t,
				3,
			),
		),
		http.StatusServiceUnavailable,
	)
	cancel()
	select {
	case response := <-credentialDone:
		objectWantStatus(
			t,
			response,
			http.StatusServiceUnavailable,
		)
	case <-time.After(5 * time.Second):
		t.Fatal("queued credential cancellation did not return")
	}
	f.bootstrap.Stop()
	select {
	case response := <-stateDone:
		objectWantStatus(
			t,
			response,
			http.StatusServiceUnavailable,
		)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not stop the in-flight recovery")
	}
	current, err := f.store.credentials.Retrieve(t.Context())
	if err != nil || !current.Expires.Equal(f.start.Add(10*time.Minute)) || f.store.creates.Load() != 0 {
		t.Fatal("canceled queued renewal changed credentials or created state")
	}
	objectWantStatus(
		t,
		postBootstrapGrant(
			t,
			f.bootstrap,
			second,
		),
		http.StatusServiceUnavailable,
	)
}
