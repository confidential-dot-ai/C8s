package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/objectcustody"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

// Real service routing, owner TLS and actor execution; storage, hardware
// material and the outbound provisioning hook are synthetic.
type custodyServiceFixture struct {
	service    *objectCustodian
	base       *acceptanceObjectStore
	store      *initializationTestStore
	owner      *issuer.CA
	client     tls.Certificate
	reader     objectstate.TemporaryCredentials
	writer     objectstate.TemporaryCredentials
	stores     atomic.Int64
	provisions atomic.Int64
}

func newCustodyServiceFixture(t *testing.T) *custodyServiceFixture {
	t.Helper()
	bootstrap := newCredentialBootstrapFixture(t)
	bootstrap.bootstrap.Stop()
	owner, err := issuer.NewMeshCA(
		"independent fixture owner",
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	f := &custodyServiceFixture{
		base:  &acceptanceObjectStore{},
		owner: owner.Current().CA,
		reader: objectstate.TemporaryCredentials{
			AccessKeyID:     "fixture-reader-access",
			SecretAccessKey: "fixture-reader-secret",
			SessionToken:    "fixture-reader-session",
			ExpiresAt:       time.Now().Add(20 * time.Minute).UTC().Truncate(time.Second),
		},
		writer: objectstate.TemporaryCredentials{
			AccessKeyID:     "fixture-writer-access",
			SecretAccessKey: "fixture-writer-secret",
			SessionToken:    "fixture-writer-session",
			ExpiresAt:       time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second),
		},
	}
	f.client = custodyOwnerCertificate(
		t,
		f.owner,
		time.Now().Add(30*time.Minute),
	)
	material := &objectcustody.Material{
		Signer:   ed25519.PrivateKey(bytes.Clone(bootstrap.signer)),
		StateKey: bytes.Clone(bootstrap.key),
	}
	t.Cleanup(material.Clear)
	f.service, err = newObjectCustodian(
		t.Context(),
		bootstrap.bootstrap.cfg,
		objectPolicyImages(bootstrap.bootstrap.cfg),
		f.owner.Cert,
		material,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.service.Stop)
	f.store = &initializationTestStore{Store: f.base}
	f.service.newStore = func(provider *objectstate.CredentialProvider) (objectstate.Store, error) {
		f.stores.Add(1)
		credentials, err := provider.Retrieve(t.Context())
		if err != nil {
			return nil, err
		}
		if credentials.AccessKeyID != f.reader.AccessKeyID || credentials.SecretAccessKey != f.reader.SecretAccessKey {
			return nil, errors.New("custody reader received a different session")
		}
		return f.store, nil
	}
	f.service.provision = func(
		ctx context.Context,
		source objectstate.RecoveryPolicySource,
		_ string,
		credentials objectstate.TemporaryCredentials,
	) error {
		f.provisions.Add(1)
		if credentials != f.writer {
			return errors.New("replica received a different writer session")
		}
		policy, err := source.Current(ctx)
		if err != nil {
			return err
		}
		return policy.Check(f.service.info.Identity)
	}
	return f
}

func custodyOwnerCertificate(
	t *testing.T,
	owner *issuer.CA,
	expires time.Time,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "independent owner client"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     expires,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		owner.Cert,
		&key.PublicKey,
		owner.Key,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{
			der,
			owner.Cert.Raw,
		},
		PrivateKey: key,
		Leaf:       leaf,
	}
}

func (f *custodyServiceFixture) initializeRequest() objectCustodyRequest {
	return objectCustodyRequest{
		ConfigSHA256: f.service.info.Identity.ConfigSHA256,
		Storage:      f.reader,
	}
}

func (f *custodyServiceFixture) provisionRequest() objectCustodyRequest {
	request := f.initializeRequest()
	request.Writer = &f.writer
	request.Origins = []string{"https://replica.fixture.invalid"}
	return request
}

func (f *custodyServiceFixture) authorizedRequest(
	method string,
	path string,
	body io.Reader,
) *http.Request {
	request := httptest.NewRequest(
		method,
		path,
		body,
	)
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			f.client.Leaf,
			f.owner.Cert,
		},
		VerifiedChains: [][]*x509.Certificate{{
			f.client.Leaf,
			f.owner.Cert,
		}},
	}
	return request
}

func (f *custodyServiceFixture) post(
	t *testing.T,
	path string,
	value objectCustodyRequest,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	response := httptest.NewRecorder()
	f.service.ServeHTTP(
		response,
		f.authorizedRequest(
			http.MethodPost,
			path,
			bytes.NewReader(body),
		).WithContext(t.Context()),
	)
	f.noSecrets(
		t,
		response.Body.Bytes(),
	)
	if response.Header().Get("Content-Type") == "application/json" {
		var result objectCustodyResult
		decodeCustodyResponse(
			t,
			response.Body.Bytes(),
			&result,
		)
		if path == objectCustodyInitializePath && response.Code != http.StatusOK &&
			(result.CAKeyID != "" || len(result.Ready) != 0) {
			t.Fatal("unconfirmed initialization published a CA or replica acknowledgment")
		}
	}
	return response
}

func decodeCustodyResponse(
	t *testing.T,
	body []byte,
	value any,
) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Fatal("custody response contained unexpected fields or invalid JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		t.Fatal("custody response contained trailing data")
	}
}

func (f *custodyServiceFixture) noSecrets(
	t *testing.T,
	body []byte,
) {
	t.Helper()
	for _, forbidden := range []string{
		base64.StdEncoding.EncodeToString(f.service.material.StateKey),
		base64.StdEncoding.EncodeToString(f.service.material.Signer),
		f.reader.SecretAccessKey,
		f.reader.SessionToken,
		f.writer.SecretAccessKey,
		f.writer.SessionToken,
		`"state_key"`,
		`"private_key"`,
	} {
		if bytes.Contains(
			body,
			[]byte(forbidden),
		) {
			t.Fatal("custody response disclosed private material")
		}
	}
}

func (f *custodyServiceFixture) committedCA(t *testing.T) string {
	t.Helper()
	cipher, err := objectCipher(
		f.service.cfg,
		f.service.material.StateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := loadInitializedObjectView(
		t.Context(),
		f.service.cfg,
		f.base,
		cipher,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Stop()
	return caKeyID(view.ca.CA.Cert)
}

func TestObjectCustodyOwnerMutualTLS(t *testing.T) {
	f := newCustodyServiceFixture(t)
	roots := x509.NewCertPool()
	roots.AddCert(f.owner.Cert)
	server := httptest.NewUnstartedServer(f.service)
	server.Config.ErrorLog = log.New(
		io.Discard,
		"",
		0,
	)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  roots,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{f.client}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	response, err := client.Get(server.URL + objectCustodyLaunchPath)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated owner could not retrieve the completed launch")
	}
	f.noSecrets(
		t,
		body,
	)
	var info objectCustodyInfo
	decodeCustodyResponse(
		t,
		body,
		&info,
	)
	if !bytes.Equal(
		info.Launch,
		f.service.cfg.measuredFile,
	) || info.Identity != f.service.info.Identity {
		t.Fatal("owner received a different completed launch identity")
	}
	encoded, err := json.Marshal(f.initializeRequest())
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.Post(
		server.URL+objectCustodyInitializePath,
		"application/json",
		bytes.NewReader(encoded),
	)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("authenticated owner initialization failed")
	}
	f.noSecrets(
		t,
		body,
	)
	var result objectCustodyResult
	decodeCustodyResponse(
		t,
		body,
		&result,
	)
	if result.CAKeyID != f.committedCA(t) || len(result.Ready) != 0 {
		t.Fatal("owner did not receive only the committed CA identifier")
	}
	if response, err := server.Client().Post(
		server.URL+objectCustodyInitializePath,
		"application/json",
		bytes.NewReader(encoded),
	); err == nil {
		response.Body.Close()
		t.Fatal("TLS accepted a client without the independent owner certificate")
	}
	if f.store.creates.Load() != 1 || f.provisions.Load() != 0 {
		t.Fatal("owner TLS or initialization crossed the provisioning boundary")
	}
}

func TestObjectCustodyRechecksOwnerOnEveryRequest(t *testing.T) {
	f := newCustodyServiceFixture(t)
	other, err := issuer.NewMeshCA(
		"different owner",
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	wrong := custodyOwnerCertificate(
		t,
		other.Current().CA,
		time.Now().Add(time.Hour),
	)
	expired := custodyOwnerCertificate(
		t,
		f.owner,
		time.Now().Add(-time.Minute),
	)
	for _, name := range []string{
		"no TLS",
		"no certificate",
		"unverified",
		"wrong owner",
		"expired",
	} {
		t.Run(
			name,
			func(t *testing.T) {
				body := &custodyTestBody{}
				request := f.authorizedRequest(
					http.MethodPost,
					objectCustodyInitializePath,
					body,
				)
				switch name {
				case "no TLS":
					request.TLS = nil
				case "no certificate":
					request.TLS.PeerCertificates = nil
				case "unverified":
					request.TLS.VerifiedChains = nil
				case "wrong owner":
					request.TLS.PeerCertificates = []*x509.Certificate{
						wrong.Leaf,
						other.Current().CA.Cert,
					}
				case "expired":
					request.TLS.PeerCertificates[0] = expired.Leaf
				}
				response := httptest.NewRecorder()
				f.service.ServeHTTP(
					response,
					request,
				)
				objectWantStatus(
					t,
					response,
					http.StatusUnauthorized,
				)
				if body.reads.Load() != 0 || f.stores.Load() != 0 || f.provisions.Load() != 0 {
					t.Fatal("owner rejection read a body or dispatched privileged work")
				}
			},
		)
	}
}

func TestObjectCustodyInitializationConfirmsLostAckAndIsIdempotent(t *testing.T) {
	f := newCustodyServiceFixture(t)
	f.store.create = func(
		ctx context.Context,
		data []byte,
	) (string, error) {
		etag, err := f.base.Create(
			ctx,
			data,
		)
		if err == nil {
			err = objectstate.ErrUnknown
		}
		return etag, err
	}
	for range 2 {
		response := f.post(
			t,
			objectCustodyInitializePath,
			f.initializeRequest(),
		)
		objectWantStatus(
			t,
			response,
			http.StatusOK,
		)
		var result objectCustodyResult
		if err := json.Unmarshal(
			response.Body.Bytes(),
			&result,
		); err != nil || result.CAKeyID != f.committedCA(t) || len(result.Ready) != 0 {
			t.Fatal("initialization did not return only the committed CA identifier")
		}
	}
	if f.store.creates.Load() != 1 || f.provisions.Load() != 0 {
		t.Fatal("idempotent initialization minted another identity or released a grant")
	}
}

func TestObjectCustodyProvisioningRequiresExistingAuthenticatedState(t *testing.T) {
	for _, name := range []string{
		"missing",
		"wrong key",
		"corrupt",
		"unreadable",
	} {
		t.Run(
			name,
			func(t *testing.T) {
				f := newCustodyServiceFixture(t)
				if name != "missing" {
					objectWantStatus(
						t,
						f.post(
							t,
							objectCustodyInitializePath,
							f.initializeRequest(),
						),
						http.StatusOK,
					)
				}
				creates := f.store.creates.Load()
				switch name {
				case "wrong key":
					f.service.material.StateKey[0] ^= 1
				case "corrupt":
					f.base.mu.Lock()
					f.base.data[len(f.base.data)-1] ^= 1
					f.base.mu.Unlock()
				case "unreadable":
					f.store.load = func(context.Context) (objectstate.Object, error) {
						return objectstate.Object{}, errors.New("fixture-reader-secret: unavailable")
					}
				}
				response := f.post(
					t,
					objectCustodyProvisionPath,
					f.provisionRequest(),
				)
				objectWantStatus(
					t,
					response,
					http.StatusServiceUnavailable,
				)
				if name != "missing" {
					objectWantStatus(
						t,
						f.post(
							t,
							objectCustodyInitializePath,
							f.initializeRequest(),
						),
						http.StatusServiceUnavailable,
					)
				}
				if f.store.creates.Load() != creates || f.provisions.Load() != 0 {
					t.Fatal("unreadable state was recreated or released material")
				}
			},
		)
	}
}

func TestObjectCustodyRenewalUsesCurrentPolicyWithoutInitialization(t *testing.T) {
	f := newCustodyServiceFixture(t)
	objectWantStatus(
		t,
		f.post(
			t,
			objectCustodyInitializePath,
			f.initializeRequest(),
		),
		http.StatusOK,
	)
	keyID := f.committedCA(t)
	request := f.provisionRequest()
	request.Origins = append(
		request.Origins,
		"https://other-replica.fixture.invalid",
	)
	for range 2 {
		response := f.post(
			t,
			objectCustodyProvisionPath,
			request,
		)
		objectWantStatus(
			t,
			response,
			http.StatusOK,
		)
		var result objectCustodyResult
		if err := json.Unmarshal(
			response.Body.Bytes(),
			&result,
		); err != nil || result.CAKeyID != "" || len(result.Ready) != 2 {
			t.Fatal("renewal returned unexpected custody material")
		}
		for index, replica := range result.Ready {
			if !replica.Ready || replica.Origin != request.Origins[index] {
				t.Fatal("renewal did not report the requested replica outcomes")
			}
		}
	}
	if f.provisions.Load() != 4 || f.store.creates.Load() != 1 || f.committedCA(t) != keyID {
		t.Fatal("renewal changed identity or repeated initialization")
	}
	f.base.mu.Lock()
	f.base.data = nil
	f.base.mu.Unlock()
	objectWantStatus(
		t,
		f.post(
			t,
			objectCustodyProvisionPath,
			request,
		),
		http.StatusServiceUnavailable,
	)
	if f.provisions.Load() != 4 || f.store.creates.Load() != 1 {
		t.Fatal("renewal reused policy after current state disappeared")
	}
}

func TestObjectCustodyRejectsScopeBeforeStorageOrProvisioning(t *testing.T) {
	f := newCustodyServiceFixture(t)
	for _, name := range []string{
		"initialize launch mismatch",
		"provision launch mismatch",
		"initialize with writer",
		"initialize with origin",
		"provision without writer",
		"provision without origins",
		"too many origins",
		"duplicate origins",
		"HTTP origin",
		"origin credentials",
		"origin query",
		"origin path",
		"expired reader",
	} {
		t.Run(
			name,
			func(t *testing.T) {
				path := objectCustodyProvisionPath
				request := f.provisionRequest()
				if strings.HasPrefix(
					name,
					"initialize",
				) {
					path = objectCustodyInitializePath
					request = f.initializeRequest()
				}
				switch name {
				case "initialize launch mismatch", "provision launch mismatch":
					request.ConfigSHA256 = strings.Repeat(
						"0",
						64,
					)
				case "initialize with writer":
					request.Writer = &f.writer
				case "initialize with origin":
					request.Origins = []string{"https://replica.fixture.invalid"}
				case "provision without writer":
					request.Writer = nil
				case "provision without origins":
					request.Origins = nil
				case "too many origins":
					request.Origins = make(
						[]string,
						17,
					)
				case "duplicate origins":
					request.Origins = append(
						request.Origins,
						request.Origins[0],
					)
				case "HTTP origin":
					request.Origins[0] = "http://replica.fixture.invalid"
				case "origin credentials":
					request.Origins[0] = "https://owner@replica.fixture.invalid"
				case "origin query":
					request.Origins[0] += "?redirect=other"
				case "origin path":
					request.Origins[0] += "/other"
				case "expired reader":
					request.Storage.ExpiresAt = time.Now().Add(-time.Minute)
				}
				objectWantStatus(
					t,
					f.post(
						t,
						path,
						request,
					),
					http.StatusServiceUnavailable,
				)
				if f.stores.Load() != 0 || f.store.loads.Load() != 0 || f.store.creates.Load() != 0 || f.provisions.Load() != 0 {
					t.Fatal("invalid custody scope accessed storage or released a grant")
				}
			},
		)
	}
}

func TestObjectCustodyRejectsNonStrictAndOversizedBodies(t *testing.T) {
	f := newCustodyServiceFixture(t)
	for _, body := range []string{
		`{"config_sha256":"first","config_sha256":"second"}`,
		`{"unknown":"fixture-reader-secret"}`,
		`{} {}`,
		`{"config_sha256":"\ud800"}`,
		strings.Repeat(
			" ",
			objectCustodyRequestLimit,
		) + "{}",
	} {
		response := httptest.NewRecorder()
		f.service.ServeHTTP(
			response,
			f.authorizedRequest(
				http.MethodPost,
				objectCustodyInitializePath,
				strings.NewReader(body),
			),
		)
		objectWantStatus(
			t,
			response,
			http.StatusBadRequest,
		)
		f.noSecrets(
			t,
			response.Body.Bytes(),
		)
	}
	if f.stores.Load() != 0 || f.provisions.Load() != 0 {
		t.Fatal("invalid request body dispatched custody work")
	}
}

type custodyTestBody struct {
	reads atomic.Int64
	read  func([]byte) (int, error)
	close func() error
}

func (b *custodyTestBody) Read(data []byte) (int, error) {
	b.reads.Add(1)
	if b.read != nil {
		return b.read(data)
	}
	return 0, errors.New("request body should not have been read")
}

func (b *custodyTestBody) Close() error {
	if b.close != nil {
		return b.close()
	}
	return nil
}

func custodyWait(
	t *testing.T,
	done <-chan struct{},
) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("custody operation did not reach the expected boundary")
	}
}

func custodyAsyncRequest(
	service *objectCustodian,
	request *http.Request,
) (*httptest.ResponseRecorder, <-chan struct{}) {
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		service.ServeHTTP(
			response,
			request,
		)
		close(done)
	}()
	return response, done
}

func TestObjectCustodyQueueBackpressureAndCanceledJob(t *testing.T) {
	f := newCustodyServiceFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	f.service.provision = func(
		ctx context.Context,
		_ objectstate.RecoveryPolicySource,
		_ string,
		_ objectstate.TemporaryCredentials,
	) error {
		if f.provisions.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	objectWantStatus(
		t,
		f.post(
			t,
			objectCustodyInitializePath,
			f.initializeRequest(),
		),
		http.StatusOK,
	)
	body, err := json.Marshal(f.provisionRequest())
	if err != nil {
		t.Fatal(err)
	}
	first, firstDone := custodyAsyncRequest(
		f.service,
		f.authorizedRequest(
			http.MethodPost,
			objectCustodyProvisionPath,
			bytes.NewReader(body),
		),
	)
	custodyWait(
		t,
		entered,
	)
	queuedContext, cancel := context.WithCancel(t.Context())
	defer cancel()
	queued, queuedDone := custodyAsyncRequest(
		f.service,
		f.authorizedRequest(
			http.MethodPost,
			objectCustodyProvisionPath,
			bytes.NewReader(body),
		).WithContext(queuedContext),
	)
	deadline := time.After(5 * time.Second)
	for len(f.service.jobs) != 1 {
		select {
		case <-deadline:
			t.Fatal("second request did not enter the bounded custody queue")
		case <-time.After(time.Millisecond):
		}
	}
	untouched := &custodyTestBody{}
	full := httptest.NewRecorder()
	f.service.ServeHTTP(
		full,
		f.authorizedRequest(
			http.MethodPost,
			objectCustodyProvisionPath,
			untouched,
		),
	)
	objectWantStatus(
		t,
		full,
		http.StatusServiceUnavailable,
	)
	if full.Header().Get("Retry-After") != "1" || untouched.reads.Load() != 0 {
		t.Fatal("overload did not reject before reading the body")
	}
	cancel()
	custodyWait(
		t,
		queuedDone,
	)
	objectWantStatus(
		t,
		queued,
		http.StatusServiceUnavailable,
	)
	close(release)
	custodyWait(
		t,
		firstDone,
	)
	objectWantStatus(
		t,
		first,
		http.StatusOK,
	)
	objectWantStatus(
		t,
		f.post(
			t,
			objectCustodyInitializePath,
			f.initializeRequest(),
		),
		http.StatusOK,
	)
	if f.stores.Load() != 3 || f.provisions.Load() != 1 || f.store.creates.Load() != 1 {
		t.Fatal("canceled queued request dispatched storage or provisioning work")
	}
}

func TestObjectCustodyShutdownJoinsActor(t *testing.T) {
	f := newCustodyServiceFixture(t)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	f.service.provision = func(
		ctx context.Context,
		_ objectstate.RecoveryPolicySource,
		_ string,
		_ objectstate.TemporaryCredentials,
	) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return ctx.Err()
	}
	objectWantStatus(
		t,
		f.post(
			t,
			objectCustodyInitializePath,
			f.initializeRequest(),
		),
		http.StatusOK,
	)
	body, err := json.Marshal(f.provisionRequest())
	if err != nil {
		t.Fatal(err)
	}
	response, done := custodyAsyncRequest(
		f.service,
		f.authorizedRequest(
			http.MethodPost,
			objectCustodyProvisionPath,
			bytes.NewReader(body),
		),
	)
	custodyWait(
		t,
		entered,
	)
	stopped := make(chan struct{})
	go func() {
		f.service.Stop()
		close(stopped)
	}()
	custodyWait(
		t,
		canceled,
	)
	select {
	case <-stopped:
		t.Fatal("Stop returned while the actor still held custody material")
	case <-time.After(25 * time.Millisecond):
	}
	custodyWait(
		t,
		done,
	)
	objectWantStatus(
		t,
		response,
		http.StatusServiceUnavailable,
	)
	close(release)
	custodyWait(
		t,
		stopped,
	)
}

func TestObjectCustodyCancellationJoinsBodyCloseCallback(t *testing.T) {
	f := newCustodyServiceFixture(t)
	reading := make(chan struct{})
	closing := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	body := &custodyTestBody{
		read: func([]byte) (int, error) {
			close(reading)
			<-closing
			return 0, context.Canceled
		},
		close: func() error {
			close(closing)
			<-release
			return nil
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	response, done := custodyAsyncRequest(
		f.service,
		f.authorizedRequest(
			http.MethodPost,
			objectCustodyInitializePath,
			body,
		).WithContext(ctx),
	)
	custodyWait(
		t,
		reading,
	)
	cancel()
	custodyWait(
		t,
		closing,
	)
	select {
	case <-done:
		t.Fatal("HTTP handler returned before its body cancellation callback finished")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	custodyWait(
		t,
		done,
	)
	objectWantStatus(
		t,
		response,
		http.StatusBadRequest,
	)
	if f.stores.Load() != 0 || len(f.service.slots) != 0 {
		t.Fatal("canceled body dispatched work or retained its admission slot")
	}
}

func TestObjectCustodySlowReplicaDoesNotBlockRenewal(t *testing.T) {
	f := newCustodyServiceFixture(t)
	objectWantStatus(
		t,
		f.post(
			t,
			objectCustodyInitializePath,
			f.initializeRequest(),
		),
		http.StatusOK,
	)
	request := f.provisionRequest()
	request.Origins = []string{
		"https://slow.example",
		"https://healthy.example",
	}
	slow, healthy, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	f.service.provision = func(
		ctx context.Context,
		_ objectstate.RecoveryPolicySource,
		origin string,
		_ objectstate.TemporaryCredentials,
	) error {
		if origin == request.Origins[1] {
			close(healthy)
			return nil
		}
		close(slow)
		select {
		case <-healthy:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-release:
			return errors.New("unavailable replica")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response, done := custodyAsyncRequest(
		f.service,
		f.authorizedRequest(
			http.MethodPost,
			objectCustodyProvisionPath,
			bytes.NewReader(body),
		),
	)
	custodyWait(
		t,
		slow,
	)
	custodyWait(
		t,
		healthy,
	)
	select {
	case <-done:
		t.Fatal("provisioning returned before joining the slow replica")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	custodyWait(
		t,
		done,
	)
	objectWantStatus(
		t,
		response,
		http.StatusServiceUnavailable,
	)
	var result objectCustodyResult
	if err := json.Unmarshal(
		response.Body.Bytes(),
		&result,
	); err != nil {
		t.Fatal(err)
	}
	if len(result.Ready) != 2 || result.Ready[0].Origin != request.Origins[0] || result.Ready[0].Ready || result.Ready[1].Origin != request.Origins[1] || !result.Ready[1].Ready {
		t.Fatal("partial results did not preserve each replica's independent outcome")
	}
}
