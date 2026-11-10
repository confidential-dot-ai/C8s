package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// This fixture supplies the storage consistency contract, not its cloud or
// hardware implementation. Every application request uses the real CDS router.
type acceptanceObjectStore struct {
	mu          sync.Mutex
	data        []byte
	version     uint64
	pause       *acceptancePause
	loseAck     bool
	loadBlocked chan struct{}
}

type acceptancePause struct {
	entered chan struct{}
	release chan struct{}
}

func (s *acceptanceObjectStore) Load(ctx context.Context) (objectstate.Object, error) {
	if err := ctx.Err(); err != nil {
		return objectstate.Object{}, err
	}
	s.mu.Lock()
	blocked := s.loadBlocked
	s.mu.Unlock()
	if blocked != nil {
		select {
		case <-blocked:
		case <-ctx.Done():
			return objectstate.Object{}, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return objectstate.Object{}, objectstate.ErrNotFound
	}
	return objectstate.Object{
		Data: bytes.Clone(s.data),
		ETag: fmt.Sprint(s.version),
	}, nil
}

func (s *acceptanceObjectStore) Create(
	ctx context.Context,
	data []byte,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data != nil {
		return "", objectstate.ErrConflict
	}
	s.data = bytes.Clone(data)
	s.version++
	return fmt.Sprint(s.version), nil
}

func (s *acceptanceObjectStore) CompareAndSwap(
	ctx context.Context,
	expected string,
	data []byte,
) (string, error) {
	s.mu.Lock()
	pause := s.pause
	s.pause = nil
	s.mu.Unlock()
	if pause != nil {
		close(pause.entered)
		select {
		case <-pause.release:
		case <-ctx.Done():
			return "", objectstate.ErrUnknown
		}
	}
	if err := ctx.Err(); err != nil {
		return "", objectstate.ErrUnknown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if fmt.Sprint(s.version) != expected {
		return "", objectstate.ErrConflict
	}
	s.data = bytes.Clone(data)
	s.version++
	if s.loseAck {
		s.loseAck = false
		return "", objectstate.ErrUnknown
	}
	return fmt.Sprint(s.version), nil
}

func (s *acceptanceObjectStore) pauseNext() *acceptancePause {
	s.mu.Lock()
	defer s.mu.Unlock()
	pause := &acceptancePause{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	s.pause = pause
	return pause
}

func (s *acceptanceObjectStore) loseNextAck() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loseAck = true
}

type objectAcceptance struct {
	cfg         config
	store       objectstate.Store
	memory      *acceptanceObjectStore
	cipher      *objectstate.Cipher
	operator    *ecdsa.PrivateKey
	sequence    atomic.Uint64
	servers     []*objectServer
	inventory   fakeDigests
	signer      *workloadclaims.SandboxTokenSigner
	leaf        *x509.Certificate
	leafKey     *ecdsa.PrivateKey
	root        *x509.Certificate
	attestation remote.Client
}

func newObjectAcceptance(t *testing.T) *objectAcceptance {
	t.Helper()
	return newObjectAcceptanceForCluster(
		t,
		"lane",
	)
}

func newObjectAcceptanceForCluster(
	t *testing.T,
	clusterID string,
) *objectAcceptance {
	t.Helper()
	key, public := operatorKeyPair(t)
	document := measuredDocument(
		t,
		cluster{
			operatorPEM: public,
			workloads:   map[string]string{"seed": digestA},
		},
	)
	var wire map[string]any
	if err := yaml.Unmarshal(
		document,
		&wire,
	); err != nil {
		t.Fatal(err)
	}
	authority, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire["clusterID"] = clusterID
	wire["objectState"] = map[string]any{
		"bucket":              "cds-acceptance",
		"key":                 "clusters/" + clusterID + "/state",
		"region":              "us-east-2",
		"expectedBucketOwner": "123456789012",
		"recoveryAuthority":   base64.StdEncoding.EncodeToString(authority),
		"workers":             2,
		"queueCapacity":       16,
	}
	document, err = yaml.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	cfg := validRunConfig(
		t,
		"http://127.0.0.1:1",
	)
	cfg.measured, err = cdsconfig.Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	cfg.measuredFile = document
	cfg.jwtClockSkew = 0
	cipher, err := objectCipher(
		cfg,
		bytes.Repeat(
			[]byte{0x39},
			32,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := initialObjectView(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Stop()
	view.state.StartedMS = time.Now().Add(-time.Hour).UnixMilli()
	plain, err := view.encode()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	sealed, err := cipher.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	store := &acceptanceObjectStore{}
	if _, err := store.Create(
		t.Context(),
		sealed,
	); err != nil {
		t.Fatal(err)
	}
	signer, err := workloadclaims.NewSandboxTokenSigner(testInventoryHost)
	if err != nil {
		t.Fatal(err)
	}
	h := &objectAcceptance{
		cfg:      cfg,
		store:    store,
		memory:   store,
		cipher:   cipher,
		operator: key,
		signer:   signer,
	}
	h.inventory = fakeDigests{
		key:     signer.PublicKey(),
		digests: map[string][]string{testSandboxID: {digestA}},
		containers: map[string][]workloadclaims.SandboxContainer{testSandboxID: {{
			Digest: digestA,
			Argv:   []string{"/serve"},
			Mounts: []pkgallowlist.ObservedMount{},
		}}},
	}
	h.root = view.ca.CA.Cert
	h.restart(t)
	t.Cleanup(h.stop)
	return h
}

func (h *objectAcceptance) stop() {
	for _, server := range h.servers {
		server.Stop()
	}
	h.servers = nil
}

func (h *objectAcceptance) restart(t *testing.T) {
	t.Helper()
	h.stop()
	for range 3 {
		h.servers = append(
			h.servers,
			h.newServer(t),
		)
	}
}

func (h *objectAcceptance) newServer(t *testing.T) *objectServer {
	t.Helper()
	limits := newTestRateLimiter(t)
	challenges := newTestRateLimiter(t)
	factory := func(back backend) (dependencies, error) {
		issuance, release := back.Challenges()
		verify := operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&h.operator.PublicKey}}
		authorize := singleUse(
			verify.AuthorizeIssuedAt,
			back.Allowlist(),
			back.TokenFloor,
			0,
		)
		return dependencies{
			AttestHandler: AttestHandler{
				RequireNonMigratable: true,
				Challenges:           issuance,
				AttestationClient:    h.attestation,
				CertTTL:              h.cfg.certTTL,
				RequestTimeout:       h.cfg.requestTimeout,
			},
			AllowlistHandler: allowlist.Handler{
				Allowlist:       back.Allowlist(),
				WriteAuthorizer: authorize,
			},
			Routes: routeHandler{
				Allowlist: back.Allowlist(),
				Authorize: authorize,
			},
			ReadyFn:          func() bool { return true },
			MeshCA:           back.MeshCA(),
			NodeImages:       back.NodeImages(),
			RateLimiter:      limits,
			ChallengeLimiter: challenges,
			MaxRequestSize:   65536,
			SecretsHandler: &secrets.Handler{
				Store:          back.Secrets(),
				Challenges:     release,
				Inventory:      h.inventory,
				Bindings:       back.Bindings(),
				Policy:         secrets.NewCachedPolicy(back.Allowlist()),
				InventoryHosts: h.cfg.measured.NodeCIDRs,
			},
			SecretsChallenges: release,
			SecretsOperator: &secrets.OperatorHandler{
				Store:     back.Secrets(),
				Authorize: authorize,
			},
			SecretsExplain: &secrets.ExplainHandler{Authorize: authorize},
		}, nil
	}
	return newObjectServer(
		t.Context(),
		h.cfg,
		h.store,
		h.cipher,
		factory,
		nil,
	)
}

func (h *objectAcceptance) token(
	t *testing.T,
	method, path string,
	body []byte,
) string {
	t.Helper()
	digest := sha256.Sum256(body)
	token, err := jwt.NewWithClaims(
		jwt.SigningMethodES256,
		jwt.MapClaims{
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"htm": method,
			"htu": path,
			"pbh": base64.RawURLEncoding.EncodeToString(digest[:]),
			"jti": fmt.Sprint(h.sequence.Add(1)),
		},
	).SignedString(h.operator)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func objectCall(
	server http.Handler,
	method, path string,
	body []byte,
	token string,
) *httptest.ResponseRecorder {
	r := httptest.NewRequest(
		method,
		path,
		bytes.NewReader(body),
	)
	r.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	w := httptest.NewRecorder()
	server.ServeHTTP(
		w,
		r,
	)
	return w
}

func objectDocument(
	t *testing.T,
	label string,
) []byte {
	t.Helper()
	doc := parseSeed(
		t,
		map[string]string{label: digestA},
	)
	canonical, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func objectWantStatus(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
) {
	t.Helper()
	if response.Code != status {
		t.Fatalf(
			"status=%d, want %d: %s",
			response.Code,
			status,
			response.Body,
		)
	}
}

func TestObjectAcceptanceRecoveryPreservesIdentityAndCanonicalReplay(t *testing.T) {
	h := newObjectAcceptance(t)
	before := objectCall(
		h.servers[0],
		http.MethodGet,
		"/ca",
		nil,
		"",
	)
	objectWantStatus(
		t,
		before,
		http.StatusOK,
	)
	first := objectDocument(
		t,
		"first",
	)
	spent := h.token(
		t,
		http.MethodPut,
		"/allowlist",
		first,
	)
	unusedBody := objectDocument(
		t,
		"unused-before-loss",
	)
	unused := h.token(
		t,
		http.MethodPut,
		"/allowlist",
		unusedBody,
	)
	objectWantStatus(
		t,
		objectCall(
			h.servers[1],
			http.MethodPut,
			"/allowlist",
			first,
			spent,
		),
		http.StatusNoContent,
	)
	h.restart(t)
	after := objectCall(
		h.servers[2],
		http.MethodGet,
		"/ca",
		nil,
		"",
	)
	objectWantStatus(
		t,
		after,
		http.StatusOK,
	)
	if !bytes.Equal(
		before.Body.Bytes(),
		after.Body.Bytes(),
	) {
		t.Fatal("total replica loss changed the CA")
	}
	objectWantStatus(
		t,
		objectCall(
			h.servers[0],
			http.MethodPut,
			"/allowlist",
			first,
			spent,
		),
		http.StatusConflict,
	)
	alternate := objectTokenTwin(
		t,
		spent,
	)
	objectWantStatus(
		t,
		objectCall(
			h.servers[1],
			http.MethodPut,
			"/allowlist",
			first,
			alternate,
		),
		http.StatusConflict,
	)
	objectWantStatus(
		t,
		objectCall(
			h.servers[2],
			http.MethodPut,
			"/allowlist",
			unusedBody,
			unused,
		),
		http.StatusNoContent,
	)
	read := objectCall(
		h.servers[0],
		http.MethodGet,
		"/allowlist",
		nil,
		"",
	)
	if !bytes.Equal(
		read.Body.Bytes(),
		unusedBody,
	) {
		t.Fatal("unused pre-loss authorization did not survive recovery")
	}
}

func TestObjectAcceptanceRejectedRequestsStillSpendAuthorization(t *testing.T) {
	h := newObjectAcceptance(t)
	invalid := []byte(`{"schema":"not-a-policy"}`)
	token := h.token(
		t,
		http.MethodPut,
		"/allowlist",
		invalid,
	)
	objectWantStatus(
		t,
		objectCall(
			h.servers[0],
			http.MethodPut,
			"/allowlist",
			invalid,
			token,
		),
		http.StatusUnprocessableEntity,
	)
	h.restart(t)
	objectWantStatus(
		t,
		objectCall(
			h.servers[1],
			http.MethodPut,
			"/allowlist",
			invalid,
			token,
		),
		http.StatusConflict,
	)
	nonce := mintChallenge(
		t,
		h.servers[0],
		"/authenticate",
	)
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge: base64.StdEncoding.EncodeToString(nonce),
		CSR:       "not a CSR",
	})
	if err != nil {
		t.Fatal(err)
	}
	first := objectCall(
		h.servers[1],
		http.MethodPost,
		"/attest",
		body,
		"",
	)
	objectWantStatus(
		t,
		first,
		http.StatusBadRequest,
	)
	if errorCode(
		t,
		first.Body.Bytes(),
	) != types.ErrorCodeInvalidCSR {
		t.Fatalf(
			"first challenge was not accepted: %s",
			first.Body,
		)
	}
	h.restart(t)
	replay := objectCall(
		h.servers[2],
		http.MethodPost,
		"/attest",
		body,
		"",
	)
	objectWantStatus(
		t,
		replay,
		http.StatusBadRequest,
	)
	if errorCode(
		t,
		replay.Body.Bytes(),
	) != types.ErrorCodeInvalidChallenge {
		t.Fatalf(
			"used challenge was accepted after loss: %s",
			replay.Body,
		)
	}
}

func TestObjectAcceptanceLostAcknowledgmentDoesNotReapply(t *testing.T) {
	h := newObjectAcceptance(t)
	body := objectDocument(
		t,
		"committed-without-ack",
	)
	token := h.token(
		t,
		http.MethodPut,
		"/allowlist",
		body,
	)
	h.memory.loseNextAck()
	response := objectCall(
		h.servers[0],
		http.MethodPut,
		"/allowlist",
		body,
		token,
	)
	objectWantStatus(
		t,
		response,
		http.StatusServiceUnavailable,
	)
	if response.Header().Get("X-C8s-Commit-Outcome") != "unknown" {
		t.Fatal("lost acknowledgment was not reported as unknown")
	}
	read := objectCall(
		h.servers[1],
		http.MethodGet,
		"/allowlist",
		nil,
		"",
	)
	if !bytes.Equal(
		read.Body.Bytes(),
		body,
	) {
		t.Fatal("fault did not occur after commitment")
	}
	objectWantStatus(
		t,
		objectCall(
			h.servers[2],
			http.MethodPut,
			"/allowlist",
			body,
			token,
		),
		http.StatusConflict,
	)
	h.memory.mu.Lock()
	version := h.memory.version
	h.memory.mu.Unlock()
	if version != 2 {
		t.Fatalf(
			"lost acknowledgment caused extra commits: object version=%d",
			version,
		)
	}
}

func (h *objectAcceptance) prepareSecret(t *testing.T) {
	t.Helper()
	view, err := recoverObjectView(
		t.Context(),
		h.cfg,
		h.store,
		h.cipher,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Stop()
	policy := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/serve"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"any"}}],"secrets":{"policy":"allow","read":["/app/**"],"write":["/app/**"]}}}}`)
	al, err := pkgallowlist.ParseJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Allowlist().ReplaceAll(
		al,
		allowlist.OperatorWrite{},
	); err != nil {
		t.Fatal(err)
	}
	if !view.Bindings().Record(
		testSandboxID,
		testInventoryHost,
	) {
		t.Fatal("cannot seed inventory binding")
	}
	if _, err := view.Secrets().Put(
		t.Context(),
		"/app/key",
		[]byte("object-acceptance-secret"),
	); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	extension, err := armtls.MarshalSandboxIDExtension(testSandboxID)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(9),
		Subject:         pkix.Name{CommonName: "object-acceptance"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{extension},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		view.ca.CA.Cert,
		&key.PublicKey,
		view.ca.CA.Key,
	)
	if err != nil {
		t.Fatal(err)
	}
	h.leafKey = key
	h.leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	object, err := h.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := view.encode()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	sealed, err := h.cipher.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CompareAndSwap(
		t.Context(),
		object.ETag,
		sealed,
	); err != nil {
		t.Fatal(err)
	}
}

func (h *objectAcceptance) secretRequest(
	t *testing.T,
	nonce []byte,
) *http.Request {
	t.Helper()
	digest, err := workloadclaims.RequesterKeyDigest(h.leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	token, err := h.signer.Sign(
		testSandboxID,
		digest,
		nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(
		http.MethodGet,
		"/secrets/app/key",
		nil,
	)
	r.Header.Set(
		secrets.ChallengeHeader,
		base64.StdEncoding.EncodeToString(nonce),
	)
	r.Header.Set(
		"Authorization",
		secrets.AuthScheme+base64.StdEncoding.EncodeToString(raw),
	)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{h.leaf},
		VerifiedChains: [][]*x509.Certificate{{
			h.leaf,
			h.root,
		}},
	}
	return r
}

func TestObjectAcceptanceRevocationFencesPausedReleaseAndSurvivesLoss(t *testing.T) {
	h := newObjectAcceptance(t)
	h.prepareSecret(t)
	nonce := mintChallenge(
		t,
		h.servers[0],
		"/secrets",
	)
	allowed := httptest.NewRecorder()
	h.servers[1].ServeHTTP(
		allowed,
		h.secretRequest(
			t,
			nonce,
		),
	)
	objectWantStatus(
		t,
		allowed,
		http.StatusOK,
	)
	secret := base64.StdEncoding.EncodeToString([]byte("object-acceptance-secret"))
	if !strings.Contains(
		allowed.Body.String(),
		secret,
	) {
		t.Fatal("positive control did not release the fixture secret")
	}
	nonce = mintChallenge(
		t,
		h.servers[2],
		"/secrets",
	)
	pause := h.memory.pauseNext()
	stale := httptest.NewRecorder()
	request := h.secretRequest(
		t,
		nonce,
	)
	done := make(chan struct{})
	go func() {
		h.servers[0].ServeHTTP(
			stale,
			request,
		)
		close(done)
	}()
	select {
	case <-pause.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("release never reached commit")
	}
	revoked := objectDocument(
		t,
		"revoked",
	)
	token := h.token(
		t,
		http.MethodPut,
		"/allowlist",
		revoked,
	)
	objectWantStatus(
		t,
		objectCall(
			h.servers[1],
			http.MethodPut,
			"/allowlist",
			revoked,
			token,
		),
		http.StatusNoContent,
	)
	close(pause.release)
	<-done
	objectWantStatus(
		t,
		stale,
		http.StatusConflict,
	)
	if strings.Contains(
		stale.Body.String(),
		secret,
	) {
		t.Fatal("stale release disclosed a secret after losing CAS")
	}
	h.restart(t)
	denied := httptest.NewRecorder()
	h.servers[2].ServeHTTP(
		denied,
		h.secretRequest(
			t,
			nonce,
		),
	)
	objectWantStatus(
		t,
		denied,
		http.StatusForbidden,
	)
	if strings.Contains(
		denied.Body.String(),
		secret,
	) {
		t.Fatal("revocation disappeared after total replica loss")
	}
	used := httptest.NewRecorder()
	h.servers[1].ServeHTTP(
		used,
		h.secretRequest(
			t,
			nonce,
		),
	)
	objectWantStatus(
		t,
		used,
		http.StatusBadRequest,
	)
}

func TestObjectAcceptanceLostReleaseAcknowledgmentDisclosesNothing(t *testing.T) {
	h := newObjectAcceptance(t)
	h.prepareSecret(t)
	nonce := mintChallenge(
		t,
		h.servers[0],
		"/secrets",
	)
	h.memory.loseNextAck()
	response := httptest.NewRecorder()
	h.servers[1].ServeHTTP(
		response,
		h.secretRequest(
			t,
			nonce,
		),
	)
	objectWantStatus(
		t,
		response,
		http.StatusServiceUnavailable,
	)
	if strings.Contains(
		response.Body.String(),
		base64.StdEncoding.EncodeToString([]byte("object-acceptance-secret")),
	) {
		t.Fatal("unknown commitment disclosed plaintext")
	}
	h.restart(t)
	replay := httptest.NewRecorder()
	h.servers[2].ServeHTTP(
		replay,
		h.secretRequest(
			t,
			nonce,
		),
	)
	objectWantStatus(
		t,
		replay,
		http.StatusBadRequest,
	)
}

func TestObjectAcceptanceCanceledCommitDoesNotAcknowledgeOrRepeat(t *testing.T) {
	h := newObjectAcceptance(t)
	body := objectDocument(
		t,
		"canceled",
	)
	token := h.token(
		t,
		http.MethodPut,
		"/allowlist",
		body,
	)
	pause := h.memory.pauseNext()
	ctx, cancel := context.WithCancel(t.Context())
	r := httptest.NewRequest(
		http.MethodPut,
		"/allowlist",
		bytes.NewReader(body),
	).WithContext(ctx)
	r.Header.Set(
		"Authorization",
		"Bearer "+token,
	)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.servers[0].ServeHTTP(
			response,
			r,
		)
		close(done)
	}()
	select {
	case <-pause.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("write never reached commit")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled operation did not finish")
	}
	if response.Code >= 200 && response.Code < 300 {
		t.Fatalf(
			"canceled commitment acknowledged with %d",
			response.Code,
		)
	}
	objectWantStatus(
		t,
		objectCall(
			h.servers[1],
			http.MethodPut,
			"/allowlist",
			body,
			token,
		),
		http.StatusNoContent,
	)
}

type objectRegisterInput struct {
	Write bool
	Value string
}

type objectRegisterOutput struct {
	Applied bool
	Value   string
}

func TestObjectAcceptanceThreeReplicasHaveLinearizablePolicyHistory(t *testing.T) {
	h := newObjectAcceptance(t)
	initial := objectCall(
		h.servers[0],
		http.MethodGet,
		"/allowlist",
		nil,
		"",
	).Body.String()
	var clock atomic.Int64
	var clients sync.WaitGroup
	operations := make(
		chan porcupine.Operation,
		96,
	)
	failures := make(
		chan error,
		96,
	)
	for client := range 3 {
		clients.Add(1)
		go func() {
			defer clients.Done()
			for step := range 12 {
				body := objectDocument(
					t,
					fmt.Sprintf(
						"client-%d-write-%d",
						client,
						step,
					),
				)
				token := h.token(
					t,
					http.MethodPut,
					"/allowlist",
					body,
				)
				start := clock.Add(1)
				response := objectCall(
					h.servers[(client+step)%3],
					http.MethodPut,
					"/allowlist",
					body,
					token,
				)
				end := clock.Add(1)
				if response.Code != http.StatusNoContent && response.Code != http.StatusConflict {
					failures <- fmt.Errorf(
						"writer %d received %d: %s",
						client,
						response.Code,
						response.Body,
					)
					return
				}
				operations <- porcupine.Operation{
					ClientId: client,
					Input: objectRegisterInput{
						Write: true,
						Value: string(body),
					},
					Call:   start,
					Output: objectRegisterOutput{Applied: response.Code == http.StatusNoContent},
					Return: end,
				}
				start = clock.Add(1)
				response = objectCall(
					h.servers[(client+step+1)%3],
					http.MethodGet,
					"/allowlist",
					nil,
					"",
				)
				end = clock.Add(1)
				if response.Code != http.StatusOK {
					failures <- fmt.Errorf(
						"reader %d received %d",
						client,
						response.Code,
					)
					return
				}
				operations <- porcupine.Operation{
					ClientId: client,
					Input:    objectRegisterInput{},
					Call:     start,
					Output:   objectRegisterOutput{Value: response.Body.String()},
					Return:   end,
				}
			}
		}()
	}
	clients.Wait()
	close(operations)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	history := make(
		[]porcupine.Operation,
		0,
		len(operations),
	)
	for operation := range operations {
		history = append(
			history,
			operation,
		)
	}
	model := porcupine.Model{
		Init: func() any { return initial },
		Step: func(state, input, output any) (bool, any) {
			in, out := input.(objectRegisterInput), output.(objectRegisterOutput)
			if in.Write {
				if out.Applied {
					return true, in.Value
				}
				return true, state
			}
			return out.Value == state.(string), state
		},
	}
	result, info := porcupine.CheckOperationsVerbose(
		model,
		history,
		10*time.Second,
	)
	if result != porcupine.Ok {
		path := filepath.Join(
			t.TempDir(),
			"object-policy-history.html",
		)
		_ = porcupine.VisualizePath(
			model,
			info,
			path,
		)
		t.Fatalf(
			"policy history=%s; visualization=%s",
			result,
			path,
		)
	}
	if len(history) != 72 {
		t.Fatalf(
			"history has %d requests, want 72",
			len(history),
		)
	}
	t.Logf(
		"Porcupine accepted %d requests across three replicas",
		len(history),
	)
}

func TestObjectAcceptanceMissingStateIsNotReinitialized(t *testing.T) {
	h := newObjectAcceptance(t)
	h.memory.mu.Lock()
	h.memory.data = nil
	h.memory.mu.Unlock()
	if _, err := recoverObjectView(
		t.Context(),
		h.cfg,
		h.store,
		h.cipher,
	); !errors.Is(
		err,
		objectstate.ErrNotFound,
	) {
		t.Fatalf(
			"missing state recovery=%v",
			err,
		)
	}
	response := objectCall(
		h.servers[0],
		http.MethodGet,
		"/ca",
		nil,
		"",
	)
	objectWantStatus(
		t,
		response,
		http.StatusServiceUnavailable,
	)
	h.memory.mu.Lock()
	defer h.memory.mu.Unlock()
	if h.memory.data != nil {
		t.Fatal("missing state minted a replacement identity")
	}
}

func TestObjectAcceptanceExistingTLSConnectionCannotUseReplacedCA(t *testing.T) {
	h := newObjectAcceptance(t)
	h.prepareSecret(t)
	nonce := mintChallenge(
		t,
		h.servers[0],
		"/secrets",
	)
	request := h.secretRequest(
		t,
		nonce,
	)
	view, err := recoverObjectView(
		t.Context(),
		h.cfg,
		h.store,
		h.cipher,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Stop()
	replacement, err := issuer.NewMeshCA(
		"replacement acceptance CA",
		24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	view.ca = replacement.Current()
	view.state.CACert = view.ca.CA.Cert.Raw
	view.state.CAKey, err = x509.MarshalPKCS8PrivateKey(view.ca.CA.Key)
	if err != nil {
		t.Fatal(err)
	}
	object, err := h.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := view.encode()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	sealed, err := h.cipher.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CompareAndSwap(
		t.Context(),
		object.ETag,
		sealed,
	); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	h.servers[1].ServeHTTP(
		response,
		request,
	)
	objectWantStatus(
		t,
		response,
		http.StatusForbidden,
	)
	if strings.Contains(
		response.Body.String(),
		base64.StdEncoding.EncodeToString([]byte("object-acceptance-secret")),
	) {
		t.Fatal("handshake-time VerifiedChains bypassed current CA")
	}
}

type acceptanceBlockingBody struct {
	entered   chan struct{}
	closed    chan struct{}
	release   chan struct{}
	finished  chan struct{}
	readOnce  sync.Once
	closeOnce sync.Once
}

func (b *acceptanceBlockingBody) Read([]byte) (int, error) {
	b.readOnce.Do(func() { close(b.entered) })
	<-b.closed
	<-b.release
	close(b.finished)
	return 0, context.Canceled
}

func (b *acceptanceBlockingBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

func TestObjectAcceptanceShutdownWaitsForWorkersAndDrainsAdmissions(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	h.cfg.measured.ObjectState.Workers = 1
	h.cfg.measured.ObjectState.QueueCapacity = 1
	h.restart(t)
	server := h.servers[0]
	body := &acceptanceBlockingBody{
		entered:  make(chan struct{}),
		closed:   make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan struct{}),
	}
	defer func() {
		_ = body.Close()
		select {
		case <-body.release:
		default:
			close(body.release)
		}
	}()
	r := httptest.NewRequest(
		http.MethodPut,
		"/allowlist",
		nil,
	)
	r.Body = body
	blocked := httptest.NewRecorder()
	blockedDone := make(chan struct{})
	go func() {
		server.ServeHTTP(
			blocked,
			r,
		)
		close(blockedDone)
	}()
	select {
	case <-body.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker never started reading body")
	}
	queued := httptest.NewRecorder()
	queuedDone := make(chan struct{})
	go func() {
		server.ServeHTTP(
			queued,
			httptest.NewRequest(
				http.MethodGet,
				"/allowlist",
				nil,
			),
		)
		close(queuedDone)
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(server.slots) != 2 {
		select {
		case <-deadline.C:
			t.Fatal("second request was not admitted")
		case <-time.After(time.Millisecond):
		}
	}
	full := objectCall(
		server,
		http.MethodGet,
		"/allowlist",
		nil,
		"",
	)
	objectWantStatus(
		t,
		full,
		http.StatusServiceUnavailable,
	)
	if full.Header().Get("Retry-After") == "" {
		t.Fatal("full admission queue returned no backpressure")
	}
	stopped := make(chan struct{})
	go func() { server.Stop(); close(stopped) }()
	select {
	case <-body.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not cancel the blocked body")
	}
	select {
	case <-blockedDone:
		t.Fatal("HTTP request returned before its worker was quiescent")
	default:
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned with a live worker")
	default:
	}
	for range 8 {
		objectWantStatus(
			t,
			objectCall(
				server,
				http.MethodGet,
				"/allowlist",
				nil,
				"",
			),
			http.StatusServiceUnavailable,
		)
	}
	close(body.release)
	for name, done := range map[string]<-chan struct{}{
		"worker":       body.finished,
		"blocked HTTP": blockedDone,
		"queued HTTP":  queuedDone,
		"Stop":         stopped,
	} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf(
				"%s did not finish",
				name,
			)
		}
	}
	objectWantStatus(
		t,
		blocked,
		http.StatusServiceUnavailable,
	)
	objectWantStatus(
		t,
		queued,
		http.StatusServiceUnavailable,
	)
	objectWantStatus(
		t,
		objectCall(
			h.servers[1],
			http.MethodGet,
			"/allowlist",
			nil,
			"",
		),
		http.StatusOK,
	)
}

func TestObjectAcceptanceClusterBackpressureIsIsolated(t *testing.T) {
	blockedCluster := newObjectAcceptanceForCluster(
		t,
		"blocked-cluster",
	)
	otherCluster := newObjectAcceptanceForCluster(
		t,
		"other-cluster",
	)
	blockedCluster.stop()
	blockedCluster.cfg.measured.ObjectState.Workers = 1
	blockedCluster.cfg.measured.ObjectState.QueueCapacity = 1
	blockedCluster.restart(t)
	blockedCluster.memory.mu.Lock()
	blockedCluster.memory.loadBlocked = make(chan struct{})
	blockedCluster.memory.mu.Unlock()
	server := blockedCluster.servers[0]
	responses := []*httptest.ResponseRecorder{
		httptest.NewRecorder(),
		httptest.NewRecorder(),
	}
	var requests sync.WaitGroup
	for _, response := range responses {
		requests.Add(1)
		go func() {
			defer requests.Done()
			server.ServeHTTP(
				response,
				httptest.NewRequest(
					http.MethodGet,
					"/ca",
					nil,
				),
			)
		}()
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(server.slots) != 2 {
		select {
		case <-deadline.C:
			t.Fatal("blocked cluster did not fill its admission budget")
		case <-time.After(time.Millisecond):
		}
	}
	full := objectCall(
		server,
		http.MethodGet,
		"/ca",
		nil,
		"",
	)
	objectWantStatus(
		t,
		full,
		http.StatusServiceUnavailable,
	)
	if full.Header().Get("Retry-After") == "" {
		t.Fatal("saturated cluster did not apply backpressure")
	}
	objectWantStatus(
		t,
		objectCall(
			otherCluster.servers[0],
			http.MethodGet,
			"/ca",
			nil,
			"",
		),
		http.StatusOK,
	)
	server.Stop()
	requests.Wait()
	for _, response := range responses {
		objectWantStatus(
			t,
			response,
			http.StatusServiceUnavailable,
		)
	}
}

func TestObjectAcceptanceIssuesUnderRecoveredCAAndRejectsChallengeReplay(t *testing.T) {
	h := newObjectAcceptance(t)
	csr, key := generateCSR(t)
	var expected []byte
	var verifications atomic.Int64
	h.attestation = remote.NewClientWithHTTP(
		"http://fixture.invalid",
		&http.Client{
			Timeout: time.Second,
			Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				var verify remote.VerifyRequest
				if err := json.NewDecoder(request.Body).Decode(&verify); err != nil {
					return nil, err
				}
				if verify.Params == nil || !bytes.Equal(
					verify.Params.ExpectedReportData,
					expected,
				) {
					return nil, errors.New("issuance did not bind the CSR key and challenge")
				}
				verifications.Add(1)
				body, err := json.Marshal(remote.VerifyResponse{Result: teetypes.VerificationResult{
					Platform:        teetypes.PlatformTDX,
					SignatureValid:  true,
					ReportDataMatch: teetypes.Ptr(true),
					Claims: teetypes.Claims{
						LaunchDigest: nodeMRTD,
						PlatformData: map[string]any{"td_attributes": "0000000000000000"},
					},
				}})
				if err != nil {
					return nil, err
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(body)),
				}, nil
			}),
		},
	)
	makeBody := func(nonce []byte) []byte {
		reportData, err := armtls.ReportDataForKey(
			&key.PublicKey,
			nonce,
		)
		if err != nil {
			t.Fatal(err)
		}
		expected = bytes.Clone(reportData[:48])
		body, err := json.Marshal(types.AttestRequestBody{
			Challenge: base64.StdEncoding.EncodeToString(nonce),
			CSR:       csr,
			Evidence: teetypes.AttestationEvidence{
				Platform: teetypes.PlatformTDX,
				Evidence: json.RawMessage(`{"quote":"synthetic fixture"}`),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	nonce := mintChallenge(
		t,
		h.servers[0],
		"/authenticate",
	)
	body := makeBody(nonce)
	issued := objectCall(
		h.servers[1],
		http.MethodPost,
		"/attest",
		body,
		"",
	)
	objectWantStatus(
		t,
		issued,
		http.StatusOK,
	)
	leaf := leafFromAttestResponse(
		t,
		issued,
	)
	if err := leaf.CheckSignatureFrom(h.root); err != nil {
		t.Fatalf(
			"issued under another CA: %v",
			err,
		)
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("certificate names another requester key")
	}
	pending := mintChallenge(
		t,
		h.servers[2],
		"/authenticate",
	)
	h.restart(t)
	replay := objectCall(
		h.servers[2],
		http.MethodPost,
		"/attest",
		body,
		"",
	)
	objectWantStatus(
		t,
		replay,
		http.StatusBadRequest,
	)
	if errorCode(
		t,
		replay.Body.Bytes(),
	) != types.ErrorCodeInvalidChallenge {
		t.Fatalf(
			"replayed issuance reached verification: %s",
			replay.Body,
		)
	}
	issued = objectCall(
		h.servers[0],
		http.MethodPost,
		"/attest",
		makeBody(pending),
		"",
	)
	objectWantStatus(
		t,
		issued,
		http.StatusOK,
	)
	if err := leafFromAttestResponse(
		t,
		issued,
	).CheckSignatureFrom(h.root); err != nil {
		t.Fatalf(
			"recovered CDS issued under another CA: %v",
			err,
		)
	}
	if verifications.Load() != 2 {
		t.Fatalf(
			"verification calls=%d, want 2; replay reached verifier",
			verifications.Load(),
		)
	}
}

func objectTokenTwin(
	t *testing.T,
	token string,
) string {
	t.Helper()
	dot := strings.LastIndexByte(
		token,
		'.',
	)
	signature, err := base64.RawURLEncoding.DecodeString(token[dot+1:])
	if err != nil {
		t.Fatal(err)
	}
	twin := new(big.Int).SetBytes(signature[32:])
	twin.Sub(
		elliptic.P256().Params().N,
		twin,
	).FillBytes(signature[32:])
	return token[:dot+1] + base64.RawURLEncoding.EncodeToString(signature)
}
