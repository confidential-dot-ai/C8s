// Package cdsattest implements the router attestation + over-encryption sidecar:
// the *dynamic* client-facing endpoints of the c8s-verify protocol. The
// router nginx front-end terminates public TLS, serves the static CDS/mesh-CA
// certs, and reverse-proxies the two explicit attestation endpoints
// (attest-pq, attest-lb) and the over-encrypted application paths to this
// sidecar on loopback. attest-pq lets an out-of-cluster JavaScript client
// verify that the LB is a genuine, CDS-issued, TEE-attested endpoint and —
// in the same round trip — establish a post-quantum over-encrypted channel
// that terminates inside the LB's enclave, independent of whatever TLS
// terminator sits in front of it. attest-lb binds fresh evidence to the exact
// serving leaf for native clients that ride ordinary nginx TLS instead. See
// c8s-verify-js/PROTOCOL.md.
package cdsattest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/internal/server"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const wellKnownPrefix = "/.well-known/c8s"

// nonceBytes is the exact client nonce length both attestation endpoints
// require: the transcripts frame a 32-byte nonce and anything else is refused
// rather than truncated or padded.
const nonceBytes = 32

// sessionHeader names the session a tunnel request rides.
const sessionHeader = "X-C8s-Session"

// Bounds on the unauthenticated endpoints: what one client may hold, and what
// the process holds across all of them.
const (
	// Session establishment: one attestation report, one X-Wing encapsulation
	// and one session per request.
	establishRateLimit = 10 // requests per second per client
	establishRateBurst = 20
	// One established session's application traffic, charged to the session.
	sessionRateLimit = 200
	sessionRateBurst = 400
	// Tunnel traffic across all of a client's sessions, charged to the client
	// on top of its per-session budget.
	clientRateLimit = 400
	clientRateBurst = 800

	// A full limiter evicts its least recently seen bucket for a new key, so
	// the map size is how many callers it meters at once. clientBuckets
	// covers the distinct clients a front door sees inside one idle timeout;
	// the session limiter also carries one bucket per live session, so its
	// map holds the whole session store on top of them.
	clientBuckets        = 1 << 16
	sessionBuckets       = maxSessions + clientBuckets
	limiterEvictInterval = time.Minute
	limiterIdleTimeout   = 5 * time.Minute

	// One client may hold a sixteenth of the store: a public address fronts
	// a whole CGNAT or corporate egress, so the per-client tier is sized for
	// the crowd behind one address. The global tier is the memory ceiling.
	maxSessionsPerClient = 512
	maxSessions          = 8192
	// minShare is the floor under a client's fair share of either store. It is
	// what stops an attacker setting the share by the number of addresses it
	// buys: below this many entries a client is never taken from, however many
	// clients hold the rest.
	minShare = 8

	// sweepInterval paces the background eviction of idle and over-age
	// sessions. Both conditions are also checked on use.
	sweepInterval = 10 * time.Second
	// lbBindingIdle is how long an attest-lb binding stays live after the
	// last request on its connection; it exceeds nginx's keepalive_timeout.
	lbBindingIdle = 2 * time.Minute
	// lbBindingLife is when a lapsed binding is dropped. It exceeds the
	// longest the router's nginx keeps a connection silent between requests
	// (keepalive_timeout, client_header_timeout, send_timeout), so nginx has
	// closed the connection by then.
	lbBindingLife = 5 * time.Minute
	// maxLBBindings and maxLBBindingsPerClient bound the attest-lb bindings in
	// all and per client.
	maxLBBindings          = 1 << 16
	maxLBBindingsPerClient = maxSessionsPerClient
	// maxConnectionIDBytes bounds the identifier nginx assigns
	// ($pid.$connection), so a caller bypassing nginx cannot grow the store.
	maxConnectionIDBytes = 64

	// shutdownGrace bounds the wait for in-flight requests at shutdown.
	shutdownGrace = 5 * time.Second
	// defaultSessionMaxAge is the absolute session lifetime: however busy a
	// session is, its keys retire after this long and the client re-attests.
	// The idle TTL alone would let whoever keeps records flowing keep one key
	// alive indefinitely.
	defaultSessionMaxAge = 5 * time.Hour
	// defaultTunnelIOTimeout is how long a tunnel upload or download may
	// make no progress.
	defaultTunnelIOTimeout = 30 * time.Second
	// tunnelWriteChunk is the piece of a sealed response written under one
	// write deadline. nginx reads the next piece only once the client has
	// drained one of its 16k proxy_buffers, so a smaller piece moves no
	// sooner.
	tunnelWriteChunk = 16 << 10
	// tunnelBodyLimit bounds one sealed tunnel request record.
	tunnelBodyLimit = routing.MaxTunnelRecordBytes
	// attestBodyLimit bounds the attest-pq request body: a nonce and an X-Wing
	// encapsulation key in JSON is well under 8 KiB.
	attestBodyLimit = 8 << 10
	// readyzCacheTTL bounds how stale a readiness answer may be. The check
	// reads and parses the whole mesh identity, and the conditions it reports
	// change on the scale of a certificate renewal.
	readyzCacheTTL = time.Second
)

var (
	errSessionInUse = errors.New("a session already holds this id")
	errSessionsFull = errors.New("too many sessions are open for this client")
	errStoreFull    = errors.New("the server is at capacity; retry shortly")
)

// Router is the one route state the attested endpoints share, so the digest
// a handshake binds is that of the manifest its tunnel routes by (A5, E2).
// *routing.Proxy implements it.
//
// Session gates a new attested session (A2, F2) and returns the manifest whose
// digest it binds (E1). Current is the applied manifest the publication serves.
// SyncRouterDigest returns the router digest bound sessions are checked
// against, rereading the router's credential first when it differs from leaf.
// Acquire reserves tunnel budget for a record of recordBytes from client.
// Forward routes a request decrypted from the tunnel of a session bound to
// bound; outer is the tunnel request itself. A *routing.BindingChangedError
// ends the session; any other error is sealed as 502.
type Router interface {
	Session() (*routing.Applied, error)
	Current() *routing.Applied
	SyncRouterDigest(leaf string) (string, error)
	Acquire(client string, recordBytes int64) (release func(), ok bool)
	Forward(outer *http.Request, req types.TunnelRequest, bound routing.Binding) (types.TunnelResponse, error)
}

// Config configures the sidecar server.
type Config struct {
	Logger   *slog.Logger
	Evidence EvidenceProvider
	// FrontDoorMode says which credential terminates public TLS in front of
	// this sidecar. Both endpoints commit it into their report_data
	// transcripts; anything but cds or acme — including an unset mode —
	// refuses attest-lb, so a misconfiguration can never serve a transport
	// binding for a host-visible key.
	FrontDoorMode types.FrontDoorMode
	// ServingCertFile is the path to the LB serving-leaf PEM (the cert nginx
	// presents on the wire). In cds front-door mode, GET .../attest-lb binds
	// report_data to this exact leaf DER plus the mesh identity. Re-read per
	// request so a get-cert renewal (which SIGHUPs nginx to a new leaf) is
	// picked up without restarting the sidecar.
	ServingCertFile string
	// MeshIdentity* are the TEE-held mesh leaf, matching private key, and CA
	// bundle whose possession both attestation endpoints prove. They are
	// deliberately separate from ServingCertFile, which may name a
	// host-visible public TLS credential. All three files are re-read for
	// each attestation request.
	MeshIdentityCertFile string
	MeshIdentityKeyFile  string
	MeshIdentityCAFile   string
	// ExpectedWorkload gates /readyz on the installed mesh identity leaf
	// carrying a matched-workload stamp with this exact name. Empty keeps
	// /readyz unconditionally 200.
	ExpectedWorkload string
	// MeasuredPoliciesFile is the node's journal of allowlist policies
	// extended into RTMR[3] (armtls.NodeJournal). Both bundles carry it,
	// read after the evidence; empty omits it.
	MeasuredPoliciesFile string
	// Routes gates attested sessions, routes the tunnel and serves the route
	// publication. Required.
	Routes Router
	// Bindings records attest-lb handshakes; the routing listener must read
	// the same store. Required.
	Bindings *Bindings
	// PublishRoutes serves the applied signed manifest at
	// /.well-known/c8s/routes (E4). Off, that path answers 404: the manifest
	// names hosts and backends a private deployment may not want public.
	PublishRoutes bool
	// DisableAttestEndpoints leaves attest-pq, attest-lb and the tunnel
	// unregistered, for a router that runs only the routing listener.
	DisableAttestEndpoints bool
	// SessionTTL is the idle TTL: a session unused for this long is dropped.
	SessionTTL time.Duration
	// SessionMaxAge is the absolute session lifetime from establishment,
	// enforced regardless of activity. Defaults to defaultSessionMaxAge.
	SessionMaxAge time.Duration
	// TunnelIOTimeout is how long reading a tunnel request body, or writing
	// its sealed response, may make no progress before the handler gives up.
	// It restarts after every read and every written chunk, so a slow client
	// is never cut off and a stalled one cannot hold tunnel budget. Defaults
	// to defaultTunnelIOTimeout.
	TunnelIOTimeout time.Duration
}

type establishedSession struct {
	channel   *overenc.Channel
	bound     routing.Binding
	createdAt time.Time
	lastUsed  time.Time
	client    string
}

// Server serves the c8s-verify endpoints.
type Server struct {
	cfg              Config
	log              *slog.Logger
	routes           Router
	measuredPolicies *armtls.Journal
	// establishLimiter meters attest-pq and attest-lb per client;
	// sessionLimiter meters one session's tunnel traffic; and clientLimiter
	// is the per-client aggregate over every session a client holds, plus
	// readiness.
	establishLimiter *issuer.IPRateLimiter
	sessionLimiter   *issuer.IPRateLimiter
	clientLimiter    *issuer.IPRateLimiter

	mu         sync.Mutex
	sessions   map[string]establishedSession // session id -> channel
	sessionsBy *holders                      // client -> its session ids
	bindings   *Bindings
	// unboundOnce logs the first attest-lb handshake without a connection
	// identifier.
	unboundOnce sync.Once

	sweepEvery time.Duration
	evictEvery time.Duration
	idleAfter  time.Duration

	readyzMu     sync.Mutex
	readyzAt     time.Time
	readyzCode   int
	readyzReason string
}

// NewServer constructs a Server.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 5 * time.Minute
	}
	if cfg.SessionMaxAge <= 0 {
		cfg.SessionMaxAge = defaultSessionMaxAge
	}
	if cfg.TunnelIOTimeout <= 0 {
		cfg.TunnelIOTimeout = defaultTunnelIOTimeout
	}
	return &Server{
		cfg:              cfg,
		log:              cfg.Logger,
		routes:           cfg.Routes,
		measuredPolicies: armtls.NewJournal(cfg.MeasuredPoliciesFile),
		establishLimiter: newLimiter(establishRateLimit, establishRateBurst, clientBuckets),
		sessionLimiter:   newLimiter(sessionRateLimit, sessionRateBurst, sessionBuckets),
		clientLimiter:    newLimiter(clientRateLimit, clientRateBurst, clientBuckets),
		sweepEvery:       sweepInterval,
		evictEvery:       limiterEvictInterval,
		idleAfter:        limiterIdleTimeout,
		sessions:         make(map[string]establishedSession),
		sessionsBy:       newHolders(),
		bindings:         cfg.Bindings,
	}
}

func newLimiter(limit rate.Limit, burst, buckets int) *issuer.IPRateLimiter {
	limiter, err := issuer.NewIPRateLimiter(limit, burst, buckets)
	if err != nil {
		panic("cdsattest: " + err.Error())
	}
	return limiter
}

// Serve runs the sidecar until ctx is cancelled: the listener, its graceful
// shutdown, and the maintenance its stores need.
func (s *Server) Serve(ctx context.Context, httpSrv *http.Server) error {
	go cmdsutil.ShutdownOnDone(ctx, httpSrv, shutdownGrace)
	go s.maintain(ctx)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// maintain evicts expired sessions, expired attest-lb bindings and quiet
// rate-limiter entries. It blocks until ctx is cancelled.
func (s *Server) maintain(ctx context.Context) {
	for _, limiter := range []*issuer.IPRateLimiter{s.establishLimiter, s.sessionLimiter, s.clientLimiter} {
		go limiter.EvictionLoop(ctx, s.evictEvery, s.idleAfter)
	}
	ticker := time.NewTicker(s.sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

// Handler returns the chi router for the LB endpoints.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(server.RequestLogger)
	// Every request, matched or not, holds its connection's binding while it
	// runs, so the binding cannot lapse under a long request.
	r.Use(s.holdingBinding)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Unmetered: the kubelet probes it through the same front door as the
	// public, so a per-client limit keyed on the address nginx records would
	// throttle the probe under externalTrafficPolicy: Cluster, which SNATs
	// every client onto the node. The cache below is what bounds a flood.
	r.Get("/readyz", s.handleReadyz)
	if s.cfg.DisableAttestEndpoints {
		return r
	}
	r.Method(http.MethodPost, wellKnownPrefix+"/attest-pq", s.establishing(http.HandlerFunc(s.handleAttestPQ)))
	// The pre-client-first shape. Kept registered so a stale client gets the
	// explicit 400 — never a 404 it might treat as transient, and never an
	// alias or downgrade.
	r.Get(wellKnownPrefix+"/attest-pq", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest,
			"attest-pq is client-first: POST a JSON body with nonce and xwing_ek")
	})
	r.Method(http.MethodGet, wellKnownPrefix+"/attest-lb", s.establishing(http.HandlerFunc(s.handleAttestLB)))
	// Over-encrypted application traffic: a single tunnel endpoint. The real
	// method/path/headers/body are sealed inside the request envelope, so nginx
	// only needs to route this one fixed path to the sidecar.
	r.Method(http.MethodPost, wellKnownPrefix+"/tunnel",
		s.perClient(issuer.RateLimitBy(s.sessionLimiter, s.tunnelKey, http.HandlerFunc(s.handleTunnel))))
	if s.cfg.PublishRoutes {
		r.Method(http.MethodGet, routes.PublicationPath, s.perClient(http.HandlerFunc(s.handleRoutePublication)))
	}
	return r
}

// holdingBinding holds the binding of the request's connection, if any, until
// the request ends.
func (s *Server) holdingBinding(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if held := s.bindings.Hold(r.Header.Get(routing.ConnectionHeader)); held != nil {
			defer held.Release()
		}
		next.ServeHTTP(w, r)
	})
}

// establishing rate-limits the session-establishment endpoints per client.
func (s *Server) establishing(next http.Handler) http.Handler {
	return issuer.RateLimitBy(s.establishLimiter, clientKey, next)
}

// perClient rate-limits on the client alone. It wraps the session limiter on
// the tunnel, so a request the client aggregate refuses never reaches the
// store lock that keying on a session needs.
func (s *Server) perClient(next http.Handler) http.Handler {
	return issuer.RateLimitBy(s.clientLimiter, clientKey, next)
}

// tunnelKey charges tunnel traffic to the session the sidecar issued. A
// request naming no live session is charged to its client, so a caller cannot
// name a bucket by inventing a session id.
func (s *Server) tunnelKey(r *http.Request) string {
	id := r.Header.Get(sessionHeader)
	if id == "" {
		return clientKey(r)
	}
	s.mu.Lock()
	_, live := s.sessions[id]
	s.mu.Unlock()
	if !live {
		return clientKey(r)
	}
	return "session:" + id
}

// clientKey charges a request to the address nginx recorded in X-Real-IP on
// the loopback hop. A request whose peer is not loopback did not come through
// the front door and is charged to its own address.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if peer := net.ParseIP(host); peer == nil || !peer.IsLoopback() {
		return ""
	}
	client := net.ParseIP(r.Header.Get("X-Real-IP"))
	if client == nil {
		return ""
	}
	return "client:" + issuer.ClientPrefix(client.String())
}

// clientBucket names the bucket a request's per-client state is counted in,
// falling back the same way the limiter does when there is no front door.
func clientBucket(r *http.Request) string {
	if key := clientKey(r); key != "" {
		return key
	}
	return issuer.SourceAddrKey(r)
}

// parseAttestPQRequest validates the attest-pq POST body and returns the
// decoded nonce and X-Wing encapsulation key, or writes the 400 and returns
// nil. There is no version, binding, or suite parameter: the endpoint serves
// exactly one construction, so there is nothing to negotiate.
func parseAttestPQRequest(w http.ResponseWriter, r *http.Request) (req types.AttestPQRequest, nonce, xwingEK []byte) {
	if err := json.NewDecoder(io.LimitReader(r.Body, attestBodyLimit)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "invalid JSON")
		return types.AttestPQRequest{}, nil, nil
	}
	nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "nonce must be base64url")
		return types.AttestPQRequest{}, nil, nil
	}
	// The transcript frames an exact 32-byte client nonce; refuse anything
	// else rather than truncate or pad the freshness binding.
	if len(nonce) != nonceBytes {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, fmt.Sprintf("nonce must be %d bytes, got %d", nonceBytes, len(nonce)))
		return types.AttestPQRequest{}, nil, nil
	}
	xwingEK, err = base64.RawURLEncoding.DecodeString(req.XWingEK)
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "xwing_ek must be base64url")
		return types.AttestPQRequest{}, nil, nil
	}
	if len(xwingEK) != overenc.XWingEKBytes {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, fmt.Sprintf("xwing_ek must be %d bytes, got %d", overenc.XWingEKBytes, len(xwingEK)))
		return types.AttestPQRequest{}, nil, nil
	}
	return req, nonce, xwingEK
}

// attestNonce validates the attest-lb request shape and returns the decoded
// nonce, or writes the 400 and returns nil. The endpoint takes no binding or
// pq parameter: it serves exactly one binding, so there is nothing to
// negotiate, and a stale query-selecting client must get a loud 400, never
// something else than it expects.
func attestNonce(w http.ResponseWriter, r *http.Request) (nonceB64 string, nonce []byte) {
	q := r.URL.Query()
	// Presence, not value: `?pq=` is still a client that thinks it selects a
	// binding, and it must hear the 400 rather than be served silently.
	if q.Has("pq") {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "the pq query selector is gone: the endpoint path selects the binding")
		return "", nil
	}
	if q.Has("binding") {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "the attestation endpoints take no binding parameter")
		return "", nil
	}
	nonceB64 = q.Get("nonce")
	if nonceB64 == "" {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "missing nonce")
		return "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "nonce must be base64url")
		return "", nil
	}
	// Both transcripts frame an exact 32-byte client nonce; refuse anything
	// else rather than truncate or pad the freshness binding.
	if len(decoded) != nonceBytes {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, fmt.Sprintf("nonce must be %d bytes, got %d", nonceBytes, len(decoded)))
		return "", nil
	}
	return nonceB64, decoded
}

// handleAttestPQ serves the identity-bound over-encryption binding, client
// first: the client POSTs its nonce and X-Wing encapsulation key, the server
// encapsulates once, and report_data commits the front-door mode and the
// complete key exchange — the client's key, the server's ciphertext, the
// session id, and the nonce — plus the exact mesh leaf, issuing mesh CA and
// applied route digest to one domain-separated transcript. The leaf signs that
// transcript to prove possession of its private key, and the session is live
// when the response leaves; there is no second round trip.
func (s *Server) handleAttestPQ(w http.ResponseWriter, r *http.Request) {
	req, nonce, xwingEK := parseAttestPQRequest(w, r)
	if nonce == nil {
		return
	}
	applied, ok := s.routesAdmit(w)
	if !ok {
		return
	}
	digest := applied.Signed.Digest()
	// Ahead of the report this request would mint: a request the store will
	// not take costs no attestation.
	client := clientBucket(r)
	if err := s.sessionRoom(client); err != nil {
		s.refuseSession(w, err)
		return
	}
	if s.cfg.FrontDoorMode == "" {
		writeErr(w, http.StatusNotImplemented, types.ErrorCodeBindingUnavailable, "no front-door mode is configured on this LB")
		return
	}
	if s.cfg.MeshIdentityCertFile == "" || s.cfg.MeshIdentityKeyFile == "" || s.cfg.MeshIdentityCAFile == "" {
		writeErr(w, http.StatusNotImplemented, types.ErrorCodeBindingUnavailable, "identity-bound PQ is not configured on this LB")
		return
	}
	identity, err := s.meshIdentity()
	if err != nil {
		s.log.Error("mesh identity binding unavailable", "error", err)
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeBindingUnavailable, "identity-bound PQ credentials are temporarily unavailable")
		return
	}
	routerDigest, ok := s.routerDigest(w, identity)
	if !ok {
		return
	}

	xwingCT, sharedSecret, err := overenc.Encapsulate(xwingEK)
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "invalid X-Wing encapsulation key")
		return
	}
	sessionID, err := overenc.GenerateSessionID()
	if err != nil {
		s.log.Error("generate session id", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "session id generation failed")
		return
	}

	reportData, proof, err := identity.bind(s.cfg.FrontDoorMode, xwingEK, xwingCT, sessionID, nonce, digest[:])
	if err != nil {
		s.log.Error("bind mesh identity", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "mesh identity binding failed")
		return
	}

	evidence, platform, generation, err := s.cfg.Evidence.Evidence(r.Context(), reportData)
	if err != nil {
		s.log.Error("evidence provider failed", "error", err)
		writeErr(w, http.StatusBadGateway, types.ErrorCodeAttestationUnavailable, "could not obtain attestation evidence")
		return
	}

	channel, err := overenc.NewServerChannel(sharedSecret, reportData, sessionID)
	if err != nil {
		s.log.Error("derive channel", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "channel derivation failed")
		return
	}
	id := base64.RawURLEncoding.EncodeToString(sessionID)
	now := time.Now()
	bound := routing.Binding{RouteDigest: digest, RouterDigest: routerDigest}
	if err := s.addSession(client, id, establishedSession{channel: channel, bound: bound, createdAt: now, lastUsed: now}); err != nil {
		s.refuseSession(w, err)
		return
	}

	writeJSON(w, http.StatusOK, types.AttestationBundle{
		Version:          types.BindingAttestPQ,
		Platform:         platform,
		Generation:       generation,
		Nonce:            req.Nonce,
		Evidence:         evidence,
		CDSCertPEM:       string(identity.bundlePEM),
		FrontDoorMode:    s.cfg.FrontDoorMode,
		XWingEK:          req.XWingEK,
		XWingCT:          base64.RawURLEncoding.EncodeToString(xwingCT),
		SessionID:        id,
		IdentityProof:    proof,
		MeasuredPolicies: s.measuredPolicies.Policies(),
		RouteDigest:      hex.EncodeToString(digest[:]),
	})
}

// handleAttestLB serves the ordinary-TLS binding: report_data commits the
// front-door mode, nonce, the exact serving leaf nginx presents, the exact
// mesh leaf, the issuing mesh CA and the applied route digest
// (overenc.LBTranscriptHash), and the mesh leaf signs that transcript. No
// over-encryption key exchange happens: the client recomputes the transcript
// from the leaf it observed on its own TLS connection and then rides that
// TLS. The handshake binds the public connection it arrived on to its route
// and router digests.
func (s *Server) handleAttestLB(w http.ResponseWriter, r *http.Request) {
	nonceB64, nonce := attestNonce(w, r)
	if nonce == nil {
		return
	}
	connection := r.Header.Get(routing.ConnectionHeader)
	if len(connection) > maxConnectionIDBytes {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeInvalidRequest, "connection identifier too long")
		return
	}
	applied, ok := s.routesAdmit(w)
	if !ok {
		return
	}
	digest := applied.Signed.Digest()
	// The exact-DER binding detects leaf substitution, not key sharing: a
	// WebPKI Secret's serving key is host-visible, so the host could terminate
	// the client's TLS with the same leaf and proxy this request. Only a
	// TEE-held (cds or acme) serving key supports transport binding.
	if s.cfg.FrontDoorMode != types.FrontDoorModeCDS && s.cfg.FrontDoorMode != types.FrontDoorModeACME {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeExternalTLS,
			"attest-lb requires a TEE-held serving key (public_tls.mode=cds or acme); this front door is attest-pq-only")
		return
	}
	// Before the report, as for attest-pq.
	if err := s.connectionRoom(connection, clientKey(r)); err != nil {
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeSessionsBusy, err.Error())
		return
	}
	servingLeafDER, err := s.servingLeafDER()
	if err != nil {
		s.log.Error("attest-lb binding unavailable", "error", err)
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeBindingUnavailable,
			"the serving certificate is unavailable; attest-lb cannot bind this connection")
		return
	}
	identity, err := s.meshIdentity()
	if err != nil {
		s.log.Error("mesh identity binding unavailable", "error", err)
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeBindingUnavailable, "mesh identity credentials are temporarily unavailable")
		return
	}
	routerDigest, ok := s.routerDigest(w, identity)
	if !ok {
		return
	}

	reportData, proof, err := identity.bindServingLeaf(s.cfg.FrontDoorMode, servingLeafDER, nonce, digest[:])
	if err != nil {
		s.log.Error("bind serving leaf", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "serving-leaf binding failed")
		return
	}

	evidence, platform, generation, err := s.cfg.Evidence.Evidence(r.Context(), reportData)
	if err != nil {
		s.log.Error("evidence provider failed", "error", err)
		writeErr(w, http.StatusBadGateway, types.ErrorCodeAttestationUnavailable, "could not obtain attestation evidence")
		return
	}

	if err := s.bindConnection(connection, clientKey(r), routing.Binding{RouteDigest: digest, RouterDigest: routerDigest}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeSessionsBusy, err.Error())
		return
	}

	servingLeafHash := sha256.Sum256(servingLeafDER)
	writeJSON(w, http.StatusOK, types.AttestationBundle{
		Version:           types.BindingAttestLB,
		Platform:          platform,
		Generation:        generation,
		Nonce:             nonceB64,
		Evidence:          evidence,
		CDSCertPEM:        string(identity.bundlePEM),
		FrontDoorMode:     s.cfg.FrontDoorMode,
		IdentityProof:     proof,
		ServingLeafSHA256: base64.RawURLEncoding.EncodeToString(servingLeafHash[:]),
		RouteDigest:       hex.EncodeToString(digest[:]),
		MeasuredPolicies:  s.measuredPolicies.Policies(),
	})
}

// routesAdmit refuses an attested handshake while no route manifest is applied
// (A2) or the applied one is stale (F2), each with its own code so a client
// can tell an unconfigured router from one cut off from the CDS. It returns
// the manifest it loaded, whose digest the handshake's evidence binds (E1);
// the handshake loads no other (E2). Later requests in the session route only
// while that manifest is still the applied one.
func (s *Server) routesAdmit(w http.ResponseWriter) (*routing.Applied, bool) {
	applied, err := s.routes.Session()
	switch {
	case errors.Is(err, routing.ErrStale):
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeRoutesStale, "the applied route manifest is stale")
		return nil, false
	case err != nil || applied == nil:
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeRoutesUnavailable, "no route manifest is applied yet")
		return nil, false
	}
	return applied, true
}

// connectionRoom reports whether bindConnection would admit connection for
// client. A handshake without a connection identifier binds nothing.
func (s *Server) connectionRoom(connection, client string) error {
	if connection == "" {
		return nil
	}
	return s.bindings.room(connection, client)
}

// bindConnection binds connection to bound. A handshake that did not come
// through nginx has no connection identifier and binds nothing.
func (s *Server) bindConnection(connection, client string, bound routing.Binding) error {
	if connection == "" {
		s.unboundOnce.Do(func() {
			s.log.Warn("attest-lb handshake without " + routing.ConnectionHeader + ": its connection is not bound; binding needs the nginx relay to set the header")
		})
		return nil
	}
	return s.bindings.bind(connection, client, bound)
}

// routerDigest returns the router digest of identity's leaf, syncing the
// router to it first. While the two differ it refuses the handshake.
func (s *Server) routerDigest(w http.ResponseWriter, identity *meshIdentity) (string, bool) {
	leaf := identity.routerDigest()
	current, err := s.routes.SyncRouterDigest(leaf)
	switch {
	case err != nil:
		s.log.Warn("router credential unreadable; refusing the handshake", "error", err)
	case current != leaf:
		// Clients retry through a renewal; one line each would flood.
		s.log.Debug("router digest differs from the attested mesh leaf's; refusing the handshake")
	default:
		return leaf, true
	}
	writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeBindingUnavailable, "the router's mesh identity is renewing; retry shortly")
	return "", false
}

// meshIdentity loads the mesh credential set from the three files.
func (s *Server) meshIdentity() (*meshIdentity, error) {
	return loadMeshIdentity(s.cfg.MeshIdentityCertFile, s.cfg.MeshIdentityKeyFile, s.cfg.MeshIdentityCAFile)
}

// servingLeafDER reads the LB serving-leaf PEM and returns the whole leaf DER.
// It is read per request so a get-cert renewal (which SIGHUPs nginx to a new
// leaf) is picked up without restarting the sidecar. Exactly one certificate
// is committed; per-SNI or multi-certificate serving is unsupported and fails
// the client's exact-DER comparison closed.
func (s *Server) servingLeafDER() ([]byte, error) {
	if s.cfg.ServingCertFile == "" {
		return nil, fmt.Errorf("no --serving-cert-file configured")
	}
	pemBytes, err := os.ReadFile(s.cfg.ServingCertFile)
	if err != nil {
		return nil, fmt.Errorf("read serving cert: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("serving cert %q is not a PEM certificate", s.cfg.ServingCertFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse serving cert: %w", err)
	}
	return cert.Raw, nil
}

// handleReadyz gates readiness on the committed mesh identity, not the outer
// serving leaf: with --expected-workload set, ready means the whole credential
// the attestation endpoints would serve loads — leaf matching its private key,
// leaf and issuing CA both inside their validity windows, chain to a configured
// mesh CA — *and* that leaf carries a valid matched-workload stamp naming that
// workload. So ingress never routes external traffic to a front door whose
// committed identity is unusable or unnamed (initial deploy, or a post-foreign
// renewal). Absent, malformed, or duplicate stamps fail closed. Without the
// flag, today's always-ready behavior is kept.
//
// nginx proxies this endpoint from the public front door (location = /readyz),
// so the 503 body carries a reason that is not configuration and the specifics
// go to the log.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	code, reason := s.readiness()
	w.WriteHeader(code)
	if reason != "" {
		fmt.Fprintln(w, reason)
	}
}

// readiness answers from a result no older than readyzCacheTTL. Concurrent
// probes collapse onto one computation of it, so the cost of a flood is the
// cost of one check per TTL.
func (s *Server) readiness() (int, string) {
	s.readyzMu.Lock()
	defer s.readyzMu.Unlock()
	if !s.readyzAt.IsZero() && time.Since(s.readyzAt) < readyzCacheTTL {
		return s.readyzCode, s.readyzReason
	}
	s.readyzCode, s.readyzReason = s.computeReadiness()
	s.readyzAt = time.Now()
	return s.readyzCode, s.readyzReason
}

func (s *Server) computeReadiness() (int, string) {
	if s.cfg.ExpectedWorkload == "" {
		return http.StatusOK, ""
	}
	notReady := func(reason string, detail ...any) (int, string) {
		s.log.Warn("readiness gate withholding traffic", append([]any{"reason", reason}, detail...)...)
		return http.StatusServiceUnavailable, reason
	}
	// Exactly the load attest-pq/attest-lb do: reading and parsing the leaf
	// alone would report ready on a credential those endpoints refuse — an
	// expired leaf above all, which is what this gate exists to catch, since
	// stamped leaves carry a short TTL (issuer.MaxNamedLeafTTL).
	identity, err := s.meshIdentity()
	if err != nil {
		return notReady("mesh identity credentials unusable", "error", err)
	}
	workload, err := armtls.MatchedWorkloadFromCert(identity.leaf)
	switch {
	case err != nil:
		return notReady("matched-workload stamp malformed", "error", err)
	case workload == nil:
		return notReady("mesh identity leaf carries no matched-workload stamp")
	case workload.Name != s.cfg.ExpectedWorkload:
		// Both names are this front door's configuration and this body is
		// reachable from the public internet; name them only in the log.
		return notReady("mesh identity leaf is stamped for a different workload",
			"stamped", workload.Name, "expected", s.cfg.ExpectedWorkload)
	}
	return http.StatusOK, ""
}

// refuseSession maps a refused session onto the wire. A colliding id is a
// 128-bit random collision, so it is this server's fault, not the caller's.
func (s *Server) refuseSession(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errSessionInUse):
		s.log.Error("session id collision", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "session id generation failed")
	case errors.Is(err, errStoreFull):
		writeErr(w, http.StatusServiceUnavailable, types.ErrorCodeAttestationUnavailable, err.Error())
	default:
		writeErr(w, http.StatusTooManyRequests, types.ErrorCodeTooManyRequests, err.Error())
	}
}

// handleTunnel terminates the over-encryption: it opens the sealed request
// envelope, forwards the reconstructed request by the applied route manifest,
// and seals the response back to the client.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	// A refusal before the body is read closes the connection, so net/http
	// does not wait on the unread body.
	refuse := func(status int, code, msg string) {
		w.Header().Set("Connection", "close")
		writeErr(w, status, code, msg)
	}
	id := r.Header.Get(sessionHeader)
	session, ok := s.useSession(id)
	if !ok {
		refuse(http.StatusUnauthorized, types.ErrorCodeChannelError, "no over-encryption session")
		return
	}
	channel := session.channel
	if r.ContentLength > tunnelBodyLimit {
		refuse(http.StatusRequestEntityTooLarge, types.ErrorCodeChannelError, "tunnel record exceeds 8 MiB; send a smaller request")
		return
	}
	// Budget goes only to a request naming a live session. Anyone can open
	// one, so the per-client share is what bounds a single client.
	recordBytes := r.ContentLength
	if recordBytes < 0 {
		recordBytes = tunnelBodyLimit
	}
	release, ok := s.routes.Acquire(clientBucket(r), recordBytes)
	if !ok {
		refuse(http.StatusServiceUnavailable, types.ErrorCodeTunnelBusy, "too many tunnelled requests in flight")
		return
	}
	defer release()
	rc := http.NewResponseController(w)
	ioDeadline := func() time.Time { return time.Now().Add(s.cfg.TunnelIOTimeout) }
	if err := errors.Join(rc.SetReadDeadline(ioDeadline()), rc.SetWriteDeadline(ioDeadline())); err != nil {
		s.log.Error("tunnel deadlines unsupported", "error", err)
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "tunnel deadlines unsupported")
		return
	}
	// Runs before release: the budget stays held until the response is on the
	// wire. The write deadline would otherwise outlive this request on a
	// kept-alive connection; net/http resets the read deadline itself.
	defer func() {
		// A failed flush has no one left to tell.
		_ = rc.Flush()
		_ = rc.SetWriteDeadline(time.Time{})
	}()

	// MaxBytesReader, unlike a LimitReader, fails an oversized body and makes
	// net/http close the connection rather than drain the rest with no
	// deadline while the budget is held.
	body := deadlineReader{ReadCloser: r.Body, extend: func() error { return rc.SetReadDeadline(ioDeadline()) }}
	recBytes, err := io.ReadAll(http.MaxBytesReader(w, body, tunnelBodyLimit))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, types.ErrorCodeChannelError, "tunnel record exceeds 8 MiB; send a smaller request")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "read record")
		return
	}
	// The body reached EOF. An expired read deadline would cancel r's context
	// mid-forward.
	_ = rc.SetReadDeadline(time.Time{})
	var rec overenc.Record
	if err := cbor.Unmarshal(recBytes, &rec); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "invalid record")
		return
	}
	plaintext, err := channel.OpenRequest(rec)
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "decrypt failed")
		return
	}

	var env types.TunnelRequest
	if err := cbor.Unmarshal(plaintext, &env); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrorCodeChannelError, "invalid request envelope")
		return
	}
	// The backend trusts this header to name the channel the request arrived
	// on, so a client-supplied value is dropped, never forwarded.
	env.Headers = setHeaderField(env.Headers, routing.ExporterHeader,
		base64.RawURLEncoding.EncodeToString(channel.Exporter()))

	resp, err := s.routes.Forward(r, env, session.bound)
	var changed *routing.BindingChangedError
	if errors.As(err, &changed) {
		// The client attests again rather than ride a session it did not verify.
		s.endSession(id)
		writeErr(w, http.StatusServiceUnavailable, changed.Code, "the router no longer routes by what this session attested; attest again")
		return
	}
	if err != nil {
		s.log.Warn("backend forward failed", "method", env.Method, "path", env.Path, "error", err)
		resp = types.TunnelResponse{Status: http.StatusBadGateway, Body: []byte("backend error")}
	}

	respCBOR, err := cbor.Marshal(resp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "marshal response envelope")
		return
	}
	out, err := channel.SealResponse(respCBOR, rec.Seq)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "seal failed")
		return
	}
	outCBOR, err := cbor.Marshal(out)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrorCodeInternal, "marshal failed")
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Content-Length", strconv.Itoa(len(outCBOR)))
	w.WriteHeader(http.StatusOK)
	for len(outCBOR) > 0 {
		n := min(len(outCBOR), tunnelWriteChunk)
		_ = rc.SetWriteDeadline(ioDeadline())
		// A failed write has no one left to tell.
		if _, err := w.Write(outCBOR[:n]); err != nil || rc.Flush() != nil {
			return
		}
		outCBOR = outCBOR[n:]
	}
}

// deadlineReader calls extend before every Read, so a read deadline it pushes
// forward expires only when no data arrives for its whole window.
type deadlineReader struct {
	io.ReadCloser
	extend func() error
}

func (d deadlineReader) Read(p []byte) (int, error) {
	if err := d.extend(); err != nil {
		return 0, err
	}
	return d.ReadCloser.Read(p)
}

// setHeaderField replaces every field named name (case-insensitively) with one
// field carrying value.
func setHeaderField(fields []types.HeaderField, name, value string) []types.HeaderField {
	kept := fields[:0]
	for _, f := range fields {
		if !strings.EqualFold(f.Name, name) {
			kept = append(kept, f)
		}
	}
	return append(kept, types.HeaderField{Name: name, Value: value})
}

// sweep evicts idle and over-age established sessions and expired attest-lb
// bindings.
func (s *Server) sweep() {
	s.bindings.prune()
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if now.Sub(v.lastUsed) > s.cfg.SessionTTL || now.Sub(v.createdAt) > s.cfg.SessionMaxAge {
			s.dropSession(k)
		}
	}
}

// sessionRoom reports why a session for client may not be admitted.
// handleAttestPQ asks before it mints anything, and addSession decides again
// under the lock that inserts.
func (s *Server) sessionRoom(client string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionsBy.count(client) >= maxSessionsPerClient {
		return errSessionsFull
	}
	if len(s.sessions) >= maxSessions {
		if _, ok := s.sessionsBy.admit(maxSessions, client); !ok {
			return errStoreFull
		}
	}
	return nil
}

// addSession stores an established channel under id. An established session is
// never evicted for a new one; a client at its own bound is refused.
func (s *Server) addSession(client, id string, entry establishedSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.sessions[id]; taken {
		return errSessionInUse
	}
	if s.sessionsBy.count(client) >= maxSessionsPerClient {
		return errSessionsFull
	}
	if len(s.sessions) >= maxSessions {
		over, ok := s.sessionsBy.admit(maxSessions, client)
		if !ok {
			return errStoreFull
		}
		s.dropSession(idlestSessionOf(s.sessions, s.sessionsBy.keys(over)))
	}
	entry.client = client
	s.sessions[id] = entry
	s.sessionsBy.add(client, id)
	return nil
}

// useSession returns the session id names, refreshing its idle deadline. An
// idle-expired or over-age session is dropped and reported as absent: use
// refreshes the idle deadline but never the absolute one, so no amount of
// traffic keeps one key schedule alive past SessionMaxAge.
func (s *Server) useSession(id string) (establishedSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[id]
	if !ok {
		return establishedSession{}, false
	}
	now := time.Now()
	if now.Sub(entry.lastUsed) > s.cfg.SessionTTL || now.Sub(entry.createdAt) > s.cfg.SessionMaxAge {
		s.dropSession(id)
		return establishedSession{}, false
	}
	entry.lastUsed = now
	s.sessions[id] = entry
	return entry, true
}

func (s *Server) endSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropSession(id)
}

func (s *Server) dropSession(id string) {
	entry, ok := s.sessions[id]
	if !ok {
		return
	}
	delete(s.sessions, id)
	s.sessionsBy.remove(entry.client, id)
}

func idlestSessionOf(sessions map[string]establishedSession, held map[string]struct{}) string {
	var chosen string
	var at time.Time
	for id := range held {
		entry, ok := sessions[id]
		if !ok {
			continue
		}
		if at.IsZero() || entry.lastUsed.Before(at) {
			chosen, at = id, entry.lastUsed
		}
	}
	return chosen
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, types.ErrorResponse{Error: code, Message: msg})
}
