// What a CDS serves from: the stores and the mesh CA of a singleton, or the
// ones its cluster's log carries. run picks one backend at startup, so no
// request path asks which kind of CDS it is on.

package cds

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

var _ backend = (*singleton)(nil)

type backend interface {
	Allowlist() *allowlist.Handle
	Secrets() *secrets.Handle
	Bindings() *sandboxledger.Handle
	// MeshCA signs every leaf this CDS issues and is published at /ca.
	MeshCA() meshCA
	// NodeImages are the node images this CDS certifies: the set its measured
	// configuration names, or the set its cluster's log carries.
	NodeImages() armtls.PinSource
	Challenges() (issuance, secrets attestation.Challenges)
	// TokenFloor refuses operator tokens issued before it; the zero time refuses none.
	TokenFloor() time.Time
	Ready() bool
	// ClusterRoutes are answered without a client certificate, by method and path.
	ClusterRoutes() map[string]http.HandlerFunc
	// Gate refuses every other route while this CDS may not answer.
	Gate(next http.Handler) http.Handler
	KeepMeshCA(ctx context.Context, peers *armtls.CertManager)
	// Stop runs before the stores close.
	Stop()
}

// meshCA is the CA a CDS issues under. A replica holds none while it may not
// issue, so a caller reads the second answer before the first.
type meshCA interface {
	Current() (issuer.CurrentCA, bool)
}

// ownCA is the mesh CA a singleton mints at its start.
type ownCA struct {
	*issuer.MeshCA
}

func (o ownCA) Current() (issuer.CurrentCA, bool) {
	return o.MeshCA.Current(), true
}

// newBackend picks what this CDS serves from; the configuration's ha block is
// the whole decision.
func newBackend(ctx context.Context, cfg config, st stores) (backend, error) {
	if cfg.measured.HA == nil {
		return newSingleton(cfg, st)
	}
	return newReplica(ctx, cfg, st)
}

// A replica's log writes all three stores, so they exist before it joins its
// cluster.
type stores struct {
	allowlist *allowlist.Store
	secrets   *secrets.MemoryStore
	bindings  *sandboxledger.Ledger
}

// openStores opens the secret store and the sandbox ledger whether or not
// /secrets is served, because a replica receives both from its cluster.
func openStores(cfg config) (stores, error) {
	db, err := allowlist.OpenStore(cfg.allowlistDB)
	if err != nil {
		return stores{}, fmt.Errorf("open allowlist database: %w", err)
	}
	return stores{
		allowlist: db,
		secrets:   newSecretsStore(cfg),
		// Written on every issuance, not only when secrets are on, so turning
		// them on later does not fail closed on an empty ledger.
		bindings: sandboxledger.New(issuer.CapTTL(cfg.certTTL, issuer.MaxLeafTTL), cfg.sandboxLedgerMax),
	}, nil
}

func (s stores) close() {
	if err := s.allowlist.Close(); err != nil {
		slog.Error("close the allowlist database", "error", err)
	}
}

// handles are the stores as their writers hold them.
type handles struct {
	allowlist *allowlist.Handle
	secrets   *secrets.Handle
	bindings  *sandboxledger.Handle
}

func (h handles) Allowlist() *allowlist.Handle {
	return h.allowlist
}

func (h handles) Secrets() *secrets.Handle {
	return h.secrets
}

func (h handles) Bindings() *sandboxledger.Handle {
	return h.bindings
}

type challengePools struct {
	issuance attestation.Challenges
	secrets  attestation.Challenges
}

func (p challengePools) Challenges() (attestation.Challenges, attestation.Challenges) {
	return p.issuance, p.secrets
}

// singleton is a CDS serving its cluster on its own: the stores are its own,
// and it mints a mesh CA at every start.
type singleton struct {
	handles
	challengePools
	mesh  *issuer.MeshCA
	nodes armtls.PinSource
	// started is the floor an operator token must be issued after: a store that
	// does not persist forgets the tokens the last process spent.
	started time.Time
}

func newSingleton(cfg config, st stores) (backend, error) {
	// The mesh CA is generated in process; the private key never leaves it.
	mesh, err := issuer.NewMeshCA(cfg.caCommonName, cfg.caCertValidity)
	if err != nil {
		return nil, fmt.Errorf("generate mesh CA: %w", err)
	}
	only := &singleton{
		handles: handles{
			allowlist: st.allowlist.Local(),
			secrets:   st.secrets.Local(),
			bindings:  st.bindings.Local(),
		},
		challengePools: challengePools{
			issuance: attestation.NewLocalChallenges(cfg.challengeTTL),
			secrets:  attestation.NewLocalChallenges(cfg.challengeTTL),
		},
		mesh:  mesh,
		nodes: armtls.FixedPins(cfg.measured.Nodes),
	}
	if !cfg.allowlistPersistent {
		only.started = time.Now()
		slog.Warn("allowlist store is not persistent: a restart resets the served allowlist to the configured workloads and regenerates the mesh CA. Operator-added digests, the allowlist history, spent operator tokens and the route manifest do not survive")
	}
	return only, nil
}

func (s *singleton) MeshCA() meshCA {
	return ownCA{s.mesh}
}

// NodeImages are the node images the configuration this CDS boots names.
func (s *singleton) NodeImages() armtls.PinSource {
	return s.nodes
}

func (s *singleton) TokenFloor() time.Time {
	return s.started
}

func (s *singleton) Ready() bool {
	return true
}

func (s *singleton) ClusterRoutes() map[string]http.HandlerFunc {
	return nil
}

func (s *singleton) Gate(next http.Handler) http.Handler {
	return next
}

func (s *singleton) KeepMeshCA(ctx context.Context, peers *armtls.CertManager) {
	renewMeshCAWhenDue(ctx, s.mesh, caRenewalCheckInterval, peers)
}

func (s *singleton) Stop() {}
