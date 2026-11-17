package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	etcdyaml "go.etcd.io/etcd/client/v3/yaml"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/pendingattestation"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/cdspin"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// haConfig is a replica's flags: none of it is measured, and a wrong value
// costs availability, not safety.
type haConfig struct {
	self         string
	runtimeDir   string
	storeEtcd    string
	storeMemory  bool
	gossip       time.Duration
	peerTimeout  time.Duration
	storeTimeout time.Duration
	warnEntries  int
	warnBytes    int64
}

// startHA builds this replica of the configured set over the CDS's mesh CA,
// allowlist store and serving certificate, and starts its gossip.
func startHA(ctx context.Context, cfg config, mesh *issuer.MeshCA, store *allowlist.Store, serving *tls.Config, meshPeers *armtls.CertManager, nodes *chainNodes) (*cdsha.Replica, error) {
	endpoints := cfg.measured.HA.Endpoints
	self := cfg.ha.self
	slot := slices.Index(endpoints, self)
	switch {
	case self == "" && len(endpoints) == 1:
		slot = 0
	case self == "":
		slot = -1 // the replica asks the endpoints which one it is
	case slot < 0:
		return nil, fmt.Errorf("--ha-self %q is not one of the configured endpoints %v", self, endpoints)
	}
	chainStore, err := openChainStore(ctx, cfg, len(endpoints))
	if err != nil {
		return nil, err
	}
	policy := chainPolicyServer(store, cfg.measured.Workloads)
	replica, err := cdsha.New(cdsha.Config{
		Attested: func(pins armtls.Pins) (*http.Client, error) {
			return armtls.NewVerifyingHTTPClient(pins, cfg.attestationApiURL)
		},
		Cluster:   cfg.measured.ClusterID,
		Endpoints: endpoints,
		Gossip:    cfg.ha.gossip,
		Mesh:      mesh,
		OnState: func(s *cdschain.State) error {
			meshPeers.UpdateClientCA(mesh.Current().CA.Cert)
			if err := policy(s); err != nil {
				return fmt.Errorf("serving the chain's allowlist (version %s): %w", s.CurrentPolicyVersion(), err)
			}
			if err := nodes.serve(s.Nodes); err != nil {
				return fmt.Errorf("certifying the chain's node images: %w", err)
			}
			if err := serveRoutes(store, s); err != nil {
				return fmt.Errorf("serving the chain's route manifest: %w", err)
			}
			return nil
		},
		OperatorKeys: cfg.measured.OperatorKeys.Keys(),
		// Gossip is authenticated by member signatures, not by the channel.
		Peer:        &http.Client{Transport: &http.Transport{TLSClientConfig: pendingattestation.TLSConfig("")}},
		PeerTimeout: cfg.ha.peerTimeout,
		Self:        slot,
		SelfCheck: func(_ context.Context, measurements string) (bool, error) {
			return ownBuildPasses(serving, measurements, cfg.attestationApiURL)
		},
		StoreTimeout: cfg.ha.storeTimeout,
		Validate:     func(b cdschain.Body) error { return validateEntry(b, cfg.measured.PodImages, mesh, store) },
		WarnBytes:    cfg.ha.warnBytes,
		WarnEntries:  cfg.ha.warnEntries,
	}, chainStore)
	if err != nil {
		return nil, err
	}
	go replica.Run(ctx)
	return replica, nil
}

// validateHAConfig holds the replica flags to values a replica can run with,
// and refuses them on a CDS whose configuration has no ha block.
func validateHAConfig(cfg config) error {
	ha := cfg.ha
	if cfg.measured.HA == nil {
		if ha.self != "" || ha.storeEtcd != "" || ha.storeMemory {
			return errors.New("--ha-self, --ha-store-etcd and --ha-store-memory serve a replica set, and the configuration has no ha block")
		}
		return nil
	}
	switch {
	case ha.gossip/2 <= 0:
		return fmt.Errorf("--ha-gossip-interval (%v) must be positive", ha.gossip)
	case ha.peerTimeout <= 0 || ha.peerTimeout > ha.gossip:
		return fmt.Errorf("--ha-peer-timeout (%v) must be positive and at most --ha-gossip-interval (%v)", ha.peerTimeout, ha.gossip)
	case ha.storeTimeout <= 0:
		return fmt.Errorf("--ha-store-timeout (%v) must be positive", ha.storeTimeout)
	}
	return nil
}

func openChainStore(ctx context.Context, cfg config, replicas int) (cdsha.Store, error) {
	if onDisk := filepath.Join(cfg.ha.runtimeDir, "etcd.yaml"); cfg.ha.storeEtcd == "" && cfg.ha.runtimeDir != "" {
		if _, err := os.Stat(onDisk); err == nil {
			cfg.ha.storeEtcd = onDisk
		}
	}
	switch {
	case cfg.ha.storeEtcd != "":
		etcdCfg, err := etcdyaml.NewConfig(cfg.ha.storeEtcd)
		if err != nil {
			return nil, fmt.Errorf("--ha-store-etcd: %w", err)
		}
		etcdCfg.Context = ctx
		return cdsha.OpenEtcd(*etcdCfg, cfg.measured.ClusterID)
	case cfg.ha.storeMemory && replicas == 1:
		slog.Warn("CDS chain store is in memory: the chain dies with this replica")
		return cdsha.NewMemory(), nil
	case cfg.ha.storeMemory:
		return nil, errors.New("--ha-store-memory serves a single replica")
	}
	slog.Warn("CDS chain store waits for its credential (c8s cds ha store-credential)")
	return nil, nil
}

// chainPolicyServer serves each state's allowlist once (servePolicy). Nodes
// get nothing until the first one is served: before it, the store holds only
// what the replica started with.
func chainPolicyServer(store *allowlist.Store, seed *pkgallowlist.Allowlist) func(*cdschain.State) error {
	store.HoldNodes()
	served := ""
	return func(s *cdschain.State) error {
		v := s.CurrentPolicyVersion()
		if v == served {
			return nil
		}
		if err := servePolicy(store, s, seed, served == ""); err != nil {
			return err
		}
		served = v
		return nil
	}
}

// servePolicy serves the chain's allowlist, or seed before a policy entry, at
// the version every replica gives it. The first one a replica serves is
// written now, so nodes get it once the node delay has passed (a restart adds
// the delay, never skips it), and nothing older: until then they are told to
// ask again (allowlist.ErrNotYetInEffect).
func servePolicy(store *allowlist.Store, s *cdschain.State, seed *pkgallowlist.Allowlist, first bool) error {
	doc := seed
	if s.Policy != nil {
		var err error
		if doc, err = pkgallowlist.ParseJSON(s.Policy); err != nil {
			return err
		}
	}
	if err := store.ReplaceAll(doc, allowlist.OperatorWrite{SetVersion: s.CurrentPolicyVersion()}); err != nil {
		return err
	}
	if first {
		return store.FloorNodesAtHead()
	}
	return nil
}

// chainNodes certifies the node images of the chain's nodes entry, the
// launch file's while the chain holds none, and on a change retires the
// inventory connections made under the images it certified before.
type chainNodes struct {
	set    *nodeSet
	launch refvalues.ReferenceValues
	pods   []remote.ImagePin
	retire func()
	served string
}

// serve makes measurements, a state's nodes entry ("" for none), the set
// this CDS certifies, when it changed.
func (c *chainNodes) serve(measurements string) error {
	if measurements == c.served {
		return nil
	}
	values, err := c.values(measurements)
	if err != nil {
		return err
	}
	if err := c.set.set(values); err != nil {
		return err
	}
	c.served = measurements
	c.retire()
	return nil
}

// values is the set measurements names. A set that names a Pod launch key
// as a node authority certifies no node, on every replica alike.
func (c *chainNodes) values(measurements string) (refvalues.ReferenceValues, error) {
	if measurements == "" {
		return c.launch, nil
	}
	values, err := refvalues.Parse([]byte(measurements))
	if err != nil {
		return values, err
	}
	if err := cdsconfig.ValidatePodNodeAuthorities(c.pods, values.Images); err != nil {
		slog.Error("CDS replica certifies no node: the chain's node images name a Pod launch key", "error", err)
		return refvalues.ReferenceValues{Family: values.Family}, nil
	}
	slog.Info("CDS certifies the chain's node images", "images", len(values.Images))
	return values, nil
}

// validateEntry checks an entry's payload beyond the chain's own rules
// before any replica takes it.
func validateEntry(b cdschain.Body, pods []remote.ImagePin, mesh *issuer.MeshCA, store *allowlist.Store) error {
	if err := validatePodAuthorities(b, pods); err != nil {
		return err
	}
	return validateRoutes(b, mesh, store)
}

// validatePodAuthorities refuses a nodes or operator-keys entry naming a Pod
// launch key of the launch file as a node or operator authority.
func validatePodAuthorities(b cdschain.Body, pods []remote.ImagePin) error {
	switch b.Type {
	case cdschain.TypeNodes:
		var p cdschain.Nodes
		if err := cdschain.DecodeStrict(b.Payload, &p); err != nil {
			return err
		}
		values, err := refvalues.Parse([]byte(p.Nodes))
		if err != nil {
			return err
		}
		return cdsconfig.ValidatePodNodeAuthorities(pods, values.Images)
	case cdschain.TypeOperatorKeys:
		var p cdschain.OperatorKeys
		if err := cdschain.DecodeStrict(b.Payload, &p); err != nil {
			return err
		}
		keys, err := operatorauth.ParsePublicKeysPEM([]byte(p.Keys))
		if err != nil {
			return err
		}
		return cdsconfig.ValidatePodOperatorAuthorities(pods, keys)
	}
	return nil
}

// serveRoutes serves the chain's route manifest, none before a routes entry:
// a resolve that drops a routes entry moves the manifest back. Routers keep
// the highest revision they took until an operator publishes one above it.
func serveRoutes(store *allowlist.Store, s *cdschain.State) error {
	if s.Routes == nil {
		warnRoutesBelowFloor(store, 0)
		return store.SetRoutes(nil)
	}
	m, err := routes.Parse(s.Routes.Manifest)
	if err != nil {
		return err
	}
	warnRoutesBelowFloor(store, m.Revision)
	return store.SetRoutes(&routes.Envelope{Manifest: s.Routes.Manifest, Token: s.Routes.Token})
}

func warnRoutesBelowFloor(store *allowlist.Store, revision uint64) {
	if floor := store.RoutesFloor(); revision < floor {
		slog.Error("CDS route manifest moved back below a revision routers took; publish a routes entry above it", "revision", revision, "routers", floor)
	}
}

// validateRoutes holds a routes entry to what PUT /routes checks.
func validateRoutes(b cdschain.Body, mesh *issuer.MeshCA, store *allowlist.Store) error {
	if b.Type != cdschain.TypeRoutes {
		return nil
	}
	var p cdschain.Routes
	if err := cdschain.DecodeStrict(b.Payload, &p); err != nil {
		return err
	}
	m, err := routes.Parse(p.Manifest)
	if err != nil {
		return err
	}
	if err := m.CheckAnchorsExclude([]*x509.Certificate{mesh.Current().CA.Cert}); err != nil {
		return err
	}
	// Not just above the stored manifest: a router keeps the highest one
	// served, also after a resolve moved the stored one back.
	if m.Revision <= store.RoutesFloor() {
		return allowlist.ErrRevisionNotGreater
	}
	return nil
}

// ownBuildPasses holds this replica's own serving certificate to one build's
// pins. A verifier that does not answer is an error, not a verdict.
func ownBuildPasses(serving *tls.Config, measurements, attestationAPI string) (bool, error) {
	values, err := refvalues.Parse([]byte(measurements))
	if err != nil {
		return false, nil
	}
	cert, err := serving.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		return false, err
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return false, err
		}
	}
	_, err = armtls.VerifyCert(leaf, armtls.Pins(values.Policy()).VerifyPolicy(attestationAPI), nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, armtls.ErrPolicyViolation):
		return false, nil
	}
	return false, err
}

// haAuthorizer checks an HA operator request under the keys the replica
// names, with the single-use token rule of every other operator write.
func haAuthorizer(store *allowlist.Store, started time.Time, skew time.Duration) cdsha.Authorizer {
	return func(r *http.Request, body []byte, keys []*ecdsa.PublicKey) error {
		v := operatorauth.Verifier{Keys: keys, ClockSkew: skew}
		return singleUse(v.AuthorizeIssuedAt, store, started, skew)(r, body)
	}
}

// haGate serves a replica's CDS routes only while it serves. A
// replica set takes allowlist and routes writes as chain entries, never
// through the old PUT routes; a single replica's PUT /secrets stays. An
// allowlist document by digest is served whatever the replica's state: the
// client checks the bytes against the digest it asked for.
const objectsPath = "/allowlist/objects/sha256/"

func haGate(replica *cdsha.Replica) func(http.Handler) http.Handler {
	open := []string{"/healthz", "/readyz", "/metrics", "/ca", "/operator-keys", "/measurements"}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id := replica.Identity(r.Header.Get(cdspin.Header)); id != "" {
				w.Header().Set(cdspin.Header, id)
			}
			switch {
			case strings.HasPrefix(r.URL.Path, "/ha/") || slices.Contains(open, r.URL.Path):
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, objectsPath):
			case r.Method == http.MethodPut && (r.URL.Path == "/allowlist" || r.URL.Path == routes.Path):
				http.Error(w, "a CDS replica set takes writes as chain entries (c8s cds ha, POST "+cdsha.EntriesPath+")", http.StatusConflict)
				return
			default:
				if _, err := replica.Current(r.Context()); err != nil {
					http.Error(w, err.Error(), http.StatusServiceUnavailable)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// haServing is AttestHandler.Serving for a replica.
func haServing(replica *cdsha.Replica) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := replica.Current(ctx)
		return err
	}
}

// haLedger is the sandbox ledger issuance records into: none for a replica
// set of more than one replica, whose replicas could not share it.
func haLedger(ha *cdsconfig.HA, ledger *sandboxledger.Ledger) sandboxBinder {
	if ha != nil && len(ha.Endpoints) > 1 {
		return nil
	}
	return ledger
}

// haSecrets is secretsEnabled, refused for a replica set of more than one
// replica: secrets and the sandbox ledger wait for a broker a set can
// share.
func haSecrets(ha *cdsconfig.HA, images []remote.ImagePin, hosts workloadclaims.CIDRHosts) (bool, string) {
	if ha != nil && len(ha.Endpoints) > 1 {
		return false, "a CDS replica set of more than one replica holds no secrets"
	}
	return secretsEnabled(images, hosts)
}
