package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// allowPlainHTTP is true only in c8s_dev builds (plainhttp_dev.go), where CDS
// may run without armTLS so HA can be exercised without a TEE.
var allowPlainHTTP = false

// haConfig enables HA CDS (internal/cdsha). Empty clusterID keeps the
// singleton: a fresh in-memory mesh CA per start.
type haConfig struct {
	yieldFile      string // baked singleton: exit when the launch document selects HA
	configFile     string // baked nodes: cds-ha.json from the signed launch document
	clusterID      string
	decreeNS       string
	peersDNS       string
	peers          []string // static peer list, instead of DNS
	advertiseIP    string
	port           int
	nodeName       string
	attestor       string
	measurement    string
	pins           []string
	operatorKey    string
	operatorKeyPEM []byte // set from --ha-config instead of a file
	recoveryKeyPEM []byte // from --ha-config or --ha-recovery-key: backups are sealed to it
	seats          int
	maxNonVoters   int
	tdxTCB         []string
	timing         cdsha.Timing
}

func bindHAFlags(flags *pflag.FlagSet, c *haConfig) {
	flags.StringVar(&c.yieldFile, "ha-yield-file", "", "baked singleton: path of the node's public cds-mode file; when it says \"ha\" (the signed launch document declares cdsHA), this singleton exits so the HA replicas on cds-role nodes are the only CDS")
	flags.StringVar(&c.configFile, "ha-config", "", "baked nodes: path of cds-ha.json published from the signed launch document (cluster id, decree key, seats, image pins); it overrides --ha-cluster-id, --ha-operator-key, --ha-replica-pins and --ha-seats, so none of those trust roots is a pod flag")
	flags.StringVar(&c.clusterID, "ha-cluster-id", "", "enable CDS high availability for this cluster id (dev/test; baked nodes use --ha-config); replicas with the same id form one Raft group and share one mesh CA (empty = singleton CDS)")
	flags.StringVar(&c.decreeNS, "ha-decree-namespace", os.Getenv("POD_NAMESPACE"), "namespace where operators write CDS decree objects (on a locked node image the CDS namespace is privileged, so use one the operator credential can write)")
	flags.StringVar(&c.peersDNS, "ha-peers-dns", "", "headless Service DNS name resolving to every CDS replica")
	flags.StringSliceVar(&c.peers, "ha-peers", nil, "static ip:port list of the other replicas' peer ports, instead of --ha-peers-dns")
	flags.StringVar(&c.advertiseIP, "ha-advertise-ip", os.Getenv("POD_IP"), "address the other replicas reach this one at (default $POD_IP)")
	flags.IntVar(&c.port, "ha-port", 9443, "port of the replica-to-replica channel (mutually attested TLS; Raft and control)")
	flags.StringVar(&c.nodeName, "ha-node-name", os.Getenv("NODE_NAME"), "the node this replica runs on: one voter seat per node, and a Genesis decree names its bootstrap node")
	flags.StringVar(&c.attestor, "ha-attestor", "node", "peer attestor: node (the node attestation-api at --attestation-api-url; TDX and SEV-SNP), tdx (DCAP quotes read in-process, inside a TD), or mock in c8s_dev builds")
	flags.StringSliceVar(&c.tdxTCB, "ha-tdx-tcb-statuses", cdsha.DefaultTDXTCBStatuses, "Intel TCB statuses a peer platform may report (PCS spelling, e.g. UpToDate,SWHardeningNeeded,OutOfDate)")
	flags.StringVar(&c.measurement, "ha-measurement", "", "this replica's measurement as reported by the mock attestor")
	flags.StringSliceVar(&c.pins, "ha-replica-pins", nil, "replica measurement pins; the Genesis replica makes them the cluster's first pin set")
	flags.StringVar(&c.operatorKey, "ha-operator-key", "", "PEM P-256 public key authorizing HA decrees, including Genesis (REQUIRED with --ha-cluster-id)")
	flags.Func("ha-recovery-key", "PEM P-256 public key the leader seals state backups to (dev/test; baked nodes take it from --ha-config). Without one there is no recovery from the loss of every replica", func(p string) error {
		raw, err := os.ReadFile(p)
		c.recoveryKeyPEM = raw
		return err
	})
	flags.IntVar(&c.seats, "ha-seats", 3, "number of voting replicas; further replicas are non-voters that serve and take a seat when one frees up")
	flags.IntVar(&c.maxNonVoters, "ha-max-non-voters", 16, "most non-voting replicas the leader admits")
	flags.DurationVar(&c.timing.Heartbeat, "ha-heartbeat", cdsha.DefaultTiming.Heartbeat, "Raft heartbeat timeout")
	flags.DurationVar(&c.timing.Election, "ha-election", cdsha.DefaultTiming.Election, "Raft election timeout")
	flags.DurationVar(&c.timing.Lease, "ha-lease", cdsha.DefaultTiming.Lease, "a follower stops issuing and releasing this long after it last heard from the leader")
	flags.DurationVar(&c.timing.DeadAfter, "ha-dead-after", cdsha.DefaultTiming.DeadAfter, "the leader removes a member that failed heartbeats this long")
	flags.DurationVar(&c.timing.Stabilize, "ha-stabilize", cdsha.DefaultTiming.Stabilize, "a non-voter must be healthy this long before it takes a seat")
	flags.DurationVar(&c.timing.Apply, "ha-apply-timeout", cdsha.DefaultTiming.Apply, "bound on one replicated write")
	flags.DurationVar(&c.timing.Backup, "ha-backup-interval", cdsha.DefaultTiming.Backup, "the leader seals and stores a backup of changed state at most this often")
	flags.DurationVar(&c.timing.Tick, "ha-tick", cdsha.DefaultTiming.Tick, "membership and decree loop period")
}

// haStores are the local stores a replica's Raft log applies to.
type haStores struct {
	allowlist *allowlist.Store
	secrets   *secrets.MemoryStore
	ledger    *sandboxledger.Ledger
}

// haStart builds this replica, makes it the replicator of every store, and
// returns once it serves the cluster's mesh CA. A nil node means singleton.
func haStart(ctx context.Context, cfg config, st haStores, preJoin func(*cdsha.Node) (stop func())) (*cdsha.Node, error) {
	if cfg.ha.yieldFile != "" {
		if err := yieldIfHA(cfg.ha.yieldFile); err != nil {
			return nil, err
		}
	}
	if cfg.ha.configFile != "" {
		if err := loadHAConfigFile(&cfg.ha); err != nil {
			return nil, err
		}
	}
	if cfg.ha.clusterID == "" {
		return nil, nil
	}
	node, err := newHANode(cfg, st)
	if err != nil {
		return nil, err
	}
	if err := resetHAAllowlist(st.allowlist); err != nil {
		return nil, err
	}
	st.allowlist.SetReplicator(node)
	st.ledger.SetReplicator(node)
	if err := node.Start(); err != nil {
		return nil, err
	}
	errc := make(chan error, 1)
	go func() {
		err := node.Run(ctx)
		errc <- err
		if err != nil && ctx.Err() == nil {
			// After startup nobody reads errc: a dead replica must not
			// leave CDS serving state it no longer tracks.
			slog.Error("cds-ha replica stopped; exiting", "err", err)
			os.Exit(1)
		}
	}()
	slog.Info("cds-ha: replica starting", "build", "v4-rollout-image-b")
	slog.Info("cds-ha: waiting to join the cluster", "cluster_id", cfg.ha.clusterID, "id", node.ID())
	if preJoin != nil {
		// Until it joins, the replica serves only health, status and the
		// operator's restore of a backup, on the CDS port.
		defer preJoin(node)()
	}
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for !node.Serving() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-errc:
			return nil, fmt.Errorf("cds-ha replica: %w", err)
		case <-t.C:
		}
	}
	slog.Info("cds-ha: serving", "status", node.Status())
	return node, nil
}

// resetHAAllowlist empties the allowlist database before the replica joins.
// Its replicated state comes only from the Raft log and snapshots: rows an
// earlier process left in a reused file (a container restart keeps the pod's
// volume) would have the log applied on top of them, and the replica's
// version, ETag and history would differ from every other replica's.
func resetHAAllowlist(s *allowlist.Store) error {
	fresh, err := allowlist.OpenInMemory()
	if err != nil {
		return err
	}
	defer fresh.Close()
	empty, err := fresh.Dump()
	if err != nil {
		return err
	}
	if err := s.Restore(empty); err != nil {
		return fmt.Errorf("reset the allowlist store for HA: %w", err)
	}
	return nil
}

func newHANode(cfg config, st haStores) (*cdsha.Node, error) {
	h := cfg.ha
	if (h.peersDNS == "" && len(h.peers) == 0) || h.decreeNS == "" || h.nodeName == "" {
		return nil, errors.New("--ha-peers-dns (or --ha-peers), --ha-decree-namespace and --ha-node-name are required with --ha-cluster-id")
	}
	att, err := newHAAttestor(h.attestor, cdsha.AttestorOptions{
		MockMeasurement:   h.measurement,
		TDXTCBStatuses:    h.tdxTCB,
		AttestationAPIURL: cfg.attestationApiURL, // the node's attestation-api, as every CDS path uses
		Timeout:           cfg.requestTimeout,
	})
	if err != nil {
		return nil, err
	}
	opKey, err := loadHAOperatorKey(h.operatorKey, h.operatorKeyPEM)
	if err != nil {
		return nil, err
	}
	// In-cluster credentials only, as for the node inventory: a pod-chosen
	// kubeconfig could load an exec credential plugin.
	kube, err := newInClusterKubeClientset()
	if err != nil {
		return nil, err
	}
	podIP := h.advertiseIP
	if podIP == "" {
		return nil, errors.New("--ha-advertise-ip (default $POD_IP) is required in HA mode: replicas advertise it to each other")
	}
	peers := dnsPeers(h.peersDNS, podIP, h.port)
	if len(h.peers) > 0 {
		static := h.peers
		peers = func(context.Context) ([]string, error) { return static, nil }
	}
	var recovery []byte
	if len(h.recoveryKeyPEM) > 0 {
		block, _ := pem.Decode(h.recoveryKeyPEM)
		if block == nil {
			return nil, errors.New("recovery key: no PEM block")
		}
		recovery = block.Bytes
	}
	decrees := cdsha.KubeDecrees{Client: kube, Namespace: h.decreeNS, ClusterID: h.clusterID}
	return cdsha.NewNode(cdsha.Config{
		ClusterID:       h.clusterID,
		NodeName:        h.nodeName,
		Bind:            net.JoinHostPort(cfg.host, strconv.Itoa(h.port)),
		Advertise:       net.JoinHostPort(podIP, strconv.Itoa(h.port)),
		Attestor:        att,
		BakedPins:       h.pins,
		OperatorPubKey:  opKey,
		Seats:           h.seats,
		MaxNonVoters:    h.maxNonVoters,
		Peers:           peers,
		Decrees:         decrees,
		RecoveryKey:     recovery,
		Backups:         decrees,
		Timing:          h.timing,
		CACommonName:    cfg.caCommonName,
		CAValidity:      cfg.caCertValidity,
		Allowlist:       st.allowlist,
		Secrets:         st.secrets,
		Ledger:          st.ledger,
		Logger:          slog.Default(),
		HistoryVersions: cfg.allowlistHistoryVersions,
	})
}

// devHARoutes adds the integration test's routes in c8s_dev builds
// (devha_dev.go); in every other build it returns the router unchanged.
var devHARoutes = func(next http.Handler, _ secrets.Store, _ *secrets.MemoryStore, _ allowlist.WriteAuthorizer, _ bool) http.Handler {
	return next
}

// newHAAttestor resolves the peer attestor; tests replace it.
var newHAAttestor = cdsha.NewAttestor

// errYield is returned by the baked singleton when the launch document selects HA.
var errYield = errors.New("this cluster runs CDS as HA replicas on cds-role nodes (launch document cdsHA); the singleton yields")

// yieldIfHA makes the singleton Deployment, which the baked image always
// carries, step aside on an HA cluster: two CDS flavours would be two trust
// roots. node-services writes cds-mode from the verified launch document;
// an unreadable or unknown value fails closed (no CDS rather than two).
func yieldIfHA(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("--ha-yield-file: %w", err)
	}
	switch strings.TrimSpace(string(raw)) {
	case nodeservices.CDSModeSingleton:
		return nil
	case nodeservices.CDSModeHA:
		return errYield
	}
	return fmt.Errorf("--ha-yield-file: unknown CDS mode %q", strings.TrimSpace(string(raw)))
}

// loadHAConfigFile takes the HA trust roots from cds-ha.json, which
// node-services publishes from the signed, measured launch document.
func loadHAConfigFile(h *haConfig) error {
	// The launch document is the only source of trust roots: refuse flags
	// that would add to or replace them.
	if h.clusterID != "" || len(h.pins) > 0 || h.operatorKey != "" || h.measurement != "" {
		return errors.New("--ha-config excludes --ha-cluster-id, --ha-replica-pins, --ha-operator-key and --ha-measurement")
	}
	raw, err := os.ReadFile(h.configFile)
	if err != nil {
		return fmt.Errorf("--ha-config: %w", err)
	}
	var c nodeservices.CDSHAConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("--ha-config: %w", err)
	}
	pin, err := cdsha.ImagePin(c.Image.Platform, c.Image.Measurement, c.Image.RTMRs)
	if err != nil {
		return fmt.Errorf("--ha-config image: %w", err)
	}
	h.clusterID, h.pins = c.ClusterID, []string{pin}
	h.operatorKeyPEM = []byte(c.DecreeKey)
	h.recoveryKeyPEM = []byte(c.RecoveryKey)
	if c.Replicas > 0 {
		h.seats = c.Replicas
	}
	return nil
}

// dnsPeers resolves the headless Service on every call, dropping self.
func dnsPeers(name, selfIP string, port int) func(context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		ips, err := net.DefaultResolver.LookupHost(ctx, name)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, ip := range ips {
			if ip != selfIP {
				out = append(out, net.JoinHostPort(ip, strconv.Itoa(port)))
			}
		}
		return out, nil
	}
}

func loadHAOperatorKey(path string, raw []byte) ([]byte, error) {
	if path == "" && len(raw) == 0 {
		return nil, errors.New("--ha-operator-key is required: genesis and every change are operator decrees")
	}
	if path != "" {
		var err error
		if raw, err = os.ReadFile(path); err != nil {
			return nil, fmt.Errorf("--ha-operator-key: %w", err)
		}
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("--ha-operator-key: no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("--ha-operator-key: %w", err)
	}
	if k, ok := pub.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		return nil, errors.New("--ha-operator-key: want an ECDSA P-256 public key")
	}
	return block.Bytes, nil
}

// followMeshCA makes client-certificate verification (the /secrets leaf
// check) use the replica's current mesh CA at each handshake, so a rotation
// immediately stops trusting leaves of the old key. While the replica
// cannot serve, no client certificate verifies.
func followMeshCA(base *tls.Config, current func() (*issuer.CA, error)) *tls.Config {
	base = base.Clone()
	out := base.Clone()
	out.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.ClientCAs = x509.NewCertPool()
		if ca, err := current(); err == nil {
			c.ClientCAs.AddCert(ca.Cert)
		}
		return c, nil
	}
	return out
}

// haGate answers 503 on every route but liveness, metrics and /ha/status
// while the replica is not serving: an isolated or stale replica must not
// issue, release, or hand out policy it may no longer hold.
func haGate(serving func() bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics", "/ha/status", "/ha/pins":
		default:
			if !serving() {
				http.Error(w, "cds-ha: this replica is not serving (not joined, not pinned, or out of contact with the cluster)", http.StatusServiceUnavailable)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// haStatus serves the replica's view for the CLI. It is untrusted output.
func haStatus(node *cdsha.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(node.Status())
	}
}

// haPins serves the signed decree behind the current CDS pin set. It is
// public: clients that no longer recognise a replica's image fetch it before
// they can trust any replica, and check the operator's signature themselves.
func haPins(node *cdsha.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		sd := node.PinsDecree()
		if sd == nil {
			http.Error(w, "cds-ha: the pin set came from Genesis; the launch document's is current", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sd)
	}
}

// haDecrees serves the record of applied decrees: every operator decision
// as the operator signed it, read over the attested channel from a serving
// replica (the decree objects in Kubernetes are only the host's word).
func haDecrees(node *cdsha.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(node.Decrees())
	}
}

// haCACertPEM serves the current mesh CA certificate.
func haCACertPEM(node *cdsha.Node) func() []byte {
	return func() []byte {
		ca, err := node.CA()
		if err != nil {
			return nil
		}
		return certutil.EncodeCertPEM(ca.Cert.Raw)
	}
}

// haChallengeKey derives a per-purpose challenge MAC key from the current
// mesh CA private key, so any replica can redeem a challenge another issued;
// nil while the replica cannot serve. A rotation invalidates outstanding ones.
func haChallengeKey(node *cdsha.Node, purpose string) func() []byte {
	return func() []byte {
		ca, err := node.CA()
		if err != nil {
			return nil
		}
		secret, err := ca.Key.Bytes()
		if err != nil {
			return nil
		}
		key, err := hkdf.Key(sha256.New, secret, nil, "c8s-cds-ha-challenge-v1/"+purpose, 32)
		if err != nil {
			return nil
		}
		return key
	}
}

// RestoreRequest is POST /ha/restore: an operator Restore decree and the
// snapshot it names, decrypted by the operator from a sealed backup. It
// travels only over the attested channel to a replica that holds no cluster.
type RestoreRequest struct {
	Decree   cdsha.SignedDecree `json:"decree"`
	Snapshot []byte             `json:"snapshot"`
}

// handleRestore restores a backup into this replica. The decree, signed by
// the operator's decree key and checked against the replica's own launch
// configuration, is the authority; the snapshot must be the one it names.
func handleRestore(node *cdsha.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RestoreRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<20)).Decode(&req); err != nil {
			http.Error(w, "bad restore request: "+err.Error(), http.StatusBadRequest)
			return
		}
		res, err := node.Restore(r.Context(), req.Decree, req.Snapshot)
		switch {
		case errors.Is(err, cdsha.ErrNotForThisNode):
			http.Error(w, err.Error(), http.StatusMisdirectedRequest)
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
}

// preJoinMux is what a replica serves before it joins.
func preJoinMux(node *cdsha.Node) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Ready only while waiting for a restore, so the operator can reach a
	// replica through the Service after every replica was lost; a replica
	// joining a live cluster takes no client traffic.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !node.AwaitingRestore() {
			http.Error(w, "joining", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /ha/status", haStatus(node))
	mux.HandleFunc("POST /ha/restore", handleRestore(node))
	mux.HandleFunc("GET /ha/pins", haPins(node))
	// Anything else is retryable: the full server takes over once joined.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "cds-ha: this replica has not joined the cluster yet", http.StatusServiceUnavailable)
	})
	return mux
}

// restoreServer returns the pre-join server starter for run(): the CDS port
// with only health, status and restore, armTLS as the full server is.
func restoreServer(cfg config) func(*cdsha.Node) func() {
	return func(node *cdsha.Node) func() {
		addr := net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))
		srv := newHTTPServer(addr, preJoinMux(node), cfg)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			var err error
			if cfg.armtlsPlatform != "" {
				if srv.TLSConfig, err = armtlsServerTLS(ctx, cfg, nil); err != nil {
					slog.Error("cds-ha: pre-join server", "err", err)
					return
				}
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Warn("cds-ha: pre-join server", "err", err)
			}
		}()
		return func() {
			cancel()
			sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			_ = srv.Shutdown(sctx)
			<-done
		}
	}
}

// haGenesis is when the cluster was born: the cutoff for single-use tokens.
func haGenesis(node *cdsha.Node) time.Time {
	return time.UnixMilli(node.Core().GenesisAtMS)
}
