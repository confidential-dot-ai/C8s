package cds

import (
	"context"
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
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
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
	timing         cdsha.Timing // c8s_dev builds can tune it (devha_dev.go)
}

func bindHAFlags(flags *pflag.FlagSet, c *haConfig) {
	flags.StringVar(&c.yieldFile, "ha-yield-file", "", "baked singleton: path of the node's public cds-mode file; when it says \"ha\" (the signed launch document declares cdsHA), this singleton exits so the HA replicas on cds-role nodes are the only CDS")
	flags.StringVar(&c.configFile, "ha-config", "", "baked nodes: path of cds-ha.json published from the signed launch document (cluster id, decree and recovery keys, seats, image pins); it excludes --ha-cluster-id, --ha-operator-key, --ha-recovery-key, --ha-replica-pins and --ha-measurement, so none of those trust roots is a pod flag, and its seat count overrides --ha-seats")
	flags.StringVar(&c.clusterID, "ha-cluster-id", "", "enable CDS high availability for this cluster id (dev/test; baked nodes use --ha-config); replicas with the same id form one Raft group and share one mesh CA (empty = singleton CDS)")
	flags.StringVar(&c.decreeNS, "ha-decree-namespace", os.Getenv("POD_NAMESPACE"), "namespace where operators write CDS decree objects (on a locked node image the CDS namespace is privileged, so use one the operator credential can write)")
	flags.StringVar(&c.peersDNS, "ha-peers-dns", "", "headless Service DNS name resolving to every CDS replica")
	flags.StringSliceVar(&c.peers, "ha-peers", nil, "static ip:port list of the other replicas' peer ports, instead of --ha-peers-dns")
	flags.StringVar(&c.advertiseIP, "ha-advertise-ip", os.Getenv("POD_IP"), "address the other replicas reach this one at (default $POD_IP)")
	flags.IntVar(&c.port, "ha-port", 9443, "port of the replica-to-replica channel (mutually attested TLS; Raft and control)")
	flags.StringVar(&c.nodeName, "ha-node-name", os.Getenv("NODE_NAME"), "the node this replica runs on: one voter seat per node, and a Genesis decree names its bootstrap node")
	flags.StringVar(&c.attestor, "ha-attestor", "node", "peer attestor: node (the node attestation-api at --attestation-api-url; TDX and SEV-SNP), or mock in c8s_dev builds")
	flags.StringSliceVar(&c.pins, "ha-replica-pins", nil, "replica measurement pins; the Genesis replica makes them the cluster's first pin set")
	flags.StringVar(&c.operatorKey, "ha-operator-key", "", "PEM P-256 public key authorizing HA decrees, including Genesis (REQUIRED with --ha-cluster-id)")
	flags.Func("ha-recovery-key", "PEM P-256 public key the leader seals state backups to (dev/test; baked nodes take it from --ha-config). Without one there is no recovery from the loss of every replica", func(p string) error {
		raw, err := os.ReadFile(p)
		c.recoveryKeyPEM = raw
		return err
	})
	flags.IntVar(&c.seats, "ha-seats", 3, "number of voting replicas; further replicas are non-voters that serve and take a seat when one frees up")
	c.timing = cdsha.DefaultTiming
	bindDevHAFlags(flags, c)
}

// bindDevHAFlags adds the integration harness's flags (the mock attestor's
// measurement and the Raft timings) in c8s_dev builds; release builds keep
// cdsha.DefaultTiming.
var bindDevHAFlags = func(*pflag.FlagSet, *haConfig) {}

// haStores are the local stores a replica's Raft log applies to.
type haStores struct {
	allowlist *allowlist.Store
	secrets   *secrets.MemoryStore
	ledger    *sandboxledger.Ledger
}

// haStart builds this replica, makes it the replicator of every store, and
// returns once it serves the cluster's mesh CA. A nil node means singleton.
// stop ends the replica and waits for it: run calls it before it closes the
// stores the Raft log applies to.
func haStart(ctx context.Context, cfg config, st haStores) (node *cdsha.Node, stop func(), err error) {
	stop = func() {}
	if cfg.ha.yieldFile != "" {
		if err := yieldIfHA(cfg.ha.yieldFile); err != nil {
			return nil, stop, err
		}
	}
	if cfg.ha.configFile != "" {
		if err := loadHAConfigFile(&cfg.ha); err != nil {
			return nil, stop, err
		}
	}
	if cfg.ha.clusterID == "" {
		return nil, stop, nil
	}
	if node, err = newHANode(cfg, st); err != nil {
		return nil, stop, err
	}
	if err := node.Start(); err != nil {
		return nil, stop, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	errc, done := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		err := node.Run(runCtx)
		errc <- err
		if err != nil && runCtx.Err() == nil {
			// After startup nobody reads errc: a dead replica must not
			// leave CDS serving state it no longer tracks.
			slog.Error("cds-ha replica stopped; exiting", "err", err)
			os.Exit(1)
		}
	}()
	stop = func() { cancel(); <-done }
	// Run ends a stuck replica, but only from its own loop. Watch
	// independently, so a loop blocked behind the fault (a call on a
	// starved store or network) cannot keep a replica that serves nothing
	// alive while its open peer port passes a TCP liveness check.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-t.C:
			}
			if reason := node.StuckOverdue(); reason != "" {
				slog.Error("cds-ha replica stuck and its loop did not end it; exiting", "reason", reason)
				os.Exit(1)
			}
		}
	}()
	slog.Info("cds-ha: replica starting", "build", "v4-rollout-image-b")
	slog.Info("cds-ha: waiting to join the cluster", "cluster_id", cfg.ha.clusterID, "id", node.ID())
	// Until it joins, the replica serves only health, status and the
	// operator's restore of a backup, on the CDS port.
	defer startPreJoinServer(cfg, node)()
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for !node.Serving() {
		select {
		case <-ctx.Done():
			stop()
			return nil, func() {}, ctx.Err()
		case err := <-errc:
			stop()
			return nil, func() {}, fmt.Errorf("cds-ha replica: %w", err)
		case <-t.C:
		}
	}
	slog.Info("cds-ha: serving", "status", node.Status())
	return node, stop, nil
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

// newHANode builds this replica and makes it the replicator of every store.
func newHANode(cfg config, st haStores) (*cdsha.Node, error) {
	h := cfg.ha
	if (h.peersDNS == "" && len(h.peers) == 0) || h.decreeNS == "" || h.nodeName == "" {
		return nil, errors.New("--ha-peers-dns (or --ha-peers), --ha-decree-namespace and --ha-node-name are required with --ha-cluster-id")
	}
	att, err := newHAAttestor(cfg)
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
	node, err := cdsha.NewNode(cdsha.Config{
		ClusterID:       h.clusterID,
		NodeName:        h.nodeName,
		Bind:            net.JoinHostPort(cfg.host, strconv.Itoa(h.port)),
		Advertise:       net.JoinHostPort(podIP, strconv.Itoa(h.port)),
		Attestor:        att,
		BakedPins:       h.pins,
		OperatorPubKey:  opKey,
		Seats:           h.seats,
		MaxNonVoters:    16,
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
		HistoryBytes:    cfg.allowlistHistoryBytes.Value(),
	})
	if err != nil {
		return nil, err
	}
	if err := resetHAAllowlist(st.allowlist); err != nil {
		return nil, err
	}
	st.allowlist.SetReplicator(node)
	st.ledger.SetReplicator(node)
	return node, nil
}

// devHARoutes adds the integration test's routes in c8s_dev builds
// (devha_dev.go); in every other build it returns the router unchanged.
var devHARoutes = func(next http.Handler, _ secrets.Store, _ *secrets.MemoryStore, _ allowlist.WriteAuthorizer, _ bool) http.Handler {
	return next
}

// newHAAttestor is the peer attestor: the node's attestation-api, as every
// CDS path uses. c8s_dev builds add the mock (devha_dev.go); tests replace it.
var newHAAttestor = func(cfg config) (cdsha.Attestor, error) {
	if cfg.ha.attestor != "node" {
		return nil, fmt.Errorf("attestor %q not available in this build (node; mock needs -tags c8s_dev)", cfg.ha.attestor)
	}
	if cfg.attestationApiURL == "" {
		return nil, errors.New("node attestor needs the attestation-api URL")
	}
	return cdsha.NewNodeAttestor(cfg.attestationApiURL, cfg.requestTimeout), nil
}

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
	if h.clusterID != "" || len(h.pins) > 0 || h.operatorKey != "" || len(h.recoveryKeyPEM) > 0 || h.measurement != "" {
		return errors.New("--ha-config excludes --ha-cluster-id, --ha-replica-pins, --ha-operator-key, --ha-recovery-key and --ha-measurement")
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
	h.seats = c.Replicas // launchconfig refuses fewer than 2
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
	keys, err := operatorauth.ParsePublicKeysPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("--ha-operator-key: %w", err)
	}
	if len(keys) != 1 || keys[0].Curve != elliptic.P256() {
		return nil, errors.New("--ha-operator-key: want one ECDSA P-256 public key")
	}
	return x509.MarshalPKIXPublicKey(keys[0])
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

// devUngated names c8s_dev diagnostic routes that stay reachable while the
// replica is not serving (devha_dev.go): a replica that has stopped serving
// is the one whose goroutines and memory need looking at. Release builds
// gate every route but the ones haGate lists.
var devUngated = func(string) bool { return false }

// haGate answers 503 on every route but liveness, metrics and /ha/status
// while the replica is not serving: an isolated or stale replica must not
// issue, release, or hand out policy it may no longer hold.
func haGate(serving func() bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics", "/ha/status", "/ha/pins":
		default:
			if !serving() && !devUngated(r.URL.Path) {
				http.Error(w, "cds-ha: this replica is not serving (not joined, not pinned, or out of contact with the cluster)", http.StatusServiceUnavailable)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// serveJSON serves what read returns as JSON. It serves /ha/status (the
// replica's own, untrusted view) and /ha/decrees (the applied decrees as the
// operator signed them; the Kubernetes objects are only the host's word).
func serveJSON[T any](read func() T) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(read())
	}
}

// haPins serves the signed decree behind the current CDS pin set. It is
// public: clients that no longer recognise a replica's image fetch it before
// they can trust any replica, and check the operator's signature themselves.
func haPins(node *cdsha.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		sd := node.Core().PinsDecree
		if sd == nil {
			http.Error(w, "cds-ha: the pin set came from Genesis; the launch document's is current", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sd)
	}
}

// haMeshCA is an HA replica's mesh CA: the replicated one, renewed by the
// leader through the log, or empty (CA nil) while the replica may not issue.
type haMeshCA struct{ node *cdsha.Node }

func (h haMeshCA) Current() issuer.CurrentCA {
	ca, err := h.node.CA()
	if err != nil {
		return issuer.CurrentCA{}
	}
	return issuer.CurrentCA{CA: ca, CertPEM: certutil.EncodeCertPEM(ca.Cert.Raw)}
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
const (
	restoreDecreeHeader   = "X-CDS-Restore-Decree"
	maxRestoreDecreeBytes = 16 << 10
	maxLegacyRestoreBytes = 1 << 20
	maxRestoreBytes       = 256 << 20 // JSON wire bytes, including base64 snapshot
)

// A process-wide budget, independent of attacker-controlled source addresses.
var restoreAdmission = make(chan struct{}, 1)

func handleRestore(node *cdsha.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case restoreAdmission <- struct{}{}:
			defer func() { <-restoreAdmission }()
		default:
			http.Error(w, "restore already in progress", http.StatusTooManyRequests)
			return
		}
		// The server also bounds request reads. Set an explicit handler deadline
		// so a slow upload cannot retain the restore admission slot indefinitely.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
		limit := int64(maxLegacyRestoreBytes)
		if header := r.Header.Get(restoreDecreeHeader); header != "" {
			var sd cdsha.SignedDecree
			if len(header) > maxRestoreDecreeBytes || json.Unmarshal([]byte(header), &sd) != nil {
				http.Error(w, "bad restore decree header", http.StatusBadRequest)
				return
			}
			if err := node.CheckRestore(sd); err != nil {
				code := http.StatusConflict
				if errors.Is(err, cdsha.ErrNotForThisNode) {
					code = http.StatusMisdirectedRequest
				}
				http.Error(w, err.Error(), code)
				return
			}
			limit = maxRestoreBytes
		}
		var req RestoreRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(&req); err != nil {
			http.Error(w, "bad restore request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if header := r.Header.Get(restoreDecreeHeader); header != "" {
			var sd cdsha.SignedDecree
			_ = json.Unmarshal([]byte(header), &sd)
			expected, _ := json.Marshal(sd)
			actual, _ := json.Marshal(req.Decree)
			if string(expected) != string(actual) {
				http.Error(w, "restore body decree differs from header", http.StatusBadRequest)
				return
			}
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
	mux.HandleFunc("GET /ha/status", serveJSON(node.Status))
	mux.HandleFunc("POST /ha/restore", handleRestore(node))
	mux.HandleFunc("GET /ha/pins", haPins(node))
	// Anything else is retryable: the full server takes over once joined.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "cds-ha: this replica has not joined the cluster yet", http.StatusServiceUnavailable)
	})
	return mux
}

// startPreJoinServer serves the CDS port with only health, status and
// restore, armTLS as the full server is, until the returned stop is called.
func startPreJoinServer(cfg config, node *cdsha.Node) (stop func()) {
	addr := net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))
	srv := newHTTPServer(addr, preJoinMux(node), cfg)
	srv.MaxHeaderBytes = maxRestoreDecreeBytes + (4 << 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		var err error
		if cfg.armtlsPlatform != "" {
			if srv.TLSConfig, _, err = armtlsServerTLS(ctx, cfg, nil); err != nil {
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
