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
	port           int
	nodeName       string
	attestor       string
	measurement    string
	pins           []string
	operatorKey    string
	operatorKeyPEM []byte // set from --ha-config instead of a file
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
	flags.IntVar(&c.port, "ha-port", 9443, "port of the replica-to-replica channel (mutually attested TLS; Raft and control)")
	flags.StringVar(&c.nodeName, "ha-node-name", os.Getenv("NODE_NAME"), "the node this replica runs on: one voter seat per node, and a Genesis decree names its bootstrap node")
	flags.StringVar(&c.attestor, "ha-attestor", "node", "peer attestor: node (the node attestation-api at --attestation-api-url; TDX and SEV-SNP), tdx (DCAP quotes read in-process, inside a TD), or mock in c8s_dev builds")
	flags.StringSliceVar(&c.tdxTCB, "ha-tdx-tcb-statuses", cdsha.DefaultTDXTCBStatuses, "Intel TCB statuses a peer platform may report (PCS spelling, e.g. UpToDate,SWHardeningNeeded,OutOfDate)")
	flags.StringVar(&c.measurement, "ha-measurement", "", "this replica's measurement as reported by the mock attestor")
	flags.StringSliceVar(&c.pins, "ha-replica-pins", nil, "replica measurement pins; the Genesis replica makes them the cluster's first pin set")
	flags.StringVar(&c.operatorKey, "ha-operator-key", "", "PEM P-256 public key authorizing HA decrees, including Genesis (REQUIRED with --ha-cluster-id)")
	flags.IntVar(&c.seats, "ha-seats", 3, "number of voting replicas; further replicas are non-voters that serve and take a seat when one frees up")
	flags.IntVar(&c.maxNonVoters, "ha-max-non-voters", 16, "most non-voting replicas the leader admits")
	flags.DurationVar(&c.timing.Heartbeat, "ha-heartbeat", cdsha.DefaultTiming.Heartbeat, "Raft heartbeat timeout")
	flags.DurationVar(&c.timing.Election, "ha-election", cdsha.DefaultTiming.Election, "Raft election timeout")
	flags.DurationVar(&c.timing.Lease, "ha-lease", cdsha.DefaultTiming.Lease, "a follower stops issuing and releasing this long after it last heard from the leader")
	flags.DurationVar(&c.timing.DeadAfter, "ha-dead-after", cdsha.DefaultTiming.DeadAfter, "the leader removes a member that failed heartbeats this long")
	flags.DurationVar(&c.timing.Stabilize, "ha-stabilize", cdsha.DefaultTiming.Stabilize, "a non-voter must be healthy this long before it takes a seat")
	flags.DurationVar(&c.timing.Apply, "ha-apply-timeout", cdsha.DefaultTiming.Apply, "bound on one replicated write")
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
func haStart(ctx context.Context, cfg config, st haStores) (*cdsha.Node, error) {
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
	slog.Info("cds-ha: waiting to join the cluster", "cluster_id", cfg.ha.clusterID, "id", node.ID())
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

func newHANode(cfg config, st haStores) (*cdsha.Node, error) {
	h := cfg.ha
	if h.peersDNS == "" || h.decreeNS == "" || h.nodeName == "" {
		return nil, errors.New("--ha-peers-dns, --ha-decree-namespace and --ha-node-name are required with --ha-cluster-id")
	}
	att, err := cdsha.NewAttestor(h.attestor, cdsha.AttestorOptions{
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
	podIP := os.Getenv("POD_IP")
	if podIP == "" {
		return nil, errors.New("POD_IP is required in HA mode: replicas advertise it to each other")
	}
	return cdsha.NewNode(cdsha.Config{
		ClusterID:      h.clusterID,
		NodeName:       h.nodeName,
		Bind:           net.JoinHostPort(cfg.host, strconv.Itoa(h.port)),
		Advertise:      net.JoinHostPort(podIP, strconv.Itoa(h.port)),
		Attestor:       att,
		BakedPins:      h.pins,
		OperatorPubKey: opKey,
		Seats:          h.seats,
		MaxNonVoters:   h.maxNonVoters,
		Peers:          dnsPeers(h.peersDNS, podIP, h.port),
		Decrees:        cdsha.KubeDecrees{Client: kube, Namespace: h.decreeNS, ClusterID: h.clusterID},
		Timing:         h.timing,
		CACommonName:   cfg.caCommonName,
		CAValidity:     cfg.caCertValidity,
		Allowlist:      st.allowlist,
		Secrets:        st.secrets,
		Ledger:         st.ledger,
		Logger:         slog.Default(),
	})
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
		case "/healthz", "/readyz", "/metrics", "/ha/status":
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

// haGenesis is when the cluster was born: the cutoff for single-use tokens.
func haGenesis(node *cdsha.Node) time.Time {
	return time.UnixMilli(node.Core().GenesisAtMS)
}
