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
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// allowPlainHTTP is true only in c8s_dev builds (plainhttp_dev.go), where CDS
// may run without armTLS so the HA prototype can be exercised without a TEE.
var allowPlainHTTP = false

// haConfig enables the CDS HA prototype (internal/cdsha). Empty clusterID
// keeps the singleton behaviour: a fresh in-memory mesh CA per start.
type haConfig struct {
	yieldFile      string // baked singleton: exit when the launch document selects HA
	configFile     string // baked nodes: cds-ha.json from the signed launch document
	clusterID      string
	namespace      string
	decreeNS       string
	peersDNS       string
	port           int
	attestor       string
	measurement    string
	pins           []string
	operatorKey    string
	operatorKeyPEM []byte // set from --ha-config instead of a file
	tdxTCB         []string
	timing         cdsha.Timing
}

func bindHAFlags(flags *pflag.FlagSet, c *haConfig) {
	flags.StringVar(&c.yieldFile, "ha-yield-file", "", "baked singleton: path of the node's public cds-mode file; when it says \"ha\" (the signed launch document declares cdsHA), this singleton exits so the HA replicas on cds-role nodes are the only CDS")
	flags.StringVar(&c.configFile, "ha-config", "", "baked nodes: path of cds-ha.json published from the signed launch document (cluster id, decree key, image pins); it overrides --ha-cluster-id, --ha-operator-key and --ha-replica-pins, so none of those trust roots is a pod flag")
	flags.StringVar(&c.clusterID, "ha-cluster-id", "", "PROTOTYPE: enable CDS high availability for this cluster id; replicas with the same id share one mesh CA (empty = singleton CDS)")
	flags.StringVar(&c.namespace, "ha-namespace", os.Getenv("POD_NAMESPACE"), "namespace holding the HA Lease and the CDSEpoch object")
	flags.StringVar(&c.decreeNS, "ha-decree-namespace", "", "namespace where operators write CDSDecree objects (default --ha-namespace; on a locked node image the CDS namespace is privileged, so use one the operator credential can write)")
	flags.StringVar(&c.peersDNS, "ha-peers-dns", "", "headless Service DNS name resolving to every CDS replica")
	flags.IntVar(&c.port, "ha-port", 9443, "port of the replica-to-replica API (mutually attested TLS)")
	flags.StringVar(&c.attestor, "ha-attestor", "node", "peer attestor: node (the node attestation-api at --attestation-api-url; TDX and SEV-SNP), tdx (DCAP quotes read in-process, inside a TD), or mock in c8s_dev builds")
	flags.StringSliceVar(&c.tdxTCB, "ha-tdx-tcb-statuses", cdsha.DefaultTDXTCBStatuses, "Intel TCB statuses a peer platform may report (PCS spelling, e.g. UpToDate,SWHardeningNeeded,OutOfDate)")
	flags.StringVar(&c.measurement, "ha-measurement", "", "this replica's measurement as reported by the mock attestor")
	flags.StringSliceVar(&c.pins, "ha-replica-pins", nil, "replica measurement pins used before genesis and copied into epoch 0 (the spec bakes these into the image)")
	flags.StringVar(&c.operatorKey, "ha-operator-key", "", "PEM P-256 public key authorizing HA decrees, including the Genesis decree that mints the first key (REQUIRED with --ha-cluster-id)")
	flags.DurationVar(&c.timing.Heartbeat, "ha-heartbeat-interval", cdsha.DefaultTiming.Heartbeat, "")
	flags.DurationVar(&c.timing.LeaseDuration, "ha-lease-duration", cdsha.DefaultTiming.LeaseDuration, "")
	flags.DurationVar(&c.timing.AckTimeout, "ha-ack-timeout", cdsha.DefaultTiming.AckTimeout, "")
}

// meshCA returns the CA to issue with. In HA mode it blocks until the
// replica holds the cluster's key (genesis or transfer, L1-L3).
func meshCA(ctx context.Context, cfg config) (*issuer.CA, *cdsha.Replica, error) {
	if cfg.ha.yieldFile != "" {
		if err := yieldIfHA(cfg.ha.yieldFile); err != nil {
			return nil, nil, err
		}
	}
	if cfg.ha.configFile != "" {
		if err := loadHAConfigFile(&cfg.ha); err != nil {
			return nil, nil, err
		}
	}
	if cfg.ha.clusterID == "" {
		ca, err := issuer.NewCAWithCurve(cfg.caCommonName, cfg.caCertValidity, elliptic.P384())
		return ca, nil, err
	}
	rep, err := newReplica(cfg)
	if err != nil {
		return nil, nil, err
	}
	errc := make(chan error, 1)
	go func() {
		err := rep.Run(ctx)
		errc <- err
		if err != nil && ctx.Err() == nil {
			// After startup nobody reads errc: a dead replica must not
			// leave CDS issuing from a key it no longer tracks.
			slog.Error("cds-ha replica stopped; exiting", "err", err)
			os.Exit(1)
		}
	}()
	slog.Info("cds-ha: waiting for the cluster mesh CA", "cluster_id", cfg.ha.clusterID)
	t := time.NewTicker(cfg.ha.timing.Heartbeat)
	defer t.Stop()
	for {
		if ca, err := rep.CA(); err == nil {
			return ca, rep, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case err := <-errc:
			return nil, nil, fmt.Errorf("cds-ha replica: %w", err)
		case <-t.C:
		}
	}
}

func newReplica(cfg config) (*cdsha.Replica, error) {
	h := cfg.ha
	if h.peersDNS == "" || h.namespace == "" {
		return nil, errors.New("--ha-peers-dns and --ha-namespace are required with --ha-cluster-id")
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
	identity, _ := os.Hostname()
	return cdsha.New(cdsha.Config{
		ClusterID:       h.clusterID,
		Identity:        identity,
		ListenAddr:      net.JoinHostPort(cfg.host, strconv.Itoa(h.port)),
		Peers:           dnsPeers(h.peersDNS, os.Getenv("POD_IP"), h.port),
		Attestor:        att,
		BakedPins:       h.pins,
		OperatorPubKey:  opKey,
		Kube:            kube,
		Namespace:       h.namespace,
		DecreeNamespace: h.decreeNS,
		CACommonName:    cfg.caCommonName,
		CAValidity:      cfg.caCertValidity,
		Timing:          h.timing,
		Logger:          slog.Default(),
	})
}

// refuseHAWrites wraps a write authorizer: on an HA replica every write is
// refused with errHAWritesDisabled; otherwise the authorizer is unchanged.
func refuseHAWrites(ha bool) func(allowlist.WriteAuthorizer) allowlist.WriteAuthorizer {
	return func(a allowlist.WriteAuthorizer) allowlist.WriteAuthorizer {
		if !ha {
			return a
		}
		return func(*http.Request, []byte) error { return errHAWritesDisabled }
	}
}

// errHAWritesDisabled refuses allowlist and secret writes on an HA cluster.
var errHAWritesDisabled = errors.New("allowlist and secret writes are not replicated across HA CDS replicas: change the policy in the signed launch document")

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
	return nil
}

// dnsPeers resolves the headless Service on every call (L2), dropping self.
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
// immediately stops trusting leaves of the old key (D16). While the replica
// cannot issue, no client certificate verifies.
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

// haStatus serves the replica's public position for the CLI (C2). It is
// untrusted output, like everything that crosses the control plane (F3).
func haStatus(rep *cdsha.Replica) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep.Heartbeat())
	}
}

// haCACertPEM serves the current epoch's mesh CA certificate.
func haCACertPEM(rep *cdsha.Replica) func() []byte {
	return func() []byte {
		ca, err := rep.CA()
		if err != nil {
			return nil
		}
		return certutil.EncodeCertPEM(ca.Cert.Raw)
	}
}

// haChallengeKey derives a per-purpose challenge MAC key from the replica's
// current mesh CA private key; nil while the replica cannot issue.
func haChallengeKey(rep *cdsha.Replica, purpose string) func() []byte {
	return func() []byte {
		ca, err := rep.CA()
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
