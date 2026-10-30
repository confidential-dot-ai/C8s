// This process as one replica of its cluster's CDS: the Raft member over the
// replicated state internal/cdsha keeps, the stores that member's log writes,
// and the mesh CA its cluster minted. Every setting comes from the ha block of
// the measured configuration every replica of the cluster boots.

package cds

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// peerPort is where every replica of every cluster answers its peers.
const peerPort = 8444

// Each nonce pool MACs its nonces under a key of its own, so a nonce minted
// for the one is redeemable in neither the other nor another cluster.
const (
	challengeIssuance = "issuance"
	challengeSecrets  = "secrets"
)

var _ backend = (*clusterCDS)(nil)

// joinPoll is how often a starting replica asks whether it serves its cluster
// yet, and caFollow how often a serving one looks at the cluster's mesh CA.
const (
	joinPoll = 250 * time.Millisecond
	caFollow = 5 * time.Second
)

// clusterCDS serves its cluster as one of its replicas: every store write
// becomes a log entry, and the mesh CA is the cluster's.
type clusterCDS struct {
	handles
	challengePools
	node *cdsha.Node
	// stopNode ends the member's loop and waits for it; ended is closed when
	// that loop is gone, whether it was stopped or it failed.
	stopNode func()
	ended    <-chan struct{}
}

// newReplica makes this process one replica of its cluster's CDS. It answers
// health, status and the cluster's pins on the client port while it joins,
// and returns once the cluster's mesh CA is this replica's to issue under.
func newReplica(ctx context.Context, cfg config, st stores) (backend, error) {
	if cfg.allowlistPersistent {
		return nil, errors.New("--allowlist-persistent and an ha block: a replica's allowlist is the cluster's, and the log it comes from lives in the replicas' memory")
	}
	node, err := newMember(cfg, st)
	if err != nil {
		return nil, err
	}
	if err := emptyAllowlist(st.allowlist); err != nil {
		return nil, err
	}
	if err := node.Start(); err != nil {
		return nil, err
	}
	stop, ended := runMember(ctx, node)
	joining := &clusterCDS{
		handles: handles{
			allowlist: node.Allowlist(),
			secrets:   node.Secrets(),
			bindings:  node.Bindings(),
		},
		challengePools: challengePools{
			issuance: attestation.NewSharedChallenges(
				challengeIssuance,
				cfg.challengeTTL,
				clusterKey(node, challengeIssuance),
			),
			secrets: attestation.NewSharedChallenges(
				challengeSecrets,
				cfg.challengeTTL,
				clusterKey(node, challengeSecrets),
			),
		},
		node:     node,
		stopNode: stop,
		ended:    ended,
	}
	if err := joining.join(ctx, cfg); err != nil {
		joining.Stop()
		return nil, err
	}
	return joining, nil
}

func newMember(cfg config, st stores) (*cdsha.Node, error) {
	ha := cfg.measured.HA
	peer, err := peerAddress(cfg)
	if err != nil {
		return nil, err
	}
	launchFile := sha256.Sum256(cfg.measuredFile)
	return cdsha.NewNode(cdsha.Config{
		Launch: cdsha.Launch{
			ClusterID:    cfg.measured.ClusterID,
			OperatorKeys: cfg.measured.OperatorKeys.Keys(),
			ConfigSHA256: hex.EncodeToString(launchFile[:]),
			Voters:       ha.Voters,
		},
		LaunchFile:     cfg.measuredFile,
		Peer:           peer,
		AttestationURL: cfg.attestationApiURL,
		Timing:         haTiming,
		Replicas:       ha.Replicas,
		Allowlist:      st.allowlist,
		Secrets:        st.secrets,
		Ledger:         st.bindings,
	})
}

// peerAddress is the one address this replica serves on, at the port a peer
// channel answers at: its peers, the nodes and the operator all reach it
// there, and the cluster's replica entries resolve to it.
func peerAddress(cfg config) (netip.AddrPort, error) {
	address, err := netip.ParseAddr(cfg.host)
	if err != nil || address.IsUnspecified() || !address.Is4() {
		return netip.AddrPort{}, fmt.Errorf("--host %q: a replica of a cluster serves at its own IPv4 address, which the cluster's ha.replicas resolve to", cfg.host)
	}
	return netip.AddrPortFrom(address, peerPort), nil
}

// emptyAllowlist drops the rows an earlier process of this VM left behind: a
// replica's state comes from the log alone, and rows under it would leave the
// version, ETag and history it serves no other replica's.
func emptyAllowlist(store *allowlist.Store) error {
	fresh, err := allowlist.OpenInMemory()
	if err != nil {
		return err
	}
	defer fresh.Close()
	empty, err := fresh.Dump()
	if err != nil {
		return err
	}
	if err := store.Restore(empty); err != nil {
		return fmt.Errorf("empty the allowlist database for a replica: %w", err)
	}
	return nil
}

// runMember drives the member until the returned stop is called, and reports
// its loop ending: a replica whose loop is gone joins nothing and, once the
// lease it holds runs out, serves nothing.
//
// A loop that ended because the replica left its cluster ends the process
// (images/cds-guest). A replica whose loop waits behind the fault is ended by
// the watchdog beside it.
func runMember(ctx context.Context, node *cdsha.Node) (stop func(), ended <-chan struct{}) {
	running, cancel := context.WithCancel(ctx)
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		err := node.Run(running)
		switch {
		case errors.Is(err, cdsha.ErrLeftItsCluster):
			exitToRestart(err.Error())
		case err != nil:
			slog.Error("cds-ha: this replica's loop ended", "error", err)
		}
	}()
	go watchStuck(running, node)
	return func() { cancel(); <-gone }, gone
}

const stuckLook = time.Second

// A replica's own loop ends it on a fault, and that loop can be waiting
// behind the very fault it would end on. A replica that serves nothing must
// hold no open port for a prober to find.
func watchStuck(ctx context.Context, node *cdsha.Node) {
	look := time.NewTicker(stuckLook)
	defer look.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-look.C:
		}
		if reason := node.StuckOverdue(); reason != "" {
			exitToRestart("its own loop did not end it: " + reason)
		}
	}
}

// A failure exit is what the unit restarts on.
func exitToRestart(reason string) {
	slog.Error("cds-ha: this replica stopped following its cluster; it exits so a restart rejoins it as a new member with the cluster's state",
		"reason", reason)
	os.Exit(1)
}

// join answers health, status and the cluster's pins on the client port until
// this replica serves. An operator reads the member id and the mesh CA of an
// unjoined replica there, and signs the Genesis decree it then acts on.
func (r *clusterCDS) join(ctx context.Context, cfg config) error {
	stopAnswering, err := r.answerWhileJoining(cfg)
	if err != nil {
		return err
	}
	defer stopAnswering()
	slog.Info("cds-ha: this replica waits to join its cluster",
		"cluster_id", cfg.measured.ClusterID,
		"member", r.node.Status().ID,
	)
	if err := r.awaitServing(ctx); err != nil {
		return err
	}
	slog.Info("cds-ha: this replica serves its cluster", "status", r.node.Status())
	return nil
}

// awaitServing ends with the reason this replica never will answer for its
// cluster: the process is going down, or the member's loop is gone.
func (r *clusterCDS) awaitServing(ctx context.Context) error {
	asking := time.NewTicker(joinPoll)
	defer asking.Stop()
	for !r.Ready() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.ended:
			return errors.New("cds-ha: this replica's loop ended before it joined its cluster")
		case <-asking.C:
		}
	}
	return nil
}

func (r *clusterCDS) MeshCA() meshCA {
	return clusterCA{node: r.node}
}

// TokenFloor is when this replica's cluster last started: a cluster that
// started again holds no record of the tokens its last life spent. A replica
// holding no cluster has no record at all, so it accepts no token's age.
func (r *clusterCDS) TokenFloor() time.Time {
	started := r.node.ClusterState().StartedAtMS
	if started == 0 {
		return time.Now()
	}
	return time.UnixMilli(started)
}

// /readyz, and the gate below holds every other route to it.
func (r *clusterCDS) Ready() bool {
	return r.node.Serving().OK
}

func (r *clusterCDS) ClusterRoutes() map[string]http.HandlerFunc {
	return clusterRoutes(r.node)
}

func (r *clusterCDS) Gate(next http.Handler) http.Handler {
	return haGate(r.Ready, next)
}

// KeepMeshCA publishes the mesh CA the cluster's log carries whenever it
// changes, so a rotation stops trusting the leaves of the old key.
func (r *clusterCDS) KeepMeshCA(ctx context.Context, peers *armtls.CertManager) {
	var published []byte
	looking := time.NewTicker(caFollow)
	defer looking.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-looking.C:
		}
		ca, issuing := r.node.CA()
		if !issuing {
			published = nil
			continue
		}
		if bytes.Equal(ca.Cert.Raw, published) {
			continue
		}
		peers.UpdateClientCA(ca.Cert)
		published = ca.Cert.Raw
		slog.Info("cds-ha: this replica issues under the mesh CA its cluster carries now",
			"audit", true,
			"key_id", caKeyID(ca.Cert),
			"fingerprint", certutil.CertFingerprint(ca.Cert.Raw),
		)
	}
}

func (r *clusterCDS) Stop() {
	r.stopNode()
}

type clusterCA struct {
	node *cdsha.Node
}

func (c clusterCA) Current() (issuer.CurrentCA, bool) {
	ca, issuing := c.node.CA()
	if !issuing {
		return issuer.CurrentCA{}, false
	}
	return issuer.CurrentCA{
		CA:      ca,
		CertPEM: certutil.EncodeCertPEM(ca.Cert.Raw),
	}, true
}

// clusterKey derives one pool's challenge key from the cluster's mesh CA
// private key, so a nonce one replica minted is redeemable at every other. A
// key rotation invalidates the nonces outstanding under the old one.
func clusterKey(node *cdsha.Node, purpose string) attestation.ClusterKey {
	return func() []byte {
		ca, issuing := node.CA()
		if !issuing {
			return nil
		}
		secret, err := ca.Key.Bytes()
		if err != nil {
			return nil
		}
		key, err := hkdf.Key(sha256.New, secret, nil, "c8s-cds-challenge-key-v1/"+purpose, sha256.Size)
		if err != nil {
			return nil
		}
		return key
	}
}
