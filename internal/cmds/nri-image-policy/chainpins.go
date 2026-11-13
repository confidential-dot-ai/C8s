package nriimagepolicy

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/pendingattestation"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/cdsgenesis"
)

// chainPins holds this node's CDS pins to the builds a replica set's chain
// accepts: the chain must hold the pinned entry, and every chain read
// later must extend the one verified before.
type chainPins struct {
	raw   string
	known *cdschain.State
	// follow reads and verifies the chain after known.
	follow func(ctx context.Context, known *cdschain.State) (*cdschain.State, error)
	// path is the pins document this node's own CDS clients load; podPins,
	// once set, the copy injected pods mount and read per handshake.
	path, podPins string
	// pullTransport builds the allowlist pull's transport over path; pull is
	// swapped when the pins change.
	pullTransport func() (*http.Transport, error)
	pull          atomic.Pointer[http.Transport]
	// mu guards known's writes and digests: the sandbox-digests listener,
	// whose CDS client pins follow the chain too, verified at attestationAPI.
	mu             sync.Mutex
	digests        *armtls.CertManager
	attestationAPI string
}

func newChainPins(cfg pullConfig, url string, clusterDNS netip.Addr) (*chainPins, error) {
	pin, err := cdschain.ParsePin(cfg.CDSChain)
	if err != nil {
		return nil, err
	}
	dial := clusterFirstDialer(netip.AddrPortFrom(clusterDNS, clusterDNSPort)).DialContext
	// Entries verify by signature; the head by the attested call.
	plain := &http.Transport{TLSClientConfig: pendingattestation.TLSConfig(""), DialContext: dial}
	attested := func(pins armtls.Pins) (*http.Client, error) {
		client, err := armtls.NewVerifyingHTTPClient(pins, cfg.AttestationApiURL)
		if err != nil {
			return nil, err
		}
		client.Transport.(*http.Transport).DialContext = dial
		client.Timeout = cfg.Timeout
		return cdsgenesis.Client(client, cfg.CDSChain), nil
	}
	path := filepath.Join(enforcerRuntimeDir, "cds.json")
	pullCfg := cfg
	pullCfg.CDSMeasurementsConfig = path
	return &chainPins{
		raw:            cfg.CDSChain,
		attestationAPI: cfg.AttestationApiURL,
		path:           path,
		follow: func(ctx context.Context, known *cdschain.State) (*cdschain.State, error) {
			return cdsha.Follow(ctx, url, &pin, known, cdsgenesis.Client(&http.Client{Transport: plain, Timeout: cfg.Timeout}, cfg.CDSChain), attested)
		},
		pullTransport: func() (*http.Transport, error) {
			client, err := allowlistPullHTTPClient(pullCfg, clusterDNS)
			if err != nil {
				return nil, err
			}
			return client.Transport.(*http.Transport), nil
		},
	}, nil
}

// refresh follows the chain and, when the accepted builds changed, rewrites
// the pins documents in place and moves the pull and the digests listener to
// them; it reports whether they changed. The chain counts as followed only
// once all of that is done, so any failed step is retried.
func (c *chainPins) refresh(ctx context.Context) (bool, error) {
	state, err := c.follow(ctx, c.known)
	if err != nil {
		return false, err
	}
	if c.known != nil && slices.Equal(c.known.Accepted, state.Accepted) {
		c.mu.Lock()
		c.known = state
		c.mu.Unlock()
		return false, nil
	}
	document, err := refvalues.Format(state.Pins())
	if err == nil {
		err = os.MkdirAll(filepath.Dir(c.path), 0o700)
	}
	// In place, not by rename: pods bind-mount the rendered file by inode.
	if err == nil {
		err = os.WriteFile(c.path, document, 0o644)
	}
	if err == nil && c.podPins != "" {
		err = os.WriteFile(c.podPins, document, 0o644)
	}
	var pull *http.Transport
	if err == nil && c.pullTransport != nil {
		pull, err = c.pullTransport()
	}
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	c.known = state
	if pull != nil {
		c.pull.Store(pull)
	}
	c.pushDigestsLocked()
	c.mu.Unlock()
	slog.Info("CDS pins follow the replica set's chain", "head", state.Head.Seq, "builds", len(state.Accepted))
	return true, nil
}

// attachDigests makes the sandbox-digests listener admit the CDS builds the
// chain accepts, now and after every change.
func (c *chainPins) attachDigests(m *armtls.CertManager) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.digests = m
	c.pushDigestsLocked()
}

// pushDigestsLocked hands the known chain's builds to the digests listener.
// INVARIANT: the listener admits a CDS replica exactly when the node's CDS
// clients would accept it.
func (c *chainPins) pushDigestsLocked() {
	if c.digests == nil || c.known == nil {
		return
	}
	if err := c.digests.UpdateClientPolicy(armtls.Pins(c.known.Pins().Policy()).VerifyPolicy(c.attestationAPI)); err != nil {
		slog.Error("the sandbox-digests endpoint cannot follow the CDS builds", "error", err)
	}
}

// RoundTrip lets the allowlist pull follow the pins as they change, held
// to the pinned chain (C-ID).
func (c *chainPins) RoundTrip(r *http.Request) (*http.Response, error) {
	return cdsgenesis.Client(&http.Client{Transport: c.pull.Load()}, c.raw).Transport.RoundTrip(r)
}

// followChainAtStart follows the chain once before the plugin serves. It
// never fails on the CDS: a node whose CDS cannot answer yet (the server
// node, whose store is the API server it is about to start) serves the base
// allowlist on its launch pins and keeps following in the pull loop.
func followChainAtStart(cfg *config, logger *slog.Logger) (*chainPins, error) {
	chain, err := newChainPins(cfg.Allowlist.Pull, cfg.pullURL(), cfg.Mesh.Resolver)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Allowlist.Pull.Timeout)
	defer cancel()
	if _, err := chain.refresh(ctx); err != nil {
		logger.Warn("CDS chain not followed yet; serving the base allowlist and retrying in the background", "error", err)
		return chain, nil
	}
	cfg.Allowlist.Pull.CDSMeasurementsConfig = chain.path
	return chain, nil
}

// refresher is the pull loop's hook: it follows the chain once per pull. The
// timeout is per request, not on the whole follow: a node with no chain yet
// reads it from genesis, which on a long chain takes longer than one pull.
func (c *chainPins) refresher() func(context.Context) {
	if c == nil {
		return nil
	}
	return func(ctx context.Context) {
		if _, err := c.refresh(ctx); err != nil {
			slog.Warn("CDS chain follow failed; keeping the pins verified before", "error", err)
		}
	}
}
