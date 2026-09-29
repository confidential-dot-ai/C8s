// The sandbox-digests callback: CDS asks the inventory that admitted a pod
// what that pod is actually running, at issuance time, over mutually-attested
// RA-TLS (docs/ratls.md, "Sandbox identity").
//
// Direction matters. The requester never reports its own images — it only
// proves, via the inventory-signed sandbox token, which sandbox it is in. CDS
// then asks the inventory directly, so the answer is live at issuance and
// comes from the component that made the admission decision.

package workloadclaims

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// DigestsPort is the port every inventory serves its digests endpoint on, and
// the only port CDS will dial for one. It is fixed rather than carried in the
// token, and it is privileged (<1024, IANA-unassigned), because that is what
// makes it an identity: answering on it at the node's address requires
// hostNetwork or a hostPort, and the chart's deny-host-namespaces policy
// withholds BOTH from tenant pods. A pod can bind any port inside its own
// netns, so an unprivileged port would let any workload answer as the
// inventory.
//
// Both halves are load-bearing. A hostPort needs no host namespace: the CNI
// publishes the pod on the node's address, which is enough to be dialled here
// and have CDS accept the responder's key as the inventory's.
const DigestsPort = 1019

// dialPort and listenPort are the ports the client connects to and the endpoint
// binds. They are package variables only so tests can use an unprivileged port;
// production always uses DigestsPort, which is never taken from the wire.
var (
	dialPort   = DigestsPort
	listenPort = DigestsPort
)

// ValidateInventoryHost reports whether host is a usable inventory host.
// See parseInventoryHost for the rules.
func ValidateInventoryHost(host string) error {
	_, err := parseInventoryHost(host)
	return err
}

// parseInventoryHost validates host and returns it re-serialized from the
// parsed IP, so what gets dialed is derived from a checked value rather than
// from the caller's bytes.
//
// SECURITY: this bounds a request-forgery primitive. The host rides a sandbox
// token, and a token is signable by anything that can reach CDS — the signature
// is only meaningful once CDS has resolved the key, which requires dialing this
// host first. Hence: an IP literal, never a name (a resolvable name lets DNS
// decide the destination after the check), and global unicast only (no
// loopback, link-local/IMDS, multicast, or unspecified). Callers additionally
// constrain it to the operator's inventory CIDRs — see InventoryHosts.
func parseInventoryHost(host string) (string, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("workloadclaims: inventory host %q must be an IP literal, not a name", host)
	}
	if !ip.IsGlobalUnicast() {
		return "", fmt.Errorf("workloadclaims: inventory host %q is not a routable unicast address", host)
	}
	return ip.String(), nil
}

// InventoryHosts bounds which addresses an inventory may live at — the
// operator's node addresses. CDS refuses to dial anything outside the set,
// which is what keeps a pod (whose IP is in the pod CIDR) from standing in
// for a node. Implementations: CIDRHosts (operator-given CIDRs, static) and
// NodeHosts (derived live from the cluster's node objects).
type InventoryHosts interface {
	// Contains reports whether host is inside the set. An empty set contains
	// nothing: callers must fail closed rather than dial anywhere.
	Contains(host string) bool
	// Empty reports whether the set currently holds nothing.
	Empty() bool
}

// CIDRHosts is the static InventoryHosts parsed from operator-given CIDRs.
type CIDRHosts []*net.IPNet

// ParseInventoryHosts builds the set from CIDR strings.
func ParseInventoryHosts(cidrs []string) (CIDRHosts, error) {
	out := make(CIDRHosts, 0, len(cidrs))
	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("workloadclaims: inventory CIDR %q: %w", c, err)
		}
		out = append(out, network)
	}
	return out, nil
}

func (h CIDRHosts) Contains(host string) bool { return cidrSet(h).contains(host) }
func (h CIDRHosts) Empty() bool               { return len(h) == 0 }

// ResolveAdvertiseHost returns the node IP an inventory signs into its sandbox
// tokens. An explicit host always wins; the chart supplies one from the
// installer DaemonSet's downward API (status.hostIP). cdsEndpoint is the
// enforcer's pull config verbatim — a URL or a bare host[:port]; a URL's host
// is used when it parses as one, so every enforcer derives the callback host
// the same way.
//
// Inference is the fallback and is deliberately weak: it asks the routing table
// which local address would reach the CDS host. That answer is wrong whenever
// CDS is reached over loopback — which the chart's own default does, since the
// plugin dials the CDS NodePort on 127.0.0.1 — so it fails loudly rather than
// advertising something CDS could never dial back.
// ctx bounds the lookup's name resolution, which net.Dial would otherwise
// block on without limit.
func ResolveAdvertiseHost(ctx context.Context, host, cdsEndpoint string) (string, error) {
	if u, err := url.Parse(cdsEndpoint); err == nil && u.Host != "" {
		cdsEndpoint = u.Host
	}
	if host == "" {
		var err error
		if host, err = outboundHost(ctx, cdsEndpoint); err != nil {
			return "", fmt.Errorf("workloadclaims: infer the inventory advertise host (set it explicitly): %w", err)
		}
	}
	return parseInventoryHost(host)
}

// outboundHost reports the local IP the kernel would source from when talking
// to target. The UDP socket is unconnected on the wire — no packet is sent —
// so this is a routing-table lookup, not a reachability test.
func outboundHost(ctx context.Context, target string) (string, error) {
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", target)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "", err
	}
	return host, nil
}

// DigestsServerTLSConfig builds the inventory's listener config for
// ServeDigests: it presents an RA-TLS certificate proving the inventory runs in
// a TEE, and requires the caller to present a hardware-attested one too. With
// cdsPins set the caller must satisfy them (launch measurement, and TDX RTMRs
// when pinned), so the endpoint discloses what a node runs only to a CDS on an
// expected measurement; zero pins accept any TEE on the network. UNSAFE
// outside development; callers warn.
func DigestsServerTLSConfig(platform string, attestFunc func(ctx context.Context, customData string) (string, error), attestationApiURL string, cdsPins ratls.Pins, certTTL time.Duration) (*tls.Config, *ratls.CertManager, error) {
	if err := requireAttestationApi(attestationApiURL); err != nil {
		return nil, nil, err
	}
	return ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:     platform,
		AttestFunc:   attestFunc,
		CertTTL:      certTTL,
		ClientPolicy: cdsPins.VerifyPolicy(attestationApiURL),
	})
}

// requireAttestationApi rejects an empty attestation-api URL at construction.
// Both sides feed it to a ratls.VerifyPolicy, which fails closed without one —
// catching it here makes a missing URL a startup error instead of a handshake
// failure inside the first pod's issuance deadline.
func requireAttestationApi(url string) error {
	if url == "" {
		return fmt.Errorf("workloadclaims: the sandbox-digests callback requires an attestation-api URL to verify its peer against")
	}
	return nil
}

// StartDigestsEndpoint binds DigestsPort and serves the identity and digests
// routes for the node's NRI inventory.
//
// The listener is bound before the certificate warm-up so a token never names a
// port nothing is listening on, and so a port conflict surfaces immediately
// rather than after the warm-up window. Warm-up failure is logged, not fatal:
// the endpoint provisions on the first handshake instead, and taking the
// inventory down would cost far more than a slow first callback.
func StartDigestsEndpoint(ctx context.Context, logger *slog.Logger, resolver SandboxResolver, identity []byte, platform string, attestFunc func(ctx context.Context, customData string) (string, error), attestationApiURL string, cdsPins ratls.Pins) error {
	tlsCfg, certMgr, err := DigestsServerTLSConfig(platform, attestFunc, attestationApiURL, cdsPins, 0)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort("", strconv.Itoa(listenPort))
	l, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	go func() {
		warmupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := certMgr.WarmUp(warmupCtx)
		cancel()
		if err != nil {
			logger.Error("sandbox-digests cert warm-up failed; the endpoint will provision on first handshake", "error", err)
		}
		logger.Info("starting sandbox-digests endpoint", "addr", addr)
		if err := ServeDigests(ctx, l, resolver, identity); err != nil {
			logger.Error("sandbox-digests endpoint error", "error", err)
		}
	}()
	return nil
}

// DigestsClient is CDS's side of the callback: an RA-TLS client that verifies
// the inventory's attestation — pinning its launch measurement when one is
// configured — and presents CDS's own RA-TLS certificate, so the inventory can
// pin CDS in turn.
type DigestsClient struct {
	http    *http.Client
	timeout time.Duration
}

// NewDigestsClient builds the client. pins hold the launch digests (and any
// TDX RTMR pins) an inventory may present — the same allowlist CDS pins for
// the inventory's RA-TLS certificate, so a sandbox token and the callback that
// follows it are held to one standard. Zero pins accept any RA-TLS-attested
// inventory, matching what an empty allowlist already means for the certificate:
// UNSAFE outside development; callers warn.
//
// It warms its own RA-TLS certificate before returning: provisioning costs an
// attestation round-trip, and paying it lazily would put it inside the first
// pod's issuance deadline.
func NewDigestsClient(ctx context.Context, platform string, attestFunc func(ctx context.Context, customData string) (string, error), attestationApiURL string, pins ratls.Pins, timeout time.Duration) (*DigestsClient, error) {
	if err := requireAttestationApi(attestationApiURL); err != nil {
		return nil, err
	}
	tlsCfg, certMgr, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:     pins.VerifyPolicy(attestationApiURL),
		Platform:   platform,
		AttestFunc: attestFunc,
	})
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: build sandbox-digests client: %w", err)
	}
	warmupCtx, cancel := context.WithTimeout(ctx, warmUpBudget)
	defer cancel()
	if err := warmUpCert(warmupCtx, certMgr); err != nil {
		return nil, fmt.Errorf("workloadclaims: warm up sandbox-digests client cert: %w", err)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &DigestsClient{
		http: &http.Client{
			Timeout: timeout,
			// Fresh Transport, so Proxy stays nil: no HTTP_PROXY can interpose
			// on a call whose whole point is to reach one attested peer. The
			// idle pool is bounded because the dial target is chosen by the
			// requester: unbounded, never-expiring idle conns would be a
			// retention primitive rather than a reuse optimisation.
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     30 * time.Second,
			},
		},
		timeout: timeout,
	}, nil
}

const (
	// Budget for provisioning the client certificate at startup.
	warmUpBudget = 30 * time.Second
	// Gap between attempts. The attestation API is reached over a DaemonSet's
	// Unix socket, so the common failure is "not there yet" rather than "slow".
	warmUpInterval = time.Second
)

// certWarmer is the slice of ratls.CertManager this needs, so the retry can be
// tested without provisioning a real certificate.
type certWarmer interface {
	WarmUp(context.Context) error
}

// peerNotUpYet reports whether err means the attestation API is not listening
// yet, as opposed to answering and refusing. Only the former is worth waiting
// on: a live peer that rejects us is a real failure and must fail closed.
func peerNotUpYet(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// warmUpCert retries only while the attestation API has not come up, returning
// the last failure once ctx's budget is spent.
//
// A single attempt is not enough: the attestation API lives on a DaemonSet
// socket that may not exist yet when CDS starts, and lstat on a missing socket
// fails instantly. One attempt therefore leaves the whole budget unspent and
// aborts startup for a peer that is usually seconds away. That is expensive
// because the allowlist is not persistent, so CDS exiting here drops every
// operator-added digest on restart.
//
// Anything else returns immediately, so a peer that answers and refuses still
// fails closed at once rather than after the budget. WarmUp caches on success,
// so the repeated calls cost nothing once provisioning lands.
func warmUpCert(ctx context.Context, w certWarmer) error {
	for {
		err := w.WarmUp(ctx)
		if err == nil {
			return nil
		}
		if !peerNotUpYet(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(warmUpInterval):
		}
	}
}

// ErrSandboxUnknown reports that the inventory does not know the sandbox — it
// never admitted it, or the pod is already gone. Distinguished from a
// transport or policy failure so the caller can say which happened; both are
// fail-closed for issuance.
var ErrSandboxUnknown = fmt.Errorf("workloadclaims: inventory does not know this sandbox")

// InventoryKey fetches the sandbox-token signing key of the inventory on host.
//
// This is what gives an inventory an identity CDS can check. The key arrives
// over RA-TLS from DigestsPort — a privileged port in the node's own network
// namespace — so answering here requires a privilege the chart's
// deny-host-namespaces policy withholds from tenant pods. Sharing the node's
// launch measurement, which every pod on a node-CVM does, is not enough.
func (c *DigestsClient) InventoryKey(ctx context.Context, host string) (*ecdsa.PublicKey, error) {
	resp, err := c.get(ctx, host, IdentityPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("workloadclaims: inventory %s identity returned %d", host, resp.StatusCode)
	}
	var out InventoryIdentity
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return nil, fmt.Errorf("workloadclaims: decode inventory identity: %w", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("workloadclaims: parse inventory key: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("workloadclaims: inventory key is not ECDSA")
	}
	return pub, nil
}

// get dials the inventory on host at DigestsPort and performs a GET.
func (c *DigestsClient) get(ctx context.Context, host, route string) (*http.Response, error) {
	dialHost, err := parseInventoryHost(host)
	if err != nil {
		return nil, err
	}
	// The timeout also bounds reading the body, which the caller does after
	// this returns, so it is cancelled when the body is closed rather than
	// here. Cancelling on return aborts a body that has not fully arrived yet,
	// which happens whenever the inventory is on another host.
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	url := "https://" + net.JoinHostPort(dialHost, strconv.Itoa(dialPort)) + route
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("workloadclaims: reach inventory %s: %w", dialHost, err)
	}
	resp.Body = cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelOnClose releases a request's context when its body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// Fetch asks the inventory on host which image digests sandboxID is running.
// host comes from the verified sandbox token, so it names the inventory that
// vouched for the sandbox.
func (c *DigestsClient) Fetch(ctx context.Context, host, sandboxID string) ([]string, error) {
	out, err := c.FetchSandbox(ctx, host, sandboxID)
	if err != nil {
		return nil, err
	}
	return out.Digests, nil
}

// ErrSandboxContainersUnsupported reports an inventory that answers with digests
// but no per-container detail — one older than the field. Distinguished so a
// caller that needs (digest, argv) fails closed on it instead of silently
// matching on digests alone.
var ErrSandboxContainersUnsupported = fmt.Errorf("workloadclaims: inventory does not report per-container detail")

// FetchSandbox is Fetch with the per-container (digest, argv) detail secret
// release needs. It fails closed when the inventory reports containers it could
// not fully resolve, and when it reports none at all for a sandbox that has
// digests.
func (c *DigestsClient) FetchSandbox(ctx context.Context, host, sandboxID string) (SandboxDigestsResponse, error) {
	var out SandboxDigestsResponse
	if err := ratls.ValidateSandboxID(sandboxID); err != nil {
		return out, err
	}
	resp, err := c.get(ctx, host, SandboxDigestsPrefix+sandboxID)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return out, ErrSandboxUnknown
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return out, fmt.Errorf("workloadclaims: inventory %s returned %d: %s", host, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return out, fmt.Errorf("workloadclaims: decode inventory response: %w", err)
	}
	return out, nil
}

// RequireContainers returns the per-container detail, refusing an answer that
// cannot support a (digest, argv) decision.
func (r SandboxDigestsResponse) RequireContainers() ([]SandboxContainer, error) {
	if len(r.Containers) == 0 {
		if len(r.Digests) == 0 {
			return nil, fmt.Errorf("workloadclaims: inventory reports no containers")
		}
		return nil, ErrSandboxContainersUnsupported
	}
	for _, c := range r.Containers {
		if c.Digest == "" {
			return nil, fmt.Errorf("workloadclaims: inventory reported a container with no digest")
		}
	}
	return r.Containers, nil
}
