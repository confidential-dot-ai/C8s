package cdsobject

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const (
	ForwardPath      = "/ha/object-wal/append"
	maxForwardBody   = 12 << 20 // bounded 8 MiB batch plus JSON/base64 overhead
	maxIncomingBytes = 32 << 20
	forwardAuth      = "ObjectWAL-HMAC "
)

// Possession of the attested WAL key authorizes a replica. Domain separation
// prevents using an encrypted object or a request for another cluster as a MAC.
func deriveForwardKey(key []byte, launch cdsha.Launch) *[32]byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("cds-object-wal-forward-v1\x00" + launch.ClusterID + "\x00" + launch.ConfigSHA256))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return &result
}

func forwardMAC(key *[32]byte, body []byte) []byte {
	h := hmac.New(sha256.New, key[:])
	h.Write(body)
	return h.Sum(nil)
}

// Only literal addresses belonging to the measured replica hosts are dialed.
// DNS queries use the launch file's names, never a name supplied by the head.
func (n *Node) checkPeer(ctx context.Context, address string) error {
	peer, err := netip.ParseAddrPort(address)
	self, selfErr := netip.ParseAddrPort(n.cfg.Address)
	if err != nil || selfErr != nil || !peer.Addr().Is4() || peer.Addr().IsUnspecified() || peer.Port() == 0 || peer.Port() != self.Port() {
		return objectwal.ErrRequestMismatch
	}
	for _, host := range n.cfg.PeerHosts {
		if ip, err := netip.ParseAddr(host); err == nil {
			if ip == peer.Addr() {
				return nil
			}
			continue
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip == peer.Addr() {
				return nil
			}
		}
	}
	return objectwal.ErrRequestMismatch
}

func (n *Node) forwardingClient() (*http.Client, error) {
	if client := n.peerClient.Load(); client != nil {
		return client, nil
	}
	core := n.fsm.ClusterState()
	if core.PinsDecree == nil || core.PinsDecree.Decree.CDSPins == nil {
		return nil, errors.New("object WAL: no committed CDS pins")
	}
	pins, err := core.PinsDecree.Decree.CDSPins.WithLaunchFile(n.cfg.LaunchFile)
	if err != nil {
		return nil, err
	}
	client, err := armtls.NewVerifyingHTTPClient(armtls.Pins(pins.Policy()), n.cfg.AttestationURL)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// This pilot supports SetNodeImages, but no CDS image/launch rotation.
	if !n.peerClient.CompareAndSwap(nil, client) {
		client.CloseIdleConnections()
		client = n.peerClient.Load()
	}
	return client, nil
}

func (n *Node) forward(ctx context.Context, owner objectwal.Owner, request objectwal.ForwardRequest) error {
	if err := n.checkPeer(ctx, owner.Address); err != nil {
		return err
	}
	key := n.forwardKey.Load()
	if key == nil {
		return objectwal.ErrClosed
	}
	client, err := n.forwardingClient()
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	defer clear(body)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+owner.Address+ForwardPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// No Idempotency-Key and no replayable GetBody: a transport must not retry
	// this POST. Ambiguous outcomes are resolved by the originating WAL actor.
	r.GetBody = nil
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", forwardAuth+hex.EncodeToString(forwardMAC(key, body)))
	response, err := client.Do(r)
	if err != nil {
		return errors.New("object WAL: forwarding response unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch response.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return objectwal.ErrNotWriter
	case http.StatusTooManyRequests:
		return objectwal.ErrBackpressure
	case http.StatusBadRequest:
		return objectwal.ErrRequestMismatch
	default:
		return errors.New("object WAL: forwarding outcome unavailable")
	}
}

// ServeForward bypasses the public freshness gate: the WAL actor verifies the
// current head and owner itself. Going through that gate would deadlock a
// replica whose actor is waiting for a forwarded command's result.
func (n *Node) ServeForward(w http.ResponseWriter, r *http.Request) {
	key, wal := n.forwardKey.Load(), n.wal.Load()
	if key == nil || wal == nil {
		http.Error(w, "not provisioned", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, forwardAuth) || len(auth) != len(forwardAuth)+64 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	mac, err := hex.DecodeString(strings.TrimPrefix(auth, forwardAuth))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.ContentLength <= 0 || r.ContentLength > maxForwardBody {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	select {
	case n.incoming <- struct{}{}:
		defer func() { <-n.incoming }()
	default:
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	for {
		used := n.incomingBytes.Load()
		if used+r.ContentLength > maxIncomingBytes {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if n.incomingBytes.CompareAndSwap(used, used+r.ContentLength) {
			break
		}
	}
	defer n.incomingBytes.Add(-r.ContentLength)
	body, err := readutil.ReadAll(r.Body, r.ContentLength)
	if err != nil || int64(len(body)) != r.ContentLength {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer clear(body)
	if !hmac.Equal(mac, forwardMAC(key, body)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var request objectwal.ForwardRequest
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := d.Token(); err != io.EOF {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = wal.CommitForwarded(r.Context(), request)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, objectwal.ErrNotWriter):
		w.WriteHeader(http.StatusConflict)
	case errors.Is(err, objectwal.ErrBackpressure):
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	case errors.Is(err, objectwal.ErrRequestMismatch):
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}
