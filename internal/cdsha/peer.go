package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Heartbeat is a replica's public position (H1). Pulled, not pushed.
type Heartbeat struct {
	ClusterID      string `json:"cluster_id"`
	Epoch          uint64 `json:"epoch"`
	Term           uint64 `json:"term"`
	TailHash       []byte `json:"tail_hash,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"` // sha256(root_cert)
	Joined         bool   `json:"joined"`
	Serving        bool   `json:"serving"`
	Measurement    string `json:"measurement,omitempty"` // own, from own evidence (public)
}

// Tuple of a heartbeat, for comparison with local state.
func (h Heartbeat) Tuple() Tuple { return Tuple{Epoch: h.Epoch, Term: h.Term, Hash: h.TailHash} }

// syncResponse is a key transfer: the full chain and the tail's key (K3).
type syncResponse struct {
	Chain Chain  `json:"chain"`
	Key   []byte `json:"key"` // PKCS#8; only ever sent over attested TLS (K1)
}

const maxPeerBody = 4 << 20

func heartbeatOf(s State, serving bool, clusterID string) Heartbeat {
	hb := Heartbeat{ClusterID: clusterID, Joined: s.Joined(), Serving: serving}
	if len(s.Chain) > 0 {
		t := s.Chain.Tuple()
		hb.Epoch, hb.Term, hb.TailHash = t.Epoch, t.Term, t.Hash
		hb.KeyFingerprint = certutil.CertFingerprint(s.Chain.Tail().RootCert)
	}
	return hb
}

// peerHandler serves the replica-to-replica API. Every route sits behind
// mutually attested TLS (peerVerifier), checked again on each connection.
func (r *Replica) peerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ha/v1/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, r.Heartbeat())
	})
	mux.HandleFunc("GET /ha/v1/sync", r.handleSync)
	return mux
}

// handleSync transfers the chain and key (K1-K4). Q3: the receiver's attested
// measurement must be in the pin set of the tail being sent, so a replica
// excluded by the newest epoch never receives its key.
func (r *Replica) handleSync(w http.ResponseWriter, req *http.Request) {
	st, serving := r.snapshot()
	if !st.Joined() || !serving {
		http.Error(w, "not serving", http.StatusServiceUnavailable)
		return
	}
	claims, err := r.verifier.claims(req.TLS.PeerCertificates[0].Raw)
	if err != nil || !slices.Contains(st.Chain.Tail().Measurements, claims.Measurement) {
		r.event("KeyTransferRefused", "peer", req.RemoteAddr)
		http.Error(w, "peer not authorized for this epoch", http.StatusForbidden)
		return
	}
	key, err := x509.MarshalPKCS8PrivateKey(st.Key)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	r.event("KeyTransferred", "peer", req.RemoteAddr, "epoch", st.Chain.Tail().Epoch)
	writeJSON(w, syncResponse{Chain: st.Chain, Key: key})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// errSelf is returned when a "peer" presents our own certificate: we
// dialled ourselves (a VM cannot always know the address peers see).
var errSelf = errors.New("dialled self")

// peerClient dials peers with a fresh attested TLS connection per request.
type peerClient struct {
	http     *http.Client
	self     []byte // our own peer certificate (DER)
	verifier peerVerifier
	hbWait   time.Duration // heartbeat timeout
	syncWait time.Duration // key transfer timeout
}

func newPeerClient(cfg *tls.Config, v peerVerifier, t Timing) peerClient {
	return peerClient{
		self: cfg.Certificates[0].Certificate[0],
		http: &http.Client{Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DisableKeepAlives: true, // D15: no connection outlives a pin-set change
		}},
		verifier: v,
		hbWait:   t.Heartbeat,
		syncWait: t.AckTimeout,
	}
}

// do returns the peer's attested measurement along with the decoded body.
func (c peerClient) do(ctx context.Context, wait time.Duration, addr, path string, out any) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+path, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", errors.New("no peer certificate")
	}
	if bytes.Equal(resp.TLS.PeerCertificates[0].Raw, c.self) {
		return "", errSelf
	}
	claims, err := c.verifier.claims(resp.TLS.PeerCertificates[0].Raw)
	if err != nil {
		return "", err
	}
	return claims.Measurement, json.NewDecoder(io.LimitReader(resp.Body, maxPeerBody)).Decode(out)
}

func (c peerClient) heartbeat(ctx context.Context, addr string) (Heartbeat, error) {
	var hb Heartbeat
	_, err := c.do(ctx, c.hbWait, addr, "/ha/v1/heartbeat", &hb)
	return hb, err
}

// sync fetches a peer's state and the measurement it attested with.
func (c peerClient) sync(ctx context.Context, addr string) (State, string, error) {
	var resp syncResponse
	meas, err := c.do(ctx, c.syncWait, addr, "/ha/v1/sync", &resp)
	if err != nil {
		return State{}, "", err
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(resp.Key)
	if err != nil {
		return State{}, "", fmt.Errorf("transferred key: %w", err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return State{}, "", errors.New("transferred key is not ECDSA")
	}
	return State{Chain: resp.Chain, Key: key}, meas, nil
}
