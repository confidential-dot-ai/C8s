package cdsha

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// One attested TLS port carries two protocols, told apart by the first byte
// after the handshake: Raft's own RPCs, and the replica control channel
// (join, forwarded writes, status).
const (
	muxRaft    byte = 'R'
	muxControl byte = 'C'

	handshakeTimeout = 10 * time.Second
	maxControlBytes  = 8 << 20
)

// certHolder serves the replica's current peer certificate and replaces it
// before it expires. Each certificate carries fresh evidence over a new key.
type certHolder struct {
	mu   sync.RWMutex
	cert tls.Certificate
	made time.Time
	mint func() (tls.Certificate, error)
}

func newCertHolder(mint func() (tls.Certificate, error)) (*certHolder, error) {
	h := &certHolder{mint: mint}
	return h, h.renew()
}

func (h *certHolder) renew() error {
	c, err := h.mint()
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.cert, h.made = c, time.Now()
	h.mu.Unlock()
	return nil
}

func (h *certHolder) current() *tls.Certificate {
	h.mu.RLock()
	defer h.mu.RUnlock()
	c := h.cert
	return &c
}

func (h *certHolder) age() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return time.Since(h.made)
}

func peerTLSConfig(v peerVerifier, h *certHolder) *tls.Config {
	cfg := v.tlsConfig(tls.Certificate{})
	cfg.Certificates = nil
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return h.current(), nil }
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return h.current(), nil }
	return cfg
}

// controlHandler answers one control request from an attested peer.
type controlHandler func(peer Claims, req controlRequest) controlResponse

// mux accepts attested connections and routes them: Raft connections to the
// stream layer, control connections to the handler.
type mux struct {
	ln       net.Listener
	tls      *tls.Config
	verifier peerVerifier
	advert   net.Addr
	raftConn chan net.Conn
	control  controlHandler
	blocked  func(addr string) bool
	done     chan struct{}
	once     sync.Once

	connMu sync.Mutex
	conns  map[*peerConn]struct{}
}

// peerConn is a live attested connection and what its peer attested. TLS
// checks a peer once, at the handshake; Raft keeps connections open, so
// recheck closes any whose peer the current pin set no longer admits.
type peerConn struct {
	*tls.Conn
	m      *mux
	claims Claims
	once   sync.Once
}

func (c *peerConn) Close() error {
	c.once.Do(func() {
		c.m.connMu.Lock()
		delete(c.m.conns, c)
		c.m.connMu.Unlock()
	})
	return c.Conn.Close()
}

func newMux(bind string, advertise string, cfg *tls.Config, v peerVerifier, control controlHandler, blocked func(string) bool) (*mux, error) {
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, err
	}
	adv, err := net.ResolveTCPAddr("tcp", advertise)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("advertise address %q: %w", advertise, err)
	}
	m := &mux{ln: ln, tls: cfg, verifier: v, advert: adv, control: control, blocked: blocked,
		raftConn: make(chan net.Conn), done: make(chan struct{}), conns: map[*peerConn]struct{}{}}
	go m.serve()
	return m, nil
}

func (m *mux) track(c *tls.Conn) (*peerConn, error) {
	cs := c.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificate")
	}
	claims, err := m.verifier.claims(cs.PeerCertificates[0].Raw)
	if err != nil {
		return nil, err
	}
	pc := &peerConn{Conn: c, m: m, claims: claims}
	m.connMu.Lock()
	m.conns[pc] = struct{}{}
	m.connMu.Unlock()
	return pc, nil
}

// recheck closes every connection whose peer is no longer admitted: its
// measurement left the pin set, or (in tests) it is partitioned away.
func (m *mux) recheck() {
	pins := m.verifier.pins()
	m.connMu.Lock()
	var drop []*peerConn
	for c := range m.conns {
		if (pins != nil && !slices.Contains(pins, c.claims.Measurement)) || (m.blocked != nil && m.blocked(c.RemoteAddr().String())) {
			drop = append(drop, c)
		}
	}
	m.connMu.Unlock()
	for _, c := range drop {
		_ = c.Close()
	}
}

func (m *mux) serve() {
	for {
		c, err := m.ln.Accept()
		if err != nil {
			select {
			case <-m.done:
				return
			default:
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go m.route(c)
	}
}

func (m *mux) route(raw net.Conn) {
	if m.blocked != nil && m.blocked(raw.RemoteAddr().String()) {
		raw.Close()
		return
	}
	c := tls.Server(raw, m.tls)
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := c.Handshake(); err != nil {
		c.Close()
		return
	}
	var kind [1]byte
	if _, err := io.ReadFull(c, kind[:]); err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	pc, err := m.track(c)
	if err != nil {
		c.Close()
		return
	}
	switch kind[0] {
	case muxRaft:
		select {
		case m.raftConn <- pc:
		case <-m.done:
			pc.Close()
		}
	case muxControl:
		defer pc.Close()
		claims := pc.claims
		if m.control == nil {
			return
		}
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		var req controlRequest
		if err := json.NewDecoder(io.LimitReader(c, maxControlBytes)).Decode(&req); err != nil {
			return
		}
		_ = json.NewEncoder(c).Encode(m.control(claims, req))
	default:
		c.Close()
	}
}

// Accept, Close and Addr make the mux the Raft stream layer's listener.
func (m *mux) Accept() (net.Conn, error) {
	select {
	case c := <-m.raftConn:
		return c, nil
	case <-m.done:
		return nil, errors.New("cds-ha transport closed")
	}
}

func (m *mux) Close() error {
	m.once.Do(func() { close(m.done) })
	return m.ln.Close()
}

func (m *mux) Addr() net.Addr { return m.advert }

// Dial opens an attested Raft connection.
func (m *mux) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	if m.blocked != nil && m.blocked(string(address)) {
		return nil, errors.New("partitioned")
	}
	c, err := dialKind(string(address), timeout, m.tls, muxRaft, m.advert)
	if err != nil {
		return nil, err
	}
	pc, err := m.track(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	return pc, nil
}

// dialKind opens an attested connection of one kind. Connections leave from
// the advertised address, so peers see the address they know us by.
func dialKind(addr string, timeout time.Duration, cfg *tls.Config, kind byte, local net.Addr) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	if a, ok := local.(*net.TCPAddr); ok && a != nil {
		d.LocalAddr = &net.TCPAddr{IP: a.IP}
	}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte{kind}); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Control requests.
const (
	ctlJoin   = "join"
	ctlApply  = "apply"
	ctlStatus = "status"
)

type controlRequest struct {
	Op      string          `json:"op"`
	ID      string          `json:"id,omitempty"`
	Address string          `json:"address,omitempty"`
	Entry   json.RawMessage `json:"entry,omitempty"`
}

type controlResponse struct {
	Err      string          `json:"err,omitempty"`
	Leader   string          `json:"leader,omitempty"` // set when the receiver is not the leader
	Member   bool            `json:"member,omitempty"` // the receiver belongs to a Raft group
	Index    uint64          `json:"index,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
	Status   *Status         `json:"status,omitempty"`
}

func callControl(addr string, cfg *tls.Config, timeout time.Duration, req controlRequest, local net.Addr) (controlResponse, error) {
	c, err := dialKind(addr, timeout, cfg, muxControl, local)
	if err != nil {
		return controlResponse{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	w := bufio.NewWriter(c)
	if err := json.NewEncoder(w).Encode(req); err != nil {
		return controlResponse{}, err
	}
	if err := w.Flush(); err != nil {
		return controlResponse{}, err
	}
	var resp controlResponse
	if err := json.NewDecoder(io.LimitReader(c, maxControlBytes)).Decode(&resp); err != nil {
		return controlResponse{}, fmt.Errorf("control %s to %s: %w", req.Op, addr, err)
	}
	return resp, nil
}
