package cdsha

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// One attested TLS port carries both peer protocols, told apart by the first
// byte after the handshake: Raft's RPCs, and the replica control channel.
const (
	muxRaft    byte = 'R'
	muxControl byte = 'C'

	handshakeDeadline = 10 * time.Second
	controlDeadline   = 30 * time.Second
	maxControlBytes   = 8 << 20
	maxInboundSockets = 64
	acceptBackoff     = 50 * time.Millisecond
)

var errTransportClosed = errors.New("cds-ha peer transport closed")

// controlHandler answers one control request, each side one JSON value.
type controlHandler func(from peer, request json.RawMessage) json.RawMessage

// raftAddr is a member's Raft address: where it listens, and which member it
// is. A Raft RPC names only its sender, so without the member id a process
// restarted at an address answers for the member that held it before.
type raftAddr struct {
	endpoint netip.AddrPort
	member   string
}

func (a raftAddr) Network() string { return "tcp" }

func (a raftAddr) String() string { return a.endpoint.String() + "#" + a.member }

// parseRaftAddr reads the address a Raft configuration holds.
func parseRaftAddr(address raft.ServerAddress) (raftAddr, error) {
	endpoint, member, named := strings.Cut(string(address), "#")
	if !named {
		return raftAddr{}, fmt.Errorf("raft address %q names no member", address)
	}
	listening, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return raftAddr{}, fmt.Errorf("raft address %q: %w", address, err)
	}
	if err := checkMemberID(member); err != nil {
		return raftAddr{}, fmt.Errorf("raft address %q: %w", address, err)
	}
	return raftAddr{endpoint: listening, member: member}, nil
}

// peerTLSConfig serves and dials with the peer certificate cert returns, and
// checks no chain: peerVerifier.handshake admits the peer instead.
func peerTLSConfig(cert func() *tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		ClientAuth:           tls.RequireAnyClientCert,
		InsecureSkipVerify:   true, //nolint:gosec // attestation, not PKI, admits a peer (peerVerifier.admit)
		GetCertificate:       func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert(), nil },
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert(), nil },
	}
}

// mux accepts attested connections on the peer port and routes them: Raft
// connections to the stream layer, control connections to the handler.
type mux struct {
	ln       net.Listener
	tls      *tls.Config
	verifier peerVerifier
	advert   raftAddr
	control  controlHandler
	raftConn chan net.Conn
	done     chan struct{}
	stop     sync.Once
	refusals refusalLog

	// mu serializes admission against the connections already admitted.
	mu      sync.Mutex
	inbound map[*inboundConn]struct{}
	peers   map[*peerConn]struct{}
}

// newMux serves peers on ln, as the member advert names. It owns ln, and
// closes it and every connection on Close.
func newMux(
	ln net.Listener,
	advert raftAddr,
	cert func() *tls.Certificate,
	verifier peerVerifier,
	control controlHandler,
) *mux {
	m := &mux{
		ln:       ln,
		tls:      peerTLSConfig(cert),
		verifier: verifier,
		advert:   advert,
		control:  control,
		raftConn: make(chan net.Conn),
		done:     make(chan struct{}),
		refusals: newRefusalLog(),
		inbound:  map[*inboundConn]struct{}{},
		peers:    map[*peerConn]struct{}{},
	}
	go m.serve()
	return m
}

// inboundConn owns an accepted socket from admission through protocol close.
// It closes the raw socket, so shutdown never waits for a TLS close_notify.
type inboundConn struct {
	net.Conn
	mux *mux
}

func (c *inboundConn) Close() error {
	c.mux.forgetSocket(c)
	return c.Conn.Close()
}

// peerConn is a live attested connection and the peer that made it. TLS
// admits a peer once, at the handshake, and Raft keeps its connections open,
// so recheck judges them again.
type peerConn struct {
	*tls.Conn
	mux  *mux
	peer peer
}

func (c *peerConn) Close() error {
	c.mux.forgetPeer(c)
	return c.Conn.Close()
}

func (m *mux) forgetSocket(socket *inboundConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.inbound, socket)
}

func (m *mux) forgetPeer(connection *peerConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, connection)
}

func (m *mux) serve() {
	for {
		raw, err := m.ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			time.Sleep(acceptBackoff)
			continue
		}
		if socket := m.admit(raw); socket != nil {
			go m.route(socket)
		}
	}
}

func (m *mux) closed() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

// admit takes ownership of an accepted socket while the inbound bound leaves
// room for it, handshakes included.
func (m *mux) admit(raw net.Conn) *inboundConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() || len(m.inbound) >= maxInboundSockets {
		raw.Close()
		return nil
	}
	socket := &inboundConn{Conn: raw, mux: m}
	m.inbound[socket] = struct{}{}
	return socket
}

// route hands an accepted socket to the protocol its first byte names.
func (m *mux) route(socket *inboundConn) {
	handshake := m.verifier.handshake(m.tls)
	server := tls.Server(socket, handshake.config)
	_ = server.SetDeadline(time.Now().Add(handshakeDeadline))
	if err := server.Handshake(); err != nil {
		m.refusals.record(socket.RemoteAddr(), handshakeStage(err), err)
		server.Close()
		return
	}
	var kind [1]byte
	if _, err := io.ReadFull(server, kind[:]); err != nil {
		server.Close()
		return
	}
	connection, err := m.register(server, handshake.admitted)
	if err != nil {
		m.refusals.record(socket.RemoteAddr(), "admission", err)
		server.Close()
		return
	}
	switch kind[0] {
	case muxRaft:
		m.serveRaft(connection)
	case muxControl:
		m.serveControl(connection)
	default:
		connection.Close()
	}
}

// handshakeStage separates a peer this replica did not admit from a
// connection that broke before it said who it was.
func handshakeStage(err error) string {
	if errors.Is(err, errPeerIdentity) {
		return "peer identity"
	}
	return "handshake"
}

// serveRaft hands a Raft connection to the stream layer, once its sender
// names this member as the target.
func (m *mux) serveRaft(connection *peerConn) {
	_ = connection.SetDeadline(time.Now().Add(handshakeDeadline))
	target, err := readTarget(connection)
	if err != nil {
		m.refusals.record(connection.RemoteAddr(), "raft target", err)
		connection.Close()
		return
	}
	if target != m.advert.member {
		m.refusals.record(
			connection.RemoteAddr(),
			"raft target",
			fmt.Errorf("addressed to member %q, this is %q", target, m.advert.member),
		)
		connection.Close()
		return
	}
	_ = connection.SetDeadline(time.Time{})
	select {
	case m.raftConn <- connection:
	case <-m.done:
		connection.Close()
	}
}

func (m *mux) serveControl(connection *peerConn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(controlDeadline))
	var request json.RawMessage
	if err := json.NewDecoder(io.LimitReader(connection, maxControlBytes)).Decode(&request); err != nil {
		return
	}
	_ = json.NewEncoder(connection).Encode(m.control(connection.peer, request))
}

// register puts an attested connection in the set recheck sweeps, judging it
// once more against an admission set the handshake may have outlasted.
func (m *mux) register(connection *tls.Conn, admitted peer) (*peerConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return nil, errTransportClosed
	}
	if err := admitted.verdict.admittedBy(m.verifier.admits()); err != nil {
		return nil, err
	}
	registered := &peerConn{Conn: connection, mux: m, peer: admitted}
	m.peers[registered] = struct{}{}
	return registered, nil
}

// recheck cuts every connection the admission set no longer admits, joining
// the cluster included.
func (m *mux) recheck() {
	for _, connection := range m.peersToCut() {
		m.refusals.record(
			connection.RemoteAddr(),
			"admission set",
			errors.New("the admission set no longer admits this peer"),
		)
		connection.Close()
	}
}

// peersToCut names the connections recheck closes, which it does after this
// function has given the lock back.
func (m *mux) peersToCut() []*peerConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	images := m.verifier.admits()
	var cut []*peerConn
	for connection := range m.peers {
		if connection.peer.verdict.admittedBy(images) != nil {
			cut = append(cut, connection)
		}
	}
	return cut
}

// Accept, Close and Addr make the mux the listener half of the Raft stream
// layer.
func (m *mux) Accept() (net.Conn, error) {
	select {
	case connection := <-m.raftConn:
		return connection, nil
	case <-m.done:
		return nil, errTransportClosed
	}
}

func (m *mux) Close() error {
	var closed error
	m.stop.Do(func() {
		for _, connection := range m.stopServing() {
			connection.Close()
		}
		closed = m.ln.Close()
	})
	return closed
}

// stopServing refuses what comes next and reports every connection still
// open, which the caller closes once it has the lock back.
func (m *mux) stopServing() []io.Closer {
	m.mu.Lock()
	defer m.mu.Unlock()
	close(m.done)
	open := make([]io.Closer, 0, len(m.inbound)+len(m.peers))
	for socket := range m.inbound {
		open = append(open, socket)
	}
	for connection := range m.peers {
		open = append(open, connection)
	}
	return open
}

func (m *mux) Addr() net.Addr { return m.advert }

// Dial opens an attested Raft connection to the member the address names, and
// refuses another member answering there.
func (m *mux) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	target, err := parseRaftAddr(address)
	if err != nil {
		return nil, err
	}
	connection, admitted, err := m.dial(target.endpoint.String(), muxRaft, timeout)
	if err != nil {
		return nil, err
	}
	if admitted.member != target.member {
		connection.Close()
		return nil, fmt.Errorf("raft address %s is answered by member %q", address, admitted.member)
	}
	if err := writeTarget(connection, target.member, timeout); err != nil {
		connection.Close()
		return nil, err
	}
	registered, err := m.register(connection, admitted)
	if err != nil {
		connection.Close()
		return nil, err
	}
	return registered, nil
}

// call sends one control request to endpoint and names the peer that answers.
func (m *mux) call(endpoint string, timeout time.Duration, request json.RawMessage) (peer, json.RawMessage, error) {
	connection, admitted, err := m.dial(endpoint, muxControl, timeout)
	if err != nil {
		return peer{}, nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return peer{}, nil, fmt.Errorf("control request to %s: %w", endpoint, err)
	}
	var answer json.RawMessage
	if err := json.NewDecoder(io.LimitReader(connection, maxControlBytes)).Decode(&answer); err != nil {
		return peer{}, nil, fmt.Errorf("control answer from %s: %w", endpoint, err)
	}
	return admitted, answer, nil
}

// dial opens an attested connection of one kind, admitting the peer during
// the handshake. It leaves from whatever address the host routes it out of.
func (m *mux) dial(endpoint string, kind byte, timeout time.Duration) (*tls.Conn, peer, error) {
	handshake := m.verifier.handshake(m.tls)
	connection, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		endpoint,
		handshake.config,
	)
	if err != nil {
		return nil, peer{}, err
	}
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if _, err := connection.Write([]byte{kind}); err != nil {
		connection.Close()
		return nil, peer{}, err
	}
	return connection, handshake.admitted, nil
}

// The frame opening a Raft connection names the member it is for: one length
// byte, then that many bytes of member id.
func writeTarget(connection net.Conn, member string, timeout time.Duration) error {
	defer func() { _ = connection.SetDeadline(time.Time{}) }()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	_, err := connection.Write(append([]byte{byte(len(member))}, member...))
	return err
}

func readTarget(connection net.Conn) (string, error) {
	var length [1]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		return "", err
	}
	member := make([]byte, length[0])
	if _, err := io.ReadFull(connection, member); err != nil {
		return "", err
	}
	if err := checkMemberID(string(member)); err != nil {
		return "", err
	}
	return string(member), nil
}

// refusalLog records why a peer connection was closed, which the other side
// sees only as a reset: one entry per remote host and stage, logged once an
// interval and bounded, because a refused peer chooses its own key.
type refusalLog struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

const (
	refusalLogInterval = time.Minute
	maxRefusalKeys     = 1024
)

func newRefusalLog() refusalLog {
	return refusalLog{seen: map[string]time.Time{}}
}

func (l *refusalLog) record(remote net.Addr, stage string, reason error) {
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		host = remote.String()
	}
	if !l.claim(host+" "+stage, time.Now()) {
		return
	}
	slog.Info("cds-ha peer connection refused", "remote", host, "stage", stage, "error", reason)
}

// claim takes key's log slot for the interval, and reports whether it got
// one. At the key bound nothing further is logged until an interval passes,
// so a peer varying its host cannot flush another host's slot.
func (l *refusalLog) claim(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.seen[key]) < refusalLogInterval {
		return false
	}
	l.expire(now)
	if len(l.seen) >= maxRefusalKeys {
		return false
	}
	l.seen[key] = now
	return true
}

func (l *refusalLog) expire(now time.Time) {
	for key, at := range l.seen {
		if now.Sub(at) >= refusalLogInterval {
			delete(l.seen, key)
		}
	}
}

var _ raft.StreamLayer = (*mux)(nil)
