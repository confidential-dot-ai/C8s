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

// controlHandler answers one control request from an admitted peer.
type controlHandler func(from peer, request controlRequest) controlAnswer

// raftAddr is a member's Raft address: where it listens, and which member it
// is. A Raft RPC names only its sender, so without the member id a process
// restarted at an address answers for the member that held it before.
type raftAddr struct {
	endpoint netip.AddrPort
	member   string
}

func (a raftAddr) Network() string { return "tcp" }

func (a raftAddr) String() string { return a.endpoint.String() + "#" + a.member }

// serverAddress is this address as a Raft configuration holds it: every
// address in one is built here, so the configuration never carries two forms
// of the same one.
func (a raftAddr) serverAddress() raft.ServerAddress { return raft.ServerAddress(a.String()) }

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
	accept   sync.Once
	stop     sync.Once
	refusals refusalLog

	// mu serializes admission against the connections already admitted.
	mu      sync.Mutex
	inbound map[*inboundConn]struct{}
	peers   map[*peerConn]struct{}
}

// newMux prepares the peer port on ln, as the member advert names, and
// serving starts answering on it. It owns ln, and closes it and every
// connection on Close.
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
	return m
}

// serving accepts peers from now on, once.
func (m *mux) serving() {
	m.accept.Do(func() { go m.serve() })
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

// serveControl answers one control connection until the peer stops asking,
// so a replica handshakes with a peer once and not once per request.
func (m *mux) serveControl(connection *peerConn) {
	defer connection.Close()
	stream := newControlStream(connection)
	for {
		var request controlRequest
		if err := stream.read(&request, controlDeadline); err != nil {
			return
		}
		if err := stream.write(m.control(connection.peer, request), controlDeadline); err != nil {
			return
		}
	}
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

// connect opens a control connection to whatever member answers at endpoint.
// The handshake attests that member, so the connection is where this replica
// knows it to be.
func (m *mux) connect(endpoint netip.AddrPort, timeout time.Duration) (*controlConn, error) {
	connection, admitted, err := m.dial(endpoint.String(), muxControl, timeout)
	if err != nil {
		return nil, err
	}
	registered, err := m.register(connection, admitted)
	if err != nil {
		connection.Close()
		return nil, err
	}
	return &controlConn{
		member: admitted.member,
		conn:   registered,
		stream: newControlStream(registered),
	}, nil
}

// controlConn is the control connection this replica holds to one member: one
// exchange at a time, so its rechecks and its forwarded writes share it.
type controlConn struct {
	member string
	conn   *peerConn

	mu     sync.Mutex
	stream *controlStream
}

// exchange sends one request and reads the answer, refusing an answer that
// names another member than the handshake admitted.
func (c *controlConn) exchange(request controlRequest, within time.Duration) (controlAnswer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.stream.write(request, within); err != nil {
		return controlAnswer{}, c.broken(err)
	}
	var answer controlAnswer
	if err := c.stream.read(&answer, within); err != nil {
		return controlAnswer{}, c.broken(err)
	}
	if answer.Member != c.member {
		return controlAnswer{}, c.broken(fmt.Errorf("member %s answered for member %s", answer.Member, c.member))
	}
	return answer, nil
}

// attested is the verdict the member on the other side was admitted on.
func (c *controlConn) attested() verdict {
	return c.conn.peer.verdict
}

// broken closes a connection whose exchange failed: the bytes left on it
// belong to a request the next exchange could not tell from its own.
func (c *controlConn) broken(err error) error {
	c.conn.Close()
	return fmt.Errorf("control exchange with member %s: %w", c.member, err)
}

func (c *controlConn) close() {
	c.conn.Close()
}

// controlStream carries the JSON values of one control connection, each
// bounded in bytes and in time.
type controlStream struct {
	conn    net.Conn
	bounded *io.LimitedReader
	decoder *json.Decoder
	encoder *json.Encoder
}

func newControlStream(conn net.Conn) *controlStream {
	bounded := &io.LimitedReader{R: conn, N: maxControlBytes}
	return &controlStream{
		conn:    conn,
		bounded: bounded,
		decoder: json.NewDecoder(bounded),
		encoder: json.NewEncoder(conn),
	}
}

func (s *controlStream) read(v any, within time.Duration) error {
	s.bounded.N = maxControlBytes
	_ = s.conn.SetReadDeadline(time.Now().Add(within))
	return s.decoder.Decode(v)
}

func (s *controlStream) write(v any, within time.Duration) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(within))
	return s.encoder.Encode(v)
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
