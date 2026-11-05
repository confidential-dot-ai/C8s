package nriimagepolicy

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

var testClusterDNS = netip.MustParseAddr("10.53.0.10")

// The kernel refuses a connect to a link-local address with no zone.
var undialableDNS = netip.MustParseAddrPort("[fe80::1]:53")

func TestClusterFirstDialerResolvesThroughTheClusterDNS(t *testing.T) {
	cds := acceptOn(t, "127.0.0.1")
	service := startClusterDNS(t, map[string][]netip.Addr{
		"cds.private.": {netip.MustParseAddr("127.0.0.1")},
	})

	conn, err := clusterFirstDialer(service).DialContext(t.Context(), "tcp", net.JoinHostPort("cds.private", cds.port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if reached := <-cds.reached; reached != "127.0.0.1:"+cds.port {
		t.Fatalf("the connection reached %q, want the address the cluster DNS answered", reached)
	}
}

func TestClusterFirstDialerTriesEveryAddressTheNameAnswers(t *testing.T) {
	cds := acceptOn(t, "127.0.0.9")
	service := startClusterDNS(t, map[string][]netip.Addr{
		"cds.replicas.": {
			netip.MustParseAddr("127.0.0.2"), // no replica answers here
			netip.MustParseAddr("127.0.0.9"),
		},
	})

	conn, err := clusterFirstDialer(service).DialContext(t.Context(), "tcp", net.JoinHostPort("cds.replicas", cds.port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if reached := <-cds.reached; reached != "127.0.0.9:"+cds.port {
		t.Fatalf("the connection reached %q, want the replica behind the second answer", reached)
	}
}

func TestClusterResolverFallsBackToTheNodeServer(t *testing.T) {
	nodeServer := startClusterDNS(t, nil)

	conn, err := clusterResolver(undialableDNS).Dial(t.Context(), "udp", nodeServer.String())
	if err != nil {
		t.Fatalf("dial the node's server: %v", err)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != nodeServer.String() {
		t.Fatalf("query sent to %v, want the node's own server %v", conn.RemoteAddr(), nodeServer)
	}
}

// cdsStandIn reports the address each connection reached it on.
type cdsStandIn struct {
	port    string
	reached chan string
}

func acceptOn(t *testing.T, host string) *cdsStandIn {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("listen address: %v", err)
	}
	cds := &cdsStandIn{port: port, reached: make(chan string, 1)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			cds.reached <- conn.LocalAddr().String()
			conn.Close()
		}
	}()
	return cds
}

// startClusterDNS answers the A records it holds and NXDOMAINs every other name.
func startClusterDNS(t *testing.T, records map[string][]netip.Addr) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go serveClusterDNS(conn, records)
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func serveClusterDNS(conn *net.UDPConn, records map[string][]netip.Addr) {
	query := make([]byte, 512)
	for {
		n, from, err := conn.ReadFromUDP(query)
		if err != nil {
			return
		}
		reply, err := answerQuery(query[:n], records)
		if err != nil {
			continue
		}
		if _, err := conn.WriteToUDP(reply, from); err != nil {
			return
		}
	}
}

func answerQuery(query []byte, records map[string][]netip.Addr) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}
	reply := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{question},
	}
	held := records[question.Name.String()]
	if len(held) == 0 || question.Type != dnsmessage.TypeA {
		reply.RCode = dnsmessage.RCodeNameError
		return reply.Pack()
	}
	for _, address := range held {
		reply.Answers = append(reply.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			},
			Body: &dnsmessage.AResource{A: address.As4()},
		})
	}
	return reply.Pack()
}
