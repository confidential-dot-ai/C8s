package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about a peer that is not a member pod dialing a member's
// application address as a mesh peer, with a certificate the scenario
// chose, and the verdict of the member's mesh endpoint. The peer runs
// armtls-dial (tools/armtls-dial) in the mesh-dialer image.
func registerPeerVerify(sc *godog.ScenarioContext) {
	sc.Step(`^"([^"]*)" holds a copy of the CDS-issued leaf and key of "([^"]*)"$`, holdsCopiedLeaf)
	sc.Step(`^"([^"]*)" holds a leaf issued by a CA other than the cluster's mesh CA$`, holdsForeignLeaf)
	sc.Step(`^"([^"]*)" holds a self-signed certificate$`, holdsSelfSigned)
	sc.Step(`^"([^"]*)" connects to the application port of "([^"]*)" as a mesh peer$`, connectsAsMeshPeer)
	sc.Step(`^the mesh endpoint of "([^"]*)" refuses the peer$`, endpointRefusesPeer)
}

const (
	// peerAuthFailed is what a pod's endpoint logs for a refused handshake
	// (internal/cmds/armtlsmesh/podendpoint.go, handleInbound).
	peerAuthFailed = "peer authentication failed"
	// chainRefusal is how the chain path names a leaf that does not chain.
	chainRefusal = "mesh peer chain to a trusted mesh CA"
	// endpointLogWait bounds the wait for that line, which the endpoint may
	// write after the dialer has already read the alert.
	endpointLogWait = 10 * time.Second
)

// peerVerifyState is the certificate source each dialing pod presents, as
// armtls-dial flags, and what its last dial reported.
type peerVerifyState struct {
	flags map[*pod][]string
	last  *dialReport
	// refusalsBefore counts the endpoint's chain refusals of the dialer
	// before the last dial, so only a refusal of that dial counts.
	refusalsBefore int
	dest           *pod
	srcIP          string
}

// dialReport mirrors armtls-dial's report (tools/armtls-dial/dial.go).
type dialReport struct {
	TLS    bool   `json:"tls"`
	Error  string `json:"error"`
	Bytes  int    `json:"bytes"`
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// refusedByEndpoint is nil when the report shows the server refusing the
// client certificate: in TLS 1.3 the handshake returns on the client, and
// the server's alert arrives on the first read, before any application byte.
func refusedByEndpoint(r dialReport) error {
	switch {
	case !r.TLS:
		return fmt.Errorf("the dial never completed a tls handshake: %s", r.Error)
	case r.Status != 0 || r.Bytes != 0:
		return fmt.Errorf("the endpoint answered with status %d and %d bytes", r.Status, r.Bytes)
	case !strings.Contains(r.Error, "remote error: tls:"):
		return fmt.Errorf("the dial ended without a tls alert from the endpoint: %q", r.Error)
	}
	return nil
}

func (w *world) setPeerFlags(name string, flags ...string) error {
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if w.peerVerify.flags == nil {
		w.peerVerify.flags = map[*pod][]string{}
	}
	w.peerVerify.flags[p] = flags
	return nil
}

// holdsCopiedLeaf writes the owner's leaf and key into the dialer, which
// presents them as its own.
func holdsCopiedLeaf(ctx context.Context, name, owner string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	o, err := w.pod(owner)
	if err != nil {
		return err
	}
	crt, err := w.certFile(o, "tls.crt")
	if err != nil {
		return err
	}
	if crt == nil {
		return fmt.Errorf("%q holds no leaf the CDS issued", owner)
	}
	key, err := w.certFile(o, "tls.key")
	if err != nil {
		return err
	}
	if key == nil {
		// A backend that cannot read the key answers UNSUPPORTED, a skip.
		return fmt.Errorf("%q holds a leaf but no key beside it", owner)
	}
	script := fmt.Sprintf("cat > /tmp/peer.crt <<'PEM'\n%s\nPEM\ncat > /tmp/peer.key <<'PEM'\n%s\nPEM",
		strings.TrimSpace(string(crt)), strings.TrimSpace(string(key)))
	res, err := w.exec(p, script)
	if err != nil {
		return err
	}
	if res.rc != 0 {
		return fmt.Errorf("writing the leaf into %q exited %d:\n%s", name, res.rc, res.out)
	}
	return w.setPeerFlags(name, "--cert", "/tmp/peer.crt", "--key", "/tmp/peer.key")
}

func holdsForeignLeaf(ctx context.Context, name string) error {
	return getWorld(ctx).setPeerFlags(name, "--foreign-ca")
}

func holdsSelfSigned(ctx context.Context, name string) error {
	return getWorld(ctx).setPeerFlags(name, "--self-signed")
}

// connectsAsMeshPeer dials the destination's hello API from the dialer. The
// destination's packet rules redirect the connection to its mesh endpoint;
// the reply, if any, is the answer receivesHello reads.
func connectsAsMeshPeer(ctx context.Context, src, dest string) error {
	w := getWorld(ctx)
	p, err := w.pod(src)
	if err != nil {
		return err
	}
	d, err := w.pod(dest)
	if err != nil {
		return err
	}
	flags, ok := w.peerFlags(p)
	if !ok {
		return fmt.Errorf("the scenario has not said which certificate %q holds", src)
	}
	if d.hello == 0 {
		return fmt.Errorf("%q serves no hello API", dest)
	}
	ip, err := w.address(d)
	if err != nil {
		return err
	}
	srcIP, err := w.address(p)
	if err != nil {
		return err
	}
	if w.peerVerify.refusalsBefore, err = endpointRefusals(d, srcIP); err != nil {
		return err
	}
	w.peerVerify.dest, w.peerVerify.srcIP = d, srcIP
	res, err := w.exec(p, dialCommand(flags, ip, d.hello))
	if err != nil {
		return err
	}
	if res.rc != 0 {
		return fmt.Errorf("armtls-dial in %q exited %d:\n%s", src, res.rc, res.out)
	}
	var r dialReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.out)), &r); err != nil {
		return fmt.Errorf("armtls-dial in %q printed no report: %w\n%s", src, err, res.out)
	}
	w.peerVerify.last = &r
	w.podMesh.answer = res
	return nil
}

// peerFlags is the certificate choice made for p.
func (w *world) peerFlags(p *pod) ([]string, bool) {
	f, ok := w.peerVerify.flags[p]
	return f, ok
}

// fromSource is whether a log line names srcIP as its src: slog's text
// form (src=IP:port), or its JSON form, which writes a net.Addr as an object.
func fromSource(line, srcIP string) bool {
	return strings.Contains(line, "src="+srcIP+":") ||
		strings.Contains(line, `"src":"`+srcIP+`:`) ||
		strings.Contains(line, `"src":{"IP":"`+srcIP+`"`)
}

// chainRefusals counts the endpoint's log lines refusing a peer at srcIP
// because its leaf does not chain to a trusted mesh CA
// (pkg/armtls/tls.go, chainVerifyPeerCallback), so a refusal for another
// reason or of another peer does not count.
func chainRefusals(log, srcIP string) int {
	n := 0
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, peerAuthFailed) && strings.Contains(line, chainRefusal) &&
			fromSource(line, srcIP) {
			n++
		}
	}
	return n
}

// dialCommand is the armtls-dial command line for a mesh dial of ip:port.
// The address is single-quoted: an IPv6 one is bracketed, a glob to sh.
func dialCommand(flags []string, ip string, port int) string {
	args := append([]string{"armtls-dial", "--mesh"}, flags...)
	return strings.Join(args, " ") + " '" + net.JoinHostPort(ip, strconv.Itoa(port)) + "'"
}

// endpointRefusals counts the chain refusals of a peer at srcIP in the log
// of the pod's endpoint.
func endpointRefusals(p *pod, srcIP string) (int, error) {
	out, err := kubectl(nil, "-n", p.namespace, "logs", p.name, "-c", meshEndpointContainer)
	if err != nil {
		return 0, err
	}
	return chainRefusals(out, srcIP), nil
}

func endpointRefusesPeer(ctx context.Context, name string) error {
	w := getWorld(ctx)
	d, err := w.pod(name)
	if err != nil {
		return err
	}
	if w.peerVerify.last == nil || w.peerVerify.dest != d {
		return fmt.Errorf("no peer has connected to %q", name)
	}
	if err := refusedByEndpoint(*w.peerVerify.last); err != nil {
		return err
	}
	ok, err := poll(endpointLogWait, func() (bool, error) {
		n, err := endpointRefusals(d, w.peerVerify.srcIP)
		return n > w.peerVerify.refusalsBefore, err
	})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the dialer saw a tls alert, but the mesh endpoint of " + strconv.Quote(name) + " logged no chain refusal of " + w.peerVerify.srcIP + " within " + endpointLogWait.String())
	}
	return nil
}
