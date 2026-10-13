package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about the armTLS mesh: which pod traffic its proxies carry, what
// its guards drop, and what the inbound proxy makes of a peer that connects
// to it. Pods act through kubectl exec (busybox's wget, nc and ping); a peer
// is the armtls-dial tool in a pod of the "mesh-dialer" image, which dials
// the inbound proxy presenting the certificate the scenario described. The
// proxies are observed through the counters of the node's mesh pod and its
// ipsets, read by the backend.
func registerMesh(sc *godog.ScenarioContext) {
	sc.Step(`^the mesh proxy of node "([^"]*)" is running$`, meshRunning)
	sc.Step(`^"([^"]*)" serves a hello API$`, servesHello)
	sc.Step(`^"([^"]*)" serves a second hello API on another port$`, servesSecondHello)
	sc.Step(`^"([^"]*)" receives datagrams on (a port of its own|port 53)$`, receivesDatagrams)
	sc.Step(`^"([^"]*)" is a guarded pod$`, carriesWorkloadID)
	sc.Step(`^"([^"]*)" carries a non-empty confidential\.ai/cw label$`, carriesCWLabel)
	sc.Step(`^"([^"]*)" runs in the node's network namespace$`, hostNetwork)
	sc.Step(`^"([^"]*)" runs as neither the proxy UID nor an excluded UID$`, ordinaryUID)
	sc.Step(`^"([^"]*)" runs as an excluded UID$`, excludedUID)
	sc.Step(`^"([^"]*)" is in an excluded namespace$`, inExcludedNamespace)
	sc.Step(`^"([^"]*)" may bind port 53$`, mayBind53)
	sc.Step(`^"([^"]*)" is running$`, podRunning)
	sc.Step(`^"([^"]*)" is (not )?in the (interception|guard) membership of node "([^"]*)"$`, membership)
	sc.Step(`^node "([^"]*)" has an (IPv4|IPv6) address$`, nodeHasAddress)
	sc.Step(`^"([^"]*)" has an (IPv4|IPv6) address$`, podHasAddress)
	sc.Step(`^the port on which "([^"]*)" (receives datagrams|serves its hello API) lies in the range 32768–60999$`, portInRange)
	sc.Step(`^an endpoint "([^"]*)" at an external address serves a hello API$`, externalEndpoint)
	sc.Step(`^"([^"]*)" holds a CDS-issued leaf$`, holdsCDSLeaf)
	sc.Step(`^"([^"]*)" holds a self-signed attested TLS certificate$`, holdsSelfSigned)
	sc.Step(`^"([^"]*)" holds an attested TLS certificate whose issuer name is not its subject name$`, holdsIssuerDiffers)
	sc.Step(`^the NotAfter of that certificate was rewritten after it was signed$`, notAfterRewritten)
	sc.Step(`^the NotAfter of that certificate is one year from now$`, notAfterOneYear)
	sc.Step(`^the NotBefore of that certificate is (\d+) (minute|minutes|hour|hours) from now$`, notBeforeFromNow)
	sc.Step(`^the evidence of node "([^"]*)" satisfies the pins of its mesh proxy$`, pinsSatisfied)
	sc.Step(`^the (?:client|server) role of the mesh proxy of node "([^"]*)" presents a CDS-issued leaf$`, rolePresentsCDSLeaf)
	sc.Step(`^the verify set of the mesh proxy of node "([^"]*)" holds the mesh CA$`, verifySetHoldsCA)
	sc.Step(`^the local attestation service of node "([^"]*)" is unreachable$`, attestationUnreachable)
	sc.Step(`^a pod object "([^"]*)" is written with a node assignment other than node "([^"]*)"$`, ghostPod)
	sc.Step(`^"([^"]*)" is recorded with a pod address$`, ghostAddress)
	sc.Step(`^"([^"]*)" requests a hello from "([^"]*)"(?: (on its second port)| at its (IPv4|IPv6) address)?$`, requestsHello)
	sc.Step(`^"([^"]*)" sends a UDP datagram( from source port 53)? to( port 53 of)? "([^"]*)"$`, sendsDatagram)
	sc.Step(`^"([^"]*)" pings "([^"]*)"(?: at its IPv4 address)?$`, pings)
	sc.Step(`^"([^"]*)" opens a TCP connection from source port 53 to the hello API of "([^"]*)"$`, connectsFrom53)
	sc.Step(`^"([^"]*)" connects straight to the outbound proxy of node "([^"]*)" at the (node|loopback) address$`, connectsToOutbound)
	sc.Step(`^"([^"]*)" connects to the inbound proxy of node "([^"]*)" naming (the second port of )?"([^"]*)" as its destination$`, dialsInbound)
	sc.Step(`^"([^"]*)" receives (the hello|no hello)$`, receivesHello)
	sc.Step(`^the mesh proxy of node "([^"]*)" (carried the connection over armTLS|did not carry the connection)$`, carried)
	sc.Step(`^the datagram (reaches|does not reach) "([^"]*)"$`, datagramReaches)
	sc.Step(`^the inbound guard of node "([^"]*)" dropped the packet$`, guardDropped)
	sc.Step(`^"([^"]*)" receives no reply$`, noReply)
	sc.Step(`^the connection is not established$`, notEstablished)
	sc.Step(`^the connection is closed with no bytes relayed$`, closedWithNoBytes)
	sc.Step(`^the handshake (completes|fails)$`, handshake)
	sc.Step(`^no bytes are relayed$`, noBytesRelayed)
}

// The ports the backends' pods serve on, inside the inbound guard's
// 32768–60999 exception window so a scenario about that window holds.
const (
	helloPort       = 40080
	secondHelloPort = 40081
	datagramPort    = 40053
	hello           = "hello"
)

// The fixture names a pod's first container "curl" and the next ones
// "c2", "c3"... The steps act and read logs through them by name, so
// kubectl's "Defaulted container" notice never lands in what they parse.
const (
	firstContainer  = "curl"
	secondContainer = "c2"
)

// certRejected is what armtls-dial reports when the inbound proxy refused
// its certificate: TLS 1.3 alerts after the client has finished, so the
// handshake itself returned. A clean close (EOF) means the certificate was
// accepted and the destination was not.
const certRejected = "bad certificate"

// Bounds on what the mesh takes to show a change: its ipsets and the
// sidecar's drop counter move on a ~30s resync tick, the proxy's connection
// counter at once.
const (
	meshSync    = 90 * time.Second
	meshCounter = 60 * time.Second
	meshQuiet   = 10 * time.Second
)

// meshState is what the scenario last did on the mesh and saw.
type meshState struct {
	nodes     map[string]bool  // nodes whose mesh proxy the scenario named
	counters  map[string]int64 // node + counter → value before the last action
	answer    *execResult      // the last request a pod made
	dial      *dialReport      // the last peer connection a dialer made
	payload   string           // the datagram last sent
	ghosts    map[string]*pod  // pod objects written with another node's assignment
	ghostNode string           // the node the ghosts are not assigned to
	endpoints map[string]string
}

// execResult is what a pod's command printed and how it exited.
type execResult struct {
	out string
	rc  int
}

// dialReport is armtls-dial's report of one peer connection; the fields are
// the tool's (tools/armtls-dial/dial.go, report), which documents them.
type dialReport struct {
	TLS       bool   `json:"tls"`
	Handshake bool   `json:"handshake"`
	Error     string `json:"error"`
	Bytes     int    `json:"bytes"`
	Status    int    `json:"status"`
	Body      string `json:"body"`
}

// peerCert is the certificate a dialer in a pod presents: the pod's
// CDS-issued leaf, or a self-signed attested TLS certificate shaped as the
// scenario says. A self-signed one is minted when the dial happens, unless a
// sentence took away what minting needs first; then it is minted at that
// point and left in the pod as files.
type peerCert struct {
	leaf            bool
	selfSigned      bool
	issuerDiffers   bool
	notBefore       time.Duration
	notAfter        time.Duration
	rewriteNotAfter time.Duration
	files           []string // the minted certificate and key, once written
}

// mintedCert refuses a change to a certificate already minted.
func (c *peerCert) shapeable() error {
	if c.files != nil {
		return fmt.Errorf("the certificate has been minted already; say its shape before the attestation service goes away")
	}
	return nil
}

// --- Description-time sentences ---

func (w *world) undeployed(name string) (*pod, error) {
	p, err := w.pod(name)
	if err != nil {
		return nil, err
	}
	if p.deployed {
		return nil, fmt.Errorf("%q is already deployed", name)
	}
	return p, nil
}

func meshRunning(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	if _, err := w.be.call("mesh_ready", k8sNode); err != nil {
		return err
	}
	w.mesh.nodes[node] = true
	return nil
}

// helloSite writes the hello body where busybox's httpd will serve it.
func helloSite(port int) string {
	return fmt.Sprintf("mkdir -p /tmp/www%d && echo %s > /tmp/www%d/index.html", port, hello, port)
}

// helloServer is busybox's httpd over a directory holding the hello body.
func helloServer(port int) []string {
	return []string{"sh", "-c", fmt.Sprintf("%s && exec httpd -f -p %d -h /tmp/www%d", helloSite(port), port, port)}
}

func servesHello(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	p.containers[0].command = helloServer(helloPort)
	p.hello = []int{helloPort}
	return nil
}

// servesSecondHello starts a second httpd in the running pod: the sentence
// comes after the Background deployed it, and busybox's httpd daemonizes
// without -f, so it outlives the exec.
func servesSecondHello(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if len(p.hello) == 0 {
		return fmt.Errorf("%q serves no first hello API", name)
	}
	if !p.deployed {
		return fmt.Errorf("%q is not deployed; the second hello API starts in the running pod", name)
	}
	r, err := w.exec(p, fmt.Sprintf("%s && httpd -p %d -h /tmp/www%d >/dev/null 2>&1", helloSite(secondHelloPort), secondHelloPort, secondHelloPort))
	if err != nil {
		return err
	}
	if r.rc != 0 {
		return fmt.Errorf("the second hello API of %q did not start (exit %d):\n%s", name, r.rc, r.out)
	}
	p.hello = append(p.hello, secondHelloPort)
	return nil
}

// datagramListener is busybox's nc listening for UDP and echoing what it
// receives to its log, over and over: one nc serves one peer.
func datagramListener(port int) []string {
	return []string{"sh", "-c", fmt.Sprintf("while :; do nc -u -l -p %d -w 2 2>/dev/null; done", port)}
}

func receivesDatagrams(ctx context.Context, name, which string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	port := datagramPort
	if which == "port 53" {
		port = 53
		p.opts = append(p.opts, "--add-capability", "NET_BIND_SERVICE")
	}
	p.listener = firstContainer
	if len(p.hello) == 0 {
		p.containers[0].command = datagramListener(port)
	} else {
		p.listener = secondContainer
		p.containers = append(p.containers, &container{ref: p.containers[0].ref, command: datagramListener(port)})
	}
	p.datagram = port
	return nil
}

func carriesCWLabel(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	p.opts = append(p.opts, "--label", "confidential.ai/cw="+name)
	return nil
}

// elsewhere moves the pod into a namespace that is not the scenario's; its
// name takes the scenario's suffix so scenarios never collide there, and the
// After hook deletes it, since deleting the scenario namespace will not.
func (w *world) elsewhere(p *pod, fn string) error {
	ns, err := w.be.call(fn)
	if err != nil {
		return err
	}
	if p.namespace != "" && p.namespace != ns {
		return fmt.Errorf("%q is already placed in namespace %q", p.name, p.namespace)
	}
	p.namespace = ns
	if !strings.HasSuffix(p.name, w.suffix()) {
		p.name += "-" + w.suffix()
	}
	return nil
}

func hostNetwork(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	p.opts = append(p.opts, "--host-network")
	return w.elsewhere(p, "host_namespace_ns")
}

func (w *world) meshUIDs() (proxy string, excluded []string, err error) {
	out, err := w.be.call("mesh_uids")
	if err != nil {
		return "", nil, err
	}
	lines := strings.Fields(out)
	if len(lines) == 0 {
		return "", nil, fmt.Errorf("the backend named no mesh UIDs")
	}
	return lines[0], lines[1:], nil
}

// fixtureUID is the user the backend's pods run as unless told otherwise.
const fixtureUID = "1000"

func ordinaryUID(ctx context.Context, name string) error {
	w := getWorld(ctx)
	if _, err := w.undeployed(name); err != nil {
		return err
	}
	proxy, excluded, err := w.meshUIDs()
	if err != nil {
		return err
	}
	for _, uid := range append(excluded, proxy) {
		if uid == fixtureUID {
			return fmt.Errorf("the pods run as UID %s, which the mesh excepts", uid)
		}
	}
	return nil
}

func excludedUID(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	_, excluded, err := w.meshUIDs()
	if err != nil {
		return err
	}
	if len(excluded) == 0 {
		return godog.ErrSkip
	}
	p.opts = append(p.opts, "--run-as-user", excluded[0])
	return w.elsewhere(p, "host_namespace_ns")
}

func inExcludedNamespace(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	return w.elsewhere(p, "excluded_namespace")
}

func mayBind53(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	p.opts = append(p.opts, "--add-capability", "NET_BIND_SERVICE")
	return nil
}

// --- Pods running, membership, addresses ---

// nsOf is the namespace the pod lives in.
func (w *world) nsOf(p *pod) string {
	if p.namespace != "" {
		return p.namespace
	}
	return w.namespace
}

func (w *world) podJSON(p *pod) (map[string]any, error) {
	out, err := kubectl(nil, "-n", w.nsOf(p), "get", "pod", p.name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("pod %s: %w", p.name, err)
	}
	return doc, nil
}

// podIPs reads the pod's addresses from its status.
func (w *world) podIPs(p *pod) ([]string, string, error) {
	doc, err := w.podJSON(p)
	if err != nil {
		return nil, "", err
	}
	status, _ := doc["status"].(map[string]any)
	phase, _ := status["phase"].(string)
	var ips []string
	if list, ok := status["podIPs"].([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				if ip, ok := m["ip"].(string); ok && ip != "" {
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, phase, nil
}

func podRunning(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if !p.deployed {
		return fmt.Errorf("%q has not been deployed", name)
	}
	var phase string
	ok, err := poll(2*time.Minute, func() (bool, error) {
		var err error
		p.addrs, phase, err = w.podIPs(p)
		if err != nil {
			return false, err
		}
		if phase == "Failed" || phase == "Succeeded" {
			return false, fmt.Errorf("%q is %s", name, phase)
		}
		return phase == "Running" && len(p.addrs) > 0, nil
	})
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%q is %s without a pod address after 2 minutes", name, phase)
	}
	return nil
}

func (w *world) addressOf(p *pod, family string) (string, error) {
	if len(p.addrs) == 0 {
		return "", fmt.Errorf("%q has no pod address; the scenario must say it is running", p.name)
	}
	for _, ip := range p.addrs {
		if family == "" || isFamily(ip, family) {
			return ip, nil
		}
	}
	return "", godog.ErrSkip
}

func isFamily(ip, family string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	return (addr.To4() != nil) == (family == "IPv4")
}

func membership(ctx context.Context, name, not, kind, node string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	ip, err := w.addressOf(p, "")
	if err != nil {
		return err
	}
	member := func() (bool, error) {
		out, err := w.be.call("mesh_member", k8sNode, kind, ip)
		return out == "yes", err
	}
	if not == "" {
		ok, err := poll(meshSync, member)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s (%s) is not in the %s membership of node %q after %s", name, ip, kind, node, meshSync)
		}
		return nil
	}
	// Absence is asserted over a sync tick, so a membership not yet synced
	// is not mistaken for one that never comes.
	for deadline := time.Now().Add(meshSync / 3); time.Now().Before(deadline); time.Sleep(5 * time.Second) {
		yes, err := member()
		if err != nil {
			return err
		}
		if yes {
			return fmt.Errorf("%s (%s) is in the %s membership of node %q", name, ip, kind, node)
		}
	}
	return nil
}

func (w *world) nodeAddress(node, family string) (string, error) {
	k8sNode, err := w.node(node)
	if err != nil {
		return "", err
	}
	return w.be.call("node_address", k8sNode, strings.ToLower(family))
}

func nodeHasAddress(ctx context.Context, node, family string) error {
	_, err := getWorld(ctx).nodeAddress(node, family)
	return err
}

func podHasAddress(ctx context.Context, name, family string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	_, err = w.addressOf(p, family)
	return err
}

func portInRange(ctx context.Context, name, what string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	port := p.datagram
	if what == "serves its hello API" {
		if len(p.hello) == 0 {
			return fmt.Errorf("%q serves no hello API", name)
		}
		port = p.hello[0]
	}
	if port < 32768 || port > 60999 {
		return fmt.Errorf("%q uses port %d, outside 32768–60999", name, port)
	}
	return nil
}

func externalEndpoint(ctx context.Context, name string) error {
	w := getWorld(ctx)
	addr, err := w.be.call("external_endpoint")
	if err != nil {
		return err
	}
	w.mesh.endpoints[name] = addr
	return nil
}

// --- What a peer presents ---

func (w *world) cert(name string) (*pod, *peerCert, error) {
	p, err := w.pod(name)
	if err != nil {
		return nil, nil, err
	}
	if p.cert == nil {
		p.cert = &peerCert{notAfter: 24 * time.Hour}
	}
	return p, p.cert, nil
}

func holdsCDSLeaf(ctx context.Context, name string) error {
	if err := holdsLeaf(ctx, name); err != nil {
		return err
	}
	_, cert, err := getWorld(ctx).cert(name)
	if err != nil {
		return err
	}
	cert.leaf = true
	return nil
}

// lastCert is the certificate a "that certificate" sentence refines: the one
// the scenario last said a pod holds.
func (w *world) lastCert() (*peerCert, error) {
	if w.lastPod == nil || w.lastPod.cert == nil {
		return nil, fmt.Errorf("no certificate has been described")
	}
	return w.lastPod.cert, nil
}

func holdsSelfSigned(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, cert, err := w.cert(name)
	if err != nil {
		return err
	}
	if err := cert.shapeable(); err != nil {
		return err
	}
	cert.selfSigned = true
	w.lastPod = p
	return nil
}

func holdsIssuerDiffers(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, cert, err := w.cert(name)
	if err != nil {
		return err
	}
	if err := cert.shapeable(); err != nil {
		return err
	}
	cert.selfSigned, cert.issuerDiffers = true, true
	w.lastPod = p
	return nil
}

func notAfterRewritten(ctx context.Context) error {
	cert, err := getWorld(ctx).lastCert()
	if err != nil {
		return err
	}
	cert.rewriteNotAfter = 48 * time.Hour
	return nil
}

func notAfterOneYear(ctx context.Context) error {
	cert, err := getWorld(ctx).lastCert()
	if err != nil {
		return err
	}
	if err := cert.shapeable(); err != nil {
		return err
	}
	cert.notAfter = 365 * 24 * time.Hour
	return nil
}

func notBeforeFromNow(ctx context.Context, n int, unit string) error {
	cert, err := getWorld(ctx).lastCert()
	if err != nil {
		return err
	}
	if err := cert.shapeable(); err != nil {
		return err
	}
	d := time.Duration(n) * time.Minute
	if strings.HasPrefix(unit, "hour") {
		d = time.Duration(n) * time.Hour
	}
	cert.notBefore = d
	return nil
}

func pinsSatisfied(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	out, err := w.be.call("mesh_pins_satisfied", k8sNode)
	if err != nil {
		return err
	}
	if out != "yes" {
		return godog.ErrSkip
	}
	return nil
}

// rolePresentsCDSLeaf: the proxy reports one certificate mode for both its
// roles, so the sentence's role does not change what is asked.
func rolePresentsCDSLeaf(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	out, err := w.be.call("mesh_cert_mode", k8sNode)
	if err != nil {
		return err
	}
	if out != "cds" {
		return godog.ErrSkip
	}
	return nil
}

func verifySetHoldsCA(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	_, err = w.be.call("mesh_chain_ready", k8sNode)
	return err
}

// attestationUnreachable stops the node's local attestation service. A
// self-signed certificate a pod is to present needs that service for its
// evidence, so one described but not yet minted is minted first.
func attestationUnreachable(ctx context.Context, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	for _, p := range w.pods {
		if p.cert != nil && p.cert.selfSigned && p.cert.files == nil {
			if err := w.mintCert(p); err != nil {
				return err
			}
		}
	}
	w.onUndo(func() error { _, err := w.be.call("attestation_service_start", k8sNode); return err })
	_, err = w.be.call("attestation_service_stop", k8sNode)
	return err
}

// --- A pod object assigned elsewhere ---

// ghostNode is a Node object the steps write for the pod to be assigned to:
// a pod assigned to a node that does not exist is an orphan the pod garbage
// collector deletes within seconds. The node is tainted so no DaemonSet
// schedules onto it, and no kubelet ever reports for it.
const ghostNode = "conformance-elsewhere"

const ghostNodeManifest = `{"apiVersion":"v1","kind":"Node","metadata":{"name":"` + ghostNode + `"},` +
	`"spec":{"unschedulable":true,"taints":[{"key":"conformance.c8s/ghost","effect":"NoSchedule"},{"key":"conformance.c8s/ghost","effect":"NoExecute"}]}}`

func ghostPod(ctx context.Context, name, node string) error {
	w := getWorld(ctx)
	k8sNode, err := w.node(node)
	if err != nil {
		return err
	}
	if k8sNode == ghostNode {
		return fmt.Errorf("node %q is the one the ghost is assigned to", node)
	}
	refs, err := w.refs("tenant-app")
	if err != nil {
		return err
	}
	if w.mesh.ghostNode == "" {
		w.onUndo(func() error {
			_, err := kubectl(nil, "delete", "node", ghostNode, "--ignore-not-found", "--wait=false")
			return err
		})
		if _, err := kubectl([]byte(ghostNodeManifest), "apply", "-f", "-"); err != nil {
			return err
		}
		w.mesh.ghostNode = k8sNode
	}
	p := &pod{name: name, containers: []*container{{ref: refs[0], command: []string{"sleep", "3600"}}}}
	manifest, err := w.be.call("pod_manifest", p.name, w.namespace, ghostNode, refs[0], "sleep", "3600")
	if err != nil {
		return err
	}
	if _, err := kubectl([]byte(manifest), "apply", "-f", "-"); err != nil {
		return err
	}
	p.deployed = true
	w.mesh.ghosts[name] = p
	return nil
}

// ghostAddress writes a pod address into the object's status: one inside the
// node's own pod range that no pod holds, so the inbound proxy's locality
// check and not its range check decides, and a host address that is not the
// node's.
func ghostAddress(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, ok := w.mesh.ghosts[name]
	if !ok {
		return fmt.Errorf("no pod object %q has been written", name)
	}
	cidr, err := kubectl(nil, "get", "node", w.mesh.ghostNode, "-o", "jsonpath={.spec.podCIDR}")
	if err != nil {
		return err
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return fmt.Errorf("the node's pod range %q: %w", cidr, err)
	}
	ip := make(net.IP, len(network.IP))
	copy(ip, network.IP)
	ip[len(ip)-1] |= 0xfa // .250 of a /24
	for _, other := range w.pods {
		for _, held := range other.addrs {
			if held == ip.String() {
				return fmt.Errorf("the address %s chosen for the ghost is held by %q", ip, other.name)
			}
		}
	}
	status := fmt.Sprintf(`{"status":{"phase":"Running","podIP":%q,"podIPs":[{"ip":%q}],"hostIP":"203.0.113.9"}}`, ip, ip)
	if _, err := kubectl(nil, "-n", w.namespace, "patch", "pod", p.name, "--subresource=status", "--type=merge", "-p", status); err != nil {
		return err
	}
	p.addrs = []string{ip.String()}
	// The mesh learns of the object through its informer; give it a moment.
	time.Sleep(3 * time.Second)
	return nil
}

// --- Actions ---

// exec runs a shell script in the pod's first container and reports what it
// printed and its exit status, which a failing command does not turn into
// an error here.
func (w *world) exec(p *pod, script string) (*execResult, error) {
	out, err := kubectl(nil, "-n", w.nsOf(p), "exec", p.name, "-c", firstContainer, "--", "sh", "-c", script+"; echo \"rc=$?\"")
	if err != nil {
		return nil, err
	}
	idx := strings.LastIndex(out, "rc=")
	if idx < 0 {
		return nil, fmt.Errorf("the command in %q printed no exit status:\n%s", p.name, out)
	}
	rc, err := strconv.Atoi(strings.TrimSpace(out[idx+3:]))
	if err != nil {
		return nil, fmt.Errorf("exit status of the command in %q: %w", p.name, err)
	}
	return &execResult{out: out[:idx], rc: rc}, nil
}

// snapshot reads the counters of every mesh proxy the scenario named, so an
// outcome can tell what the action changed.
func (w *world) snapshot() error {
	for node := range w.mesh.nodes {
		k8sNode, err := w.node(node)
		if err != nil {
			return err
		}
		counters := []string{"inbound_connections", "guard_drops"}
		values, err := w.counters(k8sNode, counters...)
		if err != nil {
			return err
		}
		for i, counter := range counters {
			w.mesh.counters[node+"/"+counter] = values[i]
		}
	}
	return nil
}

// counters reads the named counters of the node's mesh proxy from one scrape.
func (w *world) counters(k8sNode string, counters ...string) ([]int64, error) {
	out, err := w.be.call("mesh_counter", append([]string{k8sNode}, counters...)...)
	if err != nil {
		return nil, err
	}
	lines := strings.Fields(out)
	if len(lines) != len(counters) {
		return nil, fmt.Errorf("the backend answered %d counters for %d asked: %q", len(lines), len(counters), out)
	}
	values := make([]int64, len(lines))
	for i, line := range lines {
		if values[i], err = strconv.ParseInt(line, 10, 64); err != nil {
			return nil, fmt.Errorf("the %s count of %s: %w", counters[i], k8sNode, err)
		}
	}
	return values, nil
}

func (w *world) counter(k8sNode, counter string) (int64, error) {
	values, err := w.counters(k8sNode, counter)
	if err != nil {
		return 0, err
	}
	return values[0], nil
}

// target is where a request goes: a pod's address and port, or an endpoint.
func (w *world) target(dest, family string, second bool) (string, error) {
	if addr, ok := w.mesh.endpoints[dest]; ok {
		return addr, nil
	}
	d, err := w.pod(dest)
	if err != nil {
		return "", err
	}
	if len(d.hello) == 0 {
		return "", fmt.Errorf("%q serves no hello API", dest)
	}
	port := d.hello[0]
	if second {
		if len(d.hello) < 2 {
			return "", fmt.Errorf("%q serves no second hello API", dest)
		}
		port = d.hello[1]
	}
	ip, err := w.addressOf(d, family)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip, strconv.Itoa(port)), nil
}

func (w *world) requestHello(src, dest, family string, second bool) error {
	p, err := w.pod(src)
	if err != nil {
		return err
	}
	addr, err := w.target(dest, family, second)
	if err != nil {
		return err
	}
	if err := w.snapshot(); err != nil {
		return err
	}
	w.mesh.answer, err = w.exec(p, fmt.Sprintf("wget -qO- -T 5 http://%s/ 2>&1", addr))
	return err
}

func requestsHello(ctx context.Context, src, dest, second, family string) error {
	return getWorld(ctx).requestHello(src, dest, family, second != "")
}

func (w *world) sendDatagram(src, dest string, port int, sourcePort int) error {
	p, err := w.pod(src)
	if err != nil {
		return err
	}
	d, err := w.pod(dest)
	if err != nil {
		return err
	}
	if port == 0 {
		port = d.datagram
	}
	if port == 0 {
		return fmt.Errorf("%q receives no datagrams", dest)
	}
	ip, err := w.addressOf(d, "")
	if err != nil {
		return err
	}
	if err := w.snapshot(); err != nil {
		return err
	}
	w.mesh.payload = fmt.Sprintf("datagram-%s-%d", w.suffix(), time.Now().UnixNano())
	from := ""
	if sourcePort != 0 {
		from = fmt.Sprintf(" -p %d", sourcePort)
	}
	_, err = w.exec(p, fmt.Sprintf("printf '%%s\\n' %s | nc -u -w 1%s %s %d", w.mesh.payload, from, ip, port))
	return err
}

func sendsDatagram(ctx context.Context, src, from53, to53, dest string) error {
	var port, sourcePort int
	if to53 != "" {
		port = 53
	}
	if from53 != "" {
		sourcePort = 53
	}
	return getWorld(ctx).sendDatagram(src, dest, port, sourcePort)
}

func pings(ctx context.Context, src, dest string) error {
	w := getWorld(ctx)
	p, err := w.pod(src)
	if err != nil {
		return err
	}
	d, err := w.pod(dest)
	if err != nil {
		return err
	}
	ip, err := w.addressOf(d, "IPv4")
	if err != nil {
		return err
	}
	if err := w.snapshot(); err != nil {
		return err
	}
	w.mesh.answer, err = w.exec(p, fmt.Sprintf("ping -c 1 -W 2 %s 2>&1", ip))
	return err
}

func connectsFrom53(ctx context.Context, src, dest string) error {
	w := getWorld(ctx)
	p, err := w.pod(src)
	if err != nil {
		return err
	}
	addr, err := w.target(dest, "", false)
	if err != nil {
		return err
	}
	if err := w.snapshot(); err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(addr)
	w.mesh.answer, err = w.exec(p, fmt.Sprintf("printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc -w 3 -p 53 %s %s 2>&1", host, port))
	return err
}

func connectsToOutbound(ctx context.Context, src, node, where string) error {
	w := getWorld(ctx)
	p, err := w.pod(src)
	if err != nil {
		return err
	}
	port, err := w.be.call("mesh_port", "outbound")
	if err != nil {
		return err
	}
	addr := "127.0.0.1"
	if where == "node" {
		if addr, err = w.nodeAddress(node, "ipv4"); err != nil {
			return err
		}
	}
	if err := w.snapshot(); err != nil {
		return err
	}
	w.mesh.answer, err = w.exec(p, fmt.Sprintf("printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc -w 3 %s %s 2>/dev/null", addr, port))
	return err
}

// dial runs armtls-dial in the pod against the node's inbound proxy, naming
// the destination, with the certificate the scenario described.
func (w *world) dial(src, node, dest string, second bool) error {
	p, cert, err := w.cert(src)
	if err != nil {
		return err
	}
	if !p.deployed {
		return fmt.Errorf("%q has not been deployed", src)
	}
	nodeAddr, err := w.nodeAddress(node, "ipv4")
	if err != nil {
		return err
	}
	inbound, err := w.be.call("mesh_port", "inbound")
	if err != nil {
		return err
	}
	var target string
	if ghost, ok := w.mesh.ghosts[dest]; ok {
		if len(ghost.addrs) == 0 {
			return fmt.Errorf("%q is recorded with no pod address", dest)
		}
		target = net.JoinHostPort(ghost.addrs[0], strconv.Itoa(helloPort))
	} else if target, err = w.target(dest, "", second); err != nil {
		return err
	}
	args := []string{"--timeout", "15s"}
	switch {
	case cert.leaf:
		certFile, keyFile, err := w.certPaths()
		if err != nil {
			return err
		}
		args = append(args, "--cert", certFile, "--key", keyFile)
	case cert.files != nil:
		args = append(args, "--cert", cert.files[0], "--key", cert.files[1])
	case cert.selfSigned:
		args = append(args, cert.mintArgs()...)
	default:
		return fmt.Errorf("the scenario has not said what certificate %q holds", src)
	}
	if cert.rewriteNotAfter != 0 {
		args = append(args, "--rewrite-not-after", cert.rewriteNotAfter.String())
	}
	if cert.selfSigned && cert.files == nil {
		var err error
		if args, err = w.mintFlags(args); err != nil {
			return err
		}
	}
	args = append(args, net.JoinHostPort(nodeAddr, inbound), target)
	if err := w.snapshot(); err != nil {
		return err
	}
	out, err := w.armtlsDial(p, args...)
	if err != nil {
		return err
	}
	var report dialReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return fmt.Errorf("armtls-dial in %q printed no report: %w\n%s", src, err, out)
	}
	w.mesh.dial = &report
	w.mesh.answer = &execResult{out: report.Body, rc: 0}
	if report.Status == 0 {
		w.mesh.answer.rc = 1
	}
	return nil
}

func dialsInbound(ctx context.Context, src, node, second, dest string) error {
	return getWorld(ctx).dial(src, node, dest, second != "")
}

// certPaths is where a pod carrying a workload ID holds its leaf and key.
func (w *world) certPaths() (certFile, keyFile string, err error) {
	paths, err := w.be.call("cert_paths")
	if err != nil {
		return "", "", err
	}
	files := strings.Fields(paths)
	if len(files) != 2 {
		return "", "", fmt.Errorf("the backend named %d certificate paths, not two", len(files))
	}
	return files[0], files[1], nil
}

// mintArgs are the armtls-dial flags shaping a self-signed certificate as
// the scenario described it; mintFlags adds where its evidence comes from.
func (c *peerCert) mintArgs() []string {
	args := []string{"--self-signed", "--not-before", c.notBefore.String(), "--not-after", c.notAfter.String()}
	if c.issuerDiffers {
		args = append(args, "--issuer-differs")
	}
	return args
}

func (w *world) mintFlags(args []string) ([]string, error) {
	url, err := w.be.call("attestation_endpoint")
	if err != nil {
		return nil, err
	}
	platform, err := w.be.call("mesh_platform")
	if err != nil {
		return nil, err
	}
	return append(args, "--attestation-url", url, "--platform", platform), nil
}

// mintCert mints the pod's self-signed certificate now and leaves it in the
// pod for the dial to present.
func (w *world) mintCert(p *pod) error {
	if !p.deployed {
		return fmt.Errorf("%q has not been deployed, so its certificate cannot be minted yet", p.name)
	}
	files := []string{"/tmp/peer.crt", "/tmp/peer.key"}
	args, err := w.mintFlags(append(p.cert.mintArgs(), "--write-cert", files[0], "--write-key", files[1]))
	if err != nil {
		return err
	}
	if _, err := w.armtlsDial(p, args...); err != nil {
		return err
	}
	p.cert.files = files
	return nil
}

// armtlsDial runs the mesh peer in the pod's first container.
func (w *world) armtlsDial(p *pod, args ...string) (string, error) {
	return kubectl(nil, append([]string{"-n", w.nsOf(p), "exec", p.name, "-c", firstContainer, "--", "/armtls-dial"}, args...)...)
}

// --- Outcomes ---

func (w *world) lastAnswer() (*execResult, error) {
	if w.mesh.answer == nil {
		return nil, fmt.Errorf("no request has been made")
	}
	return w.mesh.answer, nil
}

func receivesHello(ctx context.Context, name, what string) error {
	w := getWorld(ctx)
	a, err := w.lastAnswer()
	if err != nil {
		return err
	}
	got := strings.Contains(a.out, hello)
	if what == "the hello" && !got {
		return fmt.Errorf("%q received no hello (exit %d):\n%s", name, a.rc, a.out)
	}
	if what == "no hello" && got {
		return fmt.Errorf("%q received the hello:\n%s", name, a.out)
	}
	return nil
}

func (w *world) baseline(node, counter string) (int64, string, error) {
	k8sNode, err := w.node(node)
	if err != nil {
		return 0, "", err
	}
	v, ok := w.mesh.counters[node+"/"+counter]
	if !ok {
		return 0, "", fmt.Errorf("no %s count of node %q was read before the action; the scenario must say its mesh proxy is running", counter, node)
	}
	return v, k8sNode, nil
}

func carried(ctx context.Context, node, what string) error {
	w := getWorld(ctx)
	before, k8sNode, err := w.baseline(node, "inbound_connections")
	if err != nil {
		return err
	}
	if what == "carried the connection over armTLS" {
		var now int64
		ok, err := poll(meshCounter, func() (bool, error) {
			now, err = w.counter(k8sNode, "inbound_connections")
			return now > before, err
		})
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("the inbound proxy of node %q accepted no connection (%d before, %d after %s)", node, before, now, meshCounter)
		}
		return nil
	}
	// A monotonic counter unchanged after a quiet period was unchanged
	// throughout it.
	time.Sleep(meshQuiet)
	now, err := w.counter(k8sNode, "inbound_connections")
	if err != nil {
		return err
	}
	if now != before {
		return fmt.Errorf("the inbound proxy of node %q accepted a connection (%d before, %d after)", node, before, now)
	}
	return nil
}

func (w *world) listenerLog(p *pod) (string, error) {
	if p.listener == "" {
		return "", fmt.Errorf("%q receives no datagrams", p.name)
	}
	return kubectl(nil, "-n", w.nsOf(p), "logs", p.name, "-c", p.listener)
}

func datagramReaches(ctx context.Context, what, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if w.mesh.payload == "" {
		return fmt.Errorf("no datagram has been sent")
	}
	received := func() (bool, error) {
		out, err := w.listenerLog(p)
		return strings.Contains(out, w.mesh.payload), err
	}
	if what == "reaches" {
		ok, err := poll(15*time.Second, received)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("the datagram did not reach %q within 15s", name)
		}
		return nil
	}
	time.Sleep(meshQuiet)
	got, err := received()
	if err != nil {
		return err
	}
	if got {
		return fmt.Errorf("the datagram reached %q", name)
	}
	return nil
}

func guardDropped(ctx context.Context, node string) error {
	w := getWorld(ctx)
	before, k8sNode, err := w.baseline(node, "guard_drops")
	if err != nil {
		return err
	}
	var now int64
	ok, err := poll(meshSync, func() (bool, error) {
		now, err = w.counter(k8sNode, "guard_drops")
		return now > before, err
	})
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the inbound guard of node %q dropped nothing (%d before, %d after %s)", node, before, now, meshSync)
	}
	return nil
}

func noReply(ctx context.Context, name string) error {
	a, err := getWorld(ctx).lastAnswer()
	if err != nil {
		return err
	}
	if a.rc == 0 {
		return fmt.Errorf("%q received a reply:\n%s", name, a.out)
	}
	return nil
}

func notEstablished(ctx context.Context) error {
	a, err := getWorld(ctx).lastAnswer()
	if err != nil {
		return err
	}
	if strings.Contains(a.out, "HTTP/1") {
		return fmt.Errorf("the connection was established and answered:\n%s", a.out)
	}
	return nil
}

func closedWithNoBytes(ctx context.Context) error {
	a, err := getWorld(ctx).lastAnswer()
	if err != nil {
		return err
	}
	if strings.TrimSpace(a.out) != "" {
		return fmt.Errorf("bytes were relayed:\n%s", a.out)
	}
	return nil
}

func (w *world) lastDial() (*dialReport, error) {
	if w.mesh.dial == nil {
		return nil, fmt.Errorf("no peer connection has been made")
	}
	return w.mesh.dial, nil
}

func handshake(ctx context.Context, what string) error {
	r, err := getWorld(ctx).lastDial()
	if err != nil {
		return err
	}
	rejected := strings.Contains(r.Error, certRejected)
	if what == "completes" && rejected {
		return fmt.Errorf("the inbound proxy refused the certificate: %s", r.Error)
	}
	if what == "completes" && !r.TLS {
		return fmt.Errorf("no TLS session was established: %s", r.Error)
	}
	if what == "fails" && !rejected {
		return fmt.Errorf("the inbound proxy accepted the certificate (handshake %t, error %q, %d bytes received)", r.Handshake, r.Error, r.Bytes)
	}
	return nil
}

func noBytesRelayed(ctx context.Context) error {
	r, err := getWorld(ctx).lastDial()
	if err != nil {
		return err
	}
	if r.Bytes != 0 {
		return fmt.Errorf("%d bytes were relayed:\n%s", r.Bytes, r.Body)
	}
	return nil
}
