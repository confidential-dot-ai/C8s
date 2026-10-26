package steps

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/cucumber/godog"
)

// Sentences about a requester the scenario drives through the issuance
// exchange itself. The requester is a pod on the node that relays HTTP for
// the steps: to the CDS, to the node's sandbox inventory over its socket,
// and (on a TEE) to the node's local attestation service. The key, the CSR,
// the attest body and any forged token are built here, so the requester can
// present what a well-behaved one never would. Outside the mesh its own pod
// address is the source address the CDS sees; as a mesh member
// (requester.member), which the node's inventory signs a sandbox token for,
// its CDS requests leave from the backend instead.
func registerRequester(sc *godog.ScenarioContext) {
	sc.Step(`^a requester "([^"]*)" on node "([^"]*)"$`, requesterOnNode)
	sc.Step(`^"([^"]*)" holds a key$`, requesterHoldsAKey)
	sc.Step(`^(?:the CDS has issued "([^"]*)" a challenge|"([^"]*)" requests a challenge)$`, requestsChallenge)
	sc.Step(`^the two challenges "([^"]*)" received differ$`, challengesDiffer)
	sc.Step(`^"([^"]*)" presents a challenge the CDS did not issue$`, presentsUnissuedChallenge)
	sc.Step(`^that challenge was issued challenge-ttl or more ago$`, challengeExpired)
	sc.Step(`^the evidence "([^"]*)" presents commits to (a different key|an earlier challenge|the key it holds)$`, evidenceCommitsTo)
	sc.Step(`^the signature of the evidence "([^"]*)" presents does not verify$`, evidenceUnsigned)
	sc.Step(`^the evidence "([^"]*)" presents reports a launch digest that is not node "([^"]*)"'s$`, evidenceOtherDigest)
	sc.Step(`^the self-signature of the CSR "([^"]*)" prepared does not verify$`, csrBadSignature)
	sc.Step(`^the CSR of "([^"]*)" carries (a DNS SAN no configured pattern matches|an IP SAN that is the address of another pod|its own address as an IP SAN)$`, csrCarries)
	sc.Step(`^"([^"]*)" requests a leaf with that challenge( and that sandbox token)?$`, requestsLeaf)
	sc.Step(`^"([^"]*)" repeats the same attest request$`, repeatsAttest)
	sc.Step(`^the CDS refuses the attest request with "([^"]*)"$`, cdsRefusesAttest)
	sc.Step(`^"([^"]*)" holds a sandbox token from the sandbox inventory on node "([^"]*)"( for a key other than its own| for that release challenge)?$`, holdsToken)
	sc.Step(`^"([^"]*)" has signed a sandbox token for its key with a signing key of its own$`, signsOwnToken)
	sc.Step(`^the inventory host of that sandbox token is (.+)$`, forgedTokenHost)
}

// inventorySocket is where the admission plugin binds the node's socket
// directory into a requester; the inventory's token route is served there.
const inventorySocket = "/run/c8s/workload-claims/workload-claims.sock"

// evidenceMode and csrMode name what a scenario changes about the evidence
// and the CSR the requester presents; empty is a well-behaved requester. The
// values are the sentences' own phrases where a sentence sets them.
type evidenceMode string

const (
	evidenceOtherKey         evidenceMode = "a different key"
	evidenceEarlierChallenge evidenceMode = "an earlier challenge"
	evidenceNoSignature      evidenceMode = "unsigned"
	evidenceForeignDigest    evidenceMode = "other launch digest"
)

type csrMode string

const (
	csrBadSig       csrMode = "bad signature"
	csrUnmatchedDNS csrMode = "a DNS SAN no configured pattern matches"
	csrOtherIP      csrMode = "an IP SAN that is the address of another pod"
	csrOwnIP        csrMode = "its own address as an IP SAN"
)

// requester is one pod the scenario drives and everything it has prepared;
// the leaf its last attest request was issued is on its pod.
type requester struct {
	pod  *pod
	node string
	addr string
	// member: the pod is a mesh member in the scenario's namespace, because
	// the backend has no namespace the mesh exempts or because the scenario
	// asked the node's inventory for a token, which it signs for a member
	// alone; its CDS requests the backend sends from outside the pod.
	// Otherwise it is outside the mesh and sends them itself, so its own
	// address is the source the CDS sees.
	member bool
	key    *ecdsa.PrivateKey
	// The current challenge and the one before it, raw bytes.
	challenge, previous []byte
	// A token the inventory signed, or one the requester forged.
	token    json.RawMessage
	forged   *forgedToken
	evidence evidenceMode
	csr      csrMode
	// The last attest request and what the CDS answered: a leaf on the pod,
	// or a refusal.
	lastBody   []byte
	lastStatus int
	refusal    *refusal
}

// answer describes what the CDS answered the last attest request.
func (r *requester) answer() string {
	if r.refusal != nil {
		return fmt.Sprintf("%d %s", r.lastStatus, r.refusal)
	}
	return fmt.Sprintf("%d", r.lastStatus)
}

// forgedToken is a sandbox token signed by a key of the requester's own,
// naming the host a sentence chooses.
type forgedToken struct {
	key  *ecdsa.PrivateKey
	host string
}

// sandboxTokenDER is the inventory's token structure: version 2 names the
// inventory host the CDS fetches the signing key from.
type sandboxTokenDER struct {
	Version       int
	SandboxID     string `asn1:"ia5"`
	KeyDigest     []byte
	Nonce         []byte
	InventoryHost string `asn1:"ia5"`
}

// sandboxTokenDomain prefixes the signed bytes of a sandbox token.
var sandboxTokenDomain = []byte("c8s/sandbox-token/v1\x00")

func (w *world) requester(name string) (*requester, error) {
	r, ok := w.issuance.requesters[name]
	if !ok {
		return nil, fmt.Errorf("no requester %q is on a node in this scenario", name)
	}
	return r, nil
}

// requesterOnNode admits the requester's image, deploys the pod and checks
// that it can reach the CDS, so a scenario fails here, with the pod's view,
// rather than at its first request. The requester runs in a namespace the
// mesh exempts where the backend has one, so that its own address is the
// source the CDS sees, and as a mesh member where it has none
// (requester.member).
func requesterOnNode(ctx context.Context, name, node string) error {
	w := getWorld(ctx)
	if _, ok := w.issuance.requesters[name]; ok {
		return fmt.Errorf("a requester %q is already on a node", name)
	}
	if _, err := w.node(node); err != nil {
		return err
	}
	if _, ok := w.entries["requester"]; !ok {
		if err := entryAdded(ctx, "requester"); err != nil {
			return err
		}
	}
	if err := pluginApplied(ctx, node); err != nil {
		return err
	}
	ref, err := w.be.call("image_ref", "requester")
	if err != nil {
		return err
	}
	r := &requester{pod: w.describe(name, ref), node: node}
	err = w.elsewhere(r.pod, "exempt_namespace")
	r.member = errors.Is(err, godog.ErrSkip)
	if err != nil && !r.member {
		return err
	}
	w.issuance.requesters[name] = r
	return w.deployRequester(r)
}

// deployRequester applies the requester's pod where it is placed, waits for
// it to run and checks that it reaches the CDS and holds the node's sockets.
func (w *world) deployRequester(r *requester) error {
	p := r.pod
	k8sNode, err := w.node(r.node)
	if err != nil {
		return err
	}
	manifest, err := w.be.call("requester_manifest", p.name, p.namespace, k8sNode)
	if err != nil {
		return err
	}
	p.deployed = true
	if _, err := kubectl([]byte(manifest), "apply", "-f", "-"); err != nil {
		return err
	}
	st, err := w.await(p, func(st []containerStatus) bool { return len(st) > 0 && st[0].running })
	if err != nil {
		return err
	}
	if len(st) == 0 || !st[0].running {
		// A member's container waits on the injected credential client's
		// first leaf, so what the CDS told that client is the likely cause.
		msg := fmt.Sprintf("the requester %q is not running after %s; denials: %s; its containers: %+v", p.name, observe, denials(st), st)
		if r.member {
			msg += "; its credential client logged: " + tail(w.certLog(p), 5)
		}
		return errors.New(msg)
	}
	addr, err := kubectl(nil, "-n", p.namespace, "get", "pod", p.name, "-o", "jsonpath={.status.podIP}")
	if err != nil {
		return err
	}
	r.addr = strings.TrimSpace(addr)
	status, _, err := w.relay(r, "GET", "/healthz", nil, "")
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("harness: the requester %q got %d from the CDS's /healthz", p.name, status)
	}
	// The pod's own view, which a member's healthz, sent from the backend,
	// does not give: the node's sockets are bound into it.
	sockets, err := w.podExec(p, "", "ls", filepath.Dir(inventorySocket))
	if err != nil {
		return err
	}
	if !strings.Contains(sockets, filepath.Base(inventorySocket)) {
		return fmt.Errorf("harness: the socket directory of the requester %q holds no %s:\n%s", p.name, filepath.Base(inventorySocket), sockets)
	}
	return nil
}

// joinMesh redeploys a requester that stands outside the mesh as a member,
// in the scenario's namespace, where the node's inventory asserts for it.
// Its key and challenge stay: the challenge is the CDS's, bound to no pod.
func (w *world) joinMesh(r *requester) error {
	p := r.pod
	if _, err := kubectl(nil, "-n", p.namespace, "delete", "pod", p.name, "--ignore-not-found", "--wait=false"); err != nil {
		return err
	}
	p.namespace, p.name, p.deployed = w.namespace, strings.TrimSuffix(p.name, "-"+w.suffix()), false
	r.member = true
	return w.deployRequester(r)
}

// relay sends a request as the requester: to a node socket, from inside its
// pod; to a CDS route, from inside its pod at the address a requester dials
// or, for a member, whose own TCP to the CDS the node drops, from where the
// backend reaches the CDS (cds_pod_request).
func (w *world) relay(r *requester, method, route string, body []byte, socket string) (int, []byte, error) {
	var out string
	send := func(bodyFile string) (err error) {
		if socket == "" && r.member {
			args := []string{method, route}
			if bodyFile != "" {
				args = append(args, bodyFile)
			}
			out, err = w.be.call("cds_pod_request", args...)
			return err
		}
		url := "http://localhost"
		if socket == "" {
			if url, err = w.requesterCDSURL(); err != nil {
				return err
			}
		}
		args := []string{r.pod.namespace, r.pod.name, method, url + route}
		if bodyFile != "" {
			args = append(args, bodyFile)
		}
		if socket != "" {
			args = append(args, socket)
		}
		out, err = w.be.call("requester_request", args...)
		return err
	}
	var err error
	if body != nil || socket != "" {
		err = withBodyFile(body, send)
	} else {
		err = send("")
	}
	if err != nil {
		return 0, nil, err
	}
	status, _, resp, err := statusLine(out)
	if err != nil {
		return 0, nil, fmt.Errorf("the requester %q could not send %s %s: %q", r.pod.name, method, route, out)
	}
	return status, resp, nil
}

func generateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func requesterHoldsAKey(ctx context.Context, name string) error {
	r, err := getWorld(ctx).requester(name)
	if err != nil {
		return err
	}
	r.key, err = generateKey()
	return err
}

// requestsChallenge fetches a challenge; the one before stays as "an
// earlier challenge".
func requestsChallenge(ctx context.Context, issued, requested string) error {
	w := getWorld(ctx)
	r, err := w.requester(issued + requested)
	if err != nil {
		return err
	}
	challenge, err := w.issuanceChallenge(r)
	if err != nil {
		return err
	}
	r.previous, r.challenge = r.challenge, challenge
	return nil
}

// issuanceChallenge fetches an issuance challenge as the requester.
func (w *world) issuanceChallenge(r *requester) ([]byte, error) {
	status, body, err := w.relay(r, "POST", "/authenticate", []byte("{}"), "")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("the CDS answered %d to a challenge request: %s", status, body)
	}
	return parseChallenge(body)
}

// parseChallenge is the challenge bytes of a CDS challenge response.
func parseChallenge(body []byte) ([]byte, error) {
	var doc struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the challenge response: %w", err)
	}
	challenge, err := base64.StdEncoding.DecodeString(doc.Challenge)
	if err != nil {
		return nil, fmt.Errorf("the challenge is not base64: %w", err)
	}
	return challenge, nil
}

func challengesDiffer(ctx context.Context, name string) error {
	r, err := getWorld(ctx).requester(name)
	if err != nil {
		return err
	}
	if r.previous == nil || r.challenge == nil {
		return fmt.Errorf("%q has not received two challenges", name)
	}
	if len(r.challenge) != 32 {
		return fmt.Errorf("the challenge is %d bytes, not 32", len(r.challenge))
	}
	if bytes.Equal(r.previous, r.challenge) {
		return errors.New("the two challenges are the same")
	}
	return nil
}

func presentsUnissuedChallenge(ctx context.Context, name string) error {
	r, err := getWorld(ctx).requester(name)
	if err != nil {
		return err
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	r.previous, r.challenge = r.challenge, challenge
	return nil
}

func challengeExpired(ctx context.Context) error {
	out, err := getWorld(ctx).cdsArg("challenge-ttl")
	if err != nil {
		return err
	}
	ttl, err := time.ParseDuration(out)
	if err != nil {
		return fmt.Errorf("challenge ttl %q: %w", out, err)
	}
	time.Sleep(ttl + 2*time.Second)
	return nil
}

func evidenceCommitsTo(ctx context.Context, name, what string) error {
	r, err := getWorld(ctx).requester(name)
	if err != nil {
		return err
	}
	r.evidence = evidenceMode(what)
	if what == "the key it holds" {
		r.evidence = ""
	}
	return nil
}

func evidenceUnsigned(ctx context.Context, name string) error {
	r, err := getWorld(ctx).requester(name)
	if err != nil {
		return err
	}
	r.evidence = evidenceNoSignature
	return nil
}

func evidenceOtherDigest(ctx context.Context, name, node string) error {
	w := getWorld(ctx)
	r, err := w.requester(name)
	if err != nil {
		return err
	}
	if _, err := w.node(node); err != nil {
		return err
	}
	r.evidence = evidenceForeignDigest
	return nil
}

func csrCarries(ctx context.Context, name, what string) error {
	r, err := getWorld(ctx).requester(name)
	if err != nil {
		return err
	}
	r.csr = csrMode(what)
	return nil
}

func csrBadSignature(ctx context.Context, name string) error {
	r, err := getWorld(ctx).requester(name)
	if err != nil {
		return err
	}
	r.csr = csrBadSig
	return nil
}

// evidenceOver asks the node's local attestation service for evidence over
// report data, as the envelope the CDS takes. The other two modes edit its
// launch measurement: where the CDS checks the evidence's signature, so that
// it no longer verifies; where it does not (a mock), to another digest.
func (w *world) evidenceOver(r *requester, reportData []byte, mode evidenceMode) (json.RawMessage, error) {
	var edit func([]byte)
	switch mode {
	case evidenceNoSignature:
		edit = func(m []byte) { m[0] ^= 0xFF }
	case evidenceForeignDigest:
		edit = func(m []byte) { copy(m, bytes.Repeat([]byte{0xaa}, len(m))) }
	}
	if edit != nil {
		signed, err := w.be.call("evidence_signed")
		if err != nil {
			return nil, err
		}
		switch {
		case mode == evidenceNoSignature && signed != "yes":
			return nil, skipf("the CDS checks no signature on this backend's evidence")
		case mode == evidenceForeignDigest && signed == "yes":
			return nil, skipf("signed evidence for another launch digest needs a second TEE")
		}
	}
	out, err := w.be.call("evidence", r.pod.namespace, r.pod.name, base64.StdEncoding.EncodeToString(reportData))
	if err != nil {
		return nil, err
	}
	if !json.Valid([]byte(out)) {
		return nil, fmt.Errorf("the evidence is not JSON: %q", out)
	}
	if edit == nil {
		return json.RawMessage(out), nil
	}
	return withMeasurement([]byte(out), edit)
}

// otherPodAddress is the address of a pod that is not the requester and not
// on the host network.
func (w *world) otherPodAddress(r *requester) (string, error) {
	out, err := kubectl(nil, "get", "pods", "-A", "-o", `jsonpath={range .items[*]}{.status.podIP} {.status.hostIP}{"\n"}{end}`)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		podIP, hostIP, _ := strings.Cut(strings.TrimSpace(line), " ")
		if podIP != "" && podIP != hostIP && podIP != r.addr {
			return podIP, nil
		}
	}
	return "", errors.New("no other pod has an address of its own")
}

// buildCSR prepares the requester's CSR: its key, a DNS SAN the cluster's
// Service pattern admits unless a sentence chose otherwise, and certificate
// evidence over the key alone, as a requester's CSR carries.
func (w *world) buildCSR(r *requester) ([]byte, error) {
	if r.key == nil {
		return nil, fmt.Errorf("%q holds no key", r.pod.name)
	}
	tmpl := x509.CertificateRequest{}
	switch r.csr {
	case csrUnmatchedDNS:
		tmpl.DNSNames = []string{"conformance.invalid"}
	case csrOtherIP:
		addr, err := w.otherPodAddress(r)
		if err != nil {
			return nil, err
		}
		tmpl.IPAddresses = []net.IP{net.ParseIP(addr)}
	case csrOwnIP:
		tmpl.IPAddresses = []net.IP{net.ParseIP(r.addr)}
	default:
		tmpl.DNSNames = []string{r.pod.name + "." + r.pod.namespace + ".svc"}
	}
	reportData, err := armtls.ReportDataForKey(&r.key.PublicKey, nil)
	if err != nil {
		return nil, err
	}
	raw, err := w.evidenceOver(r, reportData[:], "")
	if err != nil {
		return nil, err
	}
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("the evidence envelope: %w", err)
	}
	att, err := armtls.NewAttestation(env)
	if err != nil {
		return nil, fmt.Errorf("the certificate evidence: %w", err)
	}
	ext, err := att.MarshalExtension(oidARMTLSAttestation)
	if err != nil {
		return nil, err
	}
	tmpl.ExtraExtensions = []pkix.Extension{ext}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, r.key)
	if err != nil {
		return nil, err
	}
	if r.csr == csrBadSig {
		der[len(der)-1] ^= 0xff // the last byte is the signature's
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// sandboxToken is the token the request carries: the one the inventory
// signed, or the forged one, built now that its host is known.
func (r *requester) sandboxToken() (json.RawMessage, error) {
	if r.forged == nil {
		if r.token == nil {
			return nil, fmt.Errorf("%q holds no sandbox token", r.pod.name)
		}
		return r.token, nil
	}
	if r.forged.host == "" {
		return nil, errors.New("the scenario has not said which inventory host the forged token names")
	}
	return signSandboxToken(r.forged.key, "forged-sandbox", &r.key.PublicKey, r.challenge, r.forged.host)
}

// signSandboxToken builds the inventory's token over a key and sandbox ID,
// bound to nonce and naming host, signed by signer, as the JSON the
// Authorization header carries.
func signSandboxToken(signer *ecdsa.PrivateKey, sandboxID string, pub crypto.PublicKey, nonce []byte, host string) (json.RawMessage, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(pubDER)
	der, err := asn1.Marshal(sandboxTokenDER{
		Version: 2, SandboxID: sandboxID, KeyDigest: digest[:], Nonce: nonce, InventoryHost: host,
	})
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(sandboxTokenDomain)
	h.Write(der)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Token     []byte `json:"token"`
		Signature []byte `json:"signature"`
	}{der, sig})
}

// requestsLeaf builds the attest request from what the scenario prepared and
// sends it. The evidence commits to the key and the current challenge unless
// a sentence changed that.
func requestsLeaf(ctx context.Context, name, withToken string) error {
	w := getWorld(ctx)
	r, err := w.requester(name)
	if err != nil {
		return err
	}
	return w.requestLeaf(r, withToken != "")
}

// requestLeaf is the attest request of a requester as prepared, with its
// sandbox token when asked.
func (w *world) requestLeaf(r *requester, withToken bool) error {
	if r.challenge == nil {
		return fmt.Errorf("%q holds no challenge", r.pod.name)
	}
	csrPEM, err := w.buildCSR(r)
	if err != nil {
		return err
	}
	key, nonce := &r.key.PublicKey, r.challenge
	switch r.evidence {
	case evidenceOtherKey:
		other, err := generateKey()
		if err != nil {
			return err
		}
		key = &other.PublicKey
	case evidenceEarlierChallenge:
		if r.previous == nil {
			return fmt.Errorf("%q received no earlier challenge", r.pod.name)
		}
		nonce = r.previous
	}
	reportData, err := armtls.ReportDataForKey(key, nonce)
	if err != nil {
		return err
	}
	evidence, err := w.evidenceOver(r, reportData[:], r.evidence)
	if err != nil {
		return err
	}
	req := map[string]any{
		"challenge": base64.StdEncoding.EncodeToString(r.challenge),
		"evidence":  evidence,
		"csr":       string(csrPEM),
	}
	if withToken {
		token, err := r.sandboxToken()
		if err != nil {
			return err
		}
		req["sandbox_token"] = token
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return w.attest(r, body)
}

// requesterCDSURL is where a requester outside the mesh dials the CDS: the
// address an injected client dials, unless IP SAN binding needs the
// requester's own address as the request's source.
func (w *world) requesterCDSURL() (string, error) {
	if w.issuance.sourceBound {
		return w.be.call("cds_service_url")
	}
	return w.be.call("cds_pod_url")
}

// attest sends an attest body and records what the CDS answered.
func (w *world) attest(r *requester, body []byte) error {
	status, resp, err := w.relay(r, "POST", "/attest", body, "")
	if err != nil {
		return err
	}
	r.lastBody, r.lastStatus, r.refusal, r.pod.leaf = body, status, nil, nil
	w.issuance.lastAttest = r
	if status == 200 {
		l, err := parseLeaf(resp)
		if err != nil {
			return fmt.Errorf("the chain the CDS issued: %w", err)
		}
		if l == nil {
			return errors.New("the CDS answered 200 with no certificate")
		}
		r.pod.leaf = l
		return nil
	}
	var doc refusal
	if err := json.Unmarshal(resp, &doc); err != nil || doc.Code == "" {
		return fmt.Errorf("the CDS answered %d with a body that is not an error document: %s", status, resp)
	}
	r.refusal = &doc
	return nil
}

func repeatsAttest(ctx context.Context, name string) error {
	w := getWorld(ctx)
	r, err := w.requester(name)
	if err != nil {
		return err
	}
	if r.lastBody == nil {
		return fmt.Errorf("%q has sent no attest request", name)
	}
	return w.attest(r, r.lastBody)
}

func cdsRefusesAttest(ctx context.Context, code string) error {
	w := getWorld(ctx)
	last := w.issuance.lastAttest
	if last == nil {
		return errors.New("no requester has sent an attest request")
	}
	if last.refusal == nil {
		return fmt.Errorf("the CDS answered %q %s instead of refusing with %s", last.pod.name, last.answer(), code)
	}
	if last.refusal.Code != code {
		return fmt.Errorf("the CDS refused with %s, not %s", last.answer(), code)
	}
	return nil
}

// holdsInventoryToken asks the node's inventory, over its socket, for a
// token binding a key and the current challenge to the requester's sandbox.
// holdsToken is one sentence for two holders: a requester the scenario
// drives signs the token with its own key (issuance), a deployed pod has its
// sidecar redeem a release challenge (secrets). Registering it twice would
// leave godog to pick one.
func holdsToken(ctx context.Context, name, node, suffix string) error {
	switch suffix {
	case " for a key other than its own":
		return holdsInventoryToken(ctx, name, node, suffix)
	case " for that release challenge":
		return holdsSandboxToken(ctx, name, node, suffix)
	}
	if _, ok := getWorld(ctx).issuance.requesters[name]; ok {
		return holdsInventoryToken(ctx, name, node, "")
	}
	return holdsSandboxToken(ctx, name, node, "")
}

func holdsInventoryToken(ctx context.Context, name, node, otherKey string) error {
	w := getWorld(ctx)
	r, err := w.requester(name)
	if err != nil {
		return err
	}
	if r.node != node {
		return fmt.Errorf("%q is on node %q, not %q", name, r.node, node)
	}
	if r.key == nil || r.challenge == nil {
		return fmt.Errorf("%q needs a key and a challenge before a sandbox token", name)
	}
	key := r.key
	if otherKey != "" {
		if key, err = generateKey(); err != nil {
			return err
		}
	}
	// The inventory asserts only for a mesh member (workload identity B4),
	// so a requester outside the mesh joins it first; its refusal is then
	// the inventory's verdict on a member.
	if !r.member {
		if err := w.joinMesh(r); err != nil {
			return err
		}
	}
	r.token, err = w.inventoryToken(r, &key.PublicKey, r.challenge)
	r.forged = nil
	return err
}

// inventoryToken asks the inventory of the requester's node, over the socket
// bound into its pod, for a token binding pub and nonce to its sandbox.
func (w *world) inventoryToken(r *requester, pub crypto.PublicKey, nonce []byte) (json.RawMessage, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string][]byte{"public_key": pubDER, "nonce": nonce})
	if err != nil {
		return nil, err
	}
	status, resp, err := w.relay(r, "POST", "/sandbox", body, inventorySocket)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("the sandbox inventory answered %d: %s", status, resp)
	}
	if !json.Valid(resp) {
		return nil, fmt.Errorf("the sandbox token is not JSON: %s", resp)
	}
	return json.RawMessage(resp), nil
}

func signsOwnToken(ctx context.Context, name string) error {
	w := getWorld(ctx)
	r, err := w.requester(name)
	if err != nil {
		return err
	}
	if r.key == nil || r.challenge == nil {
		return fmt.Errorf("%q needs a key and a challenge before a sandbox token", name)
	}
	key, err := generateKey()
	if err != nil {
		return err
	}
	r.forged, r.token = &forgedToken{key: key}, nil
	w.issuance.forger = r
	return nil
}

// forgedTokenHost reads the host phrase of the Scenario Outline.
func forgedTokenHost(ctx context.Context, phrase string) error {
	w := getWorld(ctx)
	r := w.issuance.forger
	if r == nil {
		return errors.New("no requester has signed a sandbox token of its own")
	}
	switch {
	case phrase == "a DNS name":
		r.forged.host = "inventory.example"
	case phrase == "a loopback address":
		r.forged.host = "127.0.0.1"
	case phrase == "a link-local address":
		r.forged.host = "169.254.1.1"
	case phrase == "an address that is no node's":
		r.forged.host = "192.0.2.1"
	case strings.HasPrefix(phrase, "the pod address of "):
		name := strings.Trim(strings.TrimPrefix(phrase, "the pod address of "), `"`)
		other, err := w.requester(name)
		if err != nil {
			return err
		}
		r.forged.host = other.addr
	default:
		return fmt.Errorf("no inventory host is known for %q", phrase)
	}
	return nil
}
