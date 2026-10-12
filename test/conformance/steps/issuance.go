package steps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/cucumber/godog"
)

// Sentences about the leaves the CDS issues: to a pod carrying a workload ID,
// whose requester the webhook injects and which the scenario watches from
// outside (the files in its certificate volume, its requester's log), and to
// a requester the scenario drives itself (requester.go). What a leaf carries
// is read from the certificate; what a relying party makes of it is asked of
// the operator's verifier.
func registerIssuance(sc *godog.ScenarioContext) {
	sc.Step(`^"([^"]*)" carries a workload ID$`, carriesWorkloadID)
	sc.Step(`^"([^"]*)" holds a leaf the CDS issued$`, holdsLeaf)
	sc.Step(`^"([^"]*)" holds no leaf the CDS issued$`, holdsNoLeaf)
	sc.Step(`^"([^"]*)" renews its leaf$`, renewsLeaf)
	sc.Step(`^the leaf "([^"]*)" holds has been replaced$`, leafReplaced)
	sc.Step(`^the leaf "([^"]*)" holds is the one it held before$`, leafUnchanged)
	sc.Step(`^the message of the refusal "([^"]*)" received is "([^"]*)"$`, refusalMessage)
	sc.Step(`^the leaf "([^"]*)" holds carries no matched workload name$`, leafUnnamed)
	sc.Step(`^the leaf "([^"]*)" holds carries the matched workload name "([^"]*)"$`, leafNamed)
	sc.Step(`^the leaf "([^"]*)" holds carries no sandbox ID$`, leafNoSandboxID)
	sc.Step(`^the leaf "([^"]*)" holds carries the sandbox ID of "([^"]*)"$`, leafSandboxIDOf)
	sc.Step(`^the leaf "([^"]*)" holds certifies the key "([^"]*)" holds$`, leafCertifiesKey)
	sc.Step(`^the leaf "([^"]*)" holds carries an evidence digest$`, leafEvidenceDigest)
	sc.Step(`^the leaf "([^"]*)" holds carries certificate evidence$`, leafCertificateEvidence)
	sc.Step(`^the report data of that certificate evidence commits to the leaf's public key$`, certificateEvidenceCommitsToKey)
	sc.Step(`^the not-before of the leaf "([^"]*)" holds is the time it was issued$`, leafNotBackdated)
	sc.Step(`^the extended key usage of the leaf "([^"]*)" holds includes "([^"]*)"$`, leafExtKeyUsage)
	sc.Step(`^the leaf "([^"]*)" holds is read$`, leafRead)
	sc.Step(`^its TTL is at most (\d+) hours$`, leafTTLAtMost)
	sc.Step(`^its matched workload records the version of the served allowlist$`, matchedRecordsVersion)
	sc.Step(`^its matched workload records the digest of the served allowlist$`, matchedRecordsDigest)
	sc.Step(`^both containers of "([^"]*)" hold the same leaf$`, containersShareLeaf)
	sc.Step(`^the leaf "([^"]*)" holds carries the address of "([^"]*)" as an IP SAN$`, leafIPSAN)
	sc.Step(`^a relying party holds the mesh CA$`, relyingPartyHoldsMeshCA)
	sc.Step(`^the relying party holds the served allowlist$`, relyingPartyHoldsAllowlist)
	sc.Step(`^the relying party expects a sandbox ID$`, relyingPartyExpectsSandboxID)
	sc.Step(`^the relying party expects the matched workload name "([^"]*)"$`, relyingPartyExpectsWorkload)
	sc.Step(`^the relying party verifies the leaf "([^"]*)" holds$`, relyingPartyVerifies)
	sc.Step(`^the relying party (accepts|rejects) that leaf$`, relyingPartyVerdict)
	sc.Step(`^the CDS pins launch digests$`, cdsPinsDigests)
	sc.Step(`^the CDS has an empty pin set$`, cdsEmptyPins)
	sc.Step(`^IP SAN binding is (on|off)$`, ipSANBinding)
	sc.Step(`^the configured node address range of the CDS covers no node$`, inventoryRangeCoversNoNode)
}

// certContainer is the requester the webhook injects into a pod carrying a
// workload ID, whose log reports each issuance.
const certContainer = "c8s-cert"

// renewWindow bounds how long a renewal is waited for: the pod's renew
// interval (CW_RENEW_INTERVAL in the backends) or the unnamed fast poll, both
// at most 30s plus jitter, and the request itself.
const renewWindow = 120 * time.Second

// refusal is what a pod's requester logged about an attest request the CDS
// refused: the A3 error code and message.
type refusal struct {
	code, message string
}

// issuanceState is the scenario's view of issuance (issuance.go,
// requester.go): the requesters it drives and the relying party it stands up.
type issuanceState struct {
	requesters map[string]*requester
	lastAttest *requester
	relying    relyingParty
	// read is the leaf "is read" named, for the sentences that follow it.
	read *leaf
}

// holder resolves a name to what holds a leaf: a requester the scenario
// drives, or a pod.
func (w *world) holder(name string) (*requester, *pod, error) {
	if r, ok := w.issuance.requesters[name]; ok {
		return r, nil, nil
	}
	p, err := w.pod(name)
	if err != nil {
		return nil, nil, err
	}
	return nil, p, nil
}

// leafOf is the leaf name holds, which a sentence must have established.
func (w *world) leafOf(name string) (*leaf, error) {
	r, p, err := w.holder(name)
	if err != nil {
		return nil, err
	}
	var l *leaf
	if r != nil {
		l = r.leaf
	} else {
		l = p.leaf
	}
	if l == nil {
		return nil, fmt.Errorf("the scenario has not established that %q holds a leaf", name)
	}
	return l, nil
}

func carriesWorkloadID(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if p.deployed {
		return fmt.Errorf("%q is already deployed", name)
	}
	p.workloadID = true
	return nil
}

// certFile reads a file of the pod's certificate volume; nil while absent.
func (w *world) certFile(p *pod, file string) ([]byte, error) {
	if !p.deployed {
		return nil, fmt.Errorf("pod %q has not been deployed", p.name)
	}
	out, err := w.be.call("pod_cert_file", w.namespace, p.name, file)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return []byte(out), nil
}

// podLeaf reads the pod's chain once; nil while the requester has written
// none.
func (w *world) podLeaf(p *pod) (*leaf, error) {
	raw, err := w.certFile(p, "tls.crt")
	if err != nil || raw == nil {
		return nil, err
	}
	return parseLeaf(raw)
}

// certLog is the log of the pod's requester so far; empty before it runs.
func (w *world) certLog(p *pod) string {
	out, err := kubectl(nil, "-n", w.namespace, "logs", p.name, "-c", certContainer)
	if err != nil {
		return ""
	}
	return out
}

// Lines of the requester's log that report a refused request: the first
// request, which it retries, and a renewal.
const (
	failedFirst   = "certificate request failed"
	failedRenewal = "certificate renewal failed"
)

var errorField = regexp.MustCompile(`error="((?:[^"\\]|\\.)*)"`)

// parseRefusal reads the CDS's error document out of a logged failure, which
// quotes the error the client returned around it.
func parseRefusal(line string) (*refusal, bool) {
	m := errorField.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	text, err := strconv.Unquote(`"` + m[1] + `"`)
	if err != nil {
		text = m[1]
	}
	start, end := strings.Index(text, "{"), strings.LastIndex(text, "}")
	if start < 0 || end < start {
		return nil, false
	}
	var doc struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &doc); err != nil || doc.Error == "" {
		return nil, false
	}
	return &refusal{code: doc.Error, message: doc.Message}, true
}

// refusals lists the refusals the log reports under the given failure line.
func refusals(log, kind string) []*refusal {
	var found []*refusal
	for _, line := range strings.Split(log, "\n") {
		if !strings.Contains(line, kind) {
			continue
		}
		if r, ok := parseRefusal(line); ok {
			found = append(found, r)
		}
	}
	return found
}

func holdsLeaf(ctx context.Context, name string) error {
	w := getWorld(ctx)
	r, p, err := w.holder(name)
	if err != nil {
		return err
	}
	if r != nil {
		if r.leaf == nil {
			return fmt.Errorf("%q holds no leaf: the last attest request answered %d %s %s", name, r.lastStatus, r.lastCode, r.lastMessage)
		}
		return nil
	}
	for deadline := time.Now().Add(observe); ; time.Sleep(time.Second) {
		l, err := w.podLeaf(p)
		if err != nil {
			return err
		}
		if l != nil {
			p.leaf = l
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%q holds no leaf after %s; its requester logged: %s", name, observe, tail(w.certLog(p), 5))
		}
	}
}

// holdsNoLeaf: the pod's requester has been refused its first leaf, and
// none has appeared. Decided as soon as the log shows the refusal, since
// the requester keeps retrying.
func holdsNoLeaf(ctx context.Context, name string) error {
	w := getWorld(ctx)
	_, p, err := w.holder(name)
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("%q is a requester the scenario drives; it holds a leaf or its request was refused", name)
	}
	for deadline := time.Now().Add(observe); ; time.Sleep(time.Second) {
		l, err := w.podLeaf(p)
		if err != nil {
			return err
		}
		if l != nil {
			return fmt.Errorf("%q holds a leaf (serial %s)", name, l.serial())
		}
		if rs := refusals(w.certLog(p), failedFirst); len(rs) > 0 {
			p.refusal = rs[len(rs)-1]
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%q holds no leaf after %s, but its requester reported no refusal either: %s", name, observe, tail(w.certLog(p), 5))
		}
	}
}

// renewsLeaf waits for the pod's next issuance to settle: a new chain in the
// volume, or a refusal in its requester's log.
func renewsLeaf(ctx context.Context, name string) error {
	w := getWorld(ctx)
	_, p, err := w.holder(name)
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("%q is a requester the scenario drives; say that it requests a leaf", name)
	}
	if p.leaf == nil {
		if err := holdsLeaf(ctx, name); err != nil {
			return err
		}
	}
	before := p.leaf
	refusedBefore := len(refusals(w.certLog(p), failedRenewal))
	p.renewed, p.refusal = false, nil
	for deadline := time.Now().Add(renewWindow); ; time.Sleep(time.Second) {
		l, err := w.podLeaf(p)
		if err != nil {
			return err
		}
		if l != nil && l.serial() != before.serial() {
			p.leaf, p.renewed = l, true
			return nil
		}
		if rs := refusals(w.certLog(p), failedRenewal); len(rs) > refusedBefore {
			p.refusal = rs[len(rs)-1]
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%q neither renewed its leaf nor was refused within %s; its requester logged: %s", name, renewWindow, tail(w.certLog(p), 5))
		}
	}
}

func leafReplaced(ctx context.Context, name string) error {
	w := getWorld(ctx)
	_, p, err := w.holder(name)
	if err != nil {
		return err
	}
	if p == nil || p.leaf == nil {
		return fmt.Errorf("the scenario has not established that %q holds a leaf", name)
	}
	if !p.renewed {
		if p.refusal != nil {
			return fmt.Errorf("the leaf %q holds was not replaced; the renewal was refused: %s %s", name, p.refusal.code, p.refusal.message)
		}
		return fmt.Errorf("the leaf %q holds was not replaced", name)
	}
	return nil
}

func leafUnchanged(ctx context.Context, name string) error {
	w := getWorld(ctx)
	_, p, err := w.holder(name)
	if err != nil {
		return err
	}
	if p == nil || p.leaf == nil {
		return fmt.Errorf("the scenario has not established that %q holds a leaf", name)
	}
	if p.renewed {
		return fmt.Errorf("the leaf %q holds was replaced (serial %s)", name, p.leaf.serial())
	}
	return nil
}

func refusalMessage(ctx context.Context, name, message string) error {
	w := getWorld(ctx)
	_, p, err := w.holder(name)
	if err != nil {
		return err
	}
	if p == nil || p.refusal == nil {
		return fmt.Errorf("the scenario has not observed a refusal %q received", name)
	}
	if p.refusal.message != message {
		return fmt.Errorf("the refusal's message is %q (code %s), not %q", p.refusal.message, p.refusal.code, message)
	}
	return nil
}

func leafUnnamed(ctx context.Context, name string) error {
	l, err := getWorld(ctx).leafOf(name)
	if err != nil {
		return err
	}
	m, err := l.matched()
	if errors.Is(err, errNoMatchedWorkload) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("the leaf %q holds carries the matched workload name %q", name, m.Name)
}

func leafNamed(ctx context.Context, name, entry string) error {
	w := getWorld(ctx)
	l, err := w.leafOf(name)
	if err != nil {
		return err
	}
	m, err := l.matched()
	if err != nil {
		return err
	}
	if want := w.writtenName(entry); m.Name != want {
		return fmt.Errorf("the leaf %q holds carries the matched workload name %q, not %q", name, m.Name, want)
	}
	return nil
}

func leafNoSandboxID(ctx context.Context, name string) error {
	l, err := getWorld(ctx).leafOf(name)
	if err != nil {
		return err
	}
	id, err := l.sandboxID()
	if err != nil {
		return err
	}
	if id != "" {
		return fmt.Errorf("the leaf %q holds carries the sandbox ID %q", name, id)
	}
	return nil
}

func leafSandboxIDOf(ctx context.Context, name, podName string) error {
	w := getWorld(ctx)
	l, err := w.leafOf(name)
	if err != nil {
		return err
	}
	p, err := w.pod(podName)
	if err != nil {
		return err
	}
	want, err := w.be.call("pod_sandbox_id", w.namespace, p.name)
	if err != nil {
		return err
	}
	if want == "" {
		return fmt.Errorf("harness: the runtime reports no sandbox for %q", podName)
	}
	id, err := l.sandboxID()
	if err != nil {
		return err
	}
	if id != want {
		return fmt.Errorf("the leaf %q holds carries the sandbox ID %q; the runtime's sandbox of %q is %q", name, id, podName, want)
	}
	return nil
}

func leafCertifiesKey(ctx context.Context, name, keyHolder string) error {
	w := getWorld(ctx)
	l, err := w.leafOf(name)
	if err != nil {
		return err
	}
	r, p, err := w.holder(keyHolder)
	if err != nil {
		return err
	}
	var ok bool
	if r != nil {
		if r.key == nil {
			return fmt.Errorf("%q holds no key", keyHolder)
		}
		ok, err = l.certifies(&r.key.PublicKey)
	} else {
		raw, ferr := w.certFile(p, "tls.key")
		if ferr != nil {
			return ferr
		}
		if raw == nil {
			return fmt.Errorf("%q holds no key in its certificate volume", keyHolder)
		}
		key, kerr := parsePrivateKey(raw)
		if kerr != nil {
			return fmt.Errorf("the key %q holds: %w", keyHolder, kerr)
		}
		ok, err = l.certifies(&key.PublicKey)
	}
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the leaf %q holds certifies another key than the one %q holds", name, keyHolder)
	}
	return nil
}

func leafEvidenceDigest(ctx context.Context, name string) error {
	l, err := getWorld(ctx).leafOf(name)
	if err != nil {
		return err
	}
	value, ok := l.extension(oidEvidenceDigest)
	if !ok {
		return fmt.Errorf("the leaf %q holds carries no evidence digest", name)
	}
	var digest []byte
	if _, err := asn1.Unmarshal(value, &digest); err != nil {
		return fmt.Errorf("the evidence digest extension: %w", err)
	}
	if len(digest) != sha256.Size {
		return fmt.Errorf("the evidence digest is %d bytes, not %d", len(digest), sha256.Size)
	}
	return nil
}

func leafCertificateEvidence(ctx context.Context, name string) error {
	w := getWorld(ctx)
	l, err := w.leafOf(name)
	if err != nil {
		return err
	}
	if _, err := l.certificateEvidence(); err != nil {
		return err
	}
	w.issuance.read = l
	return nil
}

func certificateEvidenceCommitsToKey(ctx context.Context) error {
	w := getWorld(ctx)
	l := w.issuance.read
	if l == nil {
		return errors.New("no leaf's certificate evidence has been read")
	}
	data, err := l.certificateEvidence()
	if err != nil {
		return err
	}
	want, err := armtls.ReportDataForKey(l.cert.PublicKey, nil)
	if err != nil {
		return err
	}
	if len(data) < 48 || !bytes.Equal(data[:48], want[:48]) {
		return errors.New("the report data of the certificate evidence does not begin with SHA-384 of the leaf's public key")
	}
	return nil
}

// leafNotBackdated: the leaf's not-before is when it was signed, which is at
// most the moment it was first seen, less the time the write and the read
// took.
func leafNotBackdated(ctx context.Context, name string) error {
	l, err := getWorld(ctx).leafOf(name)
	if err != nil {
		return err
	}
	const slack = 2 * time.Minute
	if l.cert.NotBefore.After(l.seen.Add(time.Minute)) {
		return fmt.Errorf("the leaf's not-before %s is after it was seen at %s", l.cert.NotBefore.Format(time.RFC3339), l.seen.Format(time.RFC3339))
	}
	if l.seen.Sub(l.cert.NotBefore) > slack {
		return fmt.Errorf("the leaf's not-before %s is %s before it was seen; it is backdated", l.cert.NotBefore.Format(time.RFC3339), l.seen.Sub(l.cert.NotBefore).Round(time.Second))
	}
	return nil
}

var extKeyUsages = map[string]x509.ExtKeyUsage{
	"serverAuth": x509.ExtKeyUsageServerAuth,
	"clientAuth": x509.ExtKeyUsageClientAuth,
}

func leafExtKeyUsage(ctx context.Context, name, usage string) error {
	l, err := getWorld(ctx).leafOf(name)
	if err != nil {
		return err
	}
	want, ok := extKeyUsages[usage]
	if !ok {
		return fmt.Errorf("no extended key usage %q is known here", usage)
	}
	for _, u := range l.cert.ExtKeyUsage {
		if u == want {
			return nil
		}
	}
	return fmt.Errorf("the leaf %q holds lacks the extended key usage %s", name, usage)
}

func leafRead(ctx context.Context, name string) error {
	w := getWorld(ctx)
	l, err := w.leafOf(name)
	if err != nil {
		return err
	}
	w.issuance.read = l
	return nil
}

func (w *world) readLeaf() (*leaf, error) {
	if w.issuance.read == nil {
		return nil, errors.New("no leaf has been read")
	}
	return w.issuance.read, nil
}

func leafTTLAtMost(ctx context.Context, hours int) error {
	l, err := getWorld(ctx).readLeaf()
	if err != nil {
		return err
	}
	ttl := l.cert.NotAfter.Sub(l.cert.NotBefore)
	if ttl > time.Duration(hours)*time.Hour {
		return fmt.Errorf("the leaf's TTL is %s, more than %d hours", ttl, hours)
	}
	return nil
}

func matchedRecordsVersion(ctx context.Context) error {
	w := getWorld(ctx)
	l, err := w.readLeaf()
	if err != nil {
		return err
	}
	m, err := l.matched()
	if err != nil {
		return err
	}
	version, err := w.be.call("served_version")
	if err != nil {
		return err
	}
	if m.AllowlistVersion != version {
		return fmt.Errorf("the matched workload records allowlist version %s; the served version is %s", m.AllowlistVersion, version)
	}
	return nil
}

func matchedRecordsDigest(ctx context.Context) error {
	w := getWorld(ctx)
	l, err := w.readLeaf()
	if err != nil {
		return err
	}
	m, err := l.matched()
	if err != nil {
		return err
	}
	out, err := w.be.call("served_allowlist")
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(out))
	if !bytes.Equal(m.AllowlistDigest, sum[:]) {
		return fmt.Errorf("the matched workload records allowlist digest %x; SHA-256 of the served allowlist is %x", m.AllowlistDigest, sum)
	}
	return nil
}

// containersShareLeaf reads the chain through every container of the pod,
// once each runs, and compares.
func containersShareLeaf(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if len(p.containers) < 2 {
		return fmt.Errorf("%q has one container", name)
	}
	var first []byte
	for i := range p.containers {
		container := "curl"
		if i > 0 {
			container = fmt.Sprintf("c%d", i+1)
		}
		var raw string
		for deadline := time.Now().Add(observe); ; time.Sleep(time.Second) {
			raw, err = kubectl(nil, "-n", w.namespace, "exec", p.name, "-c", container, "--", "cat", "/etc/c8s/certs/tls.crt")
			if err == nil || !time.Now().Before(deadline) {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("reading the chain through container %d of %q: %w", i+1, name, err)
		}
		if i == 0 {
			first = []byte(raw)
		} else if !bytes.Equal(first, []byte(raw)) {
			return fmt.Errorf("container %d of %q holds a different chain than its first container", i+1, name)
		}
	}
	return nil
}

func leafIPSAN(ctx context.Context, name, addressOf string) error {
	w := getWorld(ctx)
	l, err := w.leafOf(name)
	if err != nil {
		return err
	}
	r, ok := w.issuance.requesters[addressOf]
	if !ok {
		return fmt.Errorf("%q is not a requester the scenario drives, so its address is not known here", addressOf)
	}
	want := net.ParseIP(r.addr)
	for _, ip := range l.cert.IPAddresses {
		if ip.Equal(want) {
			return nil
		}
	}
	return fmt.Errorf("the leaf %q holds carries IP SANs %v, not %s", name, l.cert.IPAddresses, r.addr)
}

// relyingParty is the operator's verifier as the scenario equips it: the
// files it holds and the properties it expects.
type relyingParty struct {
	dir       string
	caFile    string
	allowlist string
	expects   []string
	verdict   string
}

// workdir is a directory for the relying party's files, removed after the
// scenario.
func (w *world) workdir() (string, error) {
	if w.issuance.relying.dir == "" {
		dir, err := os.MkdirTemp("", "conformance-rp-*")
		if err != nil {
			return "", err
		}
		w.issuance.relying.dir = dir
		w.onUndo(func() error { return os.RemoveAll(dir) })
	}
	return w.issuance.relying.dir, nil
}

func (w *world) writeFile(name string, data []byte) (string, error) {
	dir, err := w.workdir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	return path, os.WriteFile(path, data, 0o600)
}

func relyingPartyHoldsMeshCA(ctx context.Context) error {
	w := getWorld(ctx)
	doc, err := w.readDocument("mesh CA certificate", false)
	if err != nil {
		return err
	}
	if doc.status != 200 {
		return fmt.Errorf("the CDS answered %d to a read of the mesh CA certificate", doc.status)
	}
	path, err := w.writeFile("mesh-ca.pem", doc.body)
	if err != nil {
		return err
	}
	w.issuance.relying.caFile = path
	return nil
}

func relyingPartyHoldsAllowlist(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("served_allowlist")
	if err != nil {
		return err
	}
	path, err := w.writeFile("allowlist.json", []byte(out))
	if err != nil {
		return err
	}
	w.issuance.relying.allowlist = path
	return nil
}

func relyingPartyExpectsSandboxID(ctx context.Context) error {
	w := getWorld(ctx)
	w.issuance.relying.expects = append(w.issuance.relying.expects, "--sandbox-id=expected-sandbox")
	return nil
}

func relyingPartyExpectsWorkload(ctx context.Context, entry string) error {
	w := getWorld(ctx)
	w.issuance.relying.expects = append(w.issuance.relying.expects, "--workload="+w.writtenName(entry))
	return nil
}

func relyingPartyVerifies(ctx context.Context, name string) error {
	w := getWorld(ctx)
	l, err := w.leafOf(name)
	if err != nil {
		return err
	}
	rp := &w.issuance.relying
	if rp.caFile == "" {
		return errors.New("the relying party holds no mesh CA")
	}
	leafFile, err := w.writeFile("leaf.pem", l.raw)
	if err != nil {
		return err
	}
	args := append([]string{leafFile, rp.caFile}, rp.expects...)
	if rp.allowlist != "" {
		args = append(args, "--allowlist="+rp.allowlist)
	}
	verdict, err := w.be.call("relying_party", args...)
	if err != nil {
		return err
	}
	rp.verdict = verdict
	return nil
}

func relyingPartyVerdict(ctx context.Context, want string) error {
	w := getWorld(ctx)
	if w.issuance.relying.verdict == "" {
		return errors.New("the relying party has verified nothing")
	}
	if w.issuance.relying.verdict != want {
		return fmt.Errorf("the relying party %s the leaf", w.issuance.relying.verdict)
	}
	return nil
}

// cdsPinsDigests is a precondition this environment may not meet: a CDS
// installed with no pins cannot show what pinned ones refuse.
func cdsPinsDigests(ctx context.Context) error {
	out, err := getWorld(ctx).be.call("cds_pins")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) == "" {
		return godog.ErrSkip
	}
	return nil
}

func cdsEmptyPins(ctx context.Context) error {
	return getWorld(ctx).reconfigure("pins", "none")
}

// ipSANBinding turns the CDS's --san-validation on or off, restarting it
// only when the installed value differs.
func ipSANBinding(ctx context.Context, state string) error {
	w := getWorld(ctx)
	want := strconv.FormatBool(state == "on")
	current, err := w.be.call("cds_arg", "san-validation")
	if err != nil {
		return err
	}
	if current == want {
		return nil
	}
	return w.reconfigure("san-validation", want)
}

// inventoryRangeCoversNoNode bounds the inventories the CDS may dial to a
// documentation range no node has an address in.
func inventoryRangeCoversNoNode(ctx context.Context) error {
	return getWorld(ctx).reconfigure("inventory-cidr", "192.0.2.0/24")
}

// tail is the last n lines of a log, for an error message.
func tail(log string, n int) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
