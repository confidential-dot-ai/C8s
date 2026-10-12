package steps

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/cucumber/godog"
)

// Sentences about the CDS itself: the documents it serves to any client, its
// serving certificate and the evidence in it, its mesh CA, its readiness, and
// what a restart with another configuration changes. Every reconfiguration
// is undone after the scenario.
func registerCDS(sc *godog.ScenarioContext) {
	sc.Step(`^(?:a client reads|a client has read|the client reads) the (mesh CA certificate|reference values|operator key set|allowlist)$`, clientReads)
	sc.Step(`^it is a single certificate$`, singleCertificate)
	sc.Step(`^it is self-signed$`, selfSigned)
	sc.Step(`^the mesh CA certificate the CDS serves carries a different public key$`, meshCADifferentKey)
	sc.Step(`^the CDS serves the (mesh CA certificate|reference values|operator key set|allowlist)$`, cdsServes)
	sc.Step(`^the CDS reports that it has no operator keys$`, reportsNoOperatorKeys)
	sc.Step(`^it matches the operator keys the client holds$`, matchesHeldKeys)
	sc.Step(`^they (do not )?match the pins the client holds$`, matchesHeldPins)
	sc.Step(`^a client presents no client certificate$`, noClientCertificate)
	sc.Step(`^a client requests the mesh CA certificate over plain HTTP$`, requestsPlainHTTP)
	sc.Step(`^the client receives no mesh CA certificate$`, receivesNoMeshCA)
	sc.Step(`^a client holds the operator keys the CDS loaded at startup$`, holdsOperatorKeys)
	sc.Step(`^a client holds the pins the CDS was started with$`, holdsPins)
	sc.Step(`^the CDS has no operator keys$`, cdsNoOperatorKeys)
	sc.Step(`^the mesh CA is within min-ca-validity of its expiry$`, meshCANearExpiry)
	sc.Step(`^the CDS has been restarted with different pins$`, restartedDifferentPins)
	sc.Step(`^the CDS is serving$`, cdsServing)
	sc.Step(`^the local attestation service on the node of the CDS becomes unavailable$`, attestationServiceStops)
	sc.Step(`^the readiness state of the CDS is read$`, readinessRead)
	sc.Step(`^the CDS is not ready$`, cdsNotReady)
	sc.Step(`^a client reads the serving certificate of the CDS$`, readsServingCert)
	sc.Step(`^the report data of its evidence commits to the public key the serving certificate carries$`, reportDataCommitsToKey)
	sc.Step(`^the remaining 16 bytes of its report data are zero$`, reportDataTailZero)
	sc.Step(`^every Kubernetes object and every file on node "([^"]*)" is searched for a private key matching that certificate$`, searchPrivateKeys)
	sc.Step(`^none holds it$`, noneHoldsKey)
	sc.Step(`^a requester running in an admitted TEE holds a key it generated$`, requesterHoldsKey)
	sc.Step(`^the requester sends the CDS an attest request with evidence that verifies$`, requesterAttests)
	sc.Step(`^the requester receives a leaf signed by the mesh CA$`, receivesLeafSignedByMeshCA)
}

// oidARMTLSAttestation is the X.509 extension the serving certificate carries
// its evidence in (the C8s arc 1.3.6.1.4.1.66378, .1.1).
var oidARMTLSAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 1}

// documents maps a sentence's document to the backend's name for it.
var documents = map[string]string{
	"mesh CA certificate": "mesh-ca",
	"reference values":    "reference-values",
	"operator key set":    "operator-key-set",
	"allowlist":           "allowlist",
}

// document is what a client got back from a read of the CDS.
type document struct {
	name   string
	status int
	body   []byte
}

// cdsState is the scenario's view of the CDS (cds.go): the last document
// read, the certificates it holds, and what it searched or was issued.
type cdsState struct {
	doc         *document
	meshCA      *x509.Certificate
	servingCert *x509.Certificate
	heldKeySet  []byte
	heldPins    []string
	found       []crypto.PublicKey
	chain       []*x509.Certificate
	readiness   string
}

// readDocument reads one of the CDS's documents, over plain HTTP when asked.
func (w *world) readDocument(name string, plain bool) (*document, error) {
	args := []string{documents[name]}
	if plain {
		args = append(args, "plain")
	}
	out, err := w.be.call("cds_read", args...)
	if err != nil {
		return nil, err
	}
	first, body, _ := strings.Cut(out, "\n")
	status, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil {
		return nil, fmt.Errorf("cds_read status %q: %w", first, err)
	}
	return &document{name: name, status: status, body: []byte(body)}, nil
}

// certificates parses every CERTIFICATE block of a PEM body.
func certificates(body []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := body; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certs, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
}

// meshCAServed reads the mesh CA the CDS serves now.
func (w *world) meshCAServed() (*x509.Certificate, error) {
	doc, err := w.readDocument("mesh CA certificate", false)
	if err != nil {
		return nil, err
	}
	if doc.status != http.StatusOK {
		return nil, fmt.Errorf("the mesh CA certificate was answered %d", doc.status)
	}
	certs, err := certificates(doc.body)
	if err != nil {
		return nil, fmt.Errorf("the mesh CA certificate body: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("the mesh CA certificate body holds no certificate")
	}
	return certs[0], nil
}

func clientReads(ctx context.Context, name string) error {
	w := getWorld(ctx)
	doc, err := w.readDocument(name, false)
	if err != nil {
		return err
	}
	w.cds.doc = doc
	if name == "mesh CA certificate" && doc.status == http.StatusOK {
		certs, err := certificates(doc.body)
		if err == nil && len(certs) > 0 {
			w.cds.meshCA = certs[0]
		}
	}
	return nil
}

func (w *world) lastDocument() (*document, error) {
	if w.cds.doc == nil {
		return nil, errors.New("the client has read nothing")
	}
	return w.cds.doc, nil
}

func singleCertificate(ctx context.Context) error {
	doc, err := getWorld(ctx).lastDocument()
	if err != nil {
		return err
	}
	certs, err := certificates(doc.body)
	if err != nil {
		return fmt.Errorf("the %s body: %w", doc.name, err)
	}
	if len(certs) != 1 {
		return fmt.Errorf("the %s body holds %d certificates, not one", doc.name, len(certs))
	}
	return nil
}

func selfSigned(ctx context.Context) error {
	w := getWorld(ctx)
	if w.cds.meshCA == nil {
		return errors.New("the client has read no mesh CA certificate")
	}
	ca := w.cds.meshCA
	if !bytes.Equal(ca.RawIssuer, ca.RawSubject) {
		return fmt.Errorf("the issuer %q is not the subject %q", ca.Issuer, ca.Subject)
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("the certificate's signature does not verify under its own key: %w", err)
	}
	return nil
}

func meshCADifferentKey(ctx context.Context) error {
	w := getWorld(ctx)
	if w.cds.meshCA == nil {
		return errors.New("the client has read no mesh CA certificate")
	}
	now, err := w.meshCAServed()
	if err != nil {
		return err
	}
	if bytes.Equal(now.RawSubjectPublicKeyInfo, w.cds.meshCA.RawSubjectPublicKeyInfo) {
		return errors.New("the mesh CA certificate the CDS serves carries the same public key as before")
	}
	return nil
}

// cdsServes checks the last read got the document: a 200 and a body of its
// kind.
func cdsServes(ctx context.Context, name string) error {
	doc, err := getWorld(ctx).lastDocument()
	if err != nil {
		return err
	}
	if doc.name != name {
		return fmt.Errorf("the client read the %s, not the %s", doc.name, name)
	}
	if doc.status != http.StatusOK {
		return fmt.Errorf("the %s was answered %d", name, doc.status)
	}
	switch name {
	case "mesh CA certificate":
		certs, err := certificates(doc.body)
		if err != nil || len(certs) == 0 {
			return fmt.Errorf("the body holds no certificate (%v)", err)
		}
	case "operator key set":
		if _, err := publicKeys(doc.body); err != nil {
			return err
		}
	case "reference values":
		if _, err := referenceValues(doc.body); err != nil {
			return err
		}
	case "allowlist":
		s, err := parseServed(string(doc.body))
		if err != nil {
			return err
		}
		if s.schema != "c8s.allowlist/v1" {
			return fmt.Errorf("the body's schema is %q, not an allowlist", s.schema)
		}
	}
	return nil
}

func reportsNoOperatorKeys(ctx context.Context) error {
	doc, err := getWorld(ctx).lastDocument()
	if err != nil {
		return err
	}
	if doc.name != "operator key set" {
		return fmt.Errorf("the client read the %s, not the operator key set", doc.name)
	}
	if doc.status != http.StatusNotFound {
		return fmt.Errorf("the operator key set was answered %d, not 404", doc.status)
	}
	return nil
}

// publicKeys parses the PUBLIC KEY blocks of a PEM bundle into their DER
// forms, sorted, so two bundles compare as sets.
func publicKeys(body []byte) ([]string, error) {
	var keys []string
	for rest := body; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("a PUBLIC KEY block does not parse: %w", err)
		}
		keys = append(keys, hex.EncodeToString(block.Bytes))
	}
	if len(keys) == 0 {
		return nil, errors.New("the body holds no PUBLIC KEY block")
	}
	return sortedUnique(keys), nil
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func matchesHeldKeys(ctx context.Context) error {
	w := getWorld(ctx)
	if w.cds.heldKeySet == nil {
		return errors.New("the client holds no operator keys")
	}
	doc, err := w.lastDocument()
	if err != nil {
		return err
	}
	if doc.status != http.StatusOK {
		return fmt.Errorf("the %s was answered %d", doc.name, doc.status)
	}
	served, err := publicKeys(doc.body)
	if err != nil {
		return err
	}
	held, err := publicKeys(w.cds.heldKeySet)
	if err != nil {
		return fmt.Errorf("the keys the client holds: %w", err)
	}
	if strings.Join(served, ",") != strings.Join(held, ",") {
		return fmt.Errorf("the served key set (%d keys) is not the one the client holds (%d keys)", len(served), len(held))
	}
	return nil
}

// referenceValues parses the launch digests of the reference-value document.
func referenceValues(body []byte) ([]string, error) {
	var doc struct {
		Measurements []struct {
			Measurement *string `json:"measurement"`
		} `json:"measurements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the reference values are not JSON: %w", err)
	}
	if doc.Measurements == nil {
		return nil, errors.New("the body has no measurements member")
	}
	var digests []string
	for _, m := range doc.Measurements {
		if m.Measurement != nil {
			digests = append(digests, strings.ToLower(*m.Measurement))
		}
	}
	return sortedUnique(digests), nil
}

func matchesHeldPins(ctx context.Context, negated string) error {
	w := getWorld(ctx)
	if w.cds.heldPins == nil {
		return errors.New("the client holds no pins")
	}
	doc, err := w.lastDocument()
	if err != nil {
		return err
	}
	if doc.name != "reference values" {
		return fmt.Errorf("the client read the %s, not the reference values", doc.name)
	}
	if doc.status != http.StatusOK {
		return fmt.Errorf("the reference values were answered %d", doc.status)
	}
	served, err := referenceValues(doc.body)
	if err != nil {
		return err
	}
	match := strings.Join(served, ",") == strings.Join(sortedUnique(w.cds.heldPins), ",")
	if negated != "" && match {
		return errors.New("the reference values match the pins the client holds")
	}
	if negated == "" && !match {
		return fmt.Errorf("the reference values %v are not the pins the client holds %v", served, w.cds.heldPins)
	}
	return nil
}

// noClientCertificate states what cds_read does anyway.
func noClientCertificate(context.Context) error { return nil }

func requestsPlainHTTP(ctx context.Context) error {
	w := getWorld(ctx)
	doc, err := w.readDocument("mesh CA certificate", true)
	if err != nil {
		return err
	}
	w.cds.doc = doc
	return nil
}

func receivesNoMeshCA(ctx context.Context) error {
	doc, err := getWorld(ctx).lastDocument()
	if err != nil {
		return err
	}
	certs, _ := certificates(doc.body)
	if len(certs) > 0 {
		return fmt.Errorf("the client received %d certificates (status %d)", len(certs), doc.status)
	}
	return nil
}

func holdsOperatorKeys(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("operator_key_set")
	if err != nil {
		return err
	}
	w.cds.heldKeySet = []byte(out)
	return nil
}

func holdsPins(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("cds_pins")
	if err != nil {
		return err
	}
	w.cds.heldPins = nil
	for _, line := range strings.Split(out, "\n") {
		if line = strings.ToLower(strings.TrimSpace(line)); line != "" {
			w.cds.heldPins = append(w.cds.heldPins, line)
		}
	}
	if len(w.cds.heldPins) == 0 {
		return errors.New("the backend knows no pins")
	}
	return nil
}

// reconfigure restarts the CDS with one parameter changed and records the
// restore. A restart is also what cdsRestarted says: the served allowlist
// starts over, and the plugins need a start of their own.
func (w *world) reconfigure(parameter, value string) error {
	if _, err := w.be.call("cds_restart_with", parameter, value); err != nil {
		return err
	}
	w.onUndo(func() error {
		_, err := w.be.call("cds_restart_with", "default", "")
		return err
	})
	w.cdsRestarted = true
	lastMutation = time.Now()
	return nil
}

func cdsNoOperatorKeys(ctx context.Context) error {
	return getWorld(ctx).reconfigure("operator-keys", "none")
}

// meshCANearExpiry raises min-ca-validity above any CA's validity, so the
// CA is within it from its first second.
func meshCANearExpiry(ctx context.Context) error {
	return getWorld(ctx).reconfigure("min-ca-validity", "876000h")
}

// restartedDifferentPins pins a launch digest no evidence carries.
func restartedDifferentPins(ctx context.Context) error {
	w := getWorld(ctx)
	other := strings.Repeat("a", 96)
	for _, pin := range w.cds.heldPins {
		if pin == other {
			other = strings.Repeat("b", 96)
		}
	}
	return w.reconfigure("pins", other)
}

func cdsServing(ctx context.Context) error {
	_, err := getWorld(ctx).meshCAServed()
	return err
}

func attestationServiceStops(ctx context.Context) error {
	w := getWorld(ctx)
	if _, err := w.be.call("attestation_service_stop"); err != nil {
		return err
	}
	w.onUndo(func() error {
		_, err := w.be.call("attestation_service_start")
		return err
	})
	return nil
}

func readinessRead(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("cds_ready")
	if err != nil {
		return err
	}
	w.cds.readiness = out
	return nil
}

// cdsNotReady allows the CDS a few readiness intervals to notice what the
// scenario changed, re-reading until it reports not ready.
func cdsNotReady(ctx context.Context) error {
	w := getWorld(ctx)
	if w.cds.readiness == "" {
		return errors.New("the readiness state has not been read")
	}
	deadline := time.Now().Add(observe)
	for w.cds.readiness != "no" {
		if time.Now().After(deadline) {
			return errors.New("the CDS still reports ready")
		}
		time.Sleep(5 * time.Second)
		if err := readinessRead(ctx); err != nil {
			return err
		}
	}
	return nil
}

func readsServingCert(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("cds_serving_cert")
	if err != nil {
		return err
	}
	certs, err := certificates([]byte(out))
	if err != nil {
		return fmt.Errorf("the serving certificate: %w", err)
	}
	if len(certs) == 0 {
		return errors.New("the CDS presented no certificate")
	}
	w.cds.servingCert = certs[0]
	return nil
}

// reportData is the report data of the evidence the serving certificate
// carries.
func (w *world) reportData() ([]byte, error) {
	if w.cds.servingCert == nil {
		return nil, errors.New("the client has read no serving certificate")
	}
	for _, ext := range w.cds.servingCert.Extensions {
		if !ext.Id.Equal(oidARMTLSAttestation) {
			continue
		}
		att, err := armtls.UnmarshalExtension(ext.Value)
		if err != nil {
			return nil, fmt.Errorf("the evidence extension: %w", err)
		}
		data, ok := att.ReportData()
		if !ok {
			return nil, errors.New("the evidence carries no report data")
		}
		return data, nil
	}
	return nil, errors.New("the serving certificate carries no evidence extension")
}

func reportDataCommitsToKey(ctx context.Context) error {
	w := getWorld(ctx)
	data, err := w.reportData()
	if err != nil {
		return err
	}
	want, err := armtls.ReportDataForKey(w.cds.servingCert.PublicKey, nil)
	if err != nil {
		return err
	}
	if len(data) < 48 || !bytes.Equal(data[:48], want[:48]) {
		return errors.New("the report data does not begin with SHA-384 of the serving certificate's public key")
	}
	return nil
}

func reportDataTailZero(ctx context.Context) error {
	data, err := getWorld(ctx).reportData()
	if err != nil {
		return err
	}
	if len(data) != 64 {
		return fmt.Errorf("the report data is %d bytes, not 64", len(data))
	}
	if !bytes.Equal(data[48:], make([]byte, 16)) {
		return errors.New("the last 16 bytes of the report data are not zero")
	}
	return nil
}

// privateKeys parses the PEM private keys of a search, returning their
// public halves; blocks of a kind it cannot parse are skipped.
func privateKeys(body []byte) []crypto.PublicKey {
	var keys []crypto.PublicKey
	for rest := body; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return keys
		}
		var key any
		var err error
		switch block.Type {
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		default:
			continue
		}
		if err != nil {
			continue
		}
		if signer, ok := key.(crypto.Signer); ok {
			keys = append(keys, signer.Public())
		}
	}
}

// searchPrivateKeys collects every private key held outside the CDS's
// process memory. A search that finds no key at all has not looked: the
// node holds its own control-plane keys.
func searchPrivateKeys(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if w.cds.meshCA == nil {
		return errors.New("the client has read no mesh CA certificate")
	}
	k8sNode, err := w.be.call("node_name", node)
	if err != nil {
		return err
	}
	out, err := w.be.call("private_keys", k8sNode)
	if err != nil {
		return err
	}
	w.cds.found = privateKeys([]byte(out))
	if len(w.cds.found) == 0 {
		return errors.New("harness: the search found no private key anywhere, so it has not looked")
	}
	return nil
}

func noneHoldsKey(ctx context.Context) error {
	w := getWorld(ctx)
	if w.cds.found == nil {
		return errors.New("nothing has been searched")
	}
	for _, pub := range w.cds.found {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			continue
		}
		if bytes.Equal(der, w.cds.meshCA.RawSubjectPublicKeyInfo) {
			return errors.New("a private key found outside CDS process memory matches the mesh CA certificate")
		}
	}
	return nil
}

// requesterHoldsKey states what attest_direct does: the key is generated
// for the request.
func requesterHoldsKey(context.Context) error { return nil }

func requesterAttests(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("attest_direct")
	if err != nil {
		return err
	}
	chain, err := certificates([]byte(out))
	if err != nil {
		return fmt.Errorf("the chain the requester received: %w", err)
	}
	if len(chain) == 0 {
		return errors.New("the requester received no certificate")
	}
	w.cds.chain = chain
	return nil
}

func receivesLeafSignedByMeshCA(ctx context.Context) error {
	w := getWorld(ctx)
	if len(w.cds.chain) == 0 {
		return errors.New("the requester has received no chain")
	}
	ca, err := w.meshCAServed()
	if err != nil {
		return err
	}
	leaf := w.cds.chain[0]
	if !bytes.Equal(leaf.RawIssuer, ca.RawSubject) {
		return fmt.Errorf("the leaf's issuer %q is not the mesh CA %q", leaf.Issuer, ca.Subject)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("the leaf's signature does not verify under the mesh CA: %w", err)
	}
	return nil
}
