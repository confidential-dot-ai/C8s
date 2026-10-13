package steps

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/cucumber/godog"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
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
	"readiness state":     "readiness",
}

// document is what a client got back from a read of the CDS.
type document struct {
	name   string
	status int
	body   []byte
}

// cdsState is the scenario's view of the CDS: the last document a client
// read, the serving certificate it read, what the client holds, what a
// search found, what a requester was issued, and whether the CDS has been
// reconfigured, which one restore undoes.
type cdsState struct {
	doc          *document
	servingCert  *x509.Certificate
	heldKeys     []string
	heldPins     []string
	found        []crypto.PublicKey
	chain        []*x509.Certificate
	reconfigured bool
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
	status, _, body, err := statusLine(out)
	if err != nil {
		return nil, fmt.Errorf("cds_read: %w", err)
	}
	return &document{name: name, status: status, body: body}, nil
}

// pemBlocks yields the blocks of the given types in a PEM body, in order,
// skipping the text around them.
func pemBlocks(body []byte, types ...string) iter.Seq[*pem.Block] {
	return func(yield func(*pem.Block) bool) {
		for rest := body; ; {
			var block *pem.Block
			if block, rest = pem.Decode(rest); block == nil {
				return
			}
			if slices.Contains(types, block.Type) && !yield(block) {
				return
			}
		}
	}
}

// certificates parses every CERTIFICATE block of a PEM body.
func certificates(body []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for block := range pemBlocks(body, "CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// firstCertificate is the first certificate of a PEM body, which must hold
// one.
func firstCertificate(body []byte) (*x509.Certificate, error) {
	certs, err := certificates(body)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("the body holds no certificate")
	}
	return certs[0], nil
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
	ca, err := firstCertificate(doc.body)
	if err != nil {
		return nil, fmt.Errorf("the mesh CA certificate: %w", err)
	}
	return ca, nil
}

func clientReads(ctx context.Context, name string) error {
	w := getWorld(ctx)
	doc, err := w.readDocument(name, false)
	if err != nil {
		return err
	}
	w.cds.doc = doc
	return nil
}

// lastRead is the client's last read, which must have been of name.
func (w *world) lastRead(name string) (*document, error) {
	if w.cds.doc == nil {
		return nil, errors.New("the client has read nothing")
	}
	if w.cds.doc.name != name {
		return nil, fmt.Errorf("the client read the %s, not the %s", w.cds.doc.name, name)
	}
	return w.cds.doc, nil
}

// lastServed is the client's last read, which must have got name with a 200.
func (w *world) lastServed(name string) (*document, error) {
	doc, err := w.lastRead(name)
	if err != nil {
		return nil, err
	}
	if doc.status != http.StatusOK {
		return nil, fmt.Errorf("the %s was answered %d", name, doc.status)
	}
	return doc, nil
}

// heldMeshCA is the mesh CA certificate the client last read.
func (w *world) heldMeshCA() (*x509.Certificate, error) {
	doc, err := w.lastServed("mesh CA certificate")
	if err != nil {
		return nil, err
	}
	return firstCertificate(doc.body)
}

func singleCertificate(ctx context.Context) error {
	w := getWorld(ctx)
	if w.cds.doc == nil {
		return errors.New("the client has read nothing")
	}
	certs, err := certificates(w.cds.doc.body)
	if err != nil {
		return fmt.Errorf("the %s body: %w", w.cds.doc.name, err)
	}
	if len(certs) != 1 {
		return fmt.Errorf("the %s body holds %d certificates, not one", w.cds.doc.name, len(certs))
	}
	return nil
}

func selfSigned(ctx context.Context) error {
	ca, err := getWorld(ctx).heldMeshCA()
	if err != nil {
		return err
	}
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
	before, err := w.heldMeshCA()
	if err != nil {
		return err
	}
	now, err := w.meshCAServed()
	if err != nil {
		return err
	}
	if bytes.Equal(now.RawSubjectPublicKeyInfo, before.RawSubjectPublicKeyInfo) {
		return errors.New("the mesh CA certificate the CDS serves carries the same public key as before")
	}
	return nil
}

// cdsServes checks the last read got the document: a 200 and a body of its
// kind.
func cdsServes(ctx context.Context, name string) error {
	doc, err := getWorld(ctx).lastServed(name)
	if err != nil {
		return err
	}
	switch name {
	case "mesh CA certificate":
		_, err = firstCertificate(doc.body)
	case "operator key set":
		_, err = publicKeys(doc.body)
	case "reference values":
		_, err = referenceValues(doc.body)
	case "allowlist":
		var s served
		if s, err = parseServed(string(doc.body)); err == nil && s.schema != "c8s.allowlist/v1" {
			err = fmt.Errorf("the body's schema is %q, not an allowlist", s.schema)
		}
	}
	return err
}

func reportsNoOperatorKeys(ctx context.Context) error {
	doc, err := getWorld(ctx).lastRead("operator key set")
	if err != nil {
		return err
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
	for block := range pemBlocks(body, "PUBLIC KEY") {
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
	slices.Sort(in)
	return slices.Compact(in)
}

func matchesHeldKeys(ctx context.Context) error {
	w := getWorld(ctx)
	if w.cds.heldKeys == nil {
		return errors.New("the client holds no operator keys")
	}
	doc, err := w.lastServed("operator key set")
	if err != nil {
		return err
	}
	served, err := publicKeys(doc.body)
	if err != nil {
		return err
	}
	if !slices.Equal(served, w.cds.heldKeys) {
		return fmt.Errorf("the served key set (%d keys) is not the one the client holds (%d keys)", len(served), len(w.cds.heldKeys))
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
	doc, err := w.lastServed("reference values")
	if err != nil {
		return err
	}
	served, err := referenceValues(doc.body)
	if err != nil {
		return err
	}
	match := slices.Equal(served, sortedUnique(slices.Clone(w.cds.heldPins)))
	switch {
	case negated != "" && match:
		return errors.New("the reference values match the pins the client holds")
	case negated != "" && len(served) == 0:
		return errors.New("the CDS serves no reference values at all")
	case negated == "" && !match:
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
	doc, err := getWorld(ctx).lastRead("mesh CA certificate")
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
	keys, err := publicKeys([]byte(out))
	if err != nil {
		return fmt.Errorf("the keys the client holds: %w", err)
	}
	w.cds.heldKeys = keys
	return nil
}

func holdsPins(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("cds_pins")
	if err != nil {
		return err
	}
	pins := strings.Fields(strings.ToLower(out))
	if len(pins) == 0 {
		return errors.New("the backend knows no pins")
	}
	w.cds.heldPins = pins
	return nil
}

// reconfigure restarts the CDS with one parameter changed. The first change
// of a scenario records the one restore of the installed configuration; a
// restart is also what cdsRestarted notes.
func (w *world) reconfigure(parameter, value string) error {
	if !w.cds.reconfigured {
		w.cds.reconfigured = true
		w.onUndo(func() error {
			_, err := w.be.call("cds_restart_with", "default", "")
			return err
		})
	}
	if _, err := w.be.call("cds_restart_with", parameter, value); err != nil {
		return err
	}
	w.noteCDSRestart()
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
	return getWorld(ctx).reconfigure("pins", strings.Repeat("a", 96))
}

func cdsServing(ctx context.Context) error {
	_, err := getWorld(ctx).meshCAServed()
	return err
}

func attestationServiceStops(ctx context.Context) error {
	w := getWorld(ctx)
	w.onUndo(func() error {
		_, err := w.be.call("attestation_service_start")
		return err
	})
	_, err := w.be.call("attestation_service_stop")
	return err
}

func readinessRead(ctx context.Context) error {
	return clientReads(ctx, "readiness state")
}

// cdsNotReady allows the CDS a few readiness intervals to notice what the
// scenario changed, re-reading while it reports ready. An answer that is
// neither ready nor not ready is a CDS that is not serving.
func cdsNotReady(ctx context.Context) error {
	w := getWorld(ctx)
	doc, err := w.lastRead("readiness state")
	if err != nil {
		return err
	}
	notReady, err := poll(observe, func() (bool, error) {
		switch doc.status {
		case http.StatusServiceUnavailable:
			return true, nil
		case http.StatusOK:
			if err := readinessRead(ctx); err != nil {
				return false, err
			}
			doc = w.cds.doc
			return false, nil
		default:
			return false, fmt.Errorf("the readiness state was answered %d, neither ready nor not ready", doc.status)
		}
	})
	if err != nil {
		return err
	}
	if !notReady {
		return errors.New("the CDS still reports ready")
	}
	return nil
}

func readsServingCert(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("cds_serving_cert")
	if err != nil {
		return err
	}
	cert, err := firstCertificate([]byte(out))
	if err != nil {
		return fmt.Errorf("the serving certificate: %w", err)
	}
	w.cds.servingCert = cert
	return nil
}

// reportData is the report data of the evidence the serving certificate
// carries.
func (w *world) reportData() ([]byte, error) {
	if w.cds.servingCert == nil {
		return nil, errors.New("the client has read no serving certificate")
	}
	att, err := armtls.ExtractAttestation(w.cds.servingCert, oidARMTLSAttestation)
	if err != nil {
		return nil, fmt.Errorf("the serving certificate's evidence: %w", err)
	}
	return reportDataOf(att)
}

// reportDataOf is the 64 bytes of report data the evidence commits to. The
// library reads them off a raw SEV-SNP report; evidence in an envelope, as
// every other platform's is, carries them in a quote or report the library
// leaves to its verifiers, read here instead.
func reportDataOf(att *armtls.Attestation) ([]byte, error) {
	if data, ok := att.ReportData(); ok {
		return data, nil
	}
	envelope, ok := att.EmbeddedEvidence()
	if !ok {
		return nil, errors.New("the evidence carries no report data")
	}
	switch envelope.Platform.Family() {
	case teetypes.FamilySNP:
		var evidence snp.SnpEvidence
		if err := json.Unmarshal(envelope.Evidence, &evidence); err != nil {
			return nil, fmt.Errorf("the SEV-SNP evidence: %w", err)
		}
		raw, err := base64.StdEncoding.DecodeString(evidence.AttestationReport)
		if err != nil {
			return nil, fmt.Errorf("the SEV-SNP report: %w", err)
		}
		report, err := armtls.NormalizeSEVSNPReport(raw)
		if err != nil {
			return nil, err
		}
		if len(report) < snp.ReportDataOffset+64 {
			return nil, fmt.Errorf("the SEV-SNP report is %d bytes, too short for report data", len(report))
		}
		return report[snp.ReportDataOffset : snp.ReportDataOffset+64], nil
	case teetypes.FamilyTDX:
		var evidence tdx.TdxEvidence
		if err := json.Unmarshal(envelope.Evidence, &evidence); err != nil {
			return nil, fmt.Errorf("the TDX evidence: %w", err)
		}
		raw, err := base64.StdEncoding.DecodeString(evidence.Quote)
		if err != nil {
			return nil, fmt.Errorf("the TDX quote: %w", err)
		}
		parsed, err := tdxabi.QuoteToProto(raw)
		if err != nil {
			return nil, fmt.Errorf("the TDX quote: %w", err)
		}
		quote, ok := parsed.(*tdxpb.QuoteV4)
		if !ok {
			return nil, fmt.Errorf("the TDX quote is a %T, whose report data this suite does not read", parsed)
		}
		return quote.GetTdQuoteBody().GetReportData(), nil
	}
	return nil, fmt.Errorf("the %s evidence carries report data this suite does not read", envelope.Platform)
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
	const anchor = sha512.Size384
	if len(data) < anchor || !bytes.Equal(data[:anchor], want[:anchor]) {
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
	if !bytes.Equal(data[sha512.Size384:], make([]byte, 64-sha512.Size384)) {
		return errors.New("the last 16 bytes of the report data are not zero")
	}
	return nil
}

// privateKeys parses the PEM private keys of a search, returning their
// public halves; blocks of a kind it cannot parse are skipped.
func privateKeys(body []byte) []crypto.PublicKey {
	var keys []crypto.PublicKey
	for block := range pemBlocks(body, "EC PRIVATE KEY", "RSA PRIVATE KEY", "PRIVATE KEY") {
		var key any
		var err error
		switch block.Type {
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		default:
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
		if signer, ok := key.(crypto.Signer); err == nil && ok {
			keys = append(keys, signer.Public())
		}
	}
	return keys
}

// searchPrivateKeys collects every private key held outside the CDS's
// process memory. A search that finds no key at all has not looked: the
// node holds its own control-plane keys.
func searchPrivateKeys(ctx context.Context, node string) error {
	w := getWorld(ctx)
	if _, err := w.heldMeshCA(); err != nil {
		return err
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
	ca, err := w.heldMeshCA()
	if err != nil {
		return err
	}
	for _, pub := range w.cds.found {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err == nil && bytes.Equal(der, ca.RawSubjectPublicKeyInfo) {
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
