package steps

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about secret release: the grant an entry carries, the values the
// operator supplies through the write-token path, and what the CDS answers a
// workload requester. The requester is `c8s secret-probe`, exec'd in the
// pod's injected certificate container, which holds the leaf, the key and the
// node's inventory socket; each of the request's inputs (challenge, token,
// path) is the scenario's to shape. Secret paths are logical: the scenario's
// "/models/key" is stored under a per-scenario prefix, since the store has no
// delete and outlives the scenario.
func registerSecrets(sc *godog.ScenarioContext) {
	sc.Step(`^the secret grant of "([^"]*)" allows (read|write) of the secret path "([^"]*)"$`, grantAllows)
	sc.Step(`^"([^"]*)" has no secret grant$`, noGrant)
	sc.Step(`^the secret grant of "([^"]*)" does not allow read of the secret path "([^"]*)"$`, grantDoesNotAllowRead)
	sc.Step(`^the operator writes the entry "([^"]*)" to the served allowlist(?: again)?$`, operatorWritesEntry)
	sc.Step(`^the operator adds to "([^"]*)" a secret grant allowing (read|write) of the secret path "([^"]*)"$`, operatorAddsGrant)
	sc.Step(`^the operator removes the secret grant of "([^"]*)"$`, operatorRemovesGrant)
	sc.Step(`^the operator writes an entry "([^"]*)" whose secret grant denies and names the secret path "([^"]*)"$`, operatorWritesDenyingGrant)
	sc.Step(`^the operator writes an entry "([^"]*)" whose secret grant allows write of the secret path "([^"]*)" and no read path$`, operatorWritesWriteOnlyGrant)
	sc.Step(`^the served allowlist carries no secret grant for "([^"]*)"$`, servedCarriesNoGrant)
	sc.Step(`^the served allowlist is read without client authentication$`, servedReadUnauthenticated)
	sc.Step(`^the secret grant of "([^"]*)" in it allows read of the secret path "([^"]*)"$`, readGrantAllowsRead)
	sc.Step(`^it carries no secret value$`, readCarriesNoValue)

	sc.Step(`^the operator has supplied a secret value at the secret path "([^"]*)"$`, operatorHasSupplied)
	sc.Step(`^the operator supplies a secret value at the secret path "([^"]*)"$`, operatorSupplies)
	sc.Step(`^the operator (?:replaces|has replaced) the secret value at the secret path "([^"]*)"$`, operatorReplaces)
	sc.Given(`^no secret value is stored at the secret path "([^"]*)"$`, nothingStoredGiven)
	sc.Then(`^no secret value is stored at the secret path "([^"]*)"$`, nothingStoredThen)
	sc.Step(`^the write is refused (as unauthorized|because the secret path already holds a value)$`, writeRefused)
	sc.Step(`^the write result names the existing value as a workload's$`, writeNamesWorkload)
	sc.Step(`^the write result carries no secret value$`, writeCarriesNoValue)
	sc.Step(`^a caller holding an operator key the CDS does not hold supplies a secret value at the secret path "([^"]*)"$`, foreignSupplies)
	sc.Step(`^the operator has signed a write token for a write of a secret value to the secret path "([^"]*)"$`, operatorSignsSecretWrite)
	sc.Step(`^the operator has signed a write token, now past its validity, for a write of a secret value to the secret path "([^"]*)"$`, operatorSignsExpiredSecretWrite)
	sc.Step(`^the operator sends that write token with the same write to the secret path "([^"]*)"$`, sendsTokenToOtherPath)
	sc.Step(`^the operator sends that write token with a different secret value$`, sendsTokenWithOtherValue)
	sc.Step(`^the operator sends that write token with the write it signed$`, sendsTokenAsSigned)
	sc.Step(`^the operator sends a delete for the secret path "([^"]*)"$`, operatorDeletes)
	sc.Step(`^the CDS refuses the delete$`, cdsRefusesDelete)

	sc.Step(`^the secret client of "([^"]*)" is configured with the secret path "([^"]*)"$`, secretClientConfigured)
	sc.Step(`^"([^"]*)" has an init container running image "([^"]*)"$`, hasInitContainer)
	sc.Step(`^the argv of that container begins with a helper mode c8s injects$`, argvHelperMode)
	sc.Step(`^that container mounts a volume on disk-backed storage$`, mountsDiskVolume)
	sc.Step(`^the init container of "([^"]*)" (is running|has stopped)$`, initContainerState)
	sc.Step(`^"([^"]*)" has obtained a sandbox-bound leaf from the CDS$`, obtainedSandboxLeaf)
	sc.Step(`^"([^"]*)" still holds the leaf it obtained before the restart$`, stillHoldsLeaf)

	sc.Step(`^"([^"]*)" holds a release challenge$`, holdsChallenge)
	sc.Step(`^"([^"]*)" holds no release challenge$`, holdsNoChallenge)
	sc.Step(`^"([^"]*)" holds no sandbox token$`, holdsNoToken)
	sc.Step(`^"([^"]*)" holds a release challenge (the CDS never issued|that has passed the release challenge lifetime|the CDS issued for certificate issuance|already spent by an authorized secret request|already spent by a secret request that failed authorization)$`, holdsFlawedChallenge)
	sc.Step(`^"([^"]*)" holds the sandbox token issued to "([^"]*)" for that release challenge$`, holdsOthersToken)
	sc.Step(`^"([^"]*)" holds a sandbox token bound to a release challenge already spent$`, holdsSpentToken)
	sc.Step(`^"([^"]*)" holds a sandbox token naming an inventory host other than the one bound to its sandbox$`, holdsForeignHostToken)
	sc.Step(`^a requester holds a self-signed certificate carrying the sandbox ID of "([^"]*)"$`, selfSignedRequester)
	sc.Step(`^that requester requests a read of the secret path "([^"]*)"$`, selfSignedRequests)
	sc.Step(`^that requester receives no secret value$`, selfSignedReceivesNothing)
	sc.Step(`^"([^"]*)" requests (a read of|generation at) the secret path "([^"]*)"$`, requestsSecret)
	sc.Step(`^"([^"]*)" has requested a read of the secret path "([^"]*)" and received (no secret value|the stored secret value)$`, hasRequestedRead)
	sc.Step(`^"([^"]*)" has generated a secret value at the secret path "([^"]*)"$`, hasGenerated)
	sc.Step(`^"([^"]*)" has generated secret values at distinct secret paths below "([^"]*)" up to the holder quota of "([^"]*)"$`, hasFilledQuota)
	sc.Step(`^"([^"]*)" receives the stored secret value$`, receivesStoredValue)
	sc.Step(`^"([^"]*)" receives a secret value$`, receivesAValue)
	sc.Step(`^"([^"]*)" receives no secret value$`, receivesNoValue)
	sc.Step(`^the CDS answers "([^"]*)" not authorized for this secret$`, answersNotAuthorized)
	sc.Step(`^the CDS answers "([^"]*)" no such secret$`, answersNoSuchSecret)
	sc.Step(`^the CDS rejects the request of "([^"]*)" as invalid$`, answersInvalid)
	sc.Step(`^the CDS answers "([^"]*)" that the secret path already exists$`, answersExists)
	sc.Step(`^the CDS answers "([^"]*)" that the secret storage limit is reached$`, answersQuota)
	sc.Step(`^that secret value is (\d+) bytes long$`, valueLength)
	sc.Step(`^that secret value differs from the one "([^"]*)" holds for the secret path "([^"]*)"$`, valueDiffersFromHeld)
	sc.Step(`^that secret value differs from the one "([^"]*)" received before$`, valueDiffersFromBefore)
	sc.Step(`^"([^"]*)" receives the secret value "([^"]*)" holds for the secret path "([^"]*)"$`, receivesHeldValue)
	sc.Step(`^the answer is the same as the answer "([^"]*)" received for the secret path "([^"]*)"$`, sameAnswerAs)
	sc.Step(`^the release challenge of that request is not spent$`, challengeNotSpent)
	sc.Step(`^"([^"]*)" can still read the stored secret value at the secret path "([^"]*)"$`, canStillRead)

	sc.Step(`^the output directory of the secret client of "([^"]*)" holds a file for the secret path "([^"]*)"$`, outputHoldsFile)
	sc.Step(`^that file holds the secret value the operator last supplied$`, fileHoldsSupplied)
	sc.Step(`^the file of "([^"]*)" for the secret path "([^"]*)" still holds the secret value it held before$`, fileUnchanged)
	sc.Step(`^the output directory of the secret client of "([^"]*)" is on memory-backed storage$`, outputOnMemory)
}

// The CDS's secret routes and the §11 answers the sentences name.
const (
	secretsRoute      = "/secrets"
	authenticateRoute = "/authenticate"
	msgNotAuthorized  = "not authorized for this secret"
	msgNoSuchSecret   = "no such secret"
	msgQuota          = "secret storage limit reached"
	codeHolderQuota   = "secret_holder_quota"
	originWorkload    = "workload"
	secretClientDir   = "/run/c8s/secrets"
	annotationSecrets = "confidential.ai/c8s-secrets"
	annotationCW      = "confidential.ai/cw"
	annotationRenewal = "confidential.ai/c8s-renew-interval"
	issuanceRenewal   = "10s" // below the CDS's named leaf TTL, so a renewal can be observed
	secretsRenewal    = "2h"  // leaves the leaf a secrets scenario obtained in place
)

// secretsGrant is the entry's `secrets` member in the document's shape.
type secretsGrant struct {
	Policy string   `json:"policy"`
	Read   []string `json:"read,omitempty"`
	Write  []string `json:"write,omitempty"`
}

// answer is what the CDS answered one request: status and body.
type answer struct {
	status int
	body   []byte
}

func (a *answer) ok() bool { return a.status/100 == 2 }

// value is the secret value the body carries, if any.
func (a *answer) value() ([]byte, bool) {
	var doc struct {
		Value *string `json:"value"`
	}
	if err := json.Unmarshal(a.body, &doc); err != nil || doc.Value == nil {
		return nil, false
	}
	v, err := base64.StdEncoding.DecodeString(*doc.Value)
	if err != nil {
		return nil, false
	}
	return v, true
}

func (a *answer) String() string { return fmt.Sprintf("%d %s", a.status, bytes.TrimSpace(a.body)) }

// secretReq is what a pod's next secret request presents, and what its last
// one got.
type secretReq struct {
	challenge   []byte // sent as given; nil fetches one unless noChallenge
	noChallenge bool
	token       []byte // the Authorization JSON; nil redeems one unless noToken
	noToken     bool
	// The last request: its credentials (for "that request"), path and answer.
	lastChallenge, lastToken []byte
	lastPath                 string
	last                     *answer
	// values the pod received, by logical path, and the one before.
	values, previous map[string][]byte
	// answers by logical path, for "the answer ... received for".
	answers map[string]*answer
	// files read from the secret client's output directory.
	files map[string][]byte
}

// pendingWrite is a write the operator signed but has not sent.
type pendingWrite struct {
	path  string
	body  []byte
	token string
}

// outsideRequester is a requester outside any pod: a key and a self-signed
// certificate carrying a sandbox ID.
type outsideRequester struct {
	certFile, keyFile string
	last              *answer
}

// clientFile is a file of a secret client's output directory the scenario
// read: whose, for which logical path, and what it held.
type clientFile struct {
	p       *pod
	logical string
	content []byte
}

// secretsState is the scenario's view of the secret store.
type secretsState struct {
	// active: the scenario is tagged as being about secrets; its pods renew
	// their leaf slowly, so the leaf they obtained is the one they hold.
	active bool
	// stored values by logical path, as the scenario supplied or generated
	// them.
	stored map[string][]byte
	write  *answer // the operator's last write
	signed *pendingWrite
	served string // the served allowlist as last read without authentication
	self   *outsideRequester
	last   *pod        // the pod whose request was the last
	file   *clientFile // the secret client file last read, which "that file" names
}

func (w *world) secretState(p *pod) *secretReq {
	if p.secret == nil {
		p.secret = &secretReq{values: map[string][]byte{}, previous: map[string][]byte{}, answers: map[string]*answer{}, files: map[string][]byte{}}
	}
	return p.secret
}

// secretPath is the store path a logical path names in this scenario.
func (w *world) secretPath(logical string) string { return "/" + w.suffix() + logical }

// --- Grants ---

func (w *world) grantOf(name string) (*entry, *secretsGrant, error) {
	e, err := w.entry(name)
	if err != nil {
		return nil, nil, err
	}
	if e.Secrets == nil {
		e.Secrets = &secretsGrant{Policy: "allow"}
	}
	return e, e.Secrets, nil
}

func grantAllows(ctx context.Context, name, action, p string) error {
	w := getWorld(ctx)
	_, g, err := w.grantOf(name)
	if err != nil {
		return err
	}
	if action == "read" {
		g.Read = append(g.Read, w.secretPath(p))
	} else {
		g.Write = append(g.Write, w.secretPath(p))
	}
	return nil
}

func noGrant(ctx context.Context, name string) error {
	w := getWorld(ctx)
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	e.Secrets = nil
	return nil
}

// covers reports whether the grant's glob admits the store path: exact, or
// strictly below a trailing "/**".
func covers(glob, p string) bool {
	if prefix, ok := strings.CutSuffix(glob, "/**"); ok {
		return strings.HasPrefix(p, prefix+"/") && len(p) > len(prefix)+1
	}
	return glob == p
}

func grantDoesNotAllowRead(ctx context.Context, name, p string) error {
	w := getWorld(ctx)
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	if e.Secrets == nil {
		return nil
	}
	for _, glob := range e.Secrets.Read {
		if covers(glob, w.secretPath(p)) {
			return fmt.Errorf("the grant of %q allows read of %s through %s", name, p, glob)
		}
	}
	return nil
}

func operatorWritesEntry(ctx context.Context, name string) error {
	return getWorld(ctx).rewriteEntry(name)
}

// operatorAddsGrant writes the entry with the grant through the operator's
// write path, which records the status: a grant the CDS refuses is a result
// the sentences after it read, not a broken harness.
func operatorAddsGrant(ctx context.Context, name, action, p string) error {
	if err := grantAllows(ctx, name, action, p); err != nil {
		return err
	}
	w := getWorld(ctx)
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	return w.writeEntryWithGrant(name, e.Secrets)
}

func operatorRemovesGrant(ctx context.Context, name string) error {
	if err := noGrant(ctx, name); err != nil {
		return err
	}
	return getWorld(ctx).rewriteEntry(name)
}

// writeEntryWithGrant sends the described entry with another grant through
// the operator's write path, recording the status, without changing what the
// scenario describes.
func (w *world) writeEntryWithGrant(name string, g *secretsGrant) error {
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	copy := *e
	copy.Secrets = g
	body, err := json.Marshal(&copy)
	if err != nil {
		return err
	}
	return w.operatorWrite(write{method: http.MethodPut, path: w.workloadPath(name), body: body})
}

func operatorWritesDenyingGrant(ctx context.Context, name, p string) error {
	w := getWorld(ctx)
	return w.writeEntryWithGrant(name, &secretsGrant{Policy: "deny", Read: []string{w.secretPath(p)}})
}

func operatorWritesWriteOnlyGrant(ctx context.Context, name, p string) error {
	w := getWorld(ctx)
	return w.writeEntryWithGrant(name, &secretsGrant{Policy: "allow", Write: []string{w.secretPath(p)}})
}

func servedCarriesNoGrant(ctx context.Context, name string) error {
	w := getWorld(ctx)
	s, err := w.served()
	if err != nil {
		return err
	}
	if e, ok := s.entries[w.writtenName(name)]; ok && e.Secrets != nil {
		return fmt.Errorf("the served entry %q carries the grant %+v", name, *e.Secrets)
	}
	return nil
}

func servedReadUnauthenticated(ctx context.Context) error {
	w := getWorld(ctx)
	out, err := w.be.call("served_allowlist")
	if err != nil {
		return err
	}
	w.secrets.served = out
	return nil
}

func readGrantAllowsRead(ctx context.Context, name, p string) error {
	w := getWorld(ctx)
	if w.secrets.served == "" {
		return errors.New("the served allowlist has not been read")
	}
	s, err := parseServed(w.secrets.served)
	if err != nil {
		return err
	}
	e, ok := s.entries[w.writtenName(name)]
	if !ok || e.Secrets == nil {
		return fmt.Errorf("the document carries no grant for %q", name)
	}
	for _, glob := range e.Secrets.Read {
		if covers(glob, w.secretPath(p)) {
			return nil
		}
	}
	return fmt.Errorf("the grant of %q in the document allows read of %v, not %s", name, e.Secrets.Read, p)
}

// readCarriesNoValue: no stored value, raw or base64, and no value member
// anywhere in the document.
func readCarriesNoValue(ctx context.Context) error {
	w := getWorld(ctx)
	if w.secrets.served == "" {
		return errors.New("the served allowlist has not been read")
	}
	if strings.Contains(w.secrets.served, `"value"`) {
		return errors.New("the served allowlist carries a value member")
	}
	if p, ok := w.carriesStored([]byte(w.secrets.served)); ok {
		return fmt.Errorf("the served allowlist carries the value stored at %s", p)
	}
	return nil
}

// carriesStored names the logical path of a stored value the body carries,
// raw or base64, if any.
func (w *world) carriesStored(body []byte) (string, bool) {
	for p, v := range w.secrets.stored {
		if bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(v))) || bytes.Contains(body, v) {
			return p, true
		}
	}
	return "", false
}

// --- Operator values ---

// randomValue is a fresh secret value: printable, so a file or a body that
// carries it reads back as the same bytes.
func randomValue() ([]byte, error) {
	v := make([]byte, 16)
	if _, err := rand.Read(v); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(v)), nil
}

func putBody(value []byte, overwrite bool) []byte {
	body, _ := json.Marshal(map[string]any{"value": base64.StdEncoding.EncodeToString(value), "overwrite": overwrite})
	return body
}

// cdsRequest sends one request to the CDS from the runner: a method, a
// route, a body (nil for none), an Authorization (empty for none) and a
// client certificate and key (empty for none). Status 0 when nothing
// answered.
func (w *world) cdsRequest(method, route string, body []byte, auth, cert, key string) (*answer, error) {
	return w.httpRequest("cds_request", method, route, body, auth, cert, key)
}

// httpRequest sends one request through a backend function that takes
// cds_request's arguments (cds_request, router_request), each header as
// "Name: value".
func (w *world) httpRequest(fn, method, route string, body []byte, auth, cert, key string, headers ...string) (*answer, error) {
	send := func(bodyFile string) (string, error) {
		return w.be.call(fn, append([]string{method, route, bodyFile, auth, cert, key}, headers...)...)
	}
	var out string
	var err error
	if body != nil {
		err = withBodyFile(body, func(p string) error { out, err = send(p); return err })
	} else {
		out, err = send("")
	}
	if err != nil {
		return nil, err
	}
	status, _, resp, err := statusLine(out)
	if err != nil {
		return nil, fmt.Errorf("the %s answer to %s %s: %q", fn, method, route, out)
	}
	return &answer{status: status, body: resp}, nil
}

// operatorPut writes value at the logical path with the signer's token.
func (w *world) operatorPut(signer, logical string, value []byte, overwrite bool, validity string) (*answer, error) {
	route := secretsRoute + w.secretPath(logical)
	body := putBody(value, overwrite)
	token, err := w.token(signer, write{method: http.MethodPut, path: route, body: body, validity: validity})
	if err != nil {
		return nil, err
	}
	a, err := w.cdsRequest(http.MethodPut, route, body, token, "", "")
	if err != nil {
		return nil, err
	}
	w.secrets.write = a
	return a, nil
}

// supply writes a fresh value at the logical path with the signer's token
// and records it as stored when the CDS took it.
func (w *world) supply(signer, logical string, overwrite bool) (*answer, error) {
	v, err := randomValue()
	if err != nil {
		return nil, err
	}
	a, err := w.operatorPut(signer, logical, v, overwrite, "")
	if err != nil {
		return nil, err
	}
	if a.ok() {
		w.secrets.stored[logical] = v
	}
	return a, nil
}

func operatorHasSupplied(ctx context.Context, logical string) error {
	a, err := getWorld(ctx).supply("operator", logical, false)
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated {
		return fmt.Errorf("the operator's write of %s was answered %s", logical, a)
	}
	return nil
}

func operatorSupplies(ctx context.Context, logical string) error {
	_, err := getWorld(ctx).supply("operator", logical, false)
	return err
}

func operatorReplaces(ctx context.Context, logical string) error {
	a, err := getWorld(ctx).supply("operator", logical, true)
	if err != nil {
		return err
	}
	if !a.ok() {
		return fmt.Errorf("the operator's replacement at %s was answered %s", logical, a)
	}
	return nil
}

// nothingStoredGiven: the scenario's own record is the fact, since the paths
// are the scenario's alone.
func nothingStoredGiven(ctx context.Context, logical string) error {
	w := getWorld(ctx)
	if v, ok := w.secrets.stored[logical]; ok && v != nil {
		return fmt.Errorf("the scenario stored a value at %s", logical)
	}
	return nil
}

// nothingStoredThen asks the store, by a create that a held value refuses.
func nothingStoredThen(ctx context.Context, logical string) error {
	if err := nothingStoredGiven(ctx, logical); err != nil {
		return err
	}
	a, err := getWorld(ctx).supply("operator", logical, false)
	if err != nil {
		return err
	}
	if a.status != http.StatusCreated {
		return fmt.Errorf("a value is stored at %s: a create was answered %s", logical, a)
	}
	return nil
}

func (w *world) lastWrite() (*answer, error) {
	if w.secrets.write == nil {
		return nil, errors.New("the operator has sent no write")
	}
	return w.secrets.write, nil
}

func writeRefused(ctx context.Context, why string) error {
	a, err := getWorld(ctx).lastWrite()
	if err != nil {
		return err
	}
	want := http.StatusUnauthorized
	if why != "as unauthorized" {
		want = http.StatusConflict
	}
	if a.status != want {
		return fmt.Errorf("the write was answered %s, not %d", a, want)
	}
	return nil
}

func writeNamesWorkload(ctx context.Context) error {
	a, err := getWorld(ctx).lastWrite()
	if err != nil {
		return err
	}
	var doc struct {
		Existing string `json:"existing"`
	}
	if err := json.Unmarshal(a.body, &doc); err != nil {
		return fmt.Errorf("the write result is not a document: %s", a)
	}
	if doc.Existing != originWorkload {
		return fmt.Errorf("the write result names the existing value as %q", doc.Existing)
	}
	return nil
}

func writeCarriesNoValue(ctx context.Context) error {
	w := getWorld(ctx)
	a, err := w.lastWrite()
	if err != nil {
		return err
	}
	if _, has := a.value(); has || bytes.Contains(a.body, []byte(`"value"`)) {
		return fmt.Errorf("the write result carries a value: %s", a)
	}
	if p, ok := w.carriesStored(a.body); ok {
		return fmt.Errorf("the write result carries the value stored at %s", p)
	}
	return nil
}

func foreignSupplies(ctx context.Context, logical string) error {
	_, err := getWorld(ctx).supply("foreign", logical, false)
	return err
}

func (w *world) signSecretWrite(logical, validity string) error {
	v, err := randomValue()
	if err != nil {
		return err
	}
	route := secretsRoute + w.secretPath(logical)
	body := putBody(v, false)
	token, err := w.token("operator", write{method: http.MethodPut, path: route, body: body, validity: validity})
	if err != nil {
		return err
	}
	w.secrets.signed = &pendingWrite{path: route, body: body, token: token}
	return nil
}

func operatorSignsSecretWrite(ctx context.Context, logical string) error {
	return getWorld(ctx).signSecretWrite(logical, "")
}

// operatorSignsExpiredSecretWrite signs with the shortest validity and waits
// it out, and the clock skew the CDS's verifier allows on top of it.
func operatorSignsExpiredSecretWrite(ctx context.Context, logical string) error {
	w := getWorld(ctx)
	if err := w.signSecretWrite(logical, "1s"); err != nil {
		return err
	}
	out, err := w.cdsArg("jwt-clock-skew")
	if err != nil {
		return err
	}
	skew, err := strconv.Atoi(out)
	if err != nil {
		return fmt.Errorf("the CDS's clock skew %q: %w", out, err)
	}
	time.Sleep(time.Second + time.Duration(skew)*time.Second + 2*time.Second)
	return nil
}

// signedWrite is the write the operator signed and has not sent.
func (w *world) signedWrite() (*pendingWrite, error) {
	if w.secrets.signed == nil {
		return nil, errors.New("the operator has signed no write")
	}
	return w.secrets.signed, nil
}

// sendSigned sends the signed write's token with the route and body given,
// which fn derives from the write.
func (w *world) sendSigned(fn func(*pendingWrite) (route string, body []byte, err error)) error {
	signed, err := w.signedWrite()
	if err != nil {
		return err
	}
	route, body, err := fn(signed)
	if err != nil {
		return err
	}
	a, err := w.cdsRequest(http.MethodPut, route, body, signed.token, "", "")
	if err != nil {
		return err
	}
	w.secrets.write = a
	return nil
}

func sendsTokenToOtherPath(ctx context.Context, logical string) error {
	w := getWorld(ctx)
	return w.sendSigned(func(s *pendingWrite) (string, []byte, error) {
		return secretsRoute + w.secretPath(logical), s.body, nil
	})
}

func sendsTokenWithOtherValue(ctx context.Context) error {
	return getWorld(ctx).sendSigned(func(s *pendingWrite) (string, []byte, error) {
		v, err := randomValue()
		return s.path, putBody(v, false), err
	})
}

func sendsTokenAsSigned(ctx context.Context) error {
	return getWorld(ctx).sendSigned(func(s *pendingWrite) (string, []byte, error) { return s.path, s.body, nil })
}

func operatorDeletes(ctx context.Context, logical string) error {
	w := getWorld(ctx)
	route := secretsRoute + w.secretPath(logical)
	token, err := w.token("operator", write{method: http.MethodDelete, path: route, body: []byte{}})
	if err != nil {
		return err
	}
	a, err := w.cdsRequest(http.MethodDelete, route, []byte{}, token, "", "")
	if err != nil {
		return err
	}
	w.secrets.write = a
	return nil
}

func cdsRefusesDelete(ctx context.Context) error {
	a, err := getWorld(ctx).lastWrite()
	if err != nil {
		return err
	}
	if a.ok() {
		return fmt.Errorf("the delete was answered %s", a)
	}
	return nil
}

// --- Pods ---

// secretFile is the file name the secret client writes a logical path to.
func secretFile(logical string) string { return path.Base(logical) }

func secretClientConfigured(ctx context.Context, name, logical string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	p.secrets = append(p.secrets, secretFile(logical)+"="+w.secretPath(logical))
	return nil
}

// argvHelperMode gives the container the argv of a helper the webhook
// injects, as far as the match looks: the helper binary, then a mode. The
// probe-file mode waits for a file nothing writes, so the container runs as
// long as the pod.
func argvHelperMode(ctx context.Context) error {
	w := getWorld(ctx)
	if w.lastPod == nil {
		return errors.New("no container has been described yet")
	}
	w.lastPod.last().command = []string{"/c8s", "probe-file", "--wait", "/run/c8s/never-written"}
	return nil
}

// mountsDiskVolume gives the last main container an emptyDir on the node's
// disk, a mount the node reports as neither memory-backed nor encrypted.
// Where the node's scratch is encrypted the node confines it, so the sentence
// cannot be said there.
func mountsDiskVolume(ctx context.Context) error {
	w := getWorld(ctx)
	if w.lastPod == nil {
		return errors.New("no container has been described yet")
	}
	p := w.lastPod
	if p.initLast || p.last() != p.containers[len(p.containers)-1] {
		return errors.New("harness limitation: only the last main container of a pod takes a disk volume")
	}
	answer, err := w.be.call("scratch_encrypted")
	if err != nil {
		return err
	}
	if answer == "yes" {
		return skipf("disk-backed emptyDirs are encrypted here (scratch_encrypted)")
	}
	p.opts = append(p.opts, "--disk-volume", "/scratch")
	return nil
}

// hasInitContainer describes an init container, which the argv sentence
// then addresses as "that container".
func hasInitContainer(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	refs, err := w.refs(image)
	if err != nil {
		return err
	}
	p.init = &container{ref: refs[0], command: []string{"sleep", "3600"}}
	p.initLast = true
	w.lastPod = p
	return nil
}

func initContainerState(ctx context.Context, name, state string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if p.init == nil {
		return fmt.Errorf("%q has no init container", name)
	}
	// The init container's state, a one-member object keyed running,
	// terminated or waiting; empty until the object is there.
	var seen string
	ok, err := poll(observe, func() (bool, error) {
		out, err := kubectl(nil, "-n", p.namespace, "get", "pod", p.name, "-o", `jsonpath={.status.initContainerStatuses[?(@.name=="i1")].state}`)
		if err != nil {
			return false, nil // the object may not be there yet
		}
		seen = "waiting"
		for _, key := range []string{"running", "terminated"} {
			if strings.Contains(out, `"`+key+`"`) {
				seen = key
			}
		}
		if state == "is running" {
			return seen == "running", nil
		}
		return seen == "terminated", nil
	})
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the init container of %q is %q after %s", name, seen, observe)
	}
	return nil
}

// obtainedSandboxLeaf waits for the pod's requester to report an issuance
// and reads the leaf, which must carry a sandbox ID.
func obtainedSandboxLeaf(ctx context.Context, name string) error {
	w := getWorld(ctx)
	if err := holdsLeaf(ctx, name); err != nil {
		return err
	}
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	id, err := p.leaf.sandboxID()
	if err != nil {
		return fmt.Errorf("the leaf %q holds: %w", name, err)
	}
	if id == "" {
		return fmt.Errorf("the leaf %q holds carries no sandbox ID", name)
	}
	// The first leaf is minted before the workload container is admitted,
	// so it names no workload and the requester renews it on the fast
	// unnamed schedule (getcert --unnamed-renew-interval, 30s at most)
	// until one does; only then does the two-hour interval hold. The leaf
	// the scenario goes on to speak of is the named one, so once the
	// workload is running the step waits one unnamed interval for it. A pod
	// that matches no entry (a container too many, an init container that
	// keeps the workload from starting) never gets one and keeps the leaf
	// it has.
	if p.init != nil {
		return nil
	}
	if err := w.awaitReady(p); err != nil {
		return err
	}
	_, err = poll(45*time.Second, func() (bool, error) {
		l, err := w.podLeaf(p)
		if err != nil || l == nil {
			return false, err
		}
		if _, err := l.matched(); err != nil {
			return false, nil
		}
		p.leaf = l
		return true, nil
	})
	return err
}

func stillHoldsLeaf(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.injectedPod(name)
	if err != nil {
		return err
	}
	if p.leaf == nil {
		return fmt.Errorf("the scenario has not established that %q obtained a leaf", name)
	}
	now, err := w.podLeaf(p)
	if err != nil {
		return err
	}
	if now == nil || now.serial() != p.leaf.serial() {
		return fmt.Errorf("%q no longer holds the leaf it obtained (serial %s); its requester renewed it", name, p.leaf.serial())
	}
	return nil
}

// --- The requester ---

// awaitReady waits once for every container of the pod to be running.
func (w *world) awaitReady(p *pod) error {
	if p.ready {
		return nil
	}
	if _, err := kubectl(nil, "-n", p.namespace, "wait", "--for=condition=Ready", "pod/"+p.name, "--timeout=120s"); err != nil {
		return fmt.Errorf("%q did not become Ready: %w", p.name, err)
	}
	p.ready = true
	return nil
}

// probe runs `c8s secret-probe` in the pod's certificate container.
func (w *world) probe(p *pod, args ...string) (string, error) {
	if !p.deployed || !p.workloadID {
		return "", fmt.Errorf("%q is not a deployed pod carrying a workload ID", p.name)
	}
	// The leaf exists before the workload container does (the cert-wait init
	// container gates on it), and until every main container has been
	// admitted the inventory reports no workload containers, so the CDS
	// denies by design; the real client retries through that window
	// (internal/cmds/sidecar Retry). The probe makes one request, so it
	// waits for the pod to be Ready once instead. A pod the scenario gave
	// an init container asks while that container runs, which is the point
	// of its scenario, so it is not waited for.
	if p.init == nil {
		if err := w.awaitReady(p); err != nil {
			return "", err
		}
	}
	url, err := w.be.call("cds_pod_url")
	if err != nil {
		return "", err
	}
	certFile, keyFile, err := w.certPaths()
	if err != nil {
		return "", err
	}
	verify, err := w.cdsVerification(p)
	if err != nil {
		return "", err
	}
	cmd := append([]string{"/c8s", "secret-probe", "--cds-url", url, "--cert", certFile, "--key", keyFile}, verify...)
	return w.podExec(p, certContainer, append(cmd, args...)...)
}

// cdsVerification is how the pod's certificate container verifies the CDS,
// as the probe's flags: the webhook's attestation API and pins, with the
// one $(HOST_IP) reference the kubelet expands resolved to the pod's node.
func (w *world) cdsVerification(p *pod) ([]string, error) {
	if p.verifyCDS != nil {
		return p.verifyCDS, nil
	}
	out, err := kubectl(nil, "-n", p.namespace, "get", "pod", p.name, "-o", "json")
	if err != nil {
		return nil, err
	}
	// JSON, not one arg per line: the image policy argument is a JSON
	// document that may span lines.
	var spec struct {
		Spec struct {
			InitContainers []struct {
				Name string   `json:"name"`
				Args []string `json:"args"`
			} `json:"initContainers"`
		} `json:"spec"`
		Status struct {
			HostIP string `json:"hostIP"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &spec); err != nil {
		return nil, err
	}
	hostIP := spec.Status.HostIP
	var args []string
	for _, c := range spec.Spec.InitContainers {
		if c.Name == certContainer {
			args = c.Args
		}
	}
	flags := []string{}
	for _, arg := range args {
		name, value, _ := strings.Cut(arg, "=")
		switch name {
		case "--attestation-api-url", "--image-policy-json":
		case "--cds-measurements":
			name = "--measurements"
		case "--cds-rtmrs":
			name = "--rtmrs"
		default:
			continue
		}
		value = strings.ReplaceAll(value, "$(HOST_IP)", hostIP)
		if strings.Contains(value, "$(") {
			return nil, fmt.Errorf("the %s container of %q passes %s with a reference the steps do not expand: %s", certContainer, p.name, name, value)
		}
		flags = append(flags, name+"="+value)
	}
	if len(flags) == 0 {
		return nil, fmt.Errorf("the %s container of %q names no attestation API to verify the CDS through", certContainer, p.name)
	}
	p.verifyCDS = flags
	return flags, nil
}

func (w *world) fetchChallenge(p *pod) ([]byte, error) {
	out, err := w.probe(p, "challenge")
	if err != nil {
		return nil, err
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil {
		return nil, fmt.Errorf("the challenge %q fetched is not base64: %w", p.name, err)
	}
	return c, nil
}

func (w *world) redeemToken(p *pod, challenge []byte) ([]byte, error) {
	args := []string{"token"}
	if challenge != nil {
		args = append(args, "--challenge", base64.StdEncoding.EncodeToString(challenge))
	}
	out, err := w.probe(p, args...)
	if err != nil {
		return nil, err
	}
	tok := []byte(strings.TrimSpace(out))
	if !json.Valid(tok) {
		return nil, fmt.Errorf("the sandbox token %q redeemed is not JSON: %s", p.name, out)
	}
	return tok, nil
}

// request sends the pod's next request as the scenario shaped it and
// records the answer. What the scenario did not shape, the probe obtains as
// a well-behaved requester would: a fresh challenge and a token bound to it,
// and it names both on its first line so "that request" can refer to them.
// The challenge is spent by the request, the token with it; the next request
// starts fresh unless a sentence says otherwise.
func (w *world) request(p *pod, method, logical string) (*answer, error) {
	s := w.secretState(p)
	args := []string{"request", method, w.secretPath(logical)}
	switch {
	case s.noChallenge:
		args = append(args, "--no-challenge")
	case s.challenge != nil:
		args = append(args, "--challenge", base64.StdEncoding.EncodeToString(s.challenge))
	}
	switch {
	case s.noToken:
		args = append(args, "--no-token")
	case s.token != nil:
		args = append(args, "--token", string(s.token))
	}
	// The CDS meters the workload secret routes per sandbox (cds
	// --rate-limit, 10 a second by default); a scenario that asks many
	// times in a row, such as filling the holder quota, is paced by the
	// limiter, not judged by it, so a 429 is retried after a pause.
	var status int
	var sent string
	var body []byte
	for attempt := 0; ; attempt++ {
		out, err := w.probe(p, args...)
		if err != nil {
			return nil, err
		}
		if status, sent, body, err = statusLine(out); err != nil {
			return nil, fmt.Errorf("the probe in %q printed no answer: %q", p.name, out)
		}
		if status != http.StatusTooManyRequests || attempt == 5 {
			break
		}
		time.Sleep(time.Second)
	}
	challenge, token, err := sentCredentials(sent)
	if err != nil {
		return nil, fmt.Errorf("the probe in %q: %w", p.name, err)
	}
	a := &answer{status: status, body: body}
	s.lastChallenge, s.lastToken, s.lastPath, s.last = challenge, token, logical, a
	s.answers[logical] = a
	s.challenge, s.token, s.noChallenge, s.noToken = nil, nil, false, false
	if v, ok := a.value(); ok && a.ok() {
		s.previous[logical], s.values[logical] = s.values[logical], v
	}
	w.secrets.last = p
	return a, nil
}

// sentCredentials decodes the probe's "<challenge> <token>", base64 each or
// - for a header the request omitted.
func sentCredentials(fields string) (challenge, token []byte, err error) {
	parts := strings.Fields(fields)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("named %d credentials, not two: %q", len(parts), fields)
	}
	decode := func(what, v string) ([]byte, error) {
		if v == "-" {
			return nil, nil
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("the %s sent is not base64: %w", what, err)
		}
		return b, nil
	}
	if challenge, err = decode("challenge", parts[0]); err != nil {
		return nil, nil, err
	}
	if token, err = decode("token", parts[1]); err != nil {
		return nil, nil, err
	}
	return challenge, token, nil
}

func holdsChallenge(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	s := w.secretState(p)
	s.challenge, err = w.fetchChallenge(p)
	s.noChallenge = false
	return err
}

func holdsNoChallenge(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	s := w.secretState(p)
	s.challenge, s.noChallenge = nil, true
	return nil
}

func holdsNoToken(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	s := w.secretState(p)
	s.token, s.noToken = nil, true
	return nil
}

// grantedPath is a logical path the scenario stored a value at, for a
// request that has to be authorized.
func (w *world) grantedPath() (string, error) {
	for p := range w.secrets.stored {
		return p, nil
	}
	return "", errors.New("the scenario has stored no secret value to request")
}

// spend sends one authorized read with the pod's current credentials and
// checks it was answered as such.
func (w *world) spend(p *pod, authorized bool) error {
	logical, err := w.grantedPath()
	if err != nil {
		return err
	}
	a, err := w.request(p, http.MethodGet, logical)
	if err != nil {
		return err
	}
	if authorized && a.status != http.StatusOK {
		return fmt.Errorf("the request meant to spend the challenge was answered %s", a)
	}
	if !authorized && a.status != http.StatusForbidden {
		return fmt.Errorf("the request meant to fail authorization was answered %s", a)
	}
	return nil
}

func holdsFlawedChallenge(ctx context.Context, name, flaw string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	s := w.secretState(p)
	s.noChallenge = false
	switch flaw {
	case "the CDS never issued":
		s.challenge = make([]byte, 32)
		_, err = rand.Read(s.challenge)
		return err
	case "that has passed the release challenge lifetime":
		if s.challenge, err = w.fetchChallenge(p); err != nil {
			return err
		}
		return challengeExpired(ctx)
	case "the CDS issued for certificate issuance":
		a, err := w.cdsRequest(http.MethodPost, authenticateRoute, []byte("{}"), "", "", "")
		if err != nil {
			return err
		}
		if a.status != http.StatusOK {
			return fmt.Errorf("the CDS answered %s to an issuance challenge request", a)
		}
		s.challenge, err = parseChallenge(a.body)
		return err
	case "already spent by an authorized secret request":
		if s.challenge, err = w.fetchChallenge(p); err != nil {
			return err
		}
		if s.token, err = w.redeemToken(p, s.challenge); err != nil {
			return err
		}
		spent, token := s.challenge, s.token
		if err := w.spend(p, true); err != nil {
			return err
		}
		s.challenge, s.token = spent, token
		return nil
	case "already spent by a secret request that failed authorization":
		if s.challenge, err = w.fetchChallenge(p); err != nil {
			return err
		}
		spent := s.challenge
		s.noToken = true
		if err := w.spend(p, false); err != nil {
			return err
		}
		s.challenge = spent
		return nil
	}
	return fmt.Errorf("no flaw %q is known", flaw)
}

func holdsSandboxToken(ctx context.Context, name, node, forChallenge string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if _, err := w.node(node); err != nil {
		return err
	}
	s := w.secretState(p)
	var nonce []byte
	if forChallenge != "" {
		if s.challenge == nil {
			return fmt.Errorf("%q holds no release challenge", name)
		}
		nonce = s.challenge
	}
	s.token, err = w.redeemToken(p, nonce)
	s.noToken = false
	return err
}

func holdsOthersToken(ctx context.Context, name, other string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	o, err := w.pod(other)
	if err != nil {
		return err
	}
	s := w.secretState(p)
	if s.challenge == nil {
		return fmt.Errorf("%q holds no release challenge", name)
	}
	s.token, err = w.redeemToken(o, s.challenge)
	s.noToken = false
	return err
}

// holdsSpentToken: a token bound to a challenge that an authorized request
// then spent; the token stays, the challenge goes.
func holdsSpentToken(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	s := w.secretState(p)
	if s.challenge, err = w.fetchChallenge(p); err != nil {
		return err
	}
	if s.token, err = w.redeemToken(p, s.challenge); err != nil {
		return err
	}
	token := s.token
	if err := w.spend(p, true); err != nil {
		return err
	}
	s.token = token
	return nil
}

// otherInventoryHost is a global-unicast address no node here has, so the
// token parses and the host comparison, not its validity, decides.
const otherInventoryHost = "192.0.2.1"

// holdsForeignHostToken forges a token over the pod's own key and sandbox
// ID, signed by a key of the scenario's, naming another inventory host.
func holdsForeignHostToken(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.injectedPod(name)
	if err != nil {
		return err
	}
	s := w.secretState(p)
	if s.challenge == nil {
		if s.challenge, err = w.fetchChallenge(p); err != nil {
			return err
		}
	}
	if p.leaf == nil {
		return fmt.Errorf("the scenario has not established that %q obtained a leaf", name)
	}
	id, err := p.leaf.sandboxID()
	if err != nil {
		return err
	}
	signer, err := generateKey()
	if err != nil {
		return err
	}
	s.token, err = signSandboxToken(signer, id, p.leaf.cert.PublicKey, s.challenge, otherInventoryHost)
	s.noToken = false
	return err
}

// --- A requester outside any pod ---

func selfSignedRequester(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.injectedPod(name)
	if err != nil {
		return err
	}
	if p.leaf == nil {
		return fmt.Errorf("the scenario has not established that %q obtained a leaf", name)
	}
	id, err := p.leaf.sandboxID()
	if err != nil {
		return err
	}
	key, err := generateKey()
	if err != nil {
		return err
	}
	value, err := asn1.MarshalWithParams(id, "utf8")
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{CommonName: "conformance-self-signed"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: oidSandboxID, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certFile, err := w.writeFile("self-signed.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		return err
	}
	keyFile, err := w.writeFile("self-signed.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return err
	}
	w.secrets.self = &outsideRequester{certFile: certFile, keyFile: keyFile}
	return nil
}

func selfSignedRequests(ctx context.Context, logical string) error {
	w := getWorld(ctx)
	r := w.secrets.self
	if r == nil {
		return errors.New("no requester holds a self-signed certificate")
	}
	a, err := w.cdsRequest(http.MethodGet, secretsRoute+w.secretPath(logical), nil, "", r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.last = a
	return nil
}

func selfSignedReceivesNothing(ctx context.Context) error {
	r := getWorld(ctx).secrets.self
	if r == nil || r.last == nil {
		return errors.New("the self-signed requester has sent no request")
	}
	if _, has := r.last.value(); has {
		return fmt.Errorf("the self-signed requester received a value: %s", r.last)
	}
	return nil
}

// --- Requests and answers ---

func requestsSecret(ctx context.Context, name, what, logical string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	method := http.MethodGet
	if what == "generation at" {
		method = http.MethodPost
	}
	_, err = w.request(p, method, logical)
	return err
}

func hasRequestedRead(ctx context.Context, name, logical, got string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if _, err := w.request(p, http.MethodGet, logical); err != nil {
		return err
	}
	if got == "no secret value" {
		return receivesNoValue(ctx, name)
	}
	return receivesStoredValue(ctx, name)
}

func hasGenerated(ctx context.Context, name, logical string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	a, err := w.request(p, http.MethodPost, logical)
	if err != nil {
		return err
	}
	v, ok := a.value()
	if a.status != http.StatusCreated || !ok {
		return fmt.Errorf("the generation %q requested at %s was answered %s", name, logical, a)
	}
	w.secrets.stored[logical] = v
	return nil
}

// hasFilledQuota generates one path per quota slot the holder has left.
func hasFilledQuota(ctx context.Context, name, below, holder string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if _, err := w.entry(holder); err != nil {
		return err
	}
	out, err := w.cdsArg("secrets-max-paths-per-workload")
	if err != nil {
		return err
	}
	quota, err := strconv.Atoi(out)
	if err != nil {
		return fmt.Errorf("the holder quota %q: %w", out, err)
	}
	generated := 0
	for logical := range w.secretState(p).values {
		if strings.HasPrefix(logical, below) {
			generated++
		}
	}
	for i := generated; i < quota; i++ {
		if err := hasGenerated(ctx, name, fmt.Sprintf("%sq%d", below, i)); err != nil {
			return err
		}
	}
	return nil
}

// lastOf is the record of the pod's requests, which holds at least one.
func (w *world) lastOf(name string) (*secretReq, error) {
	p, err := w.pod(name)
	if err != nil {
		return nil, err
	}
	s := w.secretState(p)
	if s.last == nil {
		return nil, fmt.Errorf("%q has sent no secret request", name)
	}
	return s, nil
}

func receivesStoredValue(ctx context.Context, name string) error {
	w := getWorld(ctx)
	s, err := w.lastOf(name)
	if err != nil {
		return err
	}
	want, ok := w.secrets.stored[s.lastPath]
	if !ok {
		return fmt.Errorf("the scenario stored no value at %s", s.lastPath)
	}
	return expectValue(name, s.last, want, "the one stored at "+s.lastPath)
}

// expectValue checks the pod's answer carried want, described as source.
func expectValue(name string, a *answer, want []byte, source string) error {
	got, has := a.value()
	if a.status != http.StatusOK || !has {
		return fmt.Errorf("%q was answered %s, not %s", name, a, source)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%q received a value other than %s", name, source)
	}
	return nil
}

func receivesAValue(ctx context.Context, name string) error {
	s, err := getWorld(ctx).lastOf(name)
	if err != nil {
		return err
	}
	if _, has := s.last.value(); !s.last.ok() || !has {
		return fmt.Errorf("%q was answered %s, no value", name, s.last)
	}
	return nil
}

func receivesNoValue(ctx context.Context, name string) error {
	s, err := getWorld(ctx).lastOf(name)
	if err != nil {
		return err
	}
	if _, has := s.last.value(); has && s.last.ok() {
		return fmt.Errorf("%q received a value: %s", name, s.last)
	}
	return nil
}

func (w *world) answered(name string, status int, message string) (*answer, error) {
	s, err := w.lastOf(name)
	if err != nil {
		return nil, err
	}
	a := s.last
	if a.status != status {
		return nil, fmt.Errorf("the CDS answered %q %s, not %d %s", name, a, status, message)
	}
	if message != "" && !bytes.Contains(a.body, []byte(message)) {
		return nil, fmt.Errorf("the CDS answered %q %d without %q: %s", name, status, message, a.body)
	}
	return a, nil
}

func answersNotAuthorized(ctx context.Context, name string) error {
	_, err := getWorld(ctx).answered(name, http.StatusForbidden, msgNotAuthorized)
	return err
}

func answersNoSuchSecret(ctx context.Context, name string) error {
	_, err := getWorld(ctx).answered(name, http.StatusNotFound, msgNoSuchSecret)
	return err
}

func answersInvalid(ctx context.Context, name string) error {
	_, err := getWorld(ctx).answered(name, http.StatusBadRequest, "")
	return err
}

func answersExists(ctx context.Context, name string) error {
	if _, err := getWorld(ctx).answered(name, http.StatusConflict, ""); err != nil {
		return err
	}
	return receivesNoValue(ctx, name)
}

func answersQuota(ctx context.Context, name string) error {
	a, err := getWorld(ctx).answered(name, http.StatusInsufficientStorage, msgQuota)
	if err != nil {
		return err
	}
	var doc struct {
		Code string `json:"error"`
	}
	if err := json.Unmarshal(a.body, &doc); err != nil || doc.Code != codeHolderQuota {
		return fmt.Errorf("the CDS refused with %s, not %s", a, codeHolderQuota)
	}
	return nil
}

// lastRequester is the pod whose secret request was the last, and that
// request's record.
func (w *world) lastRequester() (*pod, *secretReq, error) {
	p := w.secrets.last
	if p == nil || p.secret == nil || p.secret.last == nil {
		return nil, nil, errors.New("no secret request has been made")
	}
	return p, p.secret, nil
}

// lastValue is the value the last request of any pod received.
func (w *world) lastValue() (*pod, []byte, error) {
	p, s, err := w.lastRequester()
	if err != nil {
		return nil, nil, err
	}
	v, ok := s.last.value()
	if !ok {
		return nil, nil, fmt.Errorf("the last answer carried no value: %s", p.secret.last)
	}
	return p, v, nil
}

func valueLength(ctx context.Context, n int) error {
	_, v, err := getWorld(ctx).lastValue()
	if err != nil {
		return err
	}
	if len(v) != n {
		return fmt.Errorf("the value is %d bytes, not %d", len(v), n)
	}
	return nil
}

func valueDiffersFromHeld(ctx context.Context, name, logical string) error {
	w := getWorld(ctx)
	_, v, err := w.lastValue()
	if err != nil {
		return err
	}
	o, err := w.pod(name)
	if err != nil {
		return err
	}
	held, ok := w.secretState(o).values[logical]
	if !ok {
		return fmt.Errorf("%q holds no value for %s", name, logical)
	}
	if bytes.Equal(v, held) {
		return fmt.Errorf("the value is the one %q holds for %s", name, logical)
	}
	return nil
}

func valueDiffersFromBefore(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, v, err := w.lastValue()
	if err != nil {
		return err
	}
	if named, err := w.pod(name); err != nil {
		return err
	} else if named != p {
		return fmt.Errorf("the last answer was %q's, not %q's", p.name, name)
	}
	before, ok := p.secret.previous[p.secret.lastPath]
	if !ok {
		return fmt.Errorf("%q received no value for %s before", name, p.secret.lastPath)
	}
	if bytes.Equal(v, before) {
		return fmt.Errorf("the value is the one %q received before", name)
	}
	return nil
}

func receivesHeldValue(ctx context.Context, name, other, logical string) error {
	w := getWorld(ctx)
	o, err := w.pod(other)
	if err != nil {
		return err
	}
	held, ok := w.secretState(o).values[logical]
	if !ok {
		return fmt.Errorf("%q holds no value for %s", other, logical)
	}
	s, err := w.lastOf(name)
	if err != nil {
		return err
	}
	return expectValue(name, s.last, held, fmt.Sprintf("the one %q holds for %s", other, logical))
}

func sameAnswerAs(ctx context.Context, name, logical string) error {
	s, err := getWorld(ctx).lastOf(name)
	if err != nil {
		return err
	}
	earlier, ok := s.answers[logical]
	if !ok {
		return fmt.Errorf("%q received no answer for %s", name, logical)
	}
	if earlier.status != s.last.status || !bytes.Equal(earlier.body, s.last.body) {
		return fmt.Errorf("the answers differ: %s for %s, %s now", earlier, logical, s.last)
	}
	return nil
}

// challengeNotSpent repeats an authorized read with the last request's
// challenge and token; a spent challenge would be refused.
func challengeNotSpent(ctx context.Context) error {
	w := getWorld(ctx)
	p, s, err := w.lastRequester()
	if err != nil {
		return err
	}
	if s.lastChallenge == nil || s.lastToken == nil {
		return errors.New("the last request carried no challenge or no token")
	}
	s.challenge, s.token = s.lastChallenge, s.lastToken
	return w.spend(p, true)
}

func canStillRead(ctx context.Context, name, logical string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if _, err := w.request(p, http.MethodGet, logical); err != nil {
		return err
	}
	return receivesStoredValue(ctx, name)
}

// --- The secret client ---

func (w *world) readSecretFile(p *pod, logical string) ([]byte, error) {
	out, err := w.be.call("pod_file", p.namespace, p.name, p.first, secretClientDir+"/"+secretFile(logical))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out)
}

func outputHoldsFile(ctx context.Context, name, logical string) error {
	w := getWorld(ctx)
	p, err := w.injectedPod(name)
	if err != nil {
		return err
	}
	var content []byte
	ok, err := poll(observe, func() (bool, error) {
		content, err = w.readSecretFile(p, logical)
		if errors.Is(err, godog.ErrSkip) {
			return false, err
		}
		return err == nil, nil
	})
	if err != nil {
		return err
	}
	if !ok {
		log, _ := kubectl(nil, "-n", p.namespace, "logs", p.name, "-c", "c8s-secret")
		return fmt.Errorf("%q has no file for %s after %s; its secret client logged: %s", name, logical, observe, tail(log, 5))
	}
	w.secretState(p).files[logical] = content
	w.secrets.file = &clientFile{p: p, logical: logical, content: content}
	return nil
}

func fileHoldsSupplied(ctx context.Context) error {
	w := getWorld(ctx)
	f := w.secrets.file
	if f == nil {
		return errors.New("no file of a secret client has been read")
	}
	want, ok := w.secrets.stored[f.logical]
	if !ok {
		return fmt.Errorf("the operator supplied no value at %s", f.logical)
	}
	if !bytes.Equal(f.content, want) {
		return fmt.Errorf("the file of %q for %s holds other bytes than the operator supplied", f.p.name, f.logical)
	}
	return nil
}

func fileUnchanged(ctx context.Context, name, logical string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	before, ok := w.secretState(p).files[logical]
	if !ok {
		return fmt.Errorf("the file of %q for %s has not been read", name, logical)
	}
	// The client reads once; give a refresh, were there one, time to show.
	time.Sleep(10 * time.Second)
	now, err := w.readSecretFile(p, logical)
	if err != nil {
		return err
	}
	if !bytes.Equal(before, now) {
		return fmt.Errorf("the file of %q for %s changed", name, logical)
	}
	return nil
}

func outputOnMemory(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	out, err := w.be.call("pod_fstype", p.namespace, p.name, p.first, secretClientDir)
	if err != nil {
		return err
	}
	if fs := strings.TrimSpace(out); fs != "tmpfs" {
		return fmt.Errorf("the output directory of %q is on %q, not tmpfs", name, fs)
	}
	return nil
}
