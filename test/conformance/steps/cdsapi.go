package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about the CDS as its callers see it: writes by the operator with
// their write tokens, writes by callers holding none or the wrong one, and
// reads by a relying party, with the version every answer carries. A write
// here is sent as the sentence says, not through the harness's signed path.
func registerCDS(sc *godog.ScenarioContext) {
	sc.Step(`^the CDS has an operator key$`, cdsHasOperatorKey)
	sc.Step(`^the seed of the CDS declares image "([^"]*)"$`, seedDeclares)
	sc.Step(`^the served allowlist has a workload entry "([^"]*)"$`, servedHasEntry)
	sc.Step(`^the served allowlist has no workload entry "([^"]*)"$`, servedLacksEntry)
	sc.Step(`^a workload entry in the served allowlist admits image "([^"]*)" under any argv$`, servedAdmitsAnyArgv)
	sc.Step(`^a caller holds no write token$`, callerHoldsNoToken)
	sc.Step(`^a caller holds a write token signed with a key that is not an operator key$`, callerHoldsForeignToken)
	sc.Step(`^that caller sends the CDS a write of a workload entry "([^"]*)" admitting image "([^"]*)" under any argv$`, callerWrites)
	sc.Step(`^the operator (?:writes|has written) a workload entry "([^"]*)" admitting image "([^"]*)" under any argv$`, operatorWritesAnyArgv)
	sc.Step(`^the operator writes a workload entry "([^"]*)" admitting image "([^"]*)" under any argv and carrying an unknown member$`, operatorWritesUnknownMember)
	sc.Step(`^the operator has written "([^"]*)"$`, operatorWritesDescribed)
	sc.Step(`^the operator (?:removes|has removed) the workload entry "([^"]*)"$`, operatorRemoves)
	sc.Step(`^a caller replays the write token of that write on a write of a workload entry "([^"]*)" admitting image "([^"]*)" under any argv$`, replayOnWrite)
	sc.Step(`^a caller replays the write token of that write on a removal of the workload entry "([^"]*)"$`, replayOnRemoval)
	sc.Step(`^the operator signs a write token for a write of a workload entry "([^"]*)" admitting image "([^"]*)" under any argv$`, operatorSignsWrite)
	sc.Step(`^that write token expires (\d+) hours? after it was issued$`, tokenExpiresHours)
	sc.Step(`^the operator sends the CDS that write with that write token$`, operatorSendsSigned)
	sc.Step(`^the CDS refuses the write$`, cdsRefusesWrite)
	sc.Step(`^the CDS refuses the write as invalid$`, cdsRefusesInvalid)
	sc.Step(`^the CDS refuses the removal because no entry has that name$`, cdsRefusesRemovalNoEntry)
	sc.Step(`^a relying party reads the version$`, readsVersion)
	sc.Step(`^a relying party reads the allowlist with no client authentication$`, readsAllowlist)
	sc.Step(`^that relying party reads the allowlist naming the version it read before$`, readsAllowlistNamingVersion)
	sc.Step(`^that relying party receives the served allowlist$`, receivesServed)
	sc.Step(`^the CDS answers with the version and no body$`, answersVersionNoBody)
	sc.Step(`^a workload entry in the allowlist that relying party received declares image "([^"]*)"$`, receivedDeclares)
	sc.Step(`^no workload entry in the allowlist that relying party received declares image "([^"]*)"$`, receivedLacks)
	sc.Step(`^"([^"]*)" is in the allowlist that relying party received$`, receivedHasEntry)
	sc.Step(`^"([^"]*)" in that allowlist pins the mounts of "([^"]*)" to one rule of kind "([^"]*)" with destination "([^"]*)"$`, receivedPinsMounts)
	sc.Step(`^the version is (the version read before|one greater than the version read before|greater than the version read before|below the version read before)$`, versionCompares)
}

// Who a scenario's caller is, for the write it sends.
const (
	callerNone    = "none"
	callerForeign = "foreign"
)

// write is one request to the CDS's allowlist routes.
type write struct {
	method, path string
	body         []byte
}

// reading is what a relying party got back from a read.
type reading struct {
	status  int
	version string
	body    []byte
}

const workloadsPath = "/allowlist/workloads/"

func (w *world) workloadPath(name string) string { return workloadsPath + w.writtenName(name) }

// anyArgvEntry is an entry named name admitting image under any argv, as a
// write body.
func (w *world) anyArgvEntry(name, image string) ([]byte, error) {
	ref, err := w.be.call("image_ref", image)
	if err != nil {
		return nil, err
	}
	digest, err := w.digestOf(image)
	if err != nil {
		return nil, err
	}
	return json.Marshal(entry{
		Label:          name,
		InitContainers: []entryContainer{},
		Containers: []entryContainer{{
			Digest: digest, Image: ref,
			Command: anyArgv(), Args: anyArgv(),
			Mounts: mountsPolicy{Policy: "any"}, Env: policy{Policy: "any"},
		}},
	})
}

// withBodyFile runs fn with body in a file, the form the backend takes.
func withBodyFile(body []byte, fn func(path string) error) error {
	f, err := os.CreateTemp("", "body-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, werr := f.Write(body)
	if err := errors.Join(werr, f.Close()); err != nil {
		return err
	}
	return fn(f.Name())
}

// token mints the write token for wr: signer is "operator" or "foreign",
// validity a Go duration or empty for the signer's default.
func (w *world) token(signer string, wr write, validity string) (string, error) {
	var token string
	err := withBodyFile(wr.body, func(path string) error {
		args := []string{signer, wr.method, wr.path, path}
		if validity != "" {
			args = append(args, validity)
		}
		out, err := w.be.call("write_token", args...)
		token = out
		return err
	})
	return token, err
}

// send sends wr with auth as its Authorization, none when empty, and records
// the status. A stored write changed the served allowlist: a put entry is
// the scenario's to delete afterwards.
func (w *world) send(wr write, auth string) error {
	var status string
	err := withBodyFile(wr.body, func(path string) error {
		out, err := w.be.call("allowlist_request", wr.method, wr.path, path, auth)
		status = out
		return err
	})
	if err != nil {
		return err
	}
	if w.lastStatus, err = strconv.Atoi(status); err != nil {
		return fmt.Errorf("status %q: %w", status, err)
	}
	if w.lastStatus == http.StatusNoContent {
		lastMutation = time.Now()
		if wr.method == http.MethodPut {
			w.written[strings.TrimPrefix(wr.path, workloadsPath)] = true
		}
	}
	return nil
}

// operatorWrite signs wr with the operator's key and sends it, keeping the
// token for a replay.
func (w *world) operatorWrite(wr write) error {
	token, err := w.token("operator", wr, "")
	if err != nil {
		return err
	}
	w.lastToken = token
	return w.send(wr, token)
}

func cdsHasOperatorKey(ctx context.Context) error {
	answer, err := getWorld(ctx).be.call("operator_keys")
	if err != nil {
		return err
	}
	if answer != "yes" {
		return errors.New("harness precondition: the CDS holds no operator key")
	}
	return nil
}

// seedDeclares is a precondition on the installation; one whose seed does
// not declare the image cannot run the scenario.
func seedDeclares(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	answer, err := w.be.call("seed_declares", digest)
	if err != nil {
		return err
	}
	if answer != "yes" {
		return godog.ErrSkip
	}
	return nil
}

func servedHasEntry(ctx context.Context, name string) error {
	w := getWorld(ctx)
	s, err := w.served()
	if err != nil {
		return err
	}
	if _, ok := s.raw[w.writtenName(name)]; !ok {
		return fmt.Errorf("the served allowlist has no workload entry %q", name)
	}
	return nil
}

func servedLacksEntry(ctx context.Context, name string) error {
	w := getWorld(ctx)
	s, err := w.served()
	if err != nil {
		return err
	}
	if _, ok := s.raw[w.writtenName(name)]; ok {
		return fmt.Errorf("the served allowlist has a workload entry %q", name)
	}
	return nil
}

func servedAdmitsAnyArgv(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	s, err := w.served()
	if err != nil {
		return err
	}
	if !s.admitsAnyArgv(digest) {
		return fmt.Errorf("no served entry admits %s (%s) under any argv", image, digest)
	}
	return nil
}

func callerHoldsNoToken(ctx context.Context) error {
	getWorld(ctx).caller = callerNone
	return nil
}

func callerHoldsForeignToken(ctx context.Context) error {
	getWorld(ctx).caller = callerForeign
	return nil
}

func callerWrites(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	body, err := w.anyArgvEntry(name, image)
	if err != nil {
		return err
	}
	wr := write{method: http.MethodPut, path: w.workloadPath(name), body: body}
	switch w.caller {
	case callerNone:
		return w.send(wr, "")
	case callerForeign:
		token, err := w.token("foreign", wr, "")
		if err != nil {
			return err
		}
		return w.send(wr, token)
	}
	return errors.New("the scenario has not said what write token the caller holds")
}

func operatorWritesAnyArgv(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	body, err := w.anyArgvEntry(name, image)
	if err != nil {
		return err
	}
	return w.operatorWrite(write{method: http.MethodPut, path: w.workloadPath(name), body: body})
}

// operatorWritesUnknownMember adds a member no rule of the document names.
func operatorWritesUnknownMember(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	body, err := w.anyArgvEntry(name, image)
	if err != nil {
		return err
	}
	var members map[string]any
	if err := json.Unmarshal(body, &members); err != nil {
		return err
	}
	members["note"] = "a member no rule names"
	if body, err = json.Marshal(members); err != nil {
		return err
	}
	return w.operatorWrite(write{method: http.MethodPut, path: w.workloadPath(name), body: body})
}

// operatorWritesDescribed writes the entry the scenario described, through
// the signed path, without waiting for the plugin.
func operatorWritesDescribed(ctx context.Context, name string) error {
	w := getWorld(ctx)
	e, err := w.entry(name)
	if err != nil {
		return err
	}
	written := w.writtenName(name)
	if w.written[written] {
		return nil
	}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := w.putEntry(written, body); err != nil {
		return err
	}
	w.written[written] = true
	return nil
}

// operatorRemoves deletes the entry, keeping a served one the scenario did
// not write for restoreAllowlist.
func operatorRemoves(ctx context.Context, name string) error {
	w := getWorld(ctx)
	written := w.writtenName(name)
	s, err := w.served()
	if err != nil {
		return err
	}
	if raw, ok := s.raw[written]; ok && !w.written[written] {
		w.removed[written] = raw
	}
	return w.operatorWrite(write{method: http.MethodDelete, path: w.workloadPath(name)})
}

func (w *world) replay(wr write) error {
	if w.lastToken == "" {
		return errors.New("the scenario has recorded no write token to replay")
	}
	return w.send(wr, w.lastToken)
}

func replayOnWrite(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	body, err := w.anyArgvEntry(name, image)
	if err != nil {
		return err
	}
	return w.replay(write{method: http.MethodPut, path: w.workloadPath(name), body: body})
}

func replayOnRemoval(ctx context.Context, name string) error {
	w := getWorld(ctx)
	return w.replay(write{method: http.MethodDelete, path: w.workloadPath(name)})
}

// operatorSignsWrite describes a write whose token the next sentences shape;
// the token is minted when the write is sent.
func operatorSignsWrite(ctx context.Context, name, image string) error {
	w := getWorld(ctx)
	body, err := w.anyArgvEntry(name, image)
	if err != nil {
		return err
	}
	w.pending = &write{method: http.MethodPut, path: w.workloadPath(name), body: body}
	w.pendingValidity = ""
	return nil
}

func tokenExpiresHours(ctx context.Context, hours int) error {
	w := getWorld(ctx)
	if w.pending == nil {
		return errors.New("the scenario has described no write to sign")
	}
	w.pendingValidity = fmt.Sprintf("%dh", hours)
	return nil
}

func operatorSendsSigned(ctx context.Context) error {
	w := getWorld(ctx)
	if w.pending == nil {
		return errors.New("the scenario has described no write to sign")
	}
	token, err := w.token("operator", *w.pending, w.pendingValidity)
	if err != nil {
		return err
	}
	w.lastToken = token
	return w.send(*w.pending, token)
}

func (w *world) refused(status int, what string) error {
	if w.lastStatus == 0 {
		return errors.New("the scenario has sent the CDS no write")
	}
	if w.lastStatus != status {
		return fmt.Errorf("the CDS answered %d, not %d (%s)", w.lastStatus, status, what)
	}
	return nil
}

func cdsRefusesWrite(ctx context.Context) error {
	return getWorld(ctx).refused(http.StatusUnauthorized, "authorization failed")
}

func cdsRefusesInvalid(ctx context.Context) error {
	return getWorld(ctx).refused(http.StatusUnprocessableEntity, "validation failed")
}

func cdsRefusesRemovalNoEntry(ctx context.Context) error {
	return getWorld(ctx).refused(http.StatusNotFound, "no entry has that name")
}

func readsVersion(ctx context.Context) error {
	w := getWorld(ctx)
	version, err := w.be.call("served_version")
	if err != nil {
		return err
	}
	if version == "" {
		return errors.New("the CDS answered with no version")
	}
	w.versionBefore = version
	return nil
}

// get reads the allowlist, naming version in If-None-Match when given.
func (w *world) get(version string) error {
	var args []string
	if version != "" {
		args = append(args, version)
	}
	out, err := w.be.call("allowlist_get", args...)
	if err != nil {
		return err
	}
	first, body, _ := strings.Cut(out, "\n")
	fields := strings.Fields(first)
	if len(fields) == 0 {
		return errors.New("allowlist_get answered nothing")
	}
	r := &reading{body: []byte(body)}
	if r.status, err = strconv.Atoi(fields[0]); err != nil {
		return fmt.Errorf("status %q: %w", fields[0], err)
	}
	if len(fields) > 1 {
		r.version = fields[1]
	}
	w.read = r
	return nil
}

func readsAllowlist(ctx context.Context) error { return getWorld(ctx).get("") }

func readsAllowlistNamingVersion(ctx context.Context) error {
	w := getWorld(ctx)
	if w.versionBefore == "" {
		return errors.New("the relying party has read no version")
	}
	return w.get(w.versionBefore)
}

// received is the allowlist the last read carried.
func (w *world) received() (served, error) {
	if w.read == nil {
		return served{}, errors.New("the relying party has read nothing")
	}
	if w.read.status != http.StatusOK {
		return served{}, fmt.Errorf("the read was answered %d, with no allowlist", w.read.status)
	}
	return parseServed(string(w.read.body))
}

func receivesServed(ctx context.Context) error {
	w := getWorld(ctx)
	s, err := w.received()
	if err != nil {
		return err
	}
	if s.schema != "c8s.allowlist/v1" {
		return fmt.Errorf("the body's schema is %q, not an allowlist", s.schema)
	}
	if w.read.version == "" {
		return errors.New("the answer carries no version")
	}
	return nil
}

func answersVersionNoBody(ctx context.Context) error {
	w := getWorld(ctx)
	if w.read == nil {
		return errors.New("the relying party has read nothing")
	}
	if w.read.status != http.StatusNotModified {
		return fmt.Errorf("the read was answered %d, not 304", w.read.status)
	}
	if w.read.version == "" {
		return errors.New("the answer carries no version")
	}
	if len(w.read.body) != 0 {
		return fmt.Errorf("the answer carries a body of %d bytes", len(w.read.body))
	}
	return nil
}

func receivedDeclares(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	s, err := w.received()
	if err != nil {
		return err
	}
	if !s.declares(digest) {
		return fmt.Errorf("no entry in the received allowlist declares %s (%s)", image, digest)
	}
	return nil
}

func receivedLacks(ctx context.Context, image string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	s, err := w.received()
	if err != nil {
		return err
	}
	if s.declares(digest) {
		return fmt.Errorf("an entry in the received allowlist declares %s (%s)", image, digest)
	}
	return nil
}

func receivedHasEntry(ctx context.Context, name string) error {
	w := getWorld(ctx)
	s, err := w.received()
	if err != nil {
		return err
	}
	if _, ok := s.raw[w.writtenName(name)]; !ok {
		return fmt.Errorf("the received allowlist has no workload entry %q", name)
	}
	return nil
}

func receivedPinsMounts(ctx context.Context, name, image, kind, destination string) error {
	w := getWorld(ctx)
	digest, err := w.digestOf(image)
	if err != nil {
		return err
	}
	s, err := w.received()
	if err != nil {
		return err
	}
	e, ok := s.entries[w.writtenName(name)]
	if !ok {
		return fmt.Errorf("the received allowlist has no workload entry %q", name)
	}
	for _, c := range e.containers() {
		if c.Digest != digest {
			continue
		}
		want := mountRule{Destination: destination, Kind: kind}
		if c.Mounts.Policy != "exact" || len(c.Mounts.Rules) != 1 || c.Mounts.Rules[0] != want {
			return fmt.Errorf("%q pins the mounts of %s to %+v, not one rule %+v", name, image, c.Mounts, want)
		}
		return nil
	}
	return fmt.Errorf("%q in the received allowlist declares no container running %s", name, image)
}

func versionCompares(ctx context.Context, relation string) error {
	w := getWorld(ctx)
	if w.versionBefore == "" {
		return errors.New("the relying party has read no version")
	}
	before, err := strconv.Atoi(w.versionBefore)
	if err != nil {
		return fmt.Errorf("version read before %q: %w", w.versionBefore, err)
	}
	s, err := w.be.call("served_version")
	if err != nil {
		return err
	}
	now, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("served version %q: %w", s, err)
	}
	var holds bool
	switch relation {
	case "the version read before":
		holds = now == before
	case "one greater than the version read before":
		holds = now == before+1
	case "greater than the version read before":
		holds = now > before
	case "below the version read before":
		holds = now < before
	}
	if !holds {
		return fmt.Errorf("the version is %d, the version read before %d: not %s", now, before, relation)
	}
	return nil
}
