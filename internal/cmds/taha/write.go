package taha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/taconn"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/fileutil"
	haapi "github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/routes"
)

// ErrNotConfirmed marks a write that may have been applied: no answer
// confirmed or refused it. It is never recorded as acknowledged; c8s exits 3.
var ErrNotConfirmed error = &cmdsutil.ExitStatusError{
	Status: cmdsutil.ExitNotConfirmed,
	Err:    errors.New("the write may have been applied: check the replicas' heads with c8s ta ha status before writing again"),
}

// errRecordNotSaved marks a write Trust Authority answered done whose record failed: a
// retry would find the entry applied and hide the failure. c8s exits 3.
var errRecordNotSaved error = &cmdsutil.ExitStatusError{
	Status: cmdsutil.ExitNotConfirmed,
	Err:    errors.New("the write is applied: once the record can be saved, the next write records its head"),
}

// recordFailure is the error of a write Trust Authority answered done, as applied
// names it, whose acknowledgement failed with err. A record that disagrees
// is not a failed save: its advice does not apply, and c8s exits 1.
func recordFailure(applied string, err error) error {
	if errors.Is(err, ErrRecordConflict) {
		return fmt.Errorf("%s, but %w", applied, err)
	}
	return fmt.Errorf("%s, but its local record was not saved (%w): %w", applied, err, errRecordNotSaved)
}

// writer appends operator-signed entries through one replica.
type writer struct {
	o      *options
	url    string
	client *http.Client
	key    *ecdsa.PrivateKey
	// chain is the chain the last verified read verified.
	chain *verifiedChain
}

// writer writes with --operator-key through the replica of --url, or the
// first replica of --endpoints that serves.
func (o *options) writer(ctx context.Context) (*writer, error) {
	urls, err := o.urls()
	if err != nil {
		return nil, err
	}
	url := urls[0]
	if len(urls) > 1 {
		statuses := o.statuses(ctx, urls)
		i := slices.IndexFunc(statuses, func(s *haapi.Status) bool { return s != nil && s.Serving == "" })
		if i < 0 {
			return nil, errors.New("no replica of --endpoints serves")
		}
		url = urls[i]
	}
	key, err := o.OperatorPrivateKey()
	if err != nil {
		return nil, err
	}
	client, err := o.client(ctx, url)
	return &writer{o: o, url: url, client: client, key: key}, err
}

// verified reads the replica's chain, verifies it from its genesis, and
// holds it to the record as it was before the read: the recorded genesis
// and acknowledged head. Without a record, --genesis or a genesis signed by
// --operator-key starts one.
func (w *writer) verified(ctx context.Context) (*cdschain.State, error) {
	pinned, err := w.o.pinnedGenesis()
	if err != nil {
		return nil, err
	}
	if err := w.o.prepareStateDir(); err != nil {
		return nil, err
	}
	records, err := w.o.records()
	if err != nil {
		return nil, err
	}
	c, err := w.read(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the replica's chain: %w", err)
	}
	state := c.state
	if pinned != nil && *pinned != state.Genesis {
		return nil, fmt.Errorf("the replica's chain starts at genesis %s, not --genesis %s", state.Genesis, pinned)
	}
	rec := records[state.Cluster]
	if rec == nil {
		if rec, err = w.startRecord(c, pinned != nil); err != nil {
			return nil, err
		}
	}
	if rec.Genesis != state.Genesis {
		return nil, fmt.Errorf("the replica's chain starts at genesis %s, recorded %s; after a re-root, remove the record", state.Genesis, rec.Genesis)
	}
	if rec.Acknowledged.Seq > state.Head.Seq || c.Hashes[rec.Acknowledged.Seq] != rec.Acknowledged.Hash {
		return nil, fmt.Errorf("the replica serves a chain without head %d, which was acknowledged before this read: the chain was rolled back, or the replica is behind", rec.Acknowledged.Seq)
	}
	w.o.cache(c)
	w.chain = c
	return state, nil
}

// pinnedGenesis is --genesis, nil when it is not set.
func (o *options) pinnedGenesis() (*cdschain.Hash, error) {
	if o.genesisPin == "" {
		return nil, nil
	}
	h, err := cdschain.ParseHash(o.genesisPin)
	if err != nil {
		return nil, fmt.Errorf("--genesis: %w", err)
	}
	return &h, nil
}

// startRecord is the record of a cluster this CLI has none of yet, at the
// genesis of c: one --genesis pinned, which it records since the pin is
// passed once, or one --operator-key signed, recorded by the first write.
func (w *writer) startRecord(c *verifiedChain, pinned bool) (*record, error) {
	head := cdschain.Head{V: cdschain.Version, Cluster: c.state.Cluster, Hash: c.state.Genesis}
	switch {
	case pinned:
		if err := w.o.acknowledge(head.Hash, head); err != nil {
			return nil, err
		}
	case c.Genesis.VerifySignature([]*ecdsa.PublicKey{&w.key.PublicKey}) != nil:
		return nil, errors.New("the replica's genesis is not signed by --operator-key and no genesis is recorded: pass --genesis with the hash 'c8s ta ha genesis' printed, or copy the record of the operator who signed it")
	}
	return &record{Cluster: head.Cluster, Genesis: head.Hash, Acknowledged: head}, nil
}

// verifiedChain is a chain this CLI verified, kept as <cluster>.chain: its
// genesis, the hash of every entry by seq, and the state at its head. It is
// local operator state, trusted as far as it was verified, so a later read
// verifies only the entries after its head.
type verifiedChain struct {
	Genesis cdschain.Entry  `json:"genesis"`
	Hashes  []cdschain.Hash `json:"hashes"`
	State   cachedState     `json:"state"`
	state   *cdschain.State
}

// cachedState is a State with its keys as PEM.
type cachedState struct {
	cdschain.State
	OperatorKeys []string
	CAKey        string
}

// read reads the replica's chain and verifies it. A chain this CLI verified
// before (its cache) is only extended: when the replica holds the cached
// head, it sends what follows it, one round trip for a few new entries, and
// only those are verified, whatever the chain's length.
func (w *writer) read(ctx context.Context) (*verifiedChain, error) {
	dir, err := w.o.recordDir()
	if err != nil {
		return nil, err
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.chain"))
	for _, p := range paths {
		var c verifiedChain
		if data, err := os.ReadFile(p); err != nil || json.Unmarshal(data, &c) != nil || c.restore() != nil {
			continue
		}
		page, err := haapi.ReadChain(ctx, w.client, w.url, c.state.Head.Seq)
		if err == nil && len(page) > 0 && page[0].Hash() == c.state.Head.Hash {
			return &c, c.extend(page[1:])
		}
	}
	entries, err := haapi.ReadChain(ctx, w.client, w.url, 0)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("the replica serves no chain")
	}
	state, err := cdschain.VerifyGenesis(entries[0])
	if err != nil {
		return nil, err
	}
	c := &verifiedChain{Genesis: entries[0], Hashes: []cdschain.Hash{entries[0].Hash()}, state: state}
	return c, c.extend(entries[1:])
}

// extend verifies entries after the head.
func (c *verifiedChain) extend(entries []cdschain.Entry) error {
	for _, e := range entries {
		next, err := c.state.Apply(e)
		if err != nil {
			return err
		}
		c.state, c.Hashes = next, append(c.Hashes, e.Hash())
	}
	return nil
}

// restore rebuilds the state from its cached form.
func (c *verifiedChain) restore() error {
	s := c.State.State
	for _, k := range c.State.OperatorKeys {
		key, err := cdschain.ParseKey(k)
		if err != nil {
			return err
		}
		s.OperatorKeys = append(s.OperatorKeys, key)
	}
	var err error
	if s.CAKey, err = cdschain.ParseKey(c.State.CAKey); err != nil {
		return err
	}
	if uint64(len(c.Hashes)) != s.Head.Seq+1 || c.Hashes[0] != s.Genesis || c.Genesis.Hash() != s.Genesis {
		return errors.New("the cached chain is not whole")
	}
	c.state = &s
	return nil
}

// cache keeps a verified chain for the next read. It only saves work, so a
// failure to write it is not an error.
func (o *options) cache(c *verifiedChain) {
	dir, err := o.recordDir()
	if err != nil {
		return
	}
	c.State = cachedState{State: *c.state}
	for _, k := range c.state.OperatorKeys {
		p, err := cdschain.PublicKeyPEM(k)
		if err != nil {
			return
		}
		c.State.OperatorKeys = append(c.State.OperatorKeys, p)
	}
	if c.State.CAKey, err = cdschain.PublicKeyPEM(c.state.CAKey); err != nil {
		return
	}
	data, err := json.Marshal(c)
	if err == nil && os.MkdirAll(dir, 0o700) == nil {
		_ = fileutil.WriteAtomic(filepath.Join(dir, c.state.Cluster+".chain"), data, 0o600)
	}
}

// append signs payload as the entry after state's head and submits it.
func (w *writer) append(ctx context.Context, state *cdschain.State, typ cdschain.Type, payload any) (cdschain.Head, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return cdschain.Head{}, err
	}
	e, err := cdschain.Sign(w.key, cdschain.Body{Cluster: state.Cluster, Seq: state.Head.Seq + 1, Prev: state.Head.Hash, Type: typ, Payload: data})
	if err != nil {
		return cdschain.Head{}, err
	}
	if _, err := state.Apply(e); err != nil {
		return cdschain.Head{}, fmt.Errorf("the entry does not verify against the chain: %w", err)
	}
	head, err := Submit(ctx, w.client, w.url, e)
	if err != nil {
		return head, err
	}
	if head.Cluster != state.Cluster || head.Seq != state.Head.Seq+1 {
		return head, fmt.Errorf("the replica answered done for head %d of %q, not %d of %q: %w", head.Seq, head.Cluster, state.Head.Seq+1, state.Cluster, ErrNotConfirmed)
	}
	if err := w.o.acknowledge(state.Genesis, head); err != nil {
		return head, recordFailure(fmt.Sprintf("Trust Authority confirmed head %d (%s)", head.Seq, head.Hash), err)
	}
	fmt.Fprintf(os.Stderr, "committed head %d (%s)\n", head.Seq, head.Hash)
	return head, nil
}

// errHeadMoved is a 409: the replica's head moved past the entry's prev.
var errHeadMoved = errors.New("the chain's head moved")

// Submit posts e. Only a 200 is done; a 202, a 5xx other than 503, or no
// answer after the entry left, is ErrNotConfirmed; a 4xx (a 409 is
// errHeadMoved) or a 503 applied nothing.
func Submit(ctx context.Context, client *http.Client, url string, e cdschain.Entry) (cdschain.Head, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return cdschain.Head{}, err
	}
	if len(body) > cdschain.MaxEntryBytes {
		return cdschain.Head{}, fmt.Errorf("the entry is %d bytes, above the %d a replica takes", len(body), cdschain.MaxEntryBytes)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+haapi.EntriesPath, bytes.NewReader(body))
	if err != nil {
		return cdschain.Head{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return cdschain.Head{}, fmt.Errorf("no answer to the write (%w): %w", err, ErrNotConfirmed)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var head cdschain.Head
	switch {
	case err != nil:
		return head, fmt.Errorf("the answer to the write broke off (%w): %w", err, ErrNotConfirmed)
	case resp.StatusCode == http.StatusOK && json.Unmarshal(answer, &head) == nil && head.Hash == e.Hash():
		return head, nil
	case resp.StatusCode == http.StatusConflict:
		return head, fmt.Errorf("the replica refused the entry, nothing was applied: %d %s: %w", resp.StatusCode, bytes.TrimSpace(answer), errHeadMoved)
	// A replica answers 503 only before the swap (see taha.Replica.swap),
	// and a 4xx before it takes the entry.
	case resp.StatusCode >= 400 && resp.StatusCode < 500, resp.StatusCode == http.StatusServiceUnavailable:
		return head, fmt.Errorf("the replica refused the entry, nothing was applied: %d %s", resp.StatusCode, bytes.TrimSpace(answer))
	}
	return head, fmt.Errorf("%d %s: %w", resp.StatusCode, bytes.TrimSpace(answer), ErrNotConfirmed)
}

// ErrPolicyChanged is a policy write whose read is no longer the chain's:
// another write landed first, and re-reading may make it land.
var ErrPolicyChanged = errors.New("the allowlist changed since it was read")

// WritePolicy writes doc as a policy entry when the Trust Authority at opts is a replica
// set (handled), conditional on the allowlist version it was read at
// (cdschain.State.CurrentPolicyVersion).
func WritePolicy(ctx context.Context, opts *taconn.Options, doc *pkgallowlist.Allowlist, version string) (bool, error) {
	canonical, err := doc.Canonical()
	if err != nil {
		return false, err
	}
	handled, err := writeEntry(ctx, opts, cdschain.TypePolicy, func(state *cdschain.State) (any, error) {
		if version != state.CurrentPolicyVersion() {
			return nil, ErrPolicyChanged
		}
		return cdschain.Policy{Allowlist: canonical}, nil
	})
	if errors.Is(err, errHeadMoved) {
		err = fmt.Errorf("%w: %w", ErrPolicyChanged, err)
	}
	return handled, err
}

// ErrRoutesChanged is a route manifest write conditional on a manifest the
// chain no longer holds, as a single Trust Authority's 412.
var ErrRoutesChanged = errors.New("the route manifest changed since it was read")

// WriteRoutes writes a route manifest, in the envelope the router verifies,
// as a routes entry when the Trust Authority at opts is a replica set (handled). With
// ifMatch set, the chain's manifest must be the one of that hex route digest.
func WriteRoutes(ctx context.Context, opts *taconn.Options, manifest []byte, signer operatorauth.Authorizer, ifMatch string) (bool, error) {
	token, err := signer.Authorization(http.MethodPut, routes.Path, manifest)
	if err != nil {
		return false, err
	}
	token, _ = strings.CutPrefix(token, "Bearer ")
	handled, err := writeEntry(ctx, opts, cdschain.TypeRoutes, func(state *cdschain.State) (any, error) {
		if ifMatch != "" && (state.Routes == nil || routeDigest(state.Routes.Manifest) != ifMatch) {
			return nil, ErrRoutesChanged
		}
		return cdschain.Routes{Manifest: manifest, Token: token}, nil
	})
	if ifMatch != "" && errors.Is(err, errHeadMoved) {
		err = fmt.Errorf("%w: %w", ErrRoutesChanged, err)
	}
	return handled, err
}

func routeDigest(manifest []byte) string {
	d := routes.Digest(manifest)
	return hex.EncodeToString(d[:])
}

// writeEntry appends payload(state) through the replica at opts, unless the
// Trust Authority there answers no HA status (a single Trust Authority, or a router that does not
// route /ha: not handled; a replica set refuses the old write). An error
// before any answer is handled: the old write would reach the same Trust Authority.
func writeEntry(ctx context.Context, opts *taconn.Options, typ cdschain.Type, payload func(*cdschain.State) (any, error)) (bool, error) {
	o := &options{Options: *opts}
	w, err := o.writer(ctx)
	if err != nil {
		return true, err
	}
	var status haapi.Status
	err = haapi.Call(ctx, w.client, http.MethodGet, w.url+haapi.StatusPath, nil, &status)
	// Every replica answers its status, naming its member key.
	var se *operatorauth.StatusError
	if errors.As(err, &se) || (err == nil && status.Member == "") {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	state, err := w.verified(ctx)
	if err != nil {
		return true, err
	}
	p, err := payload(state)
	if err == nil {
		_, err = w.append(ctx, state, typ, p)
	}
	return true, err
}
