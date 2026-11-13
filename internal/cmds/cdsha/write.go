package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// ErrNotConfirmed is a write that may have been applied: the replica
// answered "committed, not confirmed" (202), or nothing after the entry
// was sent. It is never recorded as acknowledged; `c8s` exits 3.
var ErrNotConfirmed = errors.New("the write may have been applied but is not confirmed: check the replicas' heads with c8s cds ha status before writing again")

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
// and acknowledged head.
func (w *writer) verified(ctx context.Context) (*cdschain.State, error) {
	records, err := w.o.records()
	if err != nil {
		return nil, err
	}
	c, err := w.read(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the replica's chain: %w", err)
	}
	state := c.state
	rec := records[state.Cluster]
	switch {
	case rec != nil && rec.Genesis != state.Genesis:
		return nil, fmt.Errorf("the replica's chain starts at genesis %s, recorded %s", state.Genesis, rec.Genesis)
	case rec == nil && c.Genesis.VerifySignature([]*ecdsa.PublicKey{&w.key.PublicKey}) != nil:
		return nil, errors.New("the replica's genesis is not signed by --operator-key and no genesis is recorded")
	case rec != nil && (rec.Acknowledged.Seq > state.Head.Seq || c.Hashes[rec.Acknowledged.Seq] != rec.Acknowledged.Hash):
		return nil, fmt.Errorf("the replica serves a chain without head %d, which was acknowledged before this read: the chain was rolled back, or the replica is behind", rec.Acknowledged.Seq)
	}
	w.o.cache(c)
	w.chain = c
	return state, nil
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
	fmt.Fprintf(os.Stderr, "committed head %d (%s)\n", head.Seq, head.Hash)
	return head, w.o.acknowledge(state.Genesis, head)
}

// errHeadMoved is a 409: the replica's head moved past the entry's prev.
var errHeadMoved = errors.New("the chain's head moved")

// Submit posts e. Only a 200 is done; a 202, or no answer after the entry
// left, is ErrNotConfirmed; a 409 (errHeadMoved), 422 or 503
// applied nothing.
func Submit(ctx context.Context, client *http.Client, url string, e cdschain.Entry) (cdschain.Head, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return cdschain.Head{}, err
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
	// A replica answers 503 only before the swap (see cdsha.Replica.swap).
	case resp.StatusCode == http.StatusUnprocessableEntity, resp.StatusCode == http.StatusServiceUnavailable:
		return head, fmt.Errorf("the replica refused the entry, nothing was applied: %d %s", resp.StatusCode, bytes.TrimSpace(answer))
	}
	return head, fmt.Errorf("%d %s: %w", resp.StatusCode, bytes.TrimSpace(answer), ErrNotConfirmed)
}

func newGenesisCmd(o *options) *cobra.Command {
	var cluster, version, extraKeys string
	cmd := &cobra.Command{
		Use:   "genesis",
		Short: "Sign a new replica set's entry 0",
		Long: `Collect the member keys of every genesis-pending replica of --endpoints and
the CA key of the first, sign entry 0 and post it there; the others join on
their own. The --image-policy-file the replicas are verified with becomes
the first accepted build, at --version. Entry 0 names --operator-key's public
key, and any in --operator-keys, as the writers. The genesis hash is printed:
node launch documents pin it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(o.endpoints) == 0 {
				return errors.New("genesis takes the whole set: pass --endpoints")
			}
			urls, err := o.urls()
			if err != nil {
				return err
			}
			pin, err := os.ReadFile(o.MeasurementsConfig)
			if err != nil {
				return fmt.Errorf("--image-policy-file pins the replicas and becomes the first accepted build: %w", err)
			}
			return o.genesis(cmd.Context(), cmd.OutOrStdout(), urls, cluster, version, pin, extraKeys)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cluster, "cluster", "", "the cluster ID of the replicas' configuration")
	f.StringVar(&version, "version", "", "release version of the CDS build --image-policy-file pins, for example v1.4.0")
	f.StringVar(&extraKeys, "operator-keys", "", "PEM file of further operator public keys that may write")
	_ = cmd.MarkFlagRequired("cluster")
	_ = cmd.MarkFlagRequired("version")
	return cmd
}

// genesis signs entry 0 over the genesis-pending replicas at urls, accepting
// pin at version, posts it to the first and records it.
func (o *options) genesis(ctx context.Context, out io.Writer, urls []string, cluster, version string, pin []byte, extraKeys string) error {
	key, err := o.OperatorPrivateKey()
	if err != nil {
		return err
	}
	writers, err := publicPEM(&key.PublicKey, extraKeys)
	if err != nil {
		return err
	}
	g := cdschain.Genesis{Endpoints: o.endpoints, OperatorKeys: writers, Accepted: []cdschain.Build{{Measurements: string(pin), Version: version}}}
	for slot, url := range urls {
		s, err := o.status(ctx, url)
		switch {
		case err != nil:
			return fmt.Errorf("slot %d (%s) does not answer its status: %w", slot, url, err)
		case !s.Pending:
			return fmt.Errorf("slot %d (%s) is not a genesis-pending replica: it holds a chain, or its store does", slot, url)
		}
		g.Members = append(g.Members, s.Member)
	}
	client, err := o.client(ctx, urls[0])
	if err != nil {
		return err
	}
	var pending haapi.Pending
	if err := haapi.Call(ctx, client, http.MethodGet, urls[0]+haapi.GenesisPath, nil, &pending); err != nil {
		return err
	}
	if pending.Cluster != cluster || !slices.Equal(pending.Endpoints, o.endpoints) {
		return fmt.Errorf("the replicas serve cluster %q at %v", pending.Cluster, pending.Endpoints)
	}
	g.CAKey = pending.CAKey
	payload, _ := json.Marshal(g)
	e, err := cdschain.Sign(key, cdschain.Body{Cluster: cluster, Type: cdschain.TypeGenesis, Payload: payload})
	if err != nil {
		return err
	}
	if _, err := cdschain.VerifyGenesis(e); err != nil {
		return err
	}
	if err := haapi.Call(ctx, client, http.MethodPost, urls[0]+haapi.GenesisPath, e, nil); err != nil {
		return fmt.Errorf("the replica refused the genesis: %w", err)
	}
	head := cdschain.Head{V: cdschain.Version, Cluster: cluster, Hash: e.Hash()}
	fmt.Fprintf(out, "genesis %s\n", head.Hash)
	return o.acknowledge(head.Hash, head)
}

func publicPEM(key *ecdsa.PublicKey, extraFile string) (string, error) {
	writers, err := cdschain.PublicKeyPEM(key)
	if err != nil || extraFile == "" {
		return writers, err
	}
	extra, err := os.ReadFile(extraFile)
	if err != nil {
		return "", err
	}
	if _, err := operatorauth.ParseKeyBundle([]byte(writers + string(extra))); err != nil {
		return "", fmt.Errorf("--operator-keys: %w", err)
	}
	return writers + string(extra), nil
}

const forceUsage = "write a set that evicts the builds a majority of the members run"

func newAcceptImageCmd(o *options) *cobra.Command {
	var newPin, version, floor string
	var force bool
	cmd := &cobra.Command{
		Use:   "accept-image",
		Short: "Accept a new CDS build on the replica set's chain",
		Long: `Write an accepted-builds entry: the current set plus the build --new-pin
pins, at --version, without every build below --floor. Replicas of the new
build then get the keys from their peers. A set that evicts the builds a
majority of the members run is refused without --force (U2).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validFloor("--floor", floor); err != nil {
				return err
			}
			pin, err := os.ReadFile(newPin)
			if err != nil {
				return fmt.Errorf("--new-pin: %w", err)
			}
			return o.writeBuilds(cmd.Context(), cmd.OutOrStdout(), force, func(current []cdschain.Build) []cdschain.Build {
				return above(append(current, cdschain.Build{Measurements: string(pin), Version: version}), floor)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&newPin, "new-pin", "", "measurements document pinning the CDS build to accept, as 'c8s cds config new' writes it")
	f.StringVar(&version, "version", "", "release version of that build")
	f.StringVar(&floor, "floor", "", "evict every build below this version")
	f.BoolVar(&force, "force", false, forceUsage)
	_ = cmd.MarkFlagRequired("new-pin")
	_ = cmd.MarkFlagRequired("version")
	return cmd
}

func newRaiseFloorCmd(o *options) *cobra.Command {
	var to string
	var force bool
	cmd := &cobra.Command{
		Use:   "raise-floor",
		Short: "Evict every accepted CDS build below a version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !semver.IsValid(to) {
				return fmt.Errorf("--to %q is not a semantic version", to)
			}
			return o.writeBuilds(cmd.Context(), cmd.OutOrStdout(), force, func(current []cdschain.Build) []cdschain.Build { return above(current, to) })
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "the new build floor")
	cmd.Flags().BoolVar(&force, "force", false, forceUsage)
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

// validFloor refuses a --floor that is not a semantic version ("" evicts
// nothing): semver.Compare orders an invalid version below every valid one,
// so it would evict nothing.
func validFloor(flag, floor string) error {
	if floor != "" && !semver.IsValid(floor) {
		return fmt.Errorf("%s %q is not a semantic version (for example v1.4.0)", flag, floor)
	}
	return nil
}

// above is the builds at or above floor ("" keeps all).
func above(builds []cdschain.Build, floor string) []cdschain.Build {
	return slices.DeleteFunc(slices.Clone(builds), func(b cdschain.Build) bool {
		return floor != "" && semver.Compare(b.Version, floor) < 0
	})
}

// writeBuilds writes the accepted set next(current). A set that a majority
// of the members' running builds are not in is refused without force (U2):
// the set then serves nothing until replacements join. A write another
// writer beat (409) is re-read and retried until --retry-for has passed.
func (o *options) writeBuilds(ctx context.Context, out io.Writer, force bool, next func([]cdschain.Build) []cdschain.Build) error {
	w, err := o.writer(ctx)
	if err != nil {
		return err
	}
	var statuses []*haapi.Status
	deadline := time.Now().Add(o.retryFor)
	for attempt := 1; ; attempt++ {
		state, err := w.verified(ctx)
		if err != nil {
			return err
		}
		builds := next(state.Accepted)
		if !force {
			if statuses == nil {
				urls := make([]string, len(state.Endpoints))
				for i, e := range state.Endpoints {
					urls[i] = cmdsutil.CDSURL(e)
				}
				statuses = o.statuses(ctx, urls)
			}
			if running := runningIn(statuses, builds); running < len(statuses)/2+1 {
				return fmt.Errorf("only %d of %d members run a build of the new set: the set would serve nothing until replacements join; pass --force to write it anyway", running, len(statuses))
			}
		}
		head, err := w.append(ctx, state, cdschain.TypeAccepted, cdschain.Accepted{Accepted: builds})
		if errors.Is(err, errHeadMoved) && time.Now().Before(deadline) {
			// Jittered, so two commands racing each other drift apart.
			time.Sleep(min(time.Duration(attempt)*100*time.Millisecond, time.Second) + rand.N(100*time.Millisecond))
			continue
		}
		if err != nil {
			return fmt.Errorf("after %d attempts: %w", attempt, err)
		}
		fmt.Fprintf(out, "accepted %d builds at head %d (%s)\n", len(builds), head.Seq, head.Hash)
		return nil
	}
}

// runningIn counts the members whose own build is in builds.
func runningIn(statuses []*haapi.Status, builds []cdschain.Build) int {
	n := 0
	for _, s := range statuses {
		if s != nil && s.IsMember && slices.ContainsFunc(builds, func(b cdschain.Build) bool { return b.Version == s.Build }) {
			n++
		}
	}
	return n
}

// ErrPolicyChanged is a policy write whose read is no longer the chain's:
// another write landed first, and re-reading may make it land.
var ErrPolicyChanged = errors.New("the allowlist changed since it was read")

// WritePolicy writes doc as a policy entry when the CDS at opts is a replica
// set (handled), conditional on the allowlist version it was read at
// (cdschain.State.PolicyVersion).
func WritePolicy(ctx context.Context, opts *cdsconn.Options, doc *pkgallowlist.Allowlist, version string) (bool, error) {
	canonical, err := doc.Canonical()
	if err != nil {
		return false, err
	}
	handled, err := writeEntry(ctx, opts, cdschain.TypePolicy, func(state *cdschain.State) (any, error) {
		if version != state.PolicyVersion() {
			return nil, ErrPolicyChanged
		}
		return cdschain.Policy{Allowlist: canonical}, nil
	})
	if errors.Is(err, errHeadMoved) {
		err = fmt.Errorf("%w: %w", ErrPolicyChanged, err)
	}
	return handled, err
}

// WriteRoutes writes a route manifest, in the envelope the router verifies,
// as a routes entry when the CDS at opts is a replica set (handled).
func WriteRoutes(ctx context.Context, opts *cdsconn.Options, manifest []byte, signer operatorauth.Authorizer) (bool, error) {
	token, err := signer.Authorization(http.MethodPut, routes.Path, manifest)
	if err != nil {
		return false, err
	}
	token, _ = strings.CutPrefix(token, "Bearer ")
	return writeEntry(ctx, opts, cdschain.TypeRoutes, func(*cdschain.State) (any, error) {
		return cdschain.Routes{Manifest: manifest, Token: token}, nil
	})
}

// writeEntry appends payload(state) through the replica at opts, unless the
// CDS there answers no HA status (a single CDS: not handled). An error before
// that answer is handled: the old write would reach the same CDS, and a
// replica set refuses it.
func writeEntry(ctx context.Context, opts *cdsconn.Options, typ cdschain.Type, payload func(*cdschain.State) (any, error)) (bool, error) {
	o := &options{Options: *opts}
	w, err := o.writer(ctx)
	if err != nil {
		return true, err
	}
	var status haapi.Status
	err = haapi.Call(ctx, w.client, http.MethodGet, w.url+haapi.StatusPath, nil, &status)
	// A single CDS answers no HA status; every replica names its member key.
	var se *operatorauth.StatusError
	if (errors.As(err, &se) && se.Status == http.StatusNotFound) || (err == nil && status.Member == "") {
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
