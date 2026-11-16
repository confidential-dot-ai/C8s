// Package cdsha implements `c8s cds ha`: the operator's commands for a CDS
// replica set (docs/cds-ha.md).
package cdsha

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type options struct {
	cdsconn.Options
	endpoints []string
	stateDir  string
	retryFor  time.Duration
	// genesis pins the chain's genesis hash while the cluster has no record.
	genesisPin string
}

// NewCmd returns the `ha` subcommand.
func NewCmd() *cobra.Command {
	o := &options{Options: cdsconn.Options{DirectCDS: true}}
	cmd := &cobra.Command{
		Use:   "ha",
		Short: "Operate a CDS replica set",
		Long: `Operate a CDS replica set (docs/cds-ha.md): run its genesis, read its head,
accept or evict CDS builds, hand it the store credential and settle a fork.

Each replica is reached over the attested connection the other operator
commands use, pinned with --image-policy-file. --endpoints is the set's
<host>:<port> list in slot order. The CLI records per cluster (--state-dir)
the genesis and the last head a write was answered done for, and refuses a
replica serving a chain without that head.`,
		SilenceUsage: true,
	}
	pf := cmd.PersistentFlags()
	cdsconn.BindFlags(pf, &o.Options)
	pf.StringSliceVar(&o.endpoints, "endpoints", nil, "the replica set's <host>:<port> endpoints in slot order, in place of --url")
	pf.StringVar(&o.stateDir, "state-dir", "", "directory of the per-cluster record (default c8s/cds-ha in the user config directory: $XDG_CONFIG_HOME on Linux)")
	pf.DurationVar(&o.retryFor, "retry-for", time.Minute, "how long accept-image and raise-floor re-read and retry a write another write beat")
	pf.StringVar(&o.genesisPin, "genesis", "", "the set's genesis hash, which a write holds the chain to while this CLI has no record of the cluster (an operator who did not sign the genesis)")
	cmd.AddCommand(newStatusCmd(o), newGenesisCmd(o), newAcceptImageCmd(o), newRaiseFloorCmd(o), newStoreCredentialCmd(o), newResolveCmd(o))
	for _, c := range operatorCommands {
		cmd.AddCommand(c(o))
	}
	return cmd
}

func (o *options) urls() ([]string, error) {
	if (o.URL != "") == (len(o.endpoints) > 0) {
		return nil, errors.New("pass --url or --endpoints")
	}
	if o.URL != "" {
		return []string{o.URL}, nil
	}
	urls := make([]string, len(o.endpoints))
	for i, e := range o.endpoints {
		urls[i] = cmdsutil.CDSURL(e)
	}
	return urls, nil
}

func (o *options) client(ctx context.Context, url string) (*http.Client, error) {
	c := o.Options
	c.URL = url
	return c.HTTPClient(ctx)
}

// statuses asks every replica of urls for its status; a replica that does
// not answer has a nil status.
func (o *options) statuses(ctx context.Context, urls []string) []*haapi.Status {
	out := make([]*haapi.Status, len(urls))
	for i, url := range urls {
		out[i], _ = o.status(ctx, url)
	}
	return out
}

// status asks the replica at url for its status over the attested channel.
func (o *options) status(ctx context.Context, url string) (*haapi.Status, error) {
	client, err := o.client(ctx, url)
	if err != nil {
		return nil, err
	}
	var s haapi.Status
	if err := haapi.Call(ctx, client, http.MethodGet, url+haapi.StatusPath, nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func newStatusCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print each replica's status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			urls, err := o.urls()
			if err != nil {
				return err
			}
			failed := 0
			for _, url := range urls {
				line := map[string]any{"url": url}
				if s, err := o.status(cmd.Context(), url); err != nil {
					line["error"], failed = err.Error(), failed+1
				} else {
					line["status"] = s
				}
				if err := printJSON(cmd.OutOrStdout(), line); err != nil {
					return err
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d replicas could not be read or verified", failed, len(urls))
			}
			return nil
		},
	}
}

// operatorCommands are the commands only the operator build carries.
var operatorCommands []func(*options) *cobra.Command

func newStoreCredentialCmd(o *options) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "store-credential",
		Short: "Hand every replica the store credential",
		Long: `Post the store credential, a kubeconfig with one https server, inline CA
data, a bearer token and a namespace, to every replica; joiners get it from
their giver.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			urls, err := o.urls()
			if err != nil {
				return err
			}
			for _, url := range urls {
				if err := o.operatorPost(cmd.Context(), url, haapi.StoreCredentialPath, body); err != nil {
					return fmt.Errorf("%s: %w", url, err)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "the kubeconfig carrying the cds-store token")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

// operatorPost sends body with an operator token bound to it.
func (o *options) operatorPost(ctx context.Context, url, path string, body []byte) error {
	signer, err := o.Signer()
	if err != nil {
		return err
	}
	client, err := o.client(ctx, url)
	if err != nil {
		return err
	}
	req, err := operatorauth.NewRequest(ctx, http.MethodPost, url+path, body, signer)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return operatorauth.ResponseError(resp)
	}
	return nil
}

func newResolveCmd(o *options) *cobra.Command {
	var seq uint64
	var keep string
	var assumeLost []int
	var settle time.Duration
	var lostHead uint64
	cmd := &cobra.Command{
		Use:   "resolve",
		Short: "Settle a fork: keep one of the two entries the replicas hold at a seq",
		Long: `Read every replica's status (--endpoints), and send each an operator-signed
request to keep --keep at --seq and drop the other entry. It refuses when a
replica on the dropped side answered a write done at or after --seq, when
the dropped entry is this CLI's acknowledged head, or when a replica does not
answer; name a replica lost or restarted since the fork with --assume-lost.

Once the set serves again it writes the kept chain's allowlist again, as a
policy entry above every head a replica held, so a node that pulled the
dropped branch's allowlist sees a newer version and fetches the kept one. A
replica named by --assume-lost may have held a longer dropped branch than any
replica that answers: --lost-head then names the highest seq it may have
held. A replica still halted names the next seq to resolve.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			kept, err := cdschain.ParseHash(keep)
			if err != nil {
				return fmt.Errorf("--keep: %w", err)
			}
			if len(o.endpoints) == 0 {
				return errors.New("pass --endpoints: a resolution needs every replica of the set")
			}
			urls, err := o.urls()
			if err != nil {
				return err
			}
			return o.resolve(cmd.Context(), cmd.OutOrStdout(), urls, seq, kept, assumeLost, lostHead, cmd.Flags().Changed("lost-head"), settle)
		},
	}

	cmd.Flags().Uint64Var(&seq, "seq", 0, "the seq of the fork")
	cmd.Flags().StringVar(&keep, "keep", "", "the hash of the entry to keep at --seq")
	cmd.Flags().IntSliceVar(&assumeLost, "assume-lost", nil, "slot of a replica lost or restarted since the fork (repeatable); what it answered done is not known")
	cmd.Flags().DurationVar(&settle, "settle-timeout", 30*time.Second, "how long to wait for the set to serve again and take the allowlist refresh")
	cmd.Flags().Uint64Var(&lostHead, "lost-head", 0, "with --assume-lost: the highest seq a lost replica may have held; the allowlist refresh is written above it")
	_ = cmd.MarkFlagRequired("seq")
	_ = cmd.MarkFlagRequired("keep")
	return cmd
}

// resolve settles the fork at seq on the replicas at urls, keeping kept.
func (o *options) resolve(ctx context.Context, out io.Writer, urls []string, seq uint64, kept cdschain.Hash, assumeLost []int, lostHead uint64, lostHeadSet bool, settle time.Duration) error {
	statuses := o.statuses(ctx, urls)
	cluster := ""
	for _, s := range statuses {
		if s != nil && s.Held != nil {
			cluster = s.Held.Cluster
		}
	}
	if cluster == "" {
		return errors.New("no replica of --endpoints holds a chain")
	}
	held, err := refreshAbove(statuses, assumeLost, lostHead, lostHeadSet)
	if err != nil {
		return err
	}
	plan, err := o.plan(cluster)
	switch {
	case err != nil:
		return err
	case plan != nil && (plan.Seq != seq || plan.Keep != kept):
		path, _ := o.planPath(cluster)
		return fmt.Errorf("the resolve of seq %d keeping %s is not finished: run it again first, or remove %s to abandon it", plan.Seq, plan.Keep, path)
	case plan != nil:
		// A rerun: the first run may have cleared forks and cut chains, so
		// the plan, not the statuses now, says what was dropped and held.
		plan.Held = max(plan.Held, held)
	default:
		rec, err := o.record(cluster)
		if err != nil {
			return err
		}
		ackedAt, err := o.ackedAt(ctx, urls, statuses, seq, rec)
		if err != nil {
			return err
		}
		drop, err := planResolution(statuses, seq, kept, assumeLost, ackedAt)
		if err != nil {
			return err
		}
		plan = &resolvePlan{Seq: seq, Keep: kept, Drop: drop, Held: held}
	}
	if err := o.savePlan(cluster, plan); err != nil {
		return err
	}
	reqs := resolutions(statuses, cluster, seq, kept, plan.Drop)
	for _, slot := range slices.Sorted(maps.Keys(reqs)) {
		body, _ := json.Marshal(reqs[slot])
		if err := o.operatorPost(ctx, urls[slot], haapi.ResolvePath, body); err != nil {
			return fmt.Errorf("slot %d: %w; run the resolve again", slot, err)
		}
		fmt.Fprintf(out, "slot %d: resolved, keeping %s at seq %d\n", slot, kept, seq)
	}
	if err := o.afterResolve(ctx, urls, plan.Held, settle); err != nil {
		return err
	}
	return o.savePlan(cluster, nil)
}

// resolvePlan is a resolve in progress, kept as <cluster>.resolve until the
// set took the allowlist refresh, so a rerun after a failure resumes it.
type resolvePlan struct {
	Seq  uint64        `json:"seq"`
	Keep cdschain.Hash `json:"keep"`
	Drop cdschain.Hash `json:"drop"`
	// Held is the highest seq a replica held before the first run cut any
	// chain (refreshAbove).
	Held uint64 `json:"held"`
}

func (o *options) planPath(cluster string) (string, error) {
	dir, err := o.recordDir()
	return filepath.Join(dir, cluster+".resolve"), err
}

// plan reads the cluster's resolve in progress, nil when there is none.
func (o *options) plan(cluster string) (*resolvePlan, error) {
	path, err := o.planPath(cluster)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p resolvePlan
	return &p, json.Unmarshal(data, &p)
}

// savePlan keeps p, or removes the plan when p is nil.
func (o *options) savePlan(cluster string, p *resolvePlan) error {
	path, err := o.planPath(cluster)
	if err != nil {
		return err
	}
	if p == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fileutil.WriteAtomic(path, append(data, '\n'), 0o600)
}

// ackedAt is the entry at seq on the chain of this CLI's acknowledged head,
// zero when that head is below seq. Above seq, a replica holding the head
// shows it: its chain from seq links up to the head by prev hashes.
func (o *options) ackedAt(ctx context.Context, urls []string, statuses []*haapi.Status, seq uint64, rec *record) (cdschain.Hash, error) {
	switch {
	case rec == nil || rec.Acknowledged.Seq < seq:
		return cdschain.Hash{}, nil
	case rec.Acknowledged.Seq == seq:
		return rec.Acknowledged.Hash, nil
	}
	ack := rec.Acknowledged
	for slot, s := range statuses {
		if s == nil || s.Held == nil || s.Held.Seq < ack.Seq {
			continue
		}
		client, err := o.client(ctx, urls[slot])
		if err != nil {
			continue
		}
		entries, err := haapi.ReadChain(ctx, client, urls[slot], seq)
		if err == nil && linksUpTo(entries, seq, ack) {
			return entries[0].Hash(), nil
		}
	}
	return cdschain.Hash{}, fmt.Errorf("no replica answers with this CLI's acknowledged head %d (%s): it cannot tell whether --keep drops it", ack.Seq, ack.Hash)
}

// linksUpTo: entries, from seq on, are linked by their prev hashes up to head.
func linksUpTo(entries []cdschain.Entry, seq uint64, head cdschain.Head) bool {
	n := head.Seq - seq
	if uint64(len(entries)) <= n || entries[n].Hash() != head.Hash {
		return false
	}
	for i := uint64(1); i <= n; i++ {
		b, err := entries[i].Decode()
		if err != nil || b.Seq != seq+i || b.Prev != entries[i-1].Hash() {
			return false
		}
	}
	return true
}

// refreshAbove is the highest seq any replica may have held before the
// resolve: an allowlist served at a version above it outranks every policy
// entry of a dropped branch. A replica assumed lost did not say, so the
// operator names it (lostHead).
func refreshAbove(statuses []*haapi.Status, assumeLost []int, lostHead uint64, lostHeadSet bool) (uint64, error) {
	if len(assumeLost) > 0 && !lostHeadSet {
		return 0, errors.New("--assume-lost needs --lost-head: the highest seq a lost replica may have held, so the allowlist refresh outranks its branch")
	}
	held := lostHead
	for _, s := range statuses {
		if s != nil && s.Held != nil {
			held = max(held, s.Held.Seq)
		}
	}
	return held, nil
}

// afterResolve waits until a replica of urls takes the allowlist refresh
// (refreshPolicy), for at most settle. A replica still halted on a fork
// ends it: the resolve settled a fork above the one the chains split at.
func (o *options) afterResolve(ctx context.Context, urls []string, held uint64, settle time.Duration) error {
	key, err := o.OperatorPrivateKey()
	if err != nil {
		return err
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, settle)
	defer cancel()
	for {
		for slot, s := range o.statuses(ctx, urls) {
			if s != nil && s.Fork != nil {
				return fmt.Errorf("slot %d is still halted on a fork at seq %d (%s, %s): resolve seq %d next", slot, s.Fork.Seq, s.Fork.Mine, s.Fork.Theirs, s.Fork.Seq)
			}
		}
		for _, url := range urls {
			client, cerr := o.client(ctx, url)
			if cerr != nil {
				err = cerr
				continue
			}
			if err = (&writer{o: o, url: url, client: client, key: key}).refreshPolicy(ctx, held); err == nil {
				return nil
			}
		}
		if parent.Err() != nil {
			return parent.Err()
		}
		if ctx.Err() != nil {
			return fmt.Errorf("the set did not take the allowlist refresh before --settle-timeout; run the resolve again: %w", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// refreshPolicy writes the chain's allowlist again, as policy entries, until
// it is served at a version above held+1: the highest version a policy entry
// of a dropped branch, at seq held or below, was served at.
// INVARIANT: a node holding a dropped policy sees a newer version.
func (w *writer) refreshPolicy(ctx context.Context, held uint64) error {
	for {
		state, err := w.verified(ctx)
		switch {
		case err != nil:
			return err
		case state.Policy == nil:
			fmt.Fprintln(os.Stderr, "warning: the kept chain has no policy entry; write the allowlist (c8s allowlist) so nodes that pulled a dropped one fetch it again")
			return nil
		case state.PolicySeq > held:
			return nil
		}
		if _, err := w.append(ctx, state, cdschain.TypePolicy, cdschain.Policy{Allowlist: state.Policy}); err != nil {
			return err
		}
	}
}

// planResolution is the entry a resolution drops: every replica must
// answer unless assumed lost, and nothing dropped may have been answered done,
// nor be on the chain of this CLI's acknowledged head (ackedAt, its entry at
// seq).
func planResolution(statuses []*haapi.Status, seq uint64, keep cdschain.Hash, assumeLost []int, ackedAt cdschain.Hash) (cdschain.Hash, error) {
	var drop cdschain.Hash
	for slot, s := range statuses {
		switch {
		case s == nil && !slices.Contains(assumeLost, slot):
			return drop, fmt.Errorf("slot %d does not answer: a resolution needs every replica, or --assume-lost %d", slot, slot)
		case s == nil || s.Fork == nil || s.Fork.Seq != seq:
			continue
		case s.Fork.Mine == keep:
			drop = s.Fork.Theirs
		case s.Fork.Theirs == keep:
			drop = s.Fork.Mine
		default:
			return drop, fmt.Errorf("slot %d holds neither entry of the fork", slot)
		}
	}
	if drop == (cdschain.Hash{}) {
		return drop, fmt.Errorf("no replica is halted on a fork at seq %d holding %s", seq, keep)
	}
	for slot, s := range statuses {
		if s == nil || s.Fork == nil || s.Fork.Mine != drop {
			continue
		}
		for _, d := range s.Confirmed {
			if d.Seq >= seq {
				return drop, fmt.Errorf("slot %d answered a write done at seq %d on the branch --keep drops", slot, d.Seq)
			}
		}
	}
	if ackedAt == drop {
		return drop, fmt.Errorf("the dropped entry %s is on the chain of this CLI's acknowledged head", drop)
	}
	return drop, nil
}

// resolutions are the requests by slot: a replica that holds no chain (or
// does not answer) has nothing to resolve and joins afterwards.
func resolutions(statuses []*haapi.Status, cluster string, seq uint64, keep, drop cdschain.Hash) map[int]haapi.Resolution {
	out := map[int]haapi.Resolution{}
	for slot, s := range statuses {
		if s != nil && s.Held != nil {
			out[slot] = haapi.Resolution{Cluster: cluster, Slot: slot, Seq: seq, Keep: keep, Drop: drop, Nonce: rand.Text()}
		}
	}
	return out
}

// record is what the CLI keeps per cluster.
type record struct {
	Cluster      string        `json:"cluster"`
	Genesis      cdschain.Hash `json:"genesis"`
	Acknowledged cdschain.Head `json:"acknowledged"`
}

func (o *options) recordDir() (string, error) {
	if o.stateDir != "" {
		return o.stateDir, nil
	}
	config, err := os.UserConfigDir()
	return filepath.Join(config, "c8s", "cds-ha"), err
}

func (o *options) recordPath(cluster string) (string, error) {
	dir, err := o.recordDir()
	return filepath.Join(dir, cluster+".json"), err
}

// records reads every cluster's record, by cluster. Taken before a request,
// it is what an answer is held to: a record a concurrent command writes
// while the request is in flight may be newer than the answer, legally.
func (o *options) records() (map[string]*record, error) {
	dir, err := o.recordDir()
	if err != nil {
		return nil, err
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]*record{}
	for _, p := range paths {
		cluster := strings.TrimSuffix(filepath.Base(p), ".json")
		if out[cluster], err = o.record(cluster); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// record reads the cluster's record, nil when there is none.
func (o *options) record(cluster string) (*record, error) {
	path, err := o.recordPath(cluster)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec record
	return &rec, json.Unmarshal(data, &rec)
}

// acknowledge records head, answered done on the chain of genesis. The
// record never goes down: concurrent commands take turns under a lock file.
func (o *options) acknowledge(genesis cdschain.Hash, head cdschain.Head) error {
	path, err := o.recordPath(head.Cluster)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("locking the record: %w", err)
	}
	rec, err := o.record(head.Cluster)
	switch {
	case err != nil:
		return err
	case rec != nil && rec.Genesis != genesis:
		return fmt.Errorf("cluster %s is recorded with genesis %s, not %s; after a re-root, remove the record", head.Cluster, rec.Genesis, genesis)
	case rec != nil && head.Seq <= rec.Acknowledged.Seq:
		return nil
	}
	data, err := json.MarshalIndent(record{Cluster: head.Cluster, Genesis: genesis, Acknowledged: head}, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(path, append(data, '\n'), 0o600)
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
