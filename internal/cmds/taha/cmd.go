// Package taha implements `c8s ta ha`: the operator's commands for a Trust Authority
// replica set (docs/ta-ha.md).
package taha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/taconn"
	haapi "github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
)

type options struct {
	taconn.Options
	endpoints []string
	stateDir  string
	retryFor  time.Duration
	// genesisPin binds verified reads even when the cluster has a local record.
	genesisPin string
	// persist replaces fileutil.WriteAtomicDurable in tests.
	persist func(path string, data []byte, mode os.FileMode) error
}

// NewCmd returns the `ha` subcommand.
func NewCmd() *cobra.Command {
	o := &options{Options: taconn.Options{DirectTA: true}}
	cmd := &cobra.Command{
		Use:   "ha",
		Short: "Operate a Trust Authority replica set",
		Long: `Operate a Trust Authority replica set (docs/ta-ha.md): run its genesis, read its head,
accept or evict Trust Authority builds, prepare, verify, submit or observe a signed policy entry, hand it
the store credential and settle a fork.

Each replica is reached over the attested connection the other operator
commands use, pinned with --image-policy-file. --endpoints is the set's
<host>:<port> list in slot order. The CLI records per cluster (--state-dir)
the genesis and the last confirmed head it acknowledged, and refuses a
replica serving a chain without that head.`,
		SilenceUsage: true,
	}
	pf := cmd.PersistentFlags()
	taconn.BindFlags(pf, &o.Options)
	pf.StringSliceVar(&o.endpoints, "endpoints", nil, "the replica set's <host>:<port> endpoints in slot order, in place of --url")
	pf.StringVar(&o.stateDir, "state-dir", "", "directory of the per-cluster record (default c8s/ta-ha in the user config directory: $XDG_CONFIG_HOME on Linux)")
	pf.DurationVar(&o.retryFor, "retry-for", time.Minute, "how long accept-image and raise-floor re-read and retry a write another write beat")
	pf.StringVar(&o.genesisPin, "genesis", "", "the required genesis hash; mandatory for prepare-policy, verify-policy, submit-policy and observe-policy, including with an existing local record")
	cmd.AddCommand(newStatusCmd(o), newGenesisCmd(o), newAcceptImageCmd(o), newRaiseFloorCmd(o), newStoreCredentialCmd(o), newResolveCmd(o), newPreparePolicyCmd(o), newVerifyPolicyCmd(o), newSubmitPolicyCmd(o), newObservePolicyCmd(o))
	for _, c := range operatorCommands {
		cmd.AddCommand(c(o))
	}
	return cmd
}

// operatorCommands are the commands only the operator build carries.
var operatorCommands []func(*options) *cobra.Command

func (o *options) urls() ([]string, error) {
	if (o.URL != "") == (len(o.endpoints) > 0) {
		return nil, errors.New("pass --url or --endpoints")
	}
	if o.URL != "" {
		return []string{o.URL}, nil
	}
	urls := make([]string, len(o.endpoints))
	for i, e := range o.endpoints {
		urls[i] = cmdsutil.TAURL(e)
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

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
