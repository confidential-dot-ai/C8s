// Package cdsha implements `c8s cds ha`: the operator's commands for a CDS
// replica set (docs/cds-ha.md).
package cdsha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
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

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
