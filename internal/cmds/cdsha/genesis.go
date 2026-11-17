package cdsha

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

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
	g := cdschain.Genesis{
		Endpoints:    o.endpoints,
		OperatorKeys: writers,
		Accepted:     []cdschain.Build{{Measurements: string(pin), Version: version}},
	}
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
		var refusal *operatorauth.StatusError
		if errors.As(err, &refusal) && (refusal.Status < 500 || refusal.Status == http.StatusServiceUnavailable) {
			return fmt.Errorf("the replica refused the genesis: %w", err)
		}
		return &cmdsutil.ExitStatusError{Status: cmdsutil.ExitNotConfirmed, Err: fmt.Errorf(
			"no answer confirmed the genesis %s (%w): if c8s cds ha status shows the replicas hold it, write with --genesis %s", e.Hash(), err, e.Hash())}
	}
	head := cdschain.Head{V: cdschain.Version, Cluster: cluster, Hash: e.Hash()}
	if err := o.acknowledge(
		head.Hash,
		head,
	); err != nil {
		return fmt.Errorf(
			"CDS accepted genesis %s, but saving its local record failed (%w): %w",
			head.Hash,
			err,
			ErrNotConfirmed,
		)
	}
	fmt.Fprintf(out, "genesis %s\n", head.Hash)
	return nil
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
