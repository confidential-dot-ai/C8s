// What the operator's read commands share: the replicas of one cluster they
// cover, and the JSON they print. Each replica is read over armTLS and
// verified against the pin document naming this cluster's CDS, so what the
// operator sees is a replica's own word rather than the host's.

package cds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

type clusterReach struct {
	config string
	urls   []string
	cdsPin string
}

func bindReachFlags(cmd *cobra.Command, reach *clusterReach) {
	f := cmd.Flags()
	f.StringVar(&reach.config, "config", "", "the configuration document the cluster's CDS VMs boot on (REQUIRED); its replica entries name the replicas to read")
	f.StringArrayVar(&reach.urls, "url", nil, "<host>[:"+strconv.Itoa(replicaPort)+"] of a replica to read instead of the configuration's replica entries; repeatable")
	f.StringVar(&reach.cdsPin, "cds-pin", "", "measurements document pinning this cluster's CDS, which every replica read is verified against (REQUIRED); during an image roll the one naming both images")
	requireFlags(cmd, "config", "cds-pin")
}

// There is always at least one replica to read.
func (reach clusterReach) cluster(ctx context.Context) (decreeConfig, []replica, error) {
	c, err := readDecreeConfig(reach.config)
	if err != nil {
		return decreeConfig{}, nil, err
	}
	addresses, err := reach.addresses(ctx, c)
	if err != nil {
		return decreeConfig{}, nil, err
	}
	if len(addresses) == 0 {
		return decreeConfig{}, nil, errors.New("the cluster's replica entries resolve to no address: name a replica with --url")
	}
	replicas := make([]replica, 0, len(addresses))
	for _, address := range addresses {
		replicas = append(replicas, replica{
			address:  address,
			cdsPin:   reach.cdsPin,
			verifier: cdsconn.LocalVerifier{},
		})
	}
	return c, replicas, nil
}

// One entry may answer at several addresses, and two entries at one.
func (reach clusterReach) addresses(ctx context.Context, c decreeConfig) ([]string, error) {
	entries, err := reach.entries(c)
	if err != nil {
		return nil, err
	}
	var resolved []string
	for _, entry := range entries {
		answering, err := resolveReplicas(ctx, entry)
		if err != nil {
			return nil, err
		}
		for _, address := range answering {
			if !slices.Contains(resolved, address.String()) {
				resolved = append(resolved, address.String())
			}
		}
	}
	return resolved, nil
}

// A configuration that names no replica set runs a singleton CDS, which has
// no replicas to compare.
func (reach clusterReach) entries(c decreeConfig) ([]string, error) {
	if len(reach.urls) > 0 {
		return reach.urls, nil
	}
	if c.parsed.HA == nil {
		return nil, errors.New("--config names no replica set: a CDS of this cluster runs as its singleton. Name a replica with --url")
	}
	return c.parsed.HA.Replicas, nil
}

// These routes carry objects the operator signed and the caller checks every
// signature, so any one replica reports them for all.
func signedStateOfAnyReplica(ctx context.Context, replicas []replica, path string, limit int64) (string, []byte, error) {
	refused := make([]string, 0, len(replicas))
	for _, r := range replicas {
		body, _, err := r.answer(ctx, path, limit)
		if err != nil {
			refused = append(refused, fmt.Sprintf("%s: %v", r.address, err))
			continue
		}
		return r.address, body, nil
	}
	return "", nil, fmt.Errorf("no replica of the cluster answered GET %s:\n  %s", path, strings.Join(refused, "\n  "))
}

func printJSON(w io.Writer, report any) error {
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", body)
	return err
}
