package cds

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdsreplica"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// replica is one CDS the operator reads over armTLS, as the flags name it: its
// address, and the file holding the pin document it is verified against.
type replica struct {
	address string
	cdsPin  string
	// verifier decides whether the endpoint's evidence is a CDS of this
	// cluster, and is chosen when the flags are bound.
	verifier cdsconn.PinVerifier
}

// bindTargetFlags names the replica a decree is for, and the pin document it
// is verified against. During an image roll the document names both images,
// so it verifies the replica being replaced and the one replacing it.
func bindTargetFlags(cmd *cobra.Command, target *replica) {
	target.verifier = cdsconn.LocalVerifier{}
	f := cmd.Flags()
	f.StringVar(&target.address, "target", "", "<host>[:"+strconv.Itoa(cdsreplica.Port)+"] of the replica this decree is for (REQUIRED)")
	f.StringVar(&target.cdsPin, "cds-pin", "", "measurements document pinning this cluster's CDS, which every replica read is verified against (REQUIRED)")
	requireFlags(cmd, "target", "cds-pin")
}

// bindDeliveryFlags names the replica a decree is posted to, which hands it to
// the cluster's leader, and the pin document it is verified against.
func bindDeliveryFlags(cmd *cobra.Command, to *replica) {
	to.verifier = cdsconn.LocalVerifier{}
	f := cmd.Flags()
	f.StringVar(&to.address, "to", "", "<host>[:"+strconv.Itoa(cdsreplica.Port)+"] of a replica of the cluster to post this decree to (REQUIRED)")
	f.StringVar(&to.cdsPin, "cds-pin", "", "measurements document pinning this cluster's CDS, which the replica posted to is verified against (REQUIRED)")
	requireFlags(cmd, "to", "cds-pin")
}

func (r replica) remote() (cdsreplica.Replica, error) {
	pin, err := os.ReadFile(r.cdsPin)
	if err != nil {
		return cdsreplica.Replica{}, fmt.Errorf("--cds-pin: %w", err)
	}
	return cdsreplica.Replica{Address: r.address, Pin: pin, Verifier: r.verifier}, nil
}

func (r replica) status(ctx context.Context) (cdsha.Status, error) {
	reported, _, err := r.statusAtAddress(ctx)
	return reported, err
}

// The address a decree binding one process records.
func (r replica) statusAtAddress(ctx context.Context) (cdsha.Status, netip.AddrPort, error) {
	remote, err := r.remote()
	if err != nil {
		return cdsha.Status{}, netip.AddrPort{}, err
	}
	return remote.Status(ctx)
}

func holdsAVote(reported cdsha.Status) bool {
	return slices.Contains(reported.Voters, reported.ID)
}

func (r replica) answer(
	ctx context.Context,
	path string,
	limit int64,
) ([]byte, netip.AddrPort, error) {
	remote, err := r.remote()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return remote.Get(ctx, path, limit)
}

// postDecree hands one signed decree to this replica over the attested
// channel. A decree the cluster refused is an answer, not an error.
func (r replica) postDecree(
	ctx context.Context,
	signed cdsdecree.Signed,
) (cdsha.Delivered, string, error) {
	remote, err := r.remote()
	if err != nil {
		return cdsha.Delivered{}, "", err
	}
	delivered, address, err := remote.PostDecree(ctx, signed)
	if err != nil {
		return cdsha.Delivered{}, "", err
	}
	return delivered, address.String(), nil
}
