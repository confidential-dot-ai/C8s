package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// A replica serves its clients and the operator on one port.
const (
	replicaPort   = 8443
	statusPath    = "/ha/status"
	pinDecreePath = "/ha/pins"
	decreesPath   = "/ha/decrees"
	restorePath   = "/ha/restore"
)

// replicaTimeout bounds each read of a replica.
const replicaTimeout = 15 * time.Second

// Bounds on what a replica may answer with: one report or decree, and the
// whole record of at most 256 applied decrees.
const (
	maxReplicaReport = 1 << 20
	maxDecreeRecord  = 16 << 20
)

// replica is one CDS the operator reads over armTLS: it is verified against
// the pin document naming this cluster's CDS, and a decree records the member
// id it reported and the address it answered at.
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
	f.StringVar(&target.address, "target", "", "<host>[:"+strconv.Itoa(replicaPort)+"] of the replica this decree is for (REQUIRED)")
	f.StringVar(&target.cdsPin, "cds-pin", "", "measurements document pinning this cluster's CDS, which every replica read is verified against (REQUIRED)")
	requireFlags(cmd, "target", "cds-pin")
}

// bindDeliveryFlags names the replica a decree is posted to, which hands it to
// the cluster's leader, and the pin document it is verified against.
func bindDeliveryFlags(cmd *cobra.Command, to *replica) {
	to.verifier = cdsconn.LocalVerifier{}
	f := cmd.Flags()
	f.StringVar(&to.address, "to", "", "<host>[:"+strconv.Itoa(replicaPort)+"] of a replica of the cluster to post this decree to (REQUIRED)")
	f.StringVar(&to.cdsPin, "cds-pin", "", "measurements document pinning this cluster's CDS, which the replica posted to is verified against (REQUIRED)")
	requireFlags(cmd, "to", "cds-pin")
}

func (r replica) status(ctx context.Context) (cdsha.Status, error) {
	reported, _, err := r.statusAtAddress(ctx)
	return reported, err
}

// The address a decree binding one process records.
func (r replica) statusAtAddress(ctx context.Context) (cdsha.Status, netip.AddrPort, error) {
	body, address, err := r.answer(ctx, statusPath, maxReplicaReport)
	if err != nil {
		return cdsha.Status{}, netip.AddrPort{}, err
	}
	var reported cdsha.Status
	if err := json.Unmarshal(body, &reported); err != nil {
		return cdsha.Status{}, netip.AddrPort{}, fmt.Errorf("GET %s: %w", statusPath, err)
	}
	return reported, address, nil
}

func holdsAVote(reported cdsha.Status) bool {
	return slices.Contains(reported.Voters, reported.ID)
}

func (r replica) answer(ctx context.Context, path string, limit int64) ([]byte, netip.AddrPort, error) {
	client, address, err := r.dial(ctx)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	body, err := replicaAnswer(ctx, client, address, path, limit)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return body, address, nil
}

// dial resolves a replica to the one address it answers at and builds a client
// that has verified the endpoint is a CDS of the pinned launch file.
func (r replica) dial(ctx context.Context) (*http.Client, netip.AddrPort, error) {
	return r.dialWithin(ctx, replicaTimeout)
}

// dialWithin is dial with a deadline of its own, for the one request a
// replica takes longer over than a read of its reports.
func (r replica) dialWithin(ctx context.Context, timeout time.Duration) (*http.Client, netip.AddrPort, error) {
	address, err := resolveReplica(ctx, r.address)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	options := cdsconn.Options{
		URL:                "https://" + address.String(),
		MeasurementsConfig: r.cdsPin,
		Timeout:            timeout,
		Verifier:           r.verifier,
		DirectCDS:          true,
	}
	client, err := options.HTTPClient(ctx)
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("%s: %w", r.address, err)
	}
	return client, address, nil
}

// resolveReplica is the address one replica answers at. A decree names the
// process it reached, so a name standing for several replicas names none of
// them.
func resolveReplica(ctx context.Context, address string) (netip.AddrPort, error) {
	resolved, err := resolveReplicas(ctx, address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(resolved) != 1 {
		return netip.AddrPort{}, fmt.Errorf("%s resolves to %d addresses: name one replica", address, len(resolved))
	}
	return resolved[0], nil
}

// A cluster's replica entry may stand for several replicas.
func resolveReplicas(ctx context.Context, entry string) ([]netip.AddrPort, error) {
	host, port, err := splitReplicaAddress(entry)
	if err != nil {
		return nil, err
	}
	resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	addresses := make([]netip.AddrPort, 0, len(resolved))
	for _, answered := range resolved {
		// A resolver may answer an IPv4 lookup in 4-in-6 form.
		address := answered.Unmap()
		if !address.Is4() {
			return nil, fmt.Errorf("%s resolves to %s, and a replica answers at an IPv4 address", host, address)
		}
		addresses = append(addresses, netip.AddrPortFrom(address, port))
	}
	return addresses, nil
}

// splitReplicaAddress reads <host>[:port], where the port every CDS serves the
// operator on is the default.
func splitReplicaAddress(address string) (string, uint16, error) {
	if !strings.Contains(address, ":") {
		return address, replicaPort, nil
	}
	host, named, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("replica address %q: %w", address, err)
	}
	port, err := strconv.ParseUint(named, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("replica address %q: %w", address, err)
	}
	return host, uint16(port), nil
}

// postDecree hands one signed decree to this replica over the attested
// channel. A decree the cluster refused is an answer, not an error.
func (r replica) postDecree(ctx context.Context, signed cdsdecree.Signed) (cdsha.Delivered, string, error) {
	object, err := json.Marshal(signed)
	if err != nil {
		return cdsha.Delivered{}, "", err
	}
	client, address, err := r.dial(ctx)
	if err != nil {
		return cdsha.Delivered{}, "", err
	}
	delivered, err := postedDecree(ctx, client, address, object)
	if err != nil {
		return cdsha.Delivered{}, "", fmt.Errorf("%s: %w", address, err)
	}
	return delivered, address.String(), nil
}

func postedDecree(ctx context.Context, client *http.Client, address netip.AddrPort, object []byte) (cdsha.Delivered, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://"+address.String()+decreesPath,
		bytes.NewReader(object),
	)
	if err != nil {
		return cdsha.Delivered{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return cdsha.Delivered{}, err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxReplicaReport))
	if err != nil {
		return cdsha.Delivered{}, fmt.Errorf("POST %s: %w", decreesPath, err)
	}
	if response.StatusCode != http.StatusOK {
		return cdsha.Delivered{}, fmt.Errorf("POST %s: %s: %s", decreesPath, response.Status, bytes.TrimSpace(answer))
	}
	var delivered cdsha.Delivered
	if err := json.Unmarshal(answer, &delivered); err != nil {
		return cdsha.Delivered{}, fmt.Errorf("POST %s: %w", decreesPath, err)
	}
	return delivered, nil
}

func replicaAnswer(ctx context.Context, client *http.Client, address netip.AddrPort, path string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address.String()+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", path, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	return body, nil
}
