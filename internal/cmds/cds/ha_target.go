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

// A replica serves its clients and the operator on one port, and the decree
// commands read two of its routes and post to a third.
const (
	replicaPort   = 8443
	statusPath    = "/ha/status"
	pinDecreePath = "/ha/pins"
	decreesPath   = "/ha/decrees"
)

// replicaTimeout bounds each read of a replica.
const replicaTimeout = 15 * time.Second

// maxReplicaAnswer bounds a replica's answer, the largest of which is a pin
// decree listing the images of an image roll.
const maxReplicaAnswer = 1 << 20

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

// replicaStatus is the part of a replica's /ha/status a decree binds to: the
// member id its process minted, whether it holds a cluster, the voters it
// knows, and the mesh CA it installs if a Genesis names it.
type replicaStatus struct {
	ClusterID string   `json:"cluster_id"`
	ID        string   `json:"id"`
	Joined    bool     `json:"joined"`
	Voters    []string `json:"voters"`
	GenesisCA string   `json:"genesis_ca"`
}

// isVoter reports whether the replica holds a vote in the cluster it carries.
func (s replicaStatus) isVoter() bool {
	return slices.Contains(s.Voters, s.ID)
}

// read reports a replica's own view of itself.
func (r replica) read(ctx context.Context) (replicaStatus, error) {
	answer, _, err := r.readAtAddress(ctx)
	return answer, err
}

// readAtAddress also reports the address the replica answered at, which a
// decree binding one process records.
func (r replica) readAtAddress(ctx context.Context) (replicaStatus, netip.AddrPort, error) {
	client, address, err := r.dial(ctx)
	if err != nil {
		return replicaStatus{}, netip.AddrPort{}, err
	}
	body, err := replicaAnswer(ctx, client, address, statusPath)
	if err != nil {
		return replicaStatus{}, netip.AddrPort{}, err
	}
	var answer replicaStatus
	if err := json.Unmarshal(body, &answer); err != nil {
		return replicaStatus{}, netip.AddrPort{}, fmt.Errorf("GET %s: %w", statusPath, err)
	}
	return answer, address, nil
}

// dial resolves a replica to the one address it answers at and builds a client
// that has verified the endpoint is a CDS of the pinned launch file.
func (r replica) dial(ctx context.Context) (*http.Client, netip.AddrPort, error) {
	address, err := resolveReplica(ctx, r.address)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	options := cdsconn.Options{
		URL:                "https://" + address.String(),
		MeasurementsConfig: r.cdsPin,
		Timeout:            replicaTimeout,
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
	host, port, err := splitReplicaAddress(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(resolved) != 1 {
		return netip.AddrPort{}, fmt.Errorf("%s resolves to %d addresses: name one replica", host, len(resolved))
	}
	// A resolver may answer an IPv4 lookup in 4-in-6 form.
	resolvedIP := resolved[0].Unmap()
	if !resolvedIP.Is4() {
		return netip.AddrPort{}, fmt.Errorf("%s resolves to %s, and a replica answers at an IPv4 address", host, resolvedIP)
	}
	return netip.AddrPortFrom(resolvedIP, port), nil
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
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxReplicaAnswer))
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

// replicaAnswer is a replica's answer to one GET, at most maxReplicaAnswer bytes.
func replicaAnswer(ctx context.Context, client *http.Client, address netip.AddrPort, path string) ([]byte, error) {
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
	body, err := io.ReadAll(io.LimitReader(response.Body, maxReplicaAnswer))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	return body, nil
}
