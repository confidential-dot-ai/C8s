// Package cdsreplica reads one CDS replica and posts it decrees over armTLS.
// Every connection is verified against the pin document naming the cluster's
// CDS, and a decree records the member id the replica reported and the
// address it answered at.
package cdsreplica

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// A replica serves its clients and the operator on one port.
const (
	Port          = 8443
	StatusPath    = "/ha/status"
	PinDecreePath = "/ha/pins"
	DecreesPath   = "/ha/decrees"
)

// Bounds on what a replica may answer with: one report or decree, and the
// whole record of at most 256 applied decrees.
const (
	MaxReport       = 1 << 20
	MaxDecreeRecord = 16 << 20
)

// timeout bounds each read of a replica.
const timeout = 15 * time.Second

// Replica is one CDS, named by <host>[:port]. Pin is the pin document naming
// this cluster's CDS; during an image roll it names both images, so it
// verifies the replica being replaced and the one replacing it.
type Replica struct {
	Address string
	Pin     []byte
	// Verifier decides whether the endpoint's evidence is a CDS of this
	// cluster. Nil verifies it in-process.
	Verifier cdsconn.PinVerifier
}

// Status is the replica's own report and the address it answered at, which
// a decree binding one process records.
func (r Replica) Status(ctx context.Context) (cdsha.Status, netip.AddrPort, error) {
	body, address, err := r.Get(ctx, StatusPath, MaxReport)
	if err != nil {
		return cdsha.Status{}, netip.AddrPort{}, err
	}
	var reported cdsha.Status
	if err := json.Unmarshal(body, &reported); err != nil {
		return cdsha.Status{}, netip.AddrPort{}, fmt.Errorf("GET %s: %w", StatusPath, err)
	}
	return reported, address, nil
}

// Get reads one path of the replica, at most limit bytes of it.
func (r Replica) Get(
	ctx context.Context,
	path string,
	limit int64,
) ([]byte, netip.AddrPort, error) {
	client, address, err := r.dial(ctx)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address.String()+path, nil)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, netip.AddrPort{}, fmt.Errorf("GET %s: %s", path, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("GET %s: %w", path, err)
	}
	return body, address, nil
}

// PostDecree hands one signed decree to the replica. A decree the cluster
// refused is an answer, not an error.
func (r Replica) PostDecree(
	ctx context.Context,
	signed cdsdecree.Signed,
) (cdsha.Delivered, netip.AddrPort, error) {
	object, err := json.Marshal(signed)
	if err != nil {
		return cdsha.Delivered{}, netip.AddrPort{}, err
	}
	client, address, err := r.dial(ctx)
	if err != nil {
		return cdsha.Delivered{}, netip.AddrPort{}, err
	}
	delivered, err := post(ctx, client, address, object)
	if err != nil {
		return cdsha.Delivered{}, netip.AddrPort{}, fmt.Errorf("%s: %w", address, err)
	}
	return delivered, address, nil
}

func post(
	ctx context.Context,
	client *http.Client,
	address netip.AddrPort,
	object []byte,
) (cdsha.Delivered, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address.String()+DecreesPath, bytes.NewReader(object))
	if err != nil {
		return cdsha.Delivered{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return cdsha.Delivered{}, err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, MaxReport))
	if err != nil {
		return cdsha.Delivered{}, fmt.Errorf("POST %s: %w", DecreesPath, err)
	}
	if response.StatusCode != http.StatusOK {
		return cdsha.Delivered{}, fmt.Errorf("POST %s: %s: %s", DecreesPath, response.Status, bytes.TrimSpace(answer))
	}
	var delivered cdsha.Delivered
	if err := json.Unmarshal(answer, &delivered); err != nil {
		return cdsha.Delivered{}, fmt.Errorf("POST %s: %w", DecreesPath, err)
	}
	return delivered, nil
}

// dial resolves the replica to the one address it answers at and builds a
// client that has verified the endpoint is a CDS of the pinned launch file.
func (r Replica) dial(ctx context.Context) (*http.Client, netip.AddrPort, error) {
	address, err := ResolveOne(ctx, r.Address)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	options := cdsconn.Options{
		URL:         "https://" + address.String(),
		ImagePolicy: r.Pin,
		Timeout:     timeout,
		Verifier:    r.Verifier,
		DirectCDS:   true,
	}
	client, err := options.HTTPClient(ctx)
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("%s: %w", r.Address, err)
	}
	return client, address, nil
}

// ResolveOne is the address one replica answers at. A decree names the
// process it reached, so a name standing for several replicas names none of
// them.
func ResolveOne(ctx context.Context, address string) (netip.AddrPort, error) {
	resolved, err := Resolve(ctx, address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(resolved) != 1 {
		return netip.AddrPort{}, fmt.Errorf("%s resolves to %d addresses: name one replica", address, len(resolved))
	}
	return resolved[0], nil
}

// Resolve is every replica a cluster's replica entry stands for.
func Resolve(ctx context.Context, entry string) ([]netip.AddrPort, error) {
	host, port, err := SplitAddress(entry)
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

// SplitAddress reads <host>[:port], where the port every CDS serves the
// operator on is the default.
func SplitAddress(address string) (string, uint16, error) {
	if !strings.Contains(address, ":") {
		return address, Port, nil
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
