package launchconfig

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// CDS is the confidential data service a node's clients reach: where it
// listens and the measurements that authenticate it.
type CDS struct {
	// Address is an IPv4 address and port, the one destination a pod
	// ruleset admits for this cluster's credential clients.
	Address string `yaml:"address" json:"address"`
	// Measurements is one measurements JSON document, as `c8s cds config
	// new` writes it: every entry binds the CDS image to its launch file.
	Measurements string `yaml:"measurements" json:"measurements"`
}

// clusterCDS answers where this cluster's CDS listens and which measurements
// authenticate it, with one implementation per document version.
type clusterCDS interface {
	validateCDSFields(d *Document) error
	// addrPort is the zero value until the document carries an endpoint:
	// Stage resolves a v1 server's own address at boot.
	addrPort(d *Document) netip.AddrPort
	pins(d *Document) (refvalues.ReferenceValues, error)
}

// documentSchemas lists the document versions this image boots, each with the
// CDS that version gives a node.
var documentSchemas = map[string]clusterCDS{
	SchemaVersionV1: inClusterCDS{},
	SchemaVersionV2: externalCDS{},
}

func (d *Document) cds() (clusterCDS, error) {
	cds, known := documentSchemas[d.SchemaVersion]
	if !known {
		versions := slices.Sorted(maps.Keys(documentSchemas))
		return nil, fmt.Errorf("schemaVersion must be one of %s", strings.Join(versions, ", "))
	}
	return cds, nil
}

// CDSAddrPort is this cluster's CDS endpoint, which is what a pod ruleset
// names as a destination. A document validate accepted carries one, except a
// v1 server document whose address Stage has yet to resolve.
func (d *Document) CDSAddrPort() netip.AddrPort {
	cds, err := d.cds()
	if err != nil {
		return netip.AddrPort{}
	}
	return cds.addrPort(d)
}

// CDSPolicy is the measurements document a node's clients verify this
// cluster's CDS with.
func (d *Document) CDSPolicy() ([]byte, error) {
	cds, err := d.cds()
	if err != nil {
		return nil, err
	}
	pins, err := cds.pins(d)
	if err != nil {
		return nil, err
	}
	return refvalues.Format(pins)
}

// inClusterCDS runs on the Kubernetes server's own node: a pod on the node
// image this document pins, under the server launch key, reached at the
// image's fixed node port.
type inClusterCDS struct{}

// cdsPort is the image's fixed CDS node port.
const cdsPort = 30808

func (inClusterCDS) validateCDSFields(d *Document) error {
	if d.CDS != nil {
		return fmt.Errorf("cds requires schemaVersion %s", SchemaVersionV2)
	}
	return nil
}

func (inClusterCDS) addrPort(d *Document) netip.AddrPort {
	addr, err := netip.ParseAddr(d.Server.Address)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr, cdsPort)
}

func (inClusterCDS) pins(d *Document) (refvalues.ReferenceValues, error) {
	return d.serverReferenceValues()
}

// externalCDS is a confidential VM of its own, which the document names and
// pins. Its TEE family is the family of that VM, not of the node reading it.
type externalCDS struct{}

func (c externalCDS) validateCDSFields(d *Document) error {
	if d.CDS == nil {
		return fmt.Errorf("schemaVersion %s requires cds", SchemaVersionV2)
	}
	endpoint := c.addrPort(d)
	if !endpoint.IsValid() {
		return fmt.Errorf("cds.address must be an address and port")
	}
	if err := ValidateRoutableIPv4(endpoint.Addr()); err != nil {
		return fmt.Errorf("cds.address: %w", err)
	}
	if endpoint.Port() == 0 {
		return fmt.Errorf("cds.address must name a port")
	}
	pins, err := c.pins(d)
	if err != nil {
		return fmt.Errorf("cds.measurements: %w", err)
	}
	if !bindsEveryLaunchFile(pins) {
		return fmt.Errorf("cds.measurements must bind every entry to the CDS launch file")
	}
	return nil
}

func (externalCDS) addrPort(d *Document) netip.AddrPort {
	endpoint, err := netip.ParseAddrPort(d.CDS.Address)
	if err != nil {
		return netip.AddrPort{}
	}
	return endpoint
}

func (externalCDS) pins(d *Document) (refvalues.ReferenceValues, error) {
	return refvalues.Parse([]byte(d.CDS.Measurements))
}

// bindsEveryLaunchFile reports whether the set pins an image at all and binds
// every entry to the exact launch file of the VM it admits.
func bindsEveryLaunchFile(pins refvalues.ReferenceValues) bool {
	if len(pins.Images) == 0 {
		return false
	}
	for _, image := range pins.Images {
		if len(image.LaunchFile) == 0 {
			return false
		}
	}
	return true
}
