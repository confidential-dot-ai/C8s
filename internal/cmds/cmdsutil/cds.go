package cmdsutil

import (
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// ErrNoCDSAddress marks a document that carries no CDS at all.
var ErrNoCDSAddress = errors.New("names no <host>:<port> a CDS serves on")

// ClusterVersion counts the pin decrees this cluster's operator has signed.
// Zero is the version of a cluster whose operator has signed none.
type ClusterVersion uint64

// CDS is the confidential data service a node's clients reach: where it
// listens and the measurements that authenticate it. It runs on a
// confidential VM of its own, so its TEE family is that VM's, not the
// family of the node reading the document.
type CDS struct {
	// Address is the <host>:<port> this cluster's CDS serves on, the host a
	// DNS name its clients resolve or the IPv4 address they dial as it
	// stands. A pod ruleset admits that port outside the cluster for this
	// cluster's credential clients.
	Address string `yaml:"address" json:"address"`
	// Measurements is one measurements JSON document, as `launch-config new`
	// and `c8s cds config new` write it: every entry binds the CDS image to
	// its launch file.
	Measurements string `yaml:"measurements" json:"measurements"`
	// PinFloor is the lowest cluster version this node takes a CDS pin decree
	// at, so a node launched today never follows a decree the operator signed
	// before the set this document carries.
	PinFloor ClusterVersion `yaml:"pinFloor,omitempty" json:"pin_floor,omitempty"`
}

// CDSEndpoint is a CDS block read: the endpoint a node dials and the pin its
// clients hold that VM to.
type CDSEndpoint struct {
	// Host and Port are the endpoint. A pod ruleset admits Port outside the
	// cluster for this cluster's credential clients.
	Host string
	Port uint16
	// Pins are the launch identities of the CDS image, every entry bound to
	// LaunchFile, the configuration that VM runs on.
	Pins       refvalues.ReferenceValues
	LaunchFile []byte
}

// Parse reads the block once: the endpoint a node can dial, and a pin that is
// an identity for one VM, every entry bound to the exact launch file it boots.
func (c CDS) Parse() (CDSEndpoint, error) {
	if c.Address == "" {
		return CDSEndpoint{}, fmt.Errorf("cds.address %w", ErrNoCDSAddress)
	}
	host, port, err := SplitCDSAddress(c.Address)
	if err != nil {
		return CDSEndpoint{}, fmt.Errorf("cds.address %w", err)
	}
	// A host named as an address is held to one a node can dial; a DNS name
	// resolves to whatever the cluster's resolver answers.
	if isAddress(host) {
		if err := ValidateRoutableIPv4(host); err != nil {
			return CDSEndpoint{}, fmt.Errorf("cds.address %q: %w", host, err)
		}
	}
	pins, err := refvalues.Parse([]byte(c.Measurements))
	if err != nil {
		return CDSEndpoint{}, fmt.Errorf("cds.measurements: %w", err)
	}
	launchFile, err := CDSLaunchFile(pins)
	if err != nil {
		return CDSEndpoint{}, fmt.Errorf("cds.measurements: the pin %w", err)
	}
	return CDSEndpoint{Host: host, Port: port, Pins: pins, LaunchFile: launchFile}, nil
}

// Validate reports what Parse refuses.
func (c CDS) Validate() error {
	_, err := c.Parse()
	return err
}

// Policy is the measurements document a node's clients verify this cluster's
// CDS with.
func (e CDSEndpoint) Policy() ([]byte, error) {
	return refvalues.Format(e.Pins)
}
