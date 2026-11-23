package cmdsutil

import (
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

var ErrNoCDSAddress = errors.New("names no <host>:<port> a CDS serves on")

// ClusterVersion counts the pin decrees this cluster's operator has signed.
type ClusterVersion uint64

// CDS is the confidential data service a node's clients reach. It runs on a
// confidential VM of its own, so its TEE family is that VM's.
type CDS struct {
	// Address is a DNS name its clients resolve or an IPv4 address they dial.
	Address string `yaml:"address" json:"address"`
	// Measurements is a measurements document binding the CDS image to its
	// launch file.
	Measurements string `yaml:"measurements" json:"measurements"`
	// PinFloor is the lowest cluster version this node takes a pin decree at.
	PinFloor ClusterVersion `yaml:"pinFloor,omitempty" json:"pin_floor,omitempty"`
}

// CDSEndpoint is an accepted CDS block.
type CDSEndpoint struct {
	Host string
	// Port is what a pod ruleset admits outside the cluster.
	Port uint16
	// Pins are launch identities of the CDS image, each bound to LaunchFile.
	Pins       refvalues.ReferenceValues
	LaunchFile []byte
}

// Parse requires an endpoint a node can dial and a pin that is one VM's
// identity.
func (c CDS) Parse() (CDSEndpoint, error) {
	if c.Address == "" {
		return CDSEndpoint{}, fmt.Errorf("cds.address %w", ErrNoCDSAddress)
	}
	host, port, err := SplitCDSAddress(c.Address)
	if err != nil {
		return CDSEndpoint{}, fmt.Errorf("cds.address %w", err)
	}
	// A DNS name resolves to whatever the cluster's resolver answers.
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
	return CDSEndpoint{
		Host:       host,
		Port:       port,
		Pins:       pins,
		LaunchFile: launchFile,
	}, nil
}

// Validate reports what Parse refuses.
func (c CDS) Validate() error {
	_, err := c.Parse()
	return err
}

// Policy is the measurements document a node's clients verify CDS with.
func (e CDSEndpoint) Policy() ([]byte, error) {
	return refvalues.Format(e.Pins)
}
