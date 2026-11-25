package cmdsutil

import (
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

var ErrNoTAAddress = errors.New("names no <host>:<port> a Trust Authority serves on")

// TA names the Trust Authority a node's clients reach. It runs on a
// confidential VM of its own, so its TEE family is that VM's.
type TA struct {
	// Address is a DNS name its clients resolve or an IPv4 address they dial.
	Address string `yaml:"address" json:"address"`
	// Measurements is a measurements document binding the Trust Authority image to its
	// launch file.
	Measurements string `yaml:"measurements" json:"measurements"`
}

// TAEndpoint is an accepted Trust Authority block.
type TAEndpoint struct {
	Host string
	// Port is what a pod ruleset admits outside the cluster.
	Port uint16
	// Pins are launch identities of the Trust Authority image, each bound to LaunchFile.
	Pins       refvalues.ReferenceValues
	LaunchFile []byte
}

// Parse requires an endpoint a node can dial and a pin that is one VM's
// identity.
func (c TA) Parse() (TAEndpoint, error) {
	if c.Address == "" {
		return TAEndpoint{}, fmt.Errorf("cds.address %w", ErrNoTAAddress)
	}
	host, port, err := SplitTAAddress(c.Address)
	if err != nil {
		return TAEndpoint{}, fmt.Errorf("cds.address %w", err)
	}
	// A DNS name resolves to whatever the cluster's resolver answers.
	if isAddress(host) {
		if err := ValidateRoutableIPv4(host); err != nil {
			return TAEndpoint{}, fmt.Errorf("cds.address %q: %w", host, err)
		}
	}
	pins, err := refvalues.Parse([]byte(c.Measurements))
	if err != nil {
		return TAEndpoint{}, fmt.Errorf("cds.measurements: %w", err)
	}
	launchFile, err := TALaunchFile(pins)
	if err != nil {
		return TAEndpoint{}, fmt.Errorf("cds.measurements: the pin %w", err)
	}
	return TAEndpoint{
		Host:       host,
		Port:       port,
		Pins:       pins,
		LaunchFile: launchFile,
	}, nil
}

// Validate reports what Parse refuses.
func (c TA) Validate() error {
	_, err := c.Parse()
	return err
}

// Policy is the measurements document a node's clients verify Trust Authority with.
func (e TAEndpoint) Policy() ([]byte, error) {
	return refvalues.Format(e.Pins)
}
