//go:build !c8s_node

package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// An install names its CDS by address and pin together.
func cdsNamed(address string, pin string) bool {
	return address != "" && pin != ""
}

func cdsInstallArgs(address string, pin string) ([]string, error) {
	if !cdsNamed(address, pin) {
		if address == "" && pin == "" {
			// A node-image render names no CDS: the image runs its own.
			return nil, nil
		}
		return nil, fmt.Errorf("--%s and --%s name one CDS together: pass both", flagCDSAddress, flagCDSPin)
	}
	if _, err := netip.ParseAddrPort(address); err != nil {
		return nil, fmt.Errorf("--%s must be <ip>:<port>, the one endpoint a client's packet rules admit: %w", flagCDSAddress, err)
	}
	if _, err := os.Stat(pin); err != nil {
		return nil, fmt.Errorf("--%s: %w", flagCDSPin, err)
	}
	// helm reads the path itself, so hand it one that does not depend on the
	// working directory the install happened to run from.
	path, err := filepath.Abs(pin)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flagCDSPin, err)
	}
	return []string{
		"--set-string", "cds.address=" + address,
		"--set-file", "cds.measurementsConfig=" + path,
	}, nil
}

// cdsPinConfig is the configuration a CDS pin binds its VM to. One pin binds
// one launch file, and that file is a CDS configuration.
func cdsPinConfig(document []byte) (*cdsconfig.Config, error) {
	set, err := refvalues.Parse(document)
	if err != nil {
		return nil, fmt.Errorf("the CDS pin: %w", err)
	}
	if set.Empty() {
		return nil, fmt.Errorf("the CDS pin names no image, so nothing tells this cluster's CDS from any other attested TEE")
	}
	file := set.Images[0].LaunchFile
	if len(file) == 0 {
		return nil, fmt.Errorf("the CDS pin binds no launch file: a CDS is pinned to the configuration it runs on")
	}
	for _, image := range set.Images[1:] {
		if !bytes.Equal(image.LaunchFile, file) {
			return nil, fmt.Errorf("the CDS pin binds two configurations: one pin names one CDS")
		}
	}
	config, err := cdsconfig.Parse(file)
	if err != nil {
		return nil, fmt.Errorf("the CDS pin names a configuration this release cannot read: %w", err)
	}
	return config, nil
}

// cdsPin is the one pin this install holds its CDS to: the file helm and the
// clients read it from, and the configuration those bytes name.
type cdsPin struct {
	path   string
	config *cdsconfig.Config
}

// resolveCDSPin is the one pin this install holds its CDS to, read where the
// release reads it: --cds-pin's file, else the document the last -f file
// naming one carries. It returns nil where nothing names a CDS. A pin only a
// values file carries is copied to a file of its own, which remove deletes,
// since the clients this install dials read a path.
func resolveCDSPin(valuesFiles []string) (pin *cdsPin, remove func(), err error) {
	keep := func() {}
	if installCDSPin != "" {
		path, err := filepath.Abs(installCDSPin)
		if err != nil {
			return nil, keep, fmt.Errorf("--%s: %w", flagCDSPin, err)
		}
		document, err := os.ReadFile(path)
		if err != nil {
			return nil, keep, fmt.Errorf("--%s: %w", flagCDSPin, err)
		}
		config, err := cdsPinConfig(document)
		if err != nil {
			return nil, keep, err
		}
		return &cdsPin{path: path, config: config}, keep, nil
	}
	values, err := cdsValues(valuesFiles)
	if err != nil {
		return nil, keep, err
	}
	document, _ := values["cds.measurementsConfig"].(string)
	if document == "" {
		return nil, keep, nil
	}
	config, err := cdsPinConfig([]byte(document))
	if err != nil {
		return nil, keep, err
	}
	path, err := fileutil.WriteTemp("c8s-cds-pin-*.json", []byte(document))
	if err != nil {
		return nil, keep, fmt.Errorf("write the CDS pin a values file carries: %w", err)
	}
	return &cdsPin{path: path, config: config}, func() { os.Remove(path) }, nil
}
