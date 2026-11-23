//go:build !c8s_node

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/fileutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taconfig"
)

// An install names its Trust Authority by address and pin together.
func taNamed(address string, pin string) bool {
	return address != "" && pin != ""
}

func taInstallValues(address string, pin string) (map[string]any, error) {
	if !taNamed(address, pin) {
		if address == "" && pin == "" {
			// A node-image render names no Trust Authority: the image runs its own.
			return nil, nil
		}
		return nil, fmt.Errorf("--%s and --%s name one Trust Authority together: pass both", flagTAAddress, flagTAPin)
	}
	if _, _, err := cmdsutil.SplitCDSAddress(address); err != nil {
		return nil, fmt.Errorf("--%s %w", flagTAAddress, err)
	}
	document, err := os.ReadFile(pin)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flagTAPin, err)
	}
	return map[string]any{
		"ta": map[string]any{
			"address":            address,
			"measurementsConfig": string(document),
		},
	}, nil
}

// taPinConfig is the configuration a Trust Authority pin binds its VM to. One pin binds
// one launch file, and that file is a Trust Authority configuration.
func taPinConfig(document []byte) (*taconfig.Config, error) {
	set, err := refvalues.Parse(document)
	if err != nil {
		return nil, fmt.Errorf("the Trust Authority pin: %w", err)
	}
	file, err := cmdsutil.CDSLaunchFile(set)
	if err != nil {
		return nil, fmt.Errorf("the Trust Authority pin %w", err)
	}
	config, err := taconfig.Parse(file)
	if err != nil {
		return nil, fmt.Errorf("the Trust Authority pin names a configuration this release cannot read: %w", err)
	}
	return config, nil
}

// taPin is the one pin this install holds its Trust Authority to: the file helm and the
// clients read it from, and the configuration those bytes name.
type taPin struct {
	path   string
	config *taconfig.Config
}

// resolveTAPin is the one pin this install holds its Trust Authority to, read where the
// release reads it: --ta-pin's file, else the document the last -f file
// naming one carries. It returns nil where nothing names a Trust Authority. A pin only a
// values file carries is copied to a file of its own, which remove deletes,
// since the clients this install dials read a path.
func resolveTAPin(valuesFiles []string) (pin *taPin, remove func(), err error) {
	keep := func() {}
	if installTAPin != "" {
		path, err := filepath.Abs(installTAPin)
		if err != nil {
			return nil, keep, fmt.Errorf("--%s: %w", flagTAPin, err)
		}
		document, err := os.ReadFile(path)
		if err != nil {
			return nil, keep, fmt.Errorf("--%s: %w", flagTAPin, err)
		}
		config, err := taPinConfig(document)
		if err != nil {
			return nil, keep, err
		}
		return &taPin{path: path, config: config}, keep, nil
	}
	values, _, err := taValuesFromFiles(valuesFiles)
	if err != nil {
		return nil, keep, err
	}
	document := values["measurementsConfig"]
	if document == "" {
		return nil, keep, nil
	}
	config, err := taPinConfig([]byte(document))
	if err != nil {
		return nil, keep, err
	}
	path, err := fileutil.WriteTemp("c8s-cds-pin-*.json", []byte(document))
	if err != nil {
		return nil, keep, fmt.Errorf("write the Trust Authority pin a values file carries: %w", err)
	}
	return &taPin{path: path, config: config}, func() { os.Remove(path) }, nil
}
