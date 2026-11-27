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
	if _, _, err := cmdsutil.SplitTAAddress(address); err != nil {
		return nil, fmt.Errorf("--%s %w", flagTAAddress, err)
	}
	// The release carries the bytes that were held to a pin's rules.
	var document []byte
	if installTA != nil {
		document = installTA.document
	} else if read, err := os.ReadFile(pin); err != nil {
		return nil, fmt.Errorf("--%s: %w", flagTAPin, err)
	} else if _, err := taPinConfig(read); err != nil {
		return nil, fmt.Errorf("--%s: %w", flagTAPin, err)
	} else {
		document = read
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
	file, err := cmdsutil.TALaunchFile(set)
	if err != nil {
		return nil, fmt.Errorf("the Trust Authority pin %w", err)
	}
	config, err := taconfig.ParseForFamily(file, set.Family)
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
	// document is the pin as it was read and checked. The release carries
	// these bytes and connections read them from held, a private copy,
	// whatever the file they came from holds later.
	document []byte
	held     string
}

// resolveTAPin is the one pin this install holds its Trust Authority to, read where the
// release reads it: --ta-pin's file, else the document the last -f file
// naming one carries. It returns nil where nothing names a Trust Authority. A pin only a
// values file carries is copied to a file of its own, which remove deletes,
// since the clients this install dials read a path.
func resolveTAPin(valuesFiles []string) (pin *taPin, remove func(), err error) {
	keep := func() {}
	var document []byte
	path := ""
	if installTAPin != "" {
		if path, err = filepath.Abs(installTAPin); err == nil {
			document, err = os.ReadFile(path)
		}
		if err != nil {
			return nil, keep, fmt.Errorf("--%s: %w", flagTAPin, err)
		}
	} else {
		values, err := taValuesFromFiles(valuesFiles)
		if err != nil || values["measurementsConfig"] == "" {
			return nil, keep, err
		}
		document = []byte(values["measurementsConfig"])
	}
	config, err := taPinConfig(document)
	if err != nil {
		return nil, keep, err
	}
	held, err := fileutil.WriteTemp("c8s-ta-pin-*.json", document)
	if err != nil {
		return nil, keep, fmt.Errorf("write a copy of the Trust Authority pin: %w", err)
	}
	if path == "" {
		path = held
	}
	return &taPin{path: path, config: config, document: document, held: held}, func() { os.Remove(held) }, nil
}
