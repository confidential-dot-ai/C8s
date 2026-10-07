//go:build !c8s_node

package main

import (
	"fmt"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// installPins resolves the pins install supplies to the chart. Complete policies
// must also be expressible by the NRI installer's digest/common-register inputs;
// reject policies that would lose an image's register or launch-key constraint.
// Which TEE family pins which registers is refvalues' business; this only asks
// whether the set survives being flattened into one digest list and one map.
func installPins() (digests [][]byte, registers map[int][]byte, helmArgs []string, err error) {
	source := cmdsutil.ImagePolicySource{File: installMeasurementsConfig}
	pins := cmdsutil.MeasurementPins{Measurements: installMeasurements, Registers: installRegisters}
	if !source.IsSet() {
		policy, err := source.Load(pins)
		return policy.Measurements, policy.Registers, nil, err
	}
	set, err := source.LoadValues(pins)
	if err != nil {
		return nil, nil, nil, err
	}

	// helm reads the path itself, so hand it one that does not depend on the
	// working directory the install happened to run from.
	path, err := filepath.Abs(installMeasurementsConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("--image-policy-file: %w", err)
	}
	if set.HasAnchors() {
		return nil, nil, nil, fmt.Errorf("approver_key policies require the baked node launch flow; Helm installation cannot carry them to every NRI verifier")
	}
	common, uniform := set.CommonRegisters()
	if !uniform {
		return nil, nil, nil, fmt.Errorf("--image-policy-file contains different register pins per image; Helm installation requires identical register pins because the NRI installer accepts one shared register set")
	}
	// The chart takes the file's content; helm reads the same path this
	// command just validated.
	helmArgs = []string{
		"--set-file", "cds.measurementsConfig=" + path,
		"--set-file", "armtlsMesh.measurementsConfig=" + path,
	}
	return set.Digests(), common, helmArgs, nil
}
