package nriimagepolicy

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
)

// setMeasurePoliciesVerb selects the config patcher instead of the plugin
// daemon.
const setMeasurePoliciesVerb = "set-measure-policies"

// Outcomes printed on stdout, so the caller can decide whether the plugin
// needs restarting without diffing the file itself.
const (
	patchUpdated   = "updated"
	patchUnchanged = "unchanged"
)

// runSetMeasurePolicies writes this release's policy-measurement switch into an
// existing plugin config, leaving every other key as found.
//
// A node-as-CVM bakes the config into the measured image, and its
// allowlist.base carries the RKE2 system-image digests that only the image
// build resolves — so the chart can patch that file but never re-render it.
func runSetMeasurePolicies(stdout io.Writer, args []string) error {
	fs := flag.NewFlagSet("nri-image-policy "+setMeasurePoliciesVerb, flag.ContinueOnError)
	path := fs.String("config", DefaultConfigPath, "plugin config to patch in place")
	raw := fs.String("measure-policies", "", "allowlist.pull.measure_policies, true or false: extend TDX RTMR[3] with each pulled allowlist before applying it (required)")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}
	if *raw == "" {
		return fmt.Errorf("--measure-policies is required: the switch this release runs with is the one thing a measured boot config cannot carry")
	}
	measurePolicies, err := strconv.ParseBool(*raw)
	if err != nil {
		return fmt.Errorf("--measure-policies %q: want true or false", *raw)
	}

	data, err := os.ReadFile(*path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	// The file the plugin boots with must load before and after the patch: a
	// config that no longer validates leaves a required NRI plugin unable to
	// register, which blocks every container on the node.
	cfg, err := parseConfig(data)
	if err != nil {
		return fmt.Errorf("%s: %w", *path, err)
	}
	if cfg.Allowlist.Pull.MeasurePolicies == measurePolicies {
		fmt.Fprintln(stdout, patchUnchanged)
		return nil
	}

	patched, err := patchMeasurePolicies(data, measurePolicies)
	if err != nil {
		return fmt.Errorf("%s: %w", *path, err)
	}
	if _, err := parseConfig(patched); err != nil {
		return fmt.Errorf("%s: patched config does not load: %w", *path, err)
	}
	if err := writeFileAtomic(*path, patched); err != nil {
		return err
	}
	fmt.Fprintln(stdout, patchUpdated)
	return nil
}

// patchMeasurePolicies replaces allowlist.pull.measure_policies in a config
// document, editing the parsed node tree so every other key, and the comments
// the node image ships, survive the round-trip.
func patchMeasurePolicies(data []byte, measurePolicies bool) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("config is not a YAML document")
	}
	pull, err := yamlutil.MappingPath(doc.Content[0], "allowlist", "pull")
	if err != nil {
		return nil, err
	}
	yamlutil.SetMappingValue(pull, "measure_policies", &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!bool",
		Value: strconv.FormatBool(measurePolicies),
	})

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return buf.Bytes(), nil
}

// writeFileAtomic replaces path with data, keeping the file's current mode.
func writeFileAtomic(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := fileutil.WriteAtomic(path, data, mode); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
