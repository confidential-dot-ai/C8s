package nriimagepolicy

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// setCDSPinsVerb selects the pin patcher instead of the plugin daemon.
const setCDSPinsVerb = "set-cds-pins"

// Outcomes printed on stdout, so the caller can decide whether the plugin
// needs restarting without diffing the file itself.
const (
	pinsUpdated   = "updated"
	pinsUnchanged = "unchanged"
)

// runSetCDSPins writes this release's CDS pins into an existing plugin config,
// leaving every other key as found.
//
// A node-as-CVM bakes the config into the measured image, and its
// allowlist.base carries the RKE2 system-image digests that only the image
// build resolves — so the chart can patch that file but never re-render it.
func runSetCDSPins(stdout io.Writer, args []string) error {
	fs := flag.NewFlagSet("nri-image-policy "+setCDSPinsVerb, flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath, "plugin config to patch in place")
	rawMeasurements := fs.String("cds-measurements", "", "comma-separated SHA-384 hex CDS launch measurements; required")
	rawRTMRs := fs.String("cds-rtmrs", "", "comma-separated TDX RTMR pins <index>=<sha384-hex>; empty clears the register pins")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	measurements, err := refvalues.ParseHexMeasurements(*rawMeasurements)
	if err != nil {
		return fmt.Errorf("--cds-measurements: %w", err)
	}
	if len(measurements) == 0 {
		return fmt.Errorf("--cds-measurements is required: an empty set pins no CDS guest identity")
	}
	rtmrs, err := refvalues.ParseRegisterPinsString(*rawRTMRs)
	if err != nil {
		return fmt.Errorf("--cds-rtmrs: %w", err)
	}
	wantMeasurements := make([]string, 0, len(measurements))
	for _, m := range measurements {
		wantMeasurements = append(wantMeasurements, hex.EncodeToString(m))
	}
	wantRTMRs := make([]string, 0, len(rtmrs))
	for _, idx := range slices.Sorted(maps.Keys(rtmrs)) {
		wantRTMRs = append(wantRTMRs, fmt.Sprintf("%d=%s", idx, hex.EncodeToString(rtmrs[idx])))
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
	if slices.Equal(normalizeHex(cfg.Allowlist.Pull.CDSMeasurements), wantMeasurements) &&
		slices.Equal(normalizeHex(cfg.Allowlist.Pull.CDSRTMRs), wantRTMRs) {
		fmt.Fprintln(stdout, pinsUnchanged)
		return nil
	}

	patched, err := patchCDSPins(data, wantMeasurements, wantRTMRs)
	if err != nil {
		return fmt.Errorf("%s: %w", *path, err)
	}
	if _, err := parseConfig(patched); err != nil {
		return fmt.Errorf("%s: patched config does not load: %w", *path, err)
	}
	if err := writeFileAtomic(*path, patched); err != nil {
		return err
	}
	fmt.Fprintln(stdout, pinsUpdated)
	return nil
}

// normalizeHex folds the on-disk pins to the case the patched form writes, so
// a re-run with the same pins compares equal and skips the restart.
func normalizeHex(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, strings.ToLower(v))
	}
	return out
}

// patchCDSPins replaces allowlist.pull.cds_measurements and cds_rtmrs in a
// config document, editing the parsed node tree so every other key, and the
// comments the node image ships, survive the round-trip.
func patchCDSPins(data []byte, measurements, rtmrs []string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("config is not a YAML document")
	}
	pull, err := mappingPath(doc.Content[0], "allowlist", "pull")
	if err != nil {
		return nil, err
	}
	setMappingValue(pull, "cds_measurements", stringSeq(measurements))
	setMappingValue(pull, "cds_rtmrs", stringSeq(rtmrs))

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

// mappingPath walks nested mappings. A missing key is an error rather than a
// created one: the pins belong in the section the plugin already reads, and a
// config without it is not the one this command was pointed at.
func mappingPath(n *yaml.Node, keys ...string) (*yaml.Node, error) {
	for i, key := range keys {
		v := mappingValue(n, key)
		if v == nil {
			return nil, fmt.Errorf("config has no %s section", strings.Join(keys[:i+1], "."))
		}
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("config key %s is not a mapping", strings.Join(keys[:i+1], "."))
		}
		n = v
	}
	return n, nil
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// setMappingValue replaces key's value in place, or appends the pair when the
// mapping does not carry it yet.
func setMappingValue(n *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			value.HeadComment = n.Content[i+1].HeadComment
			value.LineComment = n.Content[i+1].LineComment
			value.FootComment = n.Content[i+1].FootComment
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		value)
}

// stringSeq renders the pins as a quoted sequence; an empty one stays inline
// as [] so a cleared list reads the way the shipped config writes it.
func stringSeq(vals []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	if len(vals) == 0 {
		n.Style = yaml.FlowStyle
		return n
	}
	for _, v := range vals {
		n.Content = append(n.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: v,
			Style: yaml.DoubleQuotedStyle,
		})
	}
	return n
}

// writeFileAtomic replaces path with data, keeping the file's current mode. The
// temp file is a sibling so the rename never crosses filesystems.
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
