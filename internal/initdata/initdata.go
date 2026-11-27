// Package initdata reads the initdata document a Kata Containers runtime
// binds to a guest's launch, as a Trust Authority launch file. It imports
// nothing of the Trust Authority's, so the configuration reader and every
// reader of a pin apply one check.
package initdata

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/yamlutil"
)

// The digests an initdata launch file may declare: the launch binding is the
// SHA-256 of the whole file on AMD SEV-SNP and its SHA-384 on Intel TDX. A
// runtime told to hash it any other way commits a value no verifier accepts.
const (
	AlgorithmSNP = "sha256"
	AlgorithmTDX = "sha384"
)

// The entries a document must carry: the Trust Authority configuration and
// the guest agent's policy. The launch binding covers a guest and this
// document, and the host names the containers afterwards: the policy is what
// holds them to the Trust Authority's. [Read] requires one and does not judge
// its rules, which whoever pins the document answers for.
const (
	ConfigFile = "ta-config.yaml"
	PolicyFile = "policy.rego"
)

// policyPackage is the package the guest agent evaluates.
const policyPackage = "agent_policy"

// MaxSize bounds an initdata document supplied by the host.
const MaxSize = 1024 * 1024

// Read returns the configuration a launch file carries and the digest it
// declares: the ConfigFile entry of an initdata document, or the file itself,
// which declares none.
//
// INVARIANT: the bytes alone decide which. Whoever starts the guest chooses
// its arguments, so a format they could name would let them choose how bound
// bytes are read. No file reads both ways: a configuration is a YAML mapping,
// which is never TOML.
//
// Keys are matched exactly, as the runtime reads them, so a document cannot
// carry a second configuration under another spelling of a key.
func Read(launchFile []byte) (configuration []byte, algorithm string, err error) {
	if len(launchFile) > MaxSize {
		return launchFile, "", nil
	}
	var document map[string]any
	if err := toml.Unmarshal(launchFile, &document); err != nil {
		return launchFile, "", nil
	}
	data, ok := document["data"].(map[string]any)
	if !ok {
		return launchFile, "", nil
	}
	algorithm, _ = document["algorithm"].(string)
	if algorithm != AlgorithmSNP && algorithm != AlgorithmTDX {
		return nil, "", fmt.Errorf("initdata algorithm is %#v, want %q on SEV-SNP or %q on TDX, the digest the launch binding commits", document["algorithm"], AlgorithmSNP, AlgorithmTDX)
	}
	entry, ok := data[ConfigFile]
	if !ok {
		return nil, "", fmt.Errorf("initdata document has no %q entry", ConfigFile)
	}
	text, ok := entry.(string)
	if !ok {
		return nil, "", fmt.Errorf("initdata entry %q is not a string", ConfigFile)
	}
	if err := checkAgentPolicy(data); err != nil {
		return nil, "", err
	}
	return []byte(text), algorithm, nil
}

// ReadFor is Read for a launch file of a known family: it also holds an
// initdata document's declared algorithm to the digest that family commits.
// The launch binding proves the file's bytes, not the algorithm written
// inside them, so a file declaring the wrong one would otherwise serve.
func ReadFor(launchFile []byte, family teetypes.Family) ([]byte, error) {
	configuration, algorithm, err := Read(launchFile)
	if err != nil || algorithm == "" {
		return configuration, err
	}
	var want string
	switch family {
	case teetypes.FamilySNP:
		want = AlgorithmSNP
	case teetypes.FamilyTDX:
		want = AlgorithmTDX
	default:
		return nil, fmt.Errorf("initdata launch file on TEE family %q, which commits none", family)
	}
	if algorithm != want {
		return nil, fmt.Errorf("initdata algorithm is %q, want %q, the digest a %s launch binding commits", algorithm, want, family)
	}
	return configuration, nil
}

// Check refuses a launch file a Trust Authority pin embeds that no Trust
// Authority starts from: one over the size cap, an initdata document
// [ReadFor] refuses, or bytes that are neither that nor a configuration. A
// pin is read by clients that never parse the configuration, so its shape
// is held here and not left to that parse.
func Check(launchFile []byte, family teetypes.Family) error {
	if len(launchFile) > MaxSize {
		return fmt.Errorf("launch file is %d bytes, over the %d one may be", len(launchFile), MaxSize)
	}
	configuration, err := ReadFor(launchFile, family)
	if err != nil {
		return err
	}
	tree, err := yamlutil.DecodeTree(configuration)
	if err != nil {
		return fmt.Errorf("the configuration the launch file carries: %w", err)
	}
	if !isMapping(tree) {
		return errors.New("launch file is neither an initdata document with a \"data\" table nor a configuration, which is a YAML mapping")
	}
	return nil
}

// isMapping reports whether a decoded YAML document is a mapping.
func isMapping(tree *yaml.Node) bool {
	if tree != nil && tree.Kind == yaml.DocumentNode && len(tree.Content) == 1 {
		tree = tree.Content[0]
	}
	return tree != nil && tree.Kind == yaml.MappingNode
}

// NamesTrustAuthority reports whether launchFile is an initdata document
// that carries a Trust Authority configuration entry. Another guest's launch
// file may be any bytes, a TOML document with a data table included, and is
// held to none of these rules.
//
// A file over the size cap is not decoded. It is taken for one when it
// names the entry anywhere, so that [Check] refuses it for its size.
func NamesTrustAuthority(launchFile []byte) bool {
	if len(launchFile) > MaxSize {
		return bytes.Contains(launchFile, []byte(ConfigFile))
	}
	var document map[string]any
	if err := toml.Unmarshal(launchFile, &document); err != nil {
		return false
	}
	data, ok := document["data"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = data[ConfigFile]
	return ok
}

// checkAgentPolicy requires an initdata document to carry a policy for the
// guest agent. Without one the agent runs whatever containers the host names,
// so the document would identify a configuration and no program.
func checkAgentPolicy(data map[string]any) error {
	entry, ok := data[PolicyFile]
	if !ok {
		return fmt.Errorf("initdata document has no %q entry, so nothing holds the guest to the Trust Authority's containers", PolicyFile)
	}
	policy, ok := entry.(string)
	if !ok {
		return fmt.Errorf("initdata entry %q is not a string", PolicyFile)
	}
	// A Rego module opens with its package, after comments alone, so the
	// first statement decides and no later line can stand in for it.
	for _, line := range strings.Split(policy, "\n") {
		statement, _, _ := strings.Cut(line, "#")
		fields := strings.Fields(statement)
		if len(fields) == 0 {
			continue
		}
		if slices.Equal(fields, []string{"package", policyPackage}) {
			return nil
		}
		break
	}
	return fmt.Errorf("initdata entry %q does not declare package %s, the one the guest agent evaluates", PolicyFile, policyPackage)
}
