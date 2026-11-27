// Package initdata reads the initdata document a Kata Containers runtime
// binds to a guest's launch, as a Trust Authority launch file. It imports
// nothing of the Trust Authority's, so the configuration reader and every
// reader of a pin apply one check.
package initdata

import (
	"fmt"
	"slices"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

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
	document, data, ok := decode(launchFile)
	if !ok {
		return launchFile, "", nil
	}
	return fromDocument(document, data)
}

// decode returns launchFile as an initdata document and its data table, or
// false for a file that is not one.
func decode(launchFile []byte) (document, data map[string]any, ok bool) {
	if len(launchFile) > MaxSize {
		return nil, nil, false
	}
	if err := toml.Unmarshal(launchFile, &document); err != nil {
		return nil, nil, false
	}
	data, ok = document["data"].(map[string]any)
	return document, data, ok
}

// fromDocument is Read for a decoded initdata document.
func fromDocument(document, data map[string]any) (configuration []byte, algorithm string, err error) {
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
	if err := holdToFamily(algorithm, family); err != nil {
		return nil, err
	}
	return configuration, nil
}

// holdToFamily holds an initdata document's declared algorithm to the digest
// family commits.
func holdToFamily(algorithm string, family teetypes.Family) error {
	var want string
	switch family {
	case teetypes.FamilySNP:
		want = AlgorithmSNP
	case teetypes.FamilyTDX:
		want = AlgorithmTDX
	default:
		return fmt.Errorf("initdata launch file on TEE family %q, which commits none", family)
	}
	if algorithm != want {
		return fmt.Errorf("initdata algorithm is %q, want %q, the digest a %s launch binding commits", algorithm, want, family)
	}
	return nil
}

// Check refuses a launch file a pin embeds that a Trust Authority of an
// earlier release serves and one of this release does not: an initdata
// document with no agent policy.
//
// INVARIANT: a pin reader need not repeat what a Trust Authority refuses at
// start with or without this check. A configuration is at most the cap and
// carries its schema, so no evidence matches a pin on a larger file or on
// bytes that are no configuration, and neither is parsed here. The cap and
// the family are held because the read yields them.
func Check(launchFile []byte, family teetypes.Family) error {
	_, err := checked(launchFile, family)
	return err
}

// checked is Check, returning the configuration the launch file carries.
func checked(launchFile []byte, family teetypes.Family) ([]byte, error) {
	if len(launchFile) > MaxSize {
		return nil, fmt.Errorf("launch file is %d bytes, over the %d one may be", len(launchFile), MaxSize)
	}
	return ReadFor(launchFile, family)
}

// ConfigSchema is the schema a Trust Authority configuration declares.
const ConfigSchema = "c8s-ta/v1"

// CheckTrustAuthority is [Check] for a pin that names a Trust Authority and
// nothing else: its launch file must also carry a configuration of the Trust
// Authority's schema, so a pin on other bytes is refused before anything is
// signed or written against it. The configuration is not otherwise parsed.
func CheckTrustAuthority(launchFile []byte, family teetypes.Family) error {
	configuration, err := checked(launchFile, family)
	if err != nil {
		return err
	}
	// Decoded as the Trust Authority decodes it, so what it refuses for its
	// form, an anchor or a repeated key, is refused here too.
	tree, err := yamlutil.DecodeTree(configuration)
	if err != nil {
		return fmt.Errorf("the configuration the launch file carries: %w", err)
	}
	var declared struct {
		SchemaVersion string `yaml:"schemaVersion"`
	}
	if err := tree.Decode(&declared); err != nil {
		return fmt.Errorf("the configuration the launch file carries is not a YAML mapping: %w", err)
	}
	if declared.SchemaVersion != ConfigSchema {
		return fmt.Errorf("the configuration the launch file carries declares schemaVersion %q, want %q", declared.SchemaVersion, ConfigSchema)
	}
	return nil
}

// CheckIfTrustAuthority is [Check] for a launch file that is an initdata
// document carrying a Trust Authority configuration entry, and passes any
// other. Another guest's launch file may be any bytes, a TOML document with a
// data table included, and is held to none of these rules.
//
// A file over the size cap is not decoded and passes: no Trust Authority
// reads a document that large as initdata.
func CheckIfTrustAuthority(launchFile []byte, family teetypes.Family) error {
	document, data, ok := decode(launchFile)
	if !ok {
		return nil
	}
	if _, named := data[ConfigFile]; !named {
		return nil
	}
	_, algorithm, err := fromDocument(document, data)
	if err != nil {
		return err
	}
	return holdToFamily(algorithm, family)
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
