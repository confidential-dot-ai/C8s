package taconfig

import (
	"fmt"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// The digests an initdata launch file may declare: the launch binding is the
// SHA-256 of the whole file on AMD SEV-SNP and its SHA-384 on Intel TDX. A
// runtime told to hash it any other way commits a value no verifier accepts.
// [CheckInitdataFamily] holds the declaration to the family that launched.
const (
	InitdataAlgorithmSNP = "sha256"
	InitdataAlgorithmTDX = "sha384"
)

// PolicyFile is the initdata entry that holds the guest agent's policy, and
// policyPackage the package the agent evaluates. The launch binding covers a
// guest and this document, and the host names the containers afterwards: the
// policy is what holds them to the Trust Authority's. [checkAgentPolicy]
// requires one and does not judge its rules, which whoever pins the document
// answers for.
const (
	PolicyFile    = "policy.rego"
	policyPackage = "package agent_policy"
)

// maxInitdataSize bounds an initdata document supplied by the host.
const maxInitdataSize = 1024 * 1024

// configDocument returns the configuration a launch file carries: the file
// itself, or the ConfigFile entry of the initdata document a Kata Containers
// runtime binds to a guest's launch.
//
// INVARIANT: the bytes alone decide which. Whoever starts the guest chooses
// its arguments, so a format they could name would let them choose how bound
// bytes are read. No file reads both ways: a configuration is a YAML mapping,
// which is never TOML.
//
// Keys are matched exactly, as the runtime reads them, so a document cannot
// carry a second configuration under another spelling of a key.
func configDocument(launchFile []byte) ([]byte, error) {
	configuration, _, err := readInitdata(launchFile)
	return configuration, err
}

// CheckInitdataFamily refuses an initdata launch file that declares another
// family's digest than the one family commits. A launch file that is the
// configuration itself declares none and passes.
//
// The launch binding proves the file's bytes, not the algorithm written inside
// them, so a file declaring the wrong one would otherwise serve.
func CheckInitdataFamily(launchFile []byte, family teetypes.Family) error {
	_, err := configDocumentFor(launchFile, family)
	return err
}

// configDocumentFor is configDocument for a launch file of a known family:
// one read yields the configuration and holds an initdata document's declared
// algorithm to the digest that family commits.
func configDocumentFor(launchFile []byte, family teetypes.Family) ([]byte, error) {
	configuration, algorithm, err := readInitdata(launchFile)
	if err != nil || algorithm == "" {
		return configuration, err
	}
	var want string
	switch family {
	case teetypes.FamilySNP:
		want = InitdataAlgorithmSNP
	case teetypes.FamilyTDX:
		want = InitdataAlgorithmTDX
	default:
		return nil, fmt.Errorf("initdata launch file on TEE family %q, which commits none", family)
	}
	if algorithm != want {
		return nil, fmt.Errorf("initdata algorithm is %q, want %q, the digest a %s launch binding commits", algorithm, want, family)
	}
	return configuration, nil
}

// readInitdata is configDocument, also returning the digest an initdata
// document declares; a file that is the configuration itself declares none.
func readInitdata(launchFile []byte) (configuration []byte, algorithm string, err error) {
	if len(launchFile) > maxInitdataSize {
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
	if algorithm != InitdataAlgorithmSNP && algorithm != InitdataAlgorithmTDX {
		return nil, "", fmt.Errorf("initdata algorithm is %#v, want %q on SEV-SNP or %q on TDX, the digest the launch binding commits", document["algorithm"], InitdataAlgorithmSNP, InitdataAlgorithmTDX)
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
	for _, line := range strings.Split(policy, "\n") {
		if strings.TrimSpace(line) == policyPackage {
			return nil
		}
	}
	return fmt.Errorf("initdata entry %q does not declare %q, the package the guest agent evaluates", PolicyFile, policyPackage)
}

// overCap names the size cap in the refusal of a launch file too large to be
// read as an initdata document, which is then read as the configuration and
// fails as one.
func overCap(launchFile []byte, err error) error {
	if len(launchFile) <= maxInitdataSize {
		return err
	}
	return fmt.Errorf("launch file is %d bytes, over the %d an initdata document may be, so it was read as the configuration itself: %w", len(launchFile), maxInitdataSize, err)
}
