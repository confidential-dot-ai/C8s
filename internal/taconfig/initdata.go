package taconfig

import (
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/initdata"
)

// The digests an initdata launch file may declare, and the entry that holds
// the guest agent's policy; [initdata] owns the document's rules.
const (
	InitdataAlgorithmSNP = initdata.AlgorithmSNP
	InitdataAlgorithmTDX = initdata.AlgorithmTDX
	PolicyFile           = initdata.PolicyFile
	maxInitdataSize      = initdata.MaxSize
)

// configDocument returns the configuration a launch file carries: the file
// itself, or the ConfigFile entry of the initdata document a Kata Containers
// runtime binds to a guest's launch. The bytes alone decide which.
func configDocument(launchFile []byte) ([]byte, error) {
	configuration, _, err := initdata.Read(launchFile)
	return configuration, err
}

// CheckInitdataFamily refuses an initdata launch file that declares another
// family's digest than the one family commits, or carries no agent policy. A
// launch file that is the configuration itself passes.
func CheckInitdataFamily(launchFile []byte, family teetypes.Family) error {
	_, err := initdata.ReadFor(launchFile, family)
	return err
}

// configDocumentFor is configDocument for a launch file of a known family.
func configDocumentFor(launchFile []byte, family teetypes.Family) ([]byte, error) {
	return initdata.ReadFor(launchFile, family)
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
