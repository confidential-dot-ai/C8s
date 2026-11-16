package podprovider

import (
	"bytes"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func providerCDSPolicy(t *testing.T, launch []byte) []byte {
	t.Helper()
	policy, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{Name: "independent-cds", Digest: bytes.Repeat([]byte{0x88}, 48), LaunchFile: launch}}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
