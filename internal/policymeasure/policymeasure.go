// Package policymeasure records in TDX RTMR[3] every allowlist policy a node
// enforces, so a verifier can check the node's whole policy history since
// boot, and lets the node's other measured consumers account for those
// extends. See docs/allowlist-and-capabilities.md, "Measured policy history".
package policymeasure

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// JournalName is the journal file in the NRI plugin's runtime directory, a
// tmpfs that lives exactly as long as the register.
const JournalName = "measured-policies"

// Open returns the journal that measures policies into this node's RTMR[3],
// whose launch seeded it from anchor. It returns nil, nil on a platform
// without a runtime register.
func Open(dir string, platform teetypes.PlatformType, anchor []byte) (*runtimemeasure.Journal, error) {
	reg, err := runtimemeasure.Open(platform)
	if errors.Is(err, runtimemeasure.ErrNoRegister) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return runtimemeasure.OpenJournalSeeded(filepath.Join(dir, JournalName), reg, runtimemeasure.Seed(anchor))
}

// Read returns the policy digests journaled at path, in extend order. A
// missing file holds none.
func Read(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var digests []string
	for line := range strings.SplitSeq(string(b), "\n") {
		if d, err := runtimemeasure.CanonicalDigest(strings.TrimSpace(line)); err == nil && !slices.Contains(digests, d) {
			digests = append(digests, d)
		}
	}
	return digests, nil
}

// Prefix returns the longest prefix of digests that, extended after the seed
// of anchor, yields the binding r reports. A journal read after r was
// produced may hold extends r does not. It extends once per digest, since
// digests may come from an untrusted peer.
func Prefix(r *teetypes.VerificationResult, anchor []byte, digests []string) ([]string, error) {
	seedErr := runtimemeasure.VerifyBinding(r, anchor, nil)
	if len(anchor) == 0 || len(digests) == 0 {
		return nil, seedErr
	}
	got, err := runtimemeasure.Binding(r)
	if err != nil {
		return nil, seedErr
	}
	k := 0
	reg := runtimemeasure.Seed(anchor)
	for i, d := range digests {
		reg = runtimemeasure.Extend(reg, runtimemeasure.Event(d))
		if bytes.Equal(got, reg[:]) {
			k = i + 1
		}
	}
	if k == 0 {
		return nil, seedErr
	}
	return digests[:k], nil
}
