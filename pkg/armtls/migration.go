package armtls

import (
	"encoding/binary"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// EnforceNonMigratable requires an authenticated native SNP or TDX result whose
// launch policy forbids migration. Call only after signature, freshness and
// key binding verification; this check does not authenticate evidence.
func EnforceNonMigratable(result *teetypes.VerificationResult) error {
	if result == nil || !result.SignatureValid {
		return fmt.Errorf(
			"%w: non-migration requires a verified result",
			ErrPolicyViolation,
		)
	}
	switch teetypes.NormalizePlatform(string(result.Platform)) {
	case teetypes.PlatformSNP:
		policy, _ := result.Claims.PlatformData["policy"].(map[string]any)
		migratable, present := policy["migrate_ma"].(bool)
		if !present || migratable {
			return fmt.Errorf(
				"%w: SNP policy.migrate_ma must be boolean false",
				ErrPolicyViolation,
			)
		}
	case teetypes.PlatformTDX:
		attributes, _ := result.Claims.PlatformData["td_attributes"].(string)
		raw, err := teetypes.ParseDigest(
			attributes,
			8,
		)
		if err != nil {
			return fmt.Errorf(
				"%w: TDX td_attributes %v",
				ErrPolicyViolation,
				err,
			)
		}
		// TD_ATTRIBUTES is little-endian; bit 29 permits migration.
		if binary.LittleEndian.Uint64(raw)&(1<<29) != 0 {
			return fmt.Errorf(
				"%w: TDX TD_ATTRIBUTES.MIGRATABLE must be clear",
				ErrPolicyViolation,
			)
		}
	default:
		return fmt.Errorf(
			"%w: non-migration is unsupported for platform %q",
			ErrPolicyViolation,
			result.Platform,
		)
	}
	return nil
}
