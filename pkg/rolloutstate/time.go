package rolloutstate

import (
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Validity is how long a signed state is good for after CDS issues it.
// Routers read the state every second, and challenge clients bind it to a
// fresh nonce, so a short window costs nothing.
const Validity = time.Minute

// MaxClockSkew is the clock difference between CDS and a verifier that
// CheckTime tolerates.
const MaxClockSkew = 2 * time.Minute

// Stamp sets st's validity window to start at now.
func Stamp(st *types.RolloutState, now time.Time) {
	st.IssuedAt = now.Unix()
	st.ExpiresAt = now.Add(Validity).Unix()
}

// CheckTime refuses a state without a validity window, issued in the future,
// or expired at now, allowing MaxClockSkew either way.
func CheckTime(st *types.RolloutState, now time.Time) error {
	if st.IssuedAt <= 0 || st.ExpiresAt <= 0 {
		return fmt.Errorf("CDS rollout state carries no issued_at/expires_at")
	}
	if st.ExpiresAt < st.IssuedAt {
		return fmt.Errorf("CDS rollout state expires before it was issued")
	}
	skew := int64(MaxClockSkew / time.Second)
	if st.IssuedAt > now.Unix()+skew {
		return fmt.Errorf("CDS rollout state was issued in the future (%s)", time.Unix(st.IssuedAt, 0).UTC().Format(time.RFC3339))
	}
	if now.Unix() > st.ExpiresAt+skew {
		return fmt.Errorf("CDS rollout state expired at %s", time.Unix(st.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	return nil
}
