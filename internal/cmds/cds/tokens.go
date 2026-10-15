package cds

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// singleUse lets each operator token authorize one write. CDS serves the token
// of a whole-document write as that document's signature, so without this
// anyone who fetched it could replay the write until it expires. A non-zero
// started refuses tokens that could have been spent before CDS started, since
// a store that does not persist forgets them. authorize returns the verified
// token's iat and accepts one up to clockSkew in the future, so the cutoff is
// started plus clockSkew.
func singleUse(authorize func(*http.Request, []byte) (time.Time, error), store *allowlist.Store, started time.Time, clockSkew time.Duration) allowlist.WriteAuthorizer {
	var notBefore time.Time
	if !started.IsZero() {
		notBefore = started.Add(clockSkew)
	}
	return func(r *http.Request, body []byte) error {
		iat, err := authorize(r, body)
		if err != nil {
			return err
		}
		if !notBefore.IsZero() && iat.Before(notBefore) {
			return fmt.Errorf("%w: issued at %s, before %s", allowlist.ErrTokenBeforeStart, iat.UTC().Format(time.RFC3339), notBefore.UTC().Format(time.RFC3339))
		}
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		return store.ConsumeToken(token)
	}
}
