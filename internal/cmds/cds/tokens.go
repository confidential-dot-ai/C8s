package cds

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// singleUse lets each operator token authorize one write. CDS serves the token
// of a whole-document write as that document's signature, so without this
// anyone who fetched it could replay the write until it expires. A non-zero
// started refuses tokens that could have been spent before CDS started, since
// a store that does not persist forgets them. authorize accepts an iat up to
// clockSkew in the future, so the cutoff is started plus clockSkew.
func singleUse(authorize allowlist.WriteAuthorizer, store *allowlist.Store, started time.Time, clockSkew time.Duration) allowlist.WriteAuthorizer {
	var notBefore time.Time
	if !started.IsZero() {
		notBefore = started.Add(clockSkew)
	}
	return func(r *http.Request, body []byte) error {
		if err := authorize(r, body); err != nil {
			return err
		}
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !notBefore.IsZero() {
			iat, err := operatorauth.TokenIssuedAt(token)
			if err != nil {
				return err
			}
			if iat.Before(notBefore) {
				return fmt.Errorf("operator token issued at %s, before %s: CDS start on a non-persistent store plus clock skew", iat.UTC().Format(time.RFC3339), notBefore.UTC().Format(time.RFC3339))
			}
		}
		return store.ConsumeToken(token)
	}
}
