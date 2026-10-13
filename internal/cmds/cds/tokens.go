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
// notBefore refuses tokens issued earlier: a store that does not persist
// forgets the tokens spent before CDS started.
func singleUse(authorize allowlist.WriteAuthorizer, store *allowlist.Store, notBefore time.Time) allowlist.WriteAuthorizer {
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
				return fmt.Errorf("operator token issued at %s, before CDS started on a non-persistent store at %s", iat.UTC().Format(time.RFC3339), notBefore.UTC().Format(time.RFC3339))
			}
		}
		return store.ConsumeToken(token)
	}
}
