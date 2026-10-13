package cds

import (
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// singleUse lets each operator token authorize one write. CDS serves the token
// of a whole-document write as that document's signature, so without this
// anyone who fetched it could replay the write until it expires. A token is
// remembered until its expiry plus skew, the verifier's leeway.
func singleUse(authorize allowlist.WriteAuthorizer, store *allowlist.Store, skew time.Duration) allowlist.WriteAuthorizer {
	return func(r *http.Request, body []byte) error {
		if err := authorize(r, body); err != nil {
			return err
		}
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		exp, err := operatorauth.TokenExpiry(token)
		if err != nil {
			return err
		}
		return store.ConsumeToken(token, exp.Add(skew))
	}
}
