package cds

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// singleUse lets each operator token authorize one request. CDS serves the token
// of a whole-document write as that document's signature, so without this
// anyone who fetched it could replay the write until it expires. A non-nil
// started refuses tokens that could have been spent before the time it
// returns, when the store may have forgotten them: CDS started on a store that
// does not persist, or an HA cluster started again (Genesis, Restore,
// Recover). It is read at every request, since a Recover moves it on a
// replica that is already serving. authorize returns the verified token's iat
// and accepts one up to clockSkew in the future, so the cutoff is started
// plus clockSkew.
func singleUse(authorize func(*http.Request, []byte) (time.Time, error), store *allowlist.Store, started func() time.Time, clockSkew time.Duration) allowlist.WriteAuthorizer {
	return func(r *http.Request, body []byte) error {
		iat, err := authorize(r, body)
		if err != nil {
			return err
		}
		if started != nil {
			if notBefore := started().Add(clockSkew); iat.Before(notBefore) {
				return fmt.Errorf("%w: issued at %s, before %s", operatorauth.ErrTokenBeforeStart, iat.UTC().Format(time.RFC3339), notBefore.UTC().Format(time.RFC3339))
			}
		}
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		err = store.ConsumeToken(token)
		if err != nil && !errors.Is(err, operatorauth.ErrTokenReused) {
			return fmt.Errorf("%w: %w", operatorauth.ErrTokenNotRecorded, err)
		}
		return err
	}
}
