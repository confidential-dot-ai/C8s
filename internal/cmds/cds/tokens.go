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

// earliestIssue is the earliest issue time a token may carry. A spent-token
// record that began at the zero time holds every token this CDS ever spent, so
// no token is refused for its age.
func earliestIssue(floor time.Time, clockSkew time.Duration) time.Time {
	if floor.IsZero() {
		return time.Time{}
	}
	return floor.Add(clockSkew)
}

// singleUse lets each operator token authorize one request. CDS serves the token
// of a whole-document write as that document's signature, so without this
// anyone who fetched it could replay the write until it expires. A non-zero
// floor refuses tokens that could have been spent before the spent-token
// record this CDS holds began: a store that does not persist forgets them, and
// a cluster that starts again forgets the ones its last life spent. It is read
// per request, because a cluster that starts again moves it.
func singleUse(
	authorize func(*http.Request, []byte) (time.Time, error),
	store *allowlist.Handle,
	floor func() time.Time,
	clockSkew time.Duration,
) allowlist.WriteAuthorizer {
	return func(r *http.Request, body []byte) error {
		iat, err := authorize(r, body)
		if err != nil {
			return err
		}
		notBefore := earliestIssue(floor(), clockSkew)
		if !notBefore.IsZero() && iat.Before(notBefore) {
			return fmt.Errorf("%w: issued at %s, before %s", operatorauth.ErrTokenBeforeStart, iat.UTC().Format(time.RFC3339), notBefore.UTC().Format(time.RFC3339))
		}
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		err = store.ConsumeToken(token)
		if err != nil && !errors.Is(err, operatorauth.ErrTokenReused) {
			return fmt.Errorf("%w: %w", operatorauth.ErrTokenNotRecorded, err)
		}
		return err
	}
}
