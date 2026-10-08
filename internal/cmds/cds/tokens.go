package cds

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// singleUse lets each operator token authorize one write. CDS publishes the
// token of a whole-document write as that policy's signature, so without this
// anyone who fetched it could replay the write until it expires. Tokens are
// remembered until their expiry plus skew, the verifier's leeway.
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

// allowlistAuthorizer is the authorizer for allowlist writes and the
// operator_keys value the rollout state attests: write as authorizes them
// under keys, or nothing when immutable or when no keys are configured.
// Secret writes keep write either way.
func allowlistAuthorizer(immutable bool, write allowlist.WriteAuthorizer, keys string) (allowlist.WriteAuthorizer, string) {
	switch {
	case immutable:
		slog.Info("allowlist is immutable: every allowlist write is refused")
		return func(*http.Request, []byte) error { return fmt.Errorf("the allowlist is immutable") }, types.OperatorKeysNone
	case keys == "":
		return write, types.OperatorKeysNone
	}
	return write, keys
}
