package cdscurrent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type Inventory interface {
	InventoryKey(
		context.Context,
		string,
	) (*ecdsa.PublicKey, error)
	FetchSandbox(
		context.Context,
		string,
		string,
	) (workloadclaims.SandboxDigestsResponse, error)
}

// Challenge stores a secret-release nonce in the same encrypted cluster state.
func (r *Replica) Challenge(ctx context.Context) ([32]byte, error) {
	var nonce [32]byte
	ctx, done, err := r.begin(ctx)
	if err != nil {
		return nonce, err
	}
	defer done()
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}
	now := time.Now()
	full := false
	_, err = r.update(
		ctx,
		func(v *view) error {
			for key, expiry := range v.state.Challenges {
				if expiry <= now.UnixMilli() {
					delete(
						v.state.Challenges,
						key,
					)
				}
			}
			full = len(v.state.Challenges) >= maxChallenges
			if !full {
				v.state.Challenges[hex.EncodeToString(nonce[:])] = now.Add(r.policy.ChallengeTTL).UnixMilli()
			}
			return nil
		},
	)
	if err != nil {
		return [32]byte{}, err
	}
	if full {
		return [32]byte{}, ErrCapacity
	}
	return nonce, nil
}

func (r *Replica) consume(
	ctx context.Context,
	nonce []byte,
) (*view, error) {
	if len(nonce) != 32 {
		return nil, ErrChallenge
	}
	live := false
	encrypted, err := r.update(
		ctx,
		func(v *view) error {
			key := hex.EncodeToString(nonce)
			expires, exists := v.state.Challenges[key]
			live = exists && time.Now().UnixMilli() < expires
			delete(
				v.state.Challenges,
				key,
			)
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, ErrChallenge
	}
	return r.open(encrypted)
}

// ServeSecret uses the existing workload release checks. Policy, secret and
// binding come from the exact state that committed this request's nonce spend.
func (r *Replica) ServeSecret(
	w http.ResponseWriter,
	request *http.Request,
	inventory Inventory,
	hosts workloadclaims.CIDRHosts,
) {
	if request.Method != http.MethodGet {
		http.Error(
			w,
			"method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}
	rest, under := strings.CutPrefix(
		request.URL.EscapedPath(),
		"/secrets",
	)
	if _, err := pkgallowlist.CanonicalSecretPath(rest); !under || err != nil || len(rest) > 4096 {
		http.Error(
			w,
			"invalid secret path",
			http.StatusBadRequest,
		)
		return
	}
	ctx, done, err := r.begin(request.Context())
	if err != nil {
		writeUnavailable(
			w,
			err,
		)
		return
	}
	defer done()
	encoded := request.Header.Get(secrets.ChallengeHeader)
	if len(encoded) > 128 {
		http.Error(
			w,
			"invalid or expired challenge",
			http.StatusBadRequest,
		)
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		http.Error(
			w,
			"invalid or expired challenge",
			http.StatusBadRequest,
		)
		return
	}
	v, err := r.consume(
		ctx,
		nonce,
	)
	if err == ErrChallenge {
		http.Error(
			w,
			"invalid or expired challenge",
			http.StatusBadRequest,
		)
		return
	}
	if err != nil {
		writeUnavailable(
			w,
			err,
		)
		return
	}
	defer v.close()
	if inventory == nil {
		http.Error(
			w,
			"inventory unavailable",
			http.StatusServiceUnavailable,
		)
		return
	}
	secrets.Handler{
		Store:          v.secrets.Local(),
		Challenges:     &committedChallenge{nonce: nonce},
		Inventory:      inventory,
		InventoryHosts: hosts,
		Bindings:       v.ledger.Local(),
		Policy:         secrets.NewCachedPolicy(v.al),
	}.ServeHTTP(
		w,
		request.Clone(ctx),
	)
}

// The existing handler must consume exactly the already committed request once.
type committedChallenge struct {
	nonce    []byte
	consumed bool
}

func (c *committedChallenge) Consume(nonce []byte) bool {
	if c.consumed || !bytes.Equal(
		nonce,
		c.nonce,
	) {
		return false
	}
	c.consumed = true
	return true
}
