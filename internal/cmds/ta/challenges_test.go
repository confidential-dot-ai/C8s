package ta

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/attestation"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/issuer"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/secrets"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/types"
)

// challengeConsumer is one Trust Authority route that redeems an attestation challenge.
type challengeConsumer struct {
	redeems string
	mintAt  string
	redeem  func(challenge []byte) bool
}

// challengeConsumers lists every route that redeems a challenge, with the
// route that mints for it.
func challengeConsumers(t *testing.T, deps dependencies) []challengeConsumer {
	t.Helper()
	if deps.SecretsHandler.Challenges != deps.SecretsChallenges {
		t.Fatal("the secrets routes mint from one pool and redeem at another")
	}
	return []challengeConsumer{
		{
			redeems: "POST /attest",
			mintAt:  "/authenticate",
			redeem:  deps.AttestHandler.Challenges.Consume,
		},
		{
			redeems: "GET and POST " + secrets.Route,
			mintAt:  secrets.ChallengeRoute,
			redeem:  deps.SecretsHandler.Challenges.Consume,
		},
	}
}

// challengeDeps is a Trust Authority whose two challenge pools are the ones given.
func challengeDeps(t *testing.T, issuance, secretsPool attestation.Challenges) dependencies {
	t.Helper()
	limiter, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	return dependencies{
		AttestHandler:     AttestHandler{Challenges: issuance},
		ReadyFn:           func() bool { return true },
		MeshCA:            testMeshCA(t),
		NodeImages:        certifying(),
		RateLimiter:       limiter,
		ChallengeLimiter:  newTestRateLimiter(t),
		MaxRequestSize:    65536,
		SecretsHandler:    &secrets.Handler{Challenges: secretsPool},
		SecretsChallenges: secretsPool,
		SecretsOperator: &secrets.OperatorHandler{
			Store: secrets.NewMemoryStore(8, 7, 64).Local(),
		},
		SecretsExplain: &secrets.ExplainHandler{},
	}
}

// mintChallenge posts to a challenge route and decodes the nonce it answers.
func mintChallenge(t *testing.T, router http.Handler, path string) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("POST %s = %d, want 200", path, w.Code)
	}
	var out types.ChallengeResponse
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode the challenge %s answered: %v", path, err)
	}
	nonce, err := base64.StdEncoding.DecodeString(out.Challenge)
	if err != nil {
		t.Fatalf("challenge from %s is not base64: %v", path, err)
	}
	return nonce
}

// Every challenge consumer redeems the nonces of its own route only, in a
// single Trust Authority and in a Trust Authority HA replica alike.
func TestChallengeConsumersRedeemTheirOwnPoolOnly(t *testing.T) {
	key := []byte("mesh-ca-derived-key")
	for name, pools := range map[string]func() (attestation.Challenges, attestation.Challenges){
		"single Trust Authority": func() (attestation.Challenges, attestation.Challenges) {
			return attestation.NewLocalChallenges(time.Minute), attestation.NewLocalChallenges(time.Minute)
		},
		"Trust Authority HA replica": func() (attestation.Challenges, attestation.Challenges) {
			return attestation.NewSharedChallenges(
					"issuance",
					time.Minute,
					func() []byte { return key },
				),
				attestation.NewSharedChallenges(
					"secrets",
					time.Minute,
					func() []byte { return key },
				)
		},
	} {
		t.Run(name, func(t *testing.T) {
			issuance, secretsPool := pools()
			deps := challengeDeps(t, issuance, secretsPool)
			router := newRouter(deps)
			consumers := challengeConsumers(t, deps)
			for i, minted := range consumers {
				nonce := mintChallenge(t, router, minted.mintAt)
				for j, consumer := range consumers {
					if got := consumer.redeem(nonce); got != (i == j) {
						t.Errorf("%s redeemed = %v for a nonce minted at %s", consumer.redeems, got, minted.mintAt)
					}
				}
			}
		})
	}
}

// A replica that holds no cluster key mints no nonce, so a challenge route is
// a retryable 503 rather than a nonce nothing will redeem.
func TestChallengeRoutesUnavailableBeforeTheReplicaServes(t *testing.T) {
	keyless := attestation.NewSharedChallenges(
		"issuance",
		time.Minute,
		func() []byte { return nil },
	)
	deps := challengeDeps(t, keyless, keyless)
	router := newRouter(deps)

	for _, consumer := range challengeConsumers(t, deps) {
		if code := get(t, router, http.MethodPost, consumer.mintAt); code != http.StatusServiceUnavailable {
			t.Errorf("POST %s = %d, want 503", consumer.mintAt, code)
		}
	}
}
