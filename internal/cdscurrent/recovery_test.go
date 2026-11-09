package cdscurrent_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdscurrent"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestRealHandlersRecoverIdentityReplayAndRevocation(t *testing.T) {
	f := newFixture(
		t,
		testCluster,
	)
	replicas := f.start(
		testCluster,
		true,
	)
	ca, err := replicas[0].CA(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	certificate := bytes.Clone(ca.Cert.Raw)
	privateDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, leafKey := tlsLeaf(
		t,
		ca,
		testSandbox,
	)
	signer, err := workloadclaims.NewSandboxTokenSigner(testHost)
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory{signer: signer}

	allowed := policy(
		t,
		"approved",
		true,
	)
	spent := f.authorization(
		"/allowlist",
		allowed,
	)
	requireStatus(
		t,
		request(
			replicas[0],
			http.MethodPut,
			"/allowlist",
			allowed,
			spent,
			"",
		),
		http.StatusNoContent,
	)
	secret := []byte("synthetic-confidential-recovery-fixture")
	body, err := json.Marshal(secrets.PutRequest{Value: base64.StdEncoding.EncodeToString(secret)})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(
		t,
		request(
			replicas[1],
			http.MethodPut,
			testSecretPath,
			body,
			f.authorization(
				testSecretPath,
				body,
			),
			"",
		),
		http.StatusCreated,
	)
	if err := replicas[2].Bind(
		t.Context(),
		testSandbox,
		testHost,
	); err != nil {
		t.Fatal(err)
	}
	before := newSecretClient(
		t,
		replicas[1],
		ca,
		leaf,
		leafKey,
		inv,
	)
	consumed, err := replicas[0].Challenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	requireSecret(
		t,
		before,
		consumed,
		secret,
	)

	// This token remains live and unused across recovery. A replacement must
	// not reset its startup floor and reject it as having preceded that process.
	pending := policy(
		t,
		"approved-after-recovery",
		true,
	)
	unspent := f.authorization(
		"/allowlist",
		pending,
	)
	revoked := policy(
		t,
		"revoked",
		false,
	)
	requireStatus(
		t,
		request(
			replicas[2],
			http.MethodPut,
			"/allowlist",
			revoked,
			f.authorization(
				"/allowlist",
				revoked,
			),
			"",
		),
		http.StatusNoContent,
	)
	denied, err := replicas[0].Challenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := before.get(
		t,
		denied,
	); code != http.StatusForbidden {
		t.Fatalf(
			"revoked access: HTTP %d",
			code,
		)
	}
	before.server.Close()

	// No replacement receives an old Replica, CA or policy object. Only the
	// configured wrapping key and the original durable authority directories survive.
	f.loseCompute()
	replicas = nil
	ca = nil
	assertEncryptedAuthorityFiles(
		t,
		f.directory,
		privateDER,
		secret,
	)
	f.restartAuthorities()
	replicas = f.start(
		testCluster,
		false,
	)
	for _, replica := range replicas {
		w := request(
			replica,
			http.MethodGet,
			"/ca",
			nil,
			"",
			"",
		)
		requireStatus(
			t,
			w,
			http.StatusOK,
		)
		block, rest := pem.Decode(w.Body.Bytes())
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(
			block.Bytes,
			certificate,
		) {
			t.Fatal("recovered CA endpoint changed the original certificate")
		}
	}
	ca, err = replicas[2].CA(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	after := newSecretClient(
		t,
		replicas[2],
		ca,
		leaf,
		leafKey,
		inv,
	)
	if code, _ := after.get(
		t,
		consumed,
	); code != http.StatusBadRequest {
		t.Fatalf(
			"consumed pre-loss challenge: HTTP %d",
			code,
		)
	}
	fresh, err := replicas[1].Challenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := after.get(
		t,
		fresh,
	); code != http.StatusForbidden {
		t.Fatalf(
			"recovered revocation: HTTP %d",
			code,
		)
	}
	for i, auth := range []string{
		spent,
		alternateSignature(
			t,
			spent,
			f.operator.Params().N,
		),
	} {
		assertLiveToken(
			t,
			f,
			"/allowlist",
			allowed,
			auth,
		)
		w := request(
			replicas[i],
			http.MethodPut,
			"/allowlist",
			allowed,
			auth,
			"",
		)
		requireStatus(
			t,
			w,
			http.StatusConflict,
		)
		if strings.TrimSpace(w.Body.String()) != operatorauth.ErrTokenReused.Error() {
			t.Fatalf(
				"replay rejected for wrong reason: %s",
				w.Body.String(),
			)
		}
	}
	assertLiveToken(
		t,
		f,
		"/allowlist",
		pending,
		unspent,
	)
	requireStatus(
		t,
		request(
			replicas[0],
			http.MethodPut,
			"/allowlist",
			pending,
			unspent,
			"",
		),
		http.StatusNoContent,
	)
	fresh, err = replicas[1].Challenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	requireSecret(
		t,
		after,
		fresh,
		secret,
	)
}

func TestAuthenticatedRefusalsPreserveTokenSemantics(t *testing.T) {
	f := newFixture(
		t,
		testCluster,
	)
	r := f.start(
		testCluster,
		true,
	)
	valid := policy(
		t,
		"initial",
		false,
	)
	auth := f.authorization(
		"/allowlist",
		valid,
	)
	requireStatus(
		t,
		request(
			r[0],
			http.MethodPut,
			"/allowlist",
			valid,
			auth,
			"*",
		),
		http.StatusPreconditionFailed,
	)
	// Invalid precondition syntax precedes authentication, so it cannot spend a token.
	requireStatus(
		t,
		request(
			r[1],
			http.MethodPut,
			"/allowlist",
			valid,
			auth,
			"",
		),
		http.StatusNoContent,
	)
	invalid := []byte("{")
	invalidAuth := f.authorization(
		"/allowlist",
		invalid,
	)
	requireStatus(
		t,
		request(
			r[0],
			http.MethodPut,
			"/allowlist",
			invalid,
			invalidAuth,
			"",
		),
		http.StatusUnprocessableEntity,
	)
	stale := policy(
		t,
		"must-not-apply",
		false,
	)
	staleAuth := f.authorization(
		"/allowlist",
		stale,
	)
	requireStatus(
		t,
		request(
			r[1],
			http.MethodPut,
			"/allowlist",
			stale,
			staleAuth,
			`"0"`,
		),
		http.StatusPreconditionFailed,
	)
	f.loseCompute()
	r = f.start(
		testCluster,
		false,
	)
	for _, refused := range []struct {
		body []byte
		auth string
	}{
		{
			body: invalid,
			auth: invalidAuth,
		},
		{
			body: stale,
			auth: staleAuth,
		},
	} {
		w := request(
			r[2],
			http.MethodPut,
			"/allowlist",
			refused.body,
			refused.auth,
			"",
		)
		requireStatus(
			t,
			w,
			http.StatusConflict,
		)
		if strings.TrimSpace(w.Body.String()) != operatorauth.ErrTokenReused.Error() {
			t.Fatalf(
				"refused mutation did not persist token spend: %s",
				w.Body.String(),
			)
		}
	}
	w := request(
		r[2],
		http.MethodGet,
		"/allowlist",
		nil,
		"",
		"",
	)
	requireStatus(
		t,
		w,
		http.StatusOK,
	)
	marker, err := policyMarker(w.Body.Bytes())
	if err != nil || marker != "initial" {
		t.Fatalf(
			"refused mutation changed policy: %q, %v",
			marker,
			err,
		)
	}
}

func TestUnknownChallengeConsumptionNeverReleasesSecrets(t *testing.T) {
	f := newFixture(
		t,
		testCluster,
	)
	var drop atomic.Bool
	var accepted, inventoryCalls atomic.Int64
	peers := f.peers()
	for i, peer := range peers {
		peers[i] = lostReplyPeer{
			Peer:     peer,
			drop:     &drop,
			accepted: &accepted,
		}
	}
	r := f.replica(
		testCluster,
		peers,
	)
	if err := r.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	allowed := policy(
		t,
		"allowed",
		true,
	)
	requireStatus(
		t,
		request(
			r,
			http.MethodPut,
			"/allowlist",
			allowed,
			f.authorization(
				"/allowlist",
				allowed,
			),
			"",
		),
		http.StatusNoContent,
	)
	secret := []byte("synthetic-secret-must-not-escape-unknown-consume")
	secretBody, err := json.Marshal(secrets.PutRequest{Value: base64.StdEncoding.EncodeToString(secret)})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(
		t,
		request(
			r,
			http.MethodPut,
			testSecretPath,
			secretBody,
			f.authorization(
				testSecretPath,
				secretBody,
			),
			"",
		),
		http.StatusCreated,
	)
	if err := r.Bind(
		t.Context(),
		testSandbox,
		testHost,
	); err != nil {
		t.Fatal(err)
	}
	ca, err := r.CA(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	leaf, key := tlsLeaf(
		t,
		ca,
		testSandbox,
	)
	signer, err := workloadclaims.NewSandboxTokenSigner(testHost)
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory{
		signer: signer,
		calls:  &inventoryCalls,
	}
	client := newSecretClient(
		t,
		r,
		ca,
		leaf,
		key,
		inv,
	)
	nonce, err := r.Challenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	drop.Store(true)
	status, headers, body := client.getResponse(
		t,
		nonce,
	)
	if status != http.StatusServiceUnavailable || headers.Get("X-CDS-Outcome") != "unknown" {
		t.Fatalf(
			"uncertain nonce consumption returned HTTP %d, outcome %q",
			status,
			headers.Get("X-CDS-Outcome"),
		)
	}
	if inventoryCalls.Load() != 0 {
		t.Fatal("uncertain nonce consumption reached inventory authorization")
	}
	if bytes.Contains(
		body,
		secret,
	) || bytes.Contains(
		body,
		[]byte(base64.StdEncoding.EncodeToString(secret)),
	) {
		t.Fatal("uncertain nonce consumption emitted secret bytes")
	}
	client.server.Close()
	f.loseCompute()
	if n := accepted.Load(); n < 2 || n > 3 {
		t.Fatalf(
			"nonce spend accepted %d times; expected one uncertain majority dispatch",
			n,
		)
	}
	drop.Store(false)
	f.restartAuthorities()
	replacements := f.start(
		testCluster,
		false,
	)
	ca, err = replacements[0].CA(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	client = newSecretClient(
		t,
		replacements[2],
		ca,
		leaf,
		key,
		inv,
	)
	if status, _ := client.get(
		t,
		nonce,
	); status != http.StatusBadRequest {
		t.Fatalf(
			"uncertain spent nonce replay returned HTTP %d",
			status,
		)
	}
	if inventoryCalls.Load() != 0 {
		t.Fatal("spent nonce replay reached inventory authorization")
	}
	revoked := policy(
		t,
		"revoked-after-unknown",
		false,
	)
	requireStatus(
		t,
		request(
			replacements[0],
			http.MethodPut,
			"/allowlist",
			revoked,
			f.authorization(
				"/allowlist",
				revoked,
			),
			"",
		),
		http.StatusNoContent,
	)
	fresh, err := replacements[1].Challenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := client.get(
		t,
		fresh,
	); status != http.StatusForbidden {
		t.Fatalf(
			"fresh nonce ignored current revocation: HTTP %d",
			status,
		)
	}
	if inventoryCalls.Load() == 0 {
		t.Fatal("fresh nonce did not exercise real workload authorization")
	}
	requireStatus(
		t,
		request(
			replacements[0],
			http.MethodPut,
			"/allowlist",
			allowed,
			f.authorization(
				"/allowlist",
				allowed,
			),
			"",
		),
		http.StatusNoContent,
	)
	fresh, err = replacements[1].Challenge(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	requireSecret(
		t,
		client,
		fresh,
		secret,
	)
}

func TestRecoveryRejectsWrongKeyAndCluster(t *testing.T) {
	f := newFixture(
		t,
		testCluster,
	)
	r := f.start(
		testCluster,
		true,
	)
	for _, change := range []struct {
		name  string
		apply func(*cdscurrent.Config)
	}{
		{
			name: "key",
			apply: func(c *cdscurrent.Config) {
				c.Key = bytes.Repeat(
					[]byte{0x42},
					32,
				)
			},
		},
		{
			name:  "cluster",
			apply: func(c *cdscurrent.Config) { c.ClusterID = "different-cluster" },
		},
		{
			name:  "limits",
			apply: func(c *cdscurrent.Config) { c.MaxPaths++ },
		},
	} {
		t.Run(
			change.name,
			func(t *testing.T) {
				cfg := f.policies[testCluster]
				change.apply(&cfg)
				replacement, err := cdscurrent.New(
					f.proposers[0],
					cfg,
				)
				if err != nil {
					t.Fatal(err)
				}
				defer replacement.Close()
				if _, err := replacement.CA(t.Context()); err == nil {
					t.Fatal("mismatched recovery context decrypted the CA")
				}
			},
		)
	}
	if _, err := r[2].CA(t.Context()); err != nil {
		t.Fatalf(
			"refused recovery damaged original state: %v",
			err,
		)
	}
}

func requireSecret(
	t *testing.T,
	client *secretClient,
	nonce [32]byte,
	want []byte,
) {
	t.Helper()
	code, body := client.get(
		t,
		nonce,
	)
	if code != http.StatusOK {
		t.Fatalf(
			"secret release HTTP %d: %s",
			code,
			body,
		)
	}
	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(
		body,
		&result,
	); err != nil {
		t.Fatal(err)
	}
	actual, err := base64.StdEncoding.DecodeString(result.Value)
	if err != nil || !bytes.Equal(
		actual,
		want,
	) {
		t.Fatal("recovered secret differs from acknowledged value")
	}
}

func assertLiveToken(
	t *testing.T,
	f *fixture,
	path string,
	body []byte,
	auth string,
) {
	t.Helper()
	req := httptest.NewRequest(
		http.MethodPut,
		path,
		bytes.NewReader(body),
	)
	req.Header.Set(
		"Authorization",
		auth,
	)
	v := operatorauth.Verifier{Keys: f.policies[testCluster].OperatorKeys}
	if err := v.Authorize(
		req,
		body,
	); err != nil {
		t.Fatalf(
			"replay fixture no longer independently verifies: %v",
			err,
		)
	}
}

func alternateSignature(
	t *testing.T,
	auth string,
	order *big.Int,
) string {
	t.Helper()
	parts := strings.Split(
		strings.TrimPrefix(
			auth,
			"Bearer ",
		),
		".",
	)
	if len(parts) != 3 {
		t.Fatal("invalid JWT fixture")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatal("invalid ES256 signature fixture")
	}
	s := new(big.Int).SetBytes(sig[32:])
	new(big.Int).Sub(
		order,
		s,
	).FillBytes(sig[32:])
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	variant := "Bearer " + strings.Join(
		parts,
		".",
	)
	if variant == auth {
		t.Fatal("signature variant did not change")
	}
	return variant
}

func assertEncryptedAuthorityFiles(
	t *testing.T,
	directory string,
	privateDER []byte,
	secret []byte,
) {
	t.Helper()
	files := 0
	err := filepath.WalkDir(
		directory,
		func(
			path string,
			entry fs.DirEntry,
			walkErr error,
		) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files++
			for _, plain := range [][]byte{
				privateDER,
				secret,
				[]byte(base64.StdEncoding.EncodeToString(privateDER)),
				[]byte(base64.StdEncoding.EncodeToString(secret)),
			} {
				if bytes.Contains(
					data,
					plain,
				) {
					t.Errorf(
						"authority file %s contains plaintext recovery material",
						filepath.Base(path),
					)
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if files < 6 {
		t.Fatalf(
			"inspected only %d authority files",
			files,
		)
	}
}
