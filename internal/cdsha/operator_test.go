package cdsha

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func signedOperator(t *testing.T, r *replica) OperatorCommand {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(r.operator)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	c := OperatorCommand{Path: "/secrets/atomic", Body: []byte(`{"value":"c2FtZQ=="}`), AtMS: time.Now().UnixMilli()}
	auth, err := signer.Authorization(http.MethodPut, c.Path, c.Body)
	if err != nil {
		t.Fatal(err)
	}
	c.Token = strings.TrimPrefix(auth, "Bearer ")
	return c
}

func TestAtomicOperatorHistoricalReplayOutlivesAuthorization(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	c := signedOperator(t, r)
	token, _, err := jwt.NewParser().ParseUnverified(c.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	then := time.Now().Add(-time.Hour)
	claims["iat"], claims["exp"] = then.Unix(), then.Add(time.Minute).Unix()
	c.AtMS = then.UnixMilli()
	c.Token, err = jwt.NewWithClaims(token.Method, claims).SignedString(r.operator)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, c.Path, nil)
	request.Header.Set("Authorization", "Bearer "+c.Token)
	verifier := operatorauth.Verifier{Keys: r.FSM.launch.OperatorKeys}
	if err := verifier.Authorize(request, c.Body); err == nil {
		t.Fatal("fixture token is still acceptable at HTTP ingress")
	}
	for _, want := range []int{http.StatusCreated, http.StatusConflict} {
		res := r.apply(Entry{Kind: KindOperator, Operator: &c})
		if res.Stop != nil || res.Operator == nil || res.Operator.Code != want {
			t.Fatalf("replay of historically committed authorization: %+v, want %d", res, want)
		}
	}
}

func TestAtomicOperatorReplayVerifiesTheSignedMutation(t *testing.T) {
	for name, tamper := range map[string]func(*OperatorCommand){
		"body":         func(c *OperatorCommand) { c.Body = []byte(`{"value":"b3RoZXI="}`) },
		"path":         func(c *OperatorCommand) { c.Path = "/secrets/other" },
		"escaped path": func(c *OperatorCommand) { c.EscapedPath = "/secrets/other" },
		"token":        func(c *OperatorCommand) { c.Token = "not-a-token" },
		"time":         func(c *OperatorCommand) { c.AtMS = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			r := newReplica(t)
			r.genesis()
			c := signedOperator(t, r)
			tamper(&c)
			res := r.apply(Entry{Kind: KindOperator, Operator: &c})
			if res.Stop == nil || r.Stuck() == "" {
				t.Fatal("tampered committed request did not fence")
			}
			if r.secrets.Len() != 0 {
				t.Fatal("tampered request changed secrets")
			}
		})
	}
}

func TestAtomicOperatorDoesNotExposeTheExistingSecret(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	c := signedOperator(t, r)
	if res := r.apply(Entry{Kind: KindOperator, Operator: &c}); res.Stop != nil || res.Operator.Code != http.StatusCreated {
		t.Fatalf("create: %+v", res)
	}
	c = signedOperator(t, r) // A different token for the occupied path.
	res := r.apply(Entry{Kind: KindOperator, Operator: &c})
	if res.Stop != nil || res.Operator.Code != http.StatusConflict || !res.Operator.JSON {
		t.Fatalf("occupied path: %+v", res)
	}
	if strings.Contains(string(res.Operator.Body), "same") || strings.Contains(string(res.Operator.Body), "c2FtZQ==") {
		t.Fatal("write response disclosed a secret")
	}
	value, err := r.secrets.Get(context.Background(), "/atomic")
	if err != nil || string(value) != "same" {
		t.Fatal("occupied-path write changed the secret")
	}
}
