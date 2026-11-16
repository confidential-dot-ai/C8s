package steps

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"os"
	"testing"
)

func TestSelfSignedRequesterUsesCanonicalSandboxID(t *testing.T) {
	const sandboxID = "sandbox-1"
	value, err := asn1.MarshalWithParams(sandboxID, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	w := &world{
		pods: map[string]*pod{
			"workload": {
				workloadID: true,
				leaf: &leaf{cert: &x509.Certificate{
					Extensions: []pkix.Extension{{
						Id:    oidSandboxID,
						Value: value,
					}},
				}},
			},
		},
	}
	w.issuance.relying.dir = t.TempDir()
	ctx := context.WithValue(t.Context(), worldKey{}, w)
	if err := selfSignedRequester(ctx, "workload"); err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(w.secrets.self.certFile)
	if err != nil {
		t.Fatal(err)
	}
	requester, err := parseLeaf(pem)
	if err != nil || requester == nil {
		t.Fatalf("parse requester = %v, %v", requester, err)
	}
	der, ok := requester.extension(oidSandboxID)
	if !ok || len(der) == 0 || der[0] != asn1.TagUTF8String {
		t.Fatalf("sandbox ID DER = %x, want UTF8String", der)
	}
	if got, err := requester.sandboxID(); err != nil || got != sandboxID {
		t.Fatalf("sandbox ID = %q, %v", got, err)
	}
	_, err = requester.cert.Verify(x509.VerifyOptions{Roots: x509.NewCertPool()})
	var untrusted x509.UnknownAuthorityError
	if !errors.As(err, &untrusted) {
		t.Fatalf("self-signed requester verification = %v, want unknown authority", err)
	}
}
