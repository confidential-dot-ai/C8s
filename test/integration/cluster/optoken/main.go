// optoken mints the operator Authorization header for a CDS write, using the
// production signer (pkg/operatorauth). The cluster harness needs it because
// the `c8s allowlist` CLI verifies CDS's armTLS evidence in-process, which
// the mock attestation-api's synthetic evidence cannot pass; CDS's own
// server-side token verification is unaffected and fully exercised.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func main() {
	hdr, err := run(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(hdr)
}

// run is main, extracted for the test: args includes argv[0]. The optional
// validity (a Go duration) replaces the signer's default token lifetime, so a
// harness can mint a token the CDS must refuse as too long-lived.
func run(args []string) (string, error) {
	if len(args) != 5 && len(args) != 6 {
		return "", fmt.Errorf("usage: optoken <key.pem> <method> <path> <body-file> [validity]")
	}
	keyPEM, err := os.ReadFile(args[1])
	if err != nil {
		return "", err
	}
	body, err := os.ReadFile(args[4])
	if err != nil {
		return "", err
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		return "", err
	}
	if len(args) == 6 {
		ttl, err := time.ParseDuration(args[5])
		if err != nil {
			return "", fmt.Errorf("validity %q: %w", args[5], err)
		}
		signer = signer.WithTTL(ttl)
	}
	return signer.Authorization(args[2], args[3], body)
}
