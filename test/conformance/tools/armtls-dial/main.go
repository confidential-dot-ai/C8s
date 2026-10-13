// armtls-dial is a mesh peer the conformance steps drive: it dials a c8s
// armTLS mesh inbound proxy over TLS 1.3 presenting a chosen client
// certificate, names a destination pod, sends one HTTP GET and prints a JSON
// report of what came back. It exercises the proxy's verification of its
// peer, so it never verifies the server's certificate. See README.md.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	exitUsage = 2
	usageText = `usage: armtls-dial [flags] <node-ip:port> <dest-ip:port>
       armtls-dial --self-signed [flags] --write-cert FILE --write-key FILE

Dials the armTLS mesh inbound proxy at <node-ip:port>, presents a client
certificate, names <dest-ip:port> as the destination pod, sends GET / and
prints one JSON report on stdout. Exactly one of --cert/--key or
--self-signed is required. With --write-cert/--write-key the minted
certificate and key are written as PEM instead, for a later dial with
--cert/--key, and nothing is dialed.

Flags:
`
)

// selfSignedOnly are the flags that shape a minted certificate; with --cert
// they would silently do nothing, so they are refused.
var selfSignedOnly = []string{"attestation-url", "platform", "not-before", "not-after", "issuer-differs", "write-cert", "write-key"}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses args, builds the certificate, then dials and writes the report,
// or writes the certificate. It returns 0 whenever a report or the files were
// produced, exitUsage otherwise.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("armtls-dial", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
	}
	var (
		certFile       = fs.String("cert", "", "PEM certificate chain to present (a CDS-issued leaf written by get-cert)")
		keyFile        = fs.String("key", "", "PEM private key of --cert")
		selfSigned     = fs.Bool("self-signed", false, "mint a P-256 key and a self-signed attested TLS certificate")
		attestationURL = fs.String("attestation-url", "", "attestation API --self-signed gets evidence from: http(s)://host:port or unix:///path/to.sock")
		platform       = fs.String("platform", "", "evidence family for --self-signed: sev-snp or tdx")
		notBefore      = fs.Duration("not-before", 0, "NotBefore = now + DUR for --self-signed (negative allowed)")
		notAfter       = fs.Duration("not-after", 24*time.Hour, "NotAfter = now + DUR for --self-signed")
		issuerDiffers  = fs.Bool("issuer-differs", false, "issuer differs from subject and the certificate is signed by an unrelated key")
		rewriteAfter   = fs.Duration("rewrite-not-after", 0, "after signing, rewrite NotAfter to now + DUR without re-signing")
		writeCert      = fs.String("write-cert", "", "write the minted certificate here as PEM and exit without dialing (with --write-key)")
		writeKey       = fs.String("write-key", "", "write the minted key here as PEM (with --write-cert)")
		timeout        = fs.Duration("timeout", 10*time.Second, "dial, handshake and read timeout")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	usage := func(msg string) int {
		fmt.Fprintf(stderr, "armtls-dial: %s\n", msg)
		fs.Usage()
		return exitUsage
	}
	writing := *writeCert != "" || *writeKey != ""
	if writing && (*writeCert == "" || *writeKey == "") {
		return usage("--write-cert and --write-key go together")
	}
	if writing && fs.NArg() != 0 {
		return usage("--write-cert dials nothing: no <node-ip:port> <dest-ip:port>")
	}
	if !writing && fs.NArg() != 2 {
		return usage("expected <node-ip:port> <dest-ip:port>")
	}
	if *timeout <= 0 {
		return usage("--timeout must be positive")
	}

	fromFile := *certFile != "" || *keyFile != ""
	switch {
	case fromFile && *selfSigned:
		return usage("--cert/--key and --self-signed are mutually exclusive")
	case !fromFile && !*selfSigned:
		return usage("one of --cert/--key or --self-signed is required")
	case fromFile && (*certFile == "" || *keyFile == ""):
		return usage("--cert and --key go together")
	}
	if fromFile {
		for _, name := range selfSignedOnly {
			if set[name] {
				return usage("--" + name + " applies to --self-signed only")
			}
		}
	} else if *attestationURL == "" || *platform == "" {
		return usage("--self-signed needs --attestation-url and --platform")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var cert tls.Certificate
	var err error
	if fromFile {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	} else {
		cert, err = selfSignedCert(ctx, certOptions{
			attestationURL: *attestationURL,
			platform:       *platform,
			notBefore:      *notBefore,
			notAfter:       *notAfter,
			issuerDiffers:  *issuerDiffers,
			timeout:        *timeout,
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "armtls-dial: build certificate: %v\n", err)
		return exitUsage
	}
	if set["rewrite-not-after"] {
		if err := rewriteLeafNotAfter(&cert, time.Now().Add(*rewriteAfter)); err != nil {
			fmt.Fprintf(stderr, "armtls-dial: rewrite NotAfter: %v\n", err)
			return exitUsage
		}
	}
	if writing {
		if err := writePEM(cert, *writeCert, *writeKey); err != nil {
			fmt.Fprintf(stderr, "armtls-dial: write certificate: %v\n", err)
			return exitUsage
		}
		return 0
	}

	r := dial(ctx, fs.Arg(0), fs.Arg(1), cert, *timeout)
	out, err := json.Marshal(r)
	if err != nil {
		fmt.Fprintf(stderr, "armtls-dial: encode report: %v\n", err)
		return exitUsage
	}
	fmt.Fprintln(stdout, string(out))
	return 0
}

// writePEM writes the chain and key as PEM, in the shape tls.LoadX509KeyPair
// reads back.
func writePEM(cert tls.Certificate, certFile, keyFile string) error {
	var chain []byte
	for _, der := range cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, chain, 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
}

// rewriteLeafNotAfter applies rewriteNotAfter to the chain's leaf and
// re-parses it, so the TLS stack presents the altered bytes unchanged.
func rewriteLeafNotAfter(cert *tls.Certificate, notAfter time.Time) error {
	if len(cert.Certificate) == 0 {
		return errors.New("no leaf certificate")
	}
	der, err := rewriteNotAfter(cert.Certificate[0], notAfter)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse rewritten leaf: %w", err)
	}
	cert.Certificate[0] = der
	cert.Leaf = leaf
	return nil
}

// joinErrors renders what the dial saw into one message, in the order it
// happened; nil entries are skipped.
func joinErrors(errs ...error) string {
	var parts []string
	for _, err := range errs {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	return strings.Join(parts, "; ")
}
