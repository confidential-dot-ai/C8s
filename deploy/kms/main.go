// Command kms is a reference key management service for C8s pod secret
// release (docs/pod-secrets.md). It is an example of the KMS side of the
// CDS broker wire, not a production service: it checks a CDS broker
// statement, the client document's signature in the reference document
// format, and a policy file, then returns the secret from Azure Key Vault.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "client-key":
		err = clientKey(os.Args[2:])
	case "client-document":
		err = clientDocument(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kms:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  kms serve -config kms.json
  kms client-key -out client.key            # new Ed25519 client key; prints its public key
  kms client-document -key client.key       # prints a reference client document with a fresh agent ID`)
	os.Exit(2)
}

// config is the KMS's own settings file.
type config struct {
	Listen          string `json:"listen"`
	TLSCert         string `json:"tls_cert"`
	TLSKey          string `json:"tls_key"`
	MeshCAKeySHA256 string `json:"mesh_ca_key_sha256"`
	KeyVaultURL     string `json:"key_vault_url"`
	PolicyFile      string `json:"policy_file"`
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "kms.json", "KMS settings file")
	_ = fs.Parse(args)
	var cfg config
	if err := readJSON(*path, &cfg); err != nil {
		return err
	}
	var pol policy
	if err := readJSON(cfg.PolicyFile, &pol); err != nil {
		return err
	}
	verifier, err := newVerifier(cfg.MeshCAKeySHA256)
	if err != nil {
		return err
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return err
	}
	vault, err := azsecrets.NewClient(cfg.KeyVaultURL, cred, nil)
	if err != nil {
		return err
	}
	h := &handler{verifier: verifier, policy: pol, secrets: keyVault{vault}, nonces: newNonceCache()}
	srv := &http.Server{Addr: cfg.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	slog.Info("reference KMS listening", "addr", cfg.Listen, "key_vault", cfg.KeyVaultURL)
	return srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
}

// keyVault reads a secret's current version from Azure Key Vault.
type keyVault struct{ client *azsecrets.Client }

func (k keyVault) Get(ctx context.Context, name string) ([]byte, error) {
	resp, err := k.client.GetSecret(ctx, name, "", nil)
	if err != nil {
		return nil, err
	}
	if resp.Value == nil {
		return nil, errors.New("secret has no value")
	}
	return []byte(*resp.Value), nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func clientKey(args []string) error {
	fs := flag.NewFlagSet("client-key", flag.ExitOnError)
	out := fs.String("out", "client.key", "file to write the Ed25519 seed to")
	_ = fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	return nil
}

func clientDocument(args []string) error {
	fs := flag.NewFlagSet("client-document", flag.ExitOnError)
	keyPath := fs.String("key", "client.key", "Ed25519 seed written by client-key")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(string(trimNewline(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("client key is not a base64 Ed25519 seed")
	}
	doc, err := newClientDocument(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return err
	}
	fmt.Println(string(doc))
	return nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
