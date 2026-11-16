package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// newKeygenCmd returns the `c8s keys new` subcommand.
func newKeygenCmd() *cobra.Command {
	var out, pubOut string
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Generate an operator EC keypair (P-256)",
		Long: `Generate an operator keypair: the private key that signs allowlist,
secret, and volume writes, and the public key CDS pins in its configuration
(c8s cds config new --operator-keys).

Both files are created new — an existing file is never overwritten. The
private key is written 0600.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				return fmt.Errorf("--out is required: where to write the private key PEM")
			}
			if pubOut == "" {
				return fmt.Errorf("--pub-out is required: where to write the public key PEM")
			}
			if out == pubOut {
				return fmt.Errorf("--out and --pub-out must differ: one file cannot hold both halves")
			}
			return run(cmd, out, pubOut)
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "private key output path (written 0600, never overwritten)")
	cmd.Flags().StringVar(&pubOut, "pub-out", "", "public key output path (never overwritten)")
	return cmd
}

func run(cmd *cobra.Command, out, pubOut string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// The private half is written first and O_EXCL: a keypair whose private
	// half silently replaced an older one would strand whatever the older
	// public half was pinned on.
	if err := writeNew(out, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeNew(pubOut, pubPEM, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (private, 0600) and %s (public)\n", out, pubOut)
	return nil
}

// writeNew writes p to path, O_EXCL with the given mode.
func writeNew(path string, p []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(p); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
