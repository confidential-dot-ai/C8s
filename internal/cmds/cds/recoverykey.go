package cds

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/shamir"
)

// RecoveryKeyShare is one custodian's share of the CDS recovery key: the key
// the replicas seal their backups to. With k of n shares the operator can
// restore a cluster that lost every replica; fewer reveal nothing about the
// key. PublicKeySHA256 names the key, so shares of different keys, or a
// wrong reconstruction, are caught.
type RecoveryKeyShare struct {
	Kind            string `json:"kind"`
	Version         int    `json:"version"`
	X               byte   `json:"x"`
	Threshold       int    `json:"threshold"`
	Shares          int    `json:"shares"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	Y               []byte `json:"y"`
}

const recoveryShareKind = "c8s-recovery-key-share"

func publicKeySHA256(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// SplitRecoveryKey splits key into n shares, any k of which rebuild it.
func SplitRecoveryKey(key *ecdsa.PrivateKey, n, k int) ([]RecoveryKeyShare, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	fp, err := publicKeySHA256(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	parts, err := shamir.Split(der, n, k)
	if err != nil {
		return nil, err
	}
	out := make([]RecoveryKeyShare, len(parts))
	for i, p := range parts {
		out[i] = RecoveryKeyShare{Kind: recoveryShareKind, Version: 1, X: p.X, Threshold: k, Shares: n, PublicKeySHA256: fp, Y: p.Y}
	}
	return out, nil
}

// CombineRecoveryKey rebuilds the recovery key from shares; it needs at
// least the threshold of distinct shares of one key.
func CombineRecoveryKey(shares []RecoveryKeyShare) (*ecdsa.PrivateKey, error) {
	if len(shares) == 0 {
		return nil, errors.New("no recovery key shares")
	}
	first := shares[0]
	parts := make([]shamir.Share, 0, len(shares))
	for _, s := range shares {
		switch {
		case s.Kind != recoveryShareKind || s.Version != 1:
			return nil, errors.New("not a c8s recovery key share")
		case s.PublicKeySHA256 != first.PublicKeySHA256 || s.Threshold != first.Threshold:
			return nil, errors.New("shares of different recovery keys")
		}
		parts = append(parts, shamir.Share{X: s.X, Y: s.Y})
	}
	if len(parts) < first.Threshold {
		return nil, fmt.Errorf("%d recovery key shares, the key needs %d", len(parts), first.Threshold)
	}
	der, err := shamir.Combine(parts)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	anyKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("the shares do not rebuild a key (a share is damaged)")
	}
	key, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the shares do not rebuild an EC key")
	}
	if fp, err := publicKeySHA256(&key.PublicKey); err != nil || fp != first.PublicKeySHA256 {
		return nil, errors.New("the shares rebuild a different key (a share is damaged)")
	}
	return key, nil
}

func loadRecoveryShares(paths []string) ([]RecoveryKeyShare, error) {
	out := make([]RecoveryKeyShare, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var s RecoveryKeyShare
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// loadRecoveryKey reads the recovery key from its file, or rebuilds it from
// custodians' shares; exactly one of the two.
func loadRecoveryKey(path string, sharePaths []string) (*ecdsa.PrivateKey, error) {
	switch {
	case path != "" && len(sharePaths) > 0:
		return nil, errors.New("--recovery-key and --recovery-key-share exclude each other")
	case path != "":
		return loadECPrivateKey(path)
	case len(sharePaths) > 0:
		shares, err := loadRecoveryShares(sharePaths)
		if err != nil {
			return nil, err
		}
		return CombineRecoveryKey(shares)
	}
	return nil, errors.New("--recovery-key or --recovery-key-share is required")
}

// newHARecoveryKeyCmd splits the recovery key among custodians.
func newHARecoveryKeyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "recovery-key", Short: "Split the backup recovery key among custodians (k of n)"}
	var (
		keyPath, outDir string
		n, k            int
	)
	split := &cobra.Command{
		Use:   "split",
		Short: "Split the recovery key into n shares, any k of which restore",
		Long: "Writes share-<x>.json files, one per custodian. c8s cds ha recover --recovery-key-share takes\n" +
			"any k of them. Hand each share to a different person, then destroy the key file: with it, one\n" +
			"person can restore every secret onto a CDS of their choosing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := loadECPrivateKey(keyPath)
			if err != nil {
				return err
			}
			shares, err := SplitRecoveryKey(key, n, k)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				return err
			}
			for _, s := range shares {
				raw, err := json.MarshalIndent(s, "", "  ")
				if err != nil {
					return err
				}
				path := filepath.Join(outDir, fmt.Sprintf("share-%d.json", s.X))
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					return err
				}
				_, werr := f.Write(append(raw, '\n'))
				if cerr := f.Close(); werr != nil || cerr != nil {
					return errors.Join(werr, cerr)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %d shares (any %d restore) to %s\n", n, k, outDir)
			fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s still holds the whole key. Hand out the shares, then destroy it.\n", keyPath)
			return nil
		},
	}
	f := split.Flags()
	f.StringVar(&keyPath, "recovery-key", "", "PEM EC private key to split (bundle recovery.key)")
	f.StringVar(&outDir, "out", "", "directory to write the shares to (created; existing shares are not overwritten)")
	f.IntVar(&n, "shares", 5, "number of shares")
	f.IntVar(&k, "threshold", 3, "shares needed to restore")
	_ = split.MarkFlagRequired("recovery-key")
	_ = split.MarkFlagRequired("out")
	cmd.AddCommand(split)
	return cmd
}
