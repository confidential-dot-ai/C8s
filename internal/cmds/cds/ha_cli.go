package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// newHACmd groups the operator side of the HA prototype (spec §14).
func newHACmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ha", Short: "PROTOTYPE: operate a highly available CDS"}
	cmd.AddCommand(newHADecreeCmd(), newHAStatusCmd())
	return cmd
}

func newHADecreeCmd() *cobra.Command {
	var (
		d         cdsha.Decree
		kind      string
		keyPath   string
		namespace string
		expiresIn time.Duration
		ackFork   bool
	)
	cmd := &cobra.Command{
		Use:   "decree",
		Short: "Sign a decree and print it as a CDSDecree object for kubectl apply",
		Long: "Signs a Genesis, UpdateMeasurements or RotateKey decree with the operator key and prints the\n" +
			"CDSDecree object (a ConfigMap in this prototype) as JSON. Apply it with kubectl; the\n" +
			"writer replica validates and applies it. Re-sign with the current epoch if it is\n" +
			"rejected for a base_epoch conflict (D3).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			d.Kind = cdsha.DecreeKind(kind)
			if d.Kind == cdsha.RotateKey {
				if !ackFork {
					return errors.New("RotateKey forks the mesh: every workload must be re-issued under the new key. Pass --i-understand-rotation-forks-the-cluster to continue (C4, D11)")
				}
				if len(d.Measurements) == 0 {
					fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: RotateKey without --measurements delivers the new key to the current pin set (D14). Prefer UpdateMeasurements first (D13).")
				}
			}
			key, err := loadECPrivateKey(keyPath)
			if err != nil {
				return err
			}
			if d.IntentID == "" {
				d.IntentID = randomID()
			}
			d.ExpiresAt = time.Now().Add(expiresIn).UTC().Truncate(time.Second)
			sd, err := cdsha.SignDecree(d, key)
			if err != nil {
				return err
			}
			cm, err := cdsha.DecreeConfigMap(namespace, sd)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(cm)
		},
	}
	f := cmd.Flags()
	f.StringVar(&d.ClusterID, "cluster-id", "", "cluster the decree is for")
	f.Uint64Var(&d.BaseEpoch, "base-epoch", 0, "the epoch you observed (c8s cds ha status)")
	f.StringVar(&kind, "kind", string(cdsha.UpdateMeasurements), "Genesis (mint the first key), UpdateMeasurements or RotateKey")
	f.StringSliceVar(&d.Measurements, "measurements", nil, "complete new replica pin set (D6); optional for RotateKey (D14)")
	f.StringVar(&d.IntentID, "intent-id", "", "decree nonce (default random)")
	f.StringVar(&keyPath, "operator-key", "", "PEM EC private key matching the cluster's --ha-operator-key")
	f.StringVar(&namespace, "namespace", "c8s-cds-decrees", "namespace the decree object is written to (the replicas' --ha-decree-namespace)")
	f.DurationVar(&expiresIn, "expires-in", time.Hour, "decree lifetime")
	f.BoolVar(&ackFork, "i-understand-rotation-forks-the-cluster", false, "required for RotateKey")
	_ = cmd.MarkFlagRequired("cluster-id")
	_ = cmd.MarkFlagRequired("operator-key")
	return cmd
}

func newHAStatusCmd() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "status URL...",
		Short: "Report each replica's (epoch, term, key_fingerprint) from GET /ha/status (C2)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, urls []string) error {
			client := &http.Client{Timeout: timeout}
			var seen []cdsha.Heartbeat
			for _, u := range urls {
				hb, err := fetchHAStatus(cmd.Context(), client, u)
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "%-40s ERROR %v\n", u, err)
					continue
				}
				seen = append(seen, hb)
				fmt.Fprintf(cmd.OutOrStdout(), "%-40s epoch=%d term=%d serving=%t key=%.16s\n", u, hb.Epoch, hb.Term, hb.Serving, hb.KeyFingerprint)
			}
			return reportDivergence(seen, len(urls))
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-replica timeout")
	return cmd
}

func reportDivergence(seen []cdsha.Heartbeat, want int) error {
	if len(seen) != want {
		return fmt.Errorf("%d of %d replicas unreachable", want-len(seen), want)
	}
	for _, hb := range seen {
		if hb.Epoch != seen[0].Epoch || hb.KeyFingerprint != seen[0].KeyFingerprint || !hb.Serving {
			return errors.New("replicas disagree or are not serving")
		}
	}
	return nil
}

func fetchHAStatus(ctx context.Context, c *http.Client, url string) (cdsha.Heartbeat, error) {
	var hb cdsha.Heartbeat
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/ha/status", nil)
	if err != nil {
		return hb, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return hb, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return hb, errors.New(resp.Status)
	}
	return hb, json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&hb)
}

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("operator key: no PEM block")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("operator key: %w", err)
	}
	k, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("operator key is not ECDSA")
	}
	return k, nil
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
