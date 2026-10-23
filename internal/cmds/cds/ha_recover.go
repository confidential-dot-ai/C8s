package cds

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// newHARecoverCmd restores a cluster that lost every replica from a sealed
// backup: decrypt it with the offline recovery key, check it is not older
// than the operator's own record, sign a Restore decree naming it, and hand
// both to the named fresh replica over the attested channel.
func newHARecoverCmd() *cobra.Command {
	var (
		conn               cdsconn.Options
		backupFile         string
		recoveryKey        string
		recoveryShares     []string
		decreeKey          string
		clusterID          string
		node               string
		minEpoch, minIndex uint64
		expiresIn          time.Duration
		attempts           int
	)
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Restore a CDS cluster that lost every replica from its sealed backup",
		Long: "Reads the backup objects (kubectl get configmaps -n <decree namespace> -l " + cdsha.LabelBackup + "=<cluster> -o json),\n" +
			"opens them with the offline recovery key, and refuses a backup older than --min-epoch/--min-index\n" +
			"(compare with your own record: an older backup rolls back decrees, policy and secrets).\n" +
			"Then signs a Restore decree with the decree key and sends it with the snapshot over armTLS to the\n" +
			"fresh replica on --bootstrap-node, which starts the cluster from it; the other replicas join.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("min-epoch") || !cmd.Flags().Changed("min-index") {
				return errors.New("--min-epoch and --min-index are required: the oldest state you accept, from your own record of the cluster")
			}
			raw, err := os.ReadFile(backupFile)
			if err != nil {
				return err
			}
			var list corev1.ConfigMapList
			if err := json.Unmarshal(raw, &list); err != nil {
				return fmt.Errorf("--backup-file: %w", err)
			}
			b, err := cdsha.BackupFromConfigMaps(clusterID, list.Items)
			if err != nil {
				return err
			}
			m := b.Meta
			fmt.Fprintf(cmd.OutOrStdout(), "backup: cluster=%s epoch=%d index=%d taken=%s ca=%.16s decrees=%s\n", m.ClusterID, m.Epoch, m.Index,
				time.UnixMilli(m.TakenAtMS).UTC().Format(time.RFC3339), m.CAFingerprint, strings.Join(m.AppliedDecrees, ","))
			if m.Epoch < minEpoch || (m.Epoch == minEpoch && m.Index < minIndex) {
				return fmt.Errorf("backup (epoch %d, index %d) is older than --min-epoch %d --min-index %d: refusing to roll the cluster back", m.Epoch, m.Index, minEpoch, minIndex)
			}
			rk, err := loadRecoveryKey(recoveryKey, recoveryShares)
			if err != nil {
				return fmt.Errorf("recovery key: %w", err)
			}
			snap, err := cdsha.OpenBackup(rk, b)
			if err != nil {
				return err
			}
			dk, err := certutil.LoadECPrivateKeyFile(decreeKey)
			if err != nil {
				return fmt.Errorf("--decree-key: %w", err)
			}
			sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "restore-" + rand.Text(), Kind: cdsha.Restore,
				BootstrapNode: node, SnapshotSHA256: cdsha.SnapshotSHA256(snap), ExpiresAt: time.Now().Add(expiresIn).UTC().Truncate(time.Second)}, dk)
			if err != nil {
				return err
			}
			body, err := json.Marshal(RestoreRequest{Decree: sd, Snapshot: snap})
			if err != nil {
				return err
			}
			url := strings.TrimRight(conn.URL, "/") + "/ha/restore"
			for i := 0; i < attempts; i++ {
				// A fresh attested connection each time: behind a Service the
				// request lands on any replica, and only the named one restores.
				hc, err := conn.HTTPClient(cmd.Context())
				if err != nil {
					return err
				}
				code, msg, err := postRestore(hc, url, body)
				switch {
				case err != nil:
					fmt.Fprintf(cmd.ErrOrStderr(), "attempt %d: %v\n", i+1, err)
				case code == http.StatusOK:
					fmt.Fprintf(cmd.OutOrStdout(), "restored on %s: %s", node, msg)
					return nil
				case code == http.StatusMisdirectedRequest:
				default:
					// An earlier attempt may have restored the cluster after
					// its request timed out: a serving replica no longer takes
					// /ha/restore. The decree record says whether ours applied.
					if restoreApplied(cmd.Context(), hc, conn.URL, sd.Decree.IntentID) {
						fmt.Fprintf(cmd.OutOrStdout(), "restored on %s (the decree record holds %s)\n", node, sd.Decree.IntentID)
						return nil
					}
					if code == http.StatusNotFound {
						return errors.New("restore refused: the replica is serving; a Restore only goes to a fresh replica after a total loss (c8s cds ha status shows the cluster)")
					}
					return fmt.Errorf("restore refused (%d): %s", code, strings.TrimSpace(msg))
				}
				time.Sleep(time.Second)
			}
			return fmt.Errorf("no answer from the replica on %s after %d attempts", node, attempts)
		},
	}
	cdsconn.BindFlags(cmd.Flags(), &conn)
	f := cmd.Flags()
	f.StringVar(&backupFile, "backup-file", "", "JSON list of the backup ConfigMaps (kubectl get configmaps -l "+cdsha.LabelBackup+"=<cluster> -o json)")
	f.StringVar(&recoveryKey, "recovery-key", "", "PEM EC private key the backups are sealed to (bundle recovery.key)")
	f.StringArrayVar(&recoveryShares, "recovery-key-share", nil, "a custodian's share of the recovery key (c8s cds ha recovery-key split); repeat for at least the threshold. Excludes --recovery-key")
	f.StringVar(&decreeKey, "decree-key", "", "PEM EC private key that signs decrees (bundle decree.key)")
	f.StringVar(&clusterID, "cluster-id", "", "cluster to restore")
	f.StringVar(&node, "bootstrap-node", "", "node whose fresh replica starts the restored cluster")
	f.Uint64Var(&minEpoch, "min-epoch", 0, "refuse a backup below this epoch (required)")
	f.Uint64Var(&minIndex, "min-index", 0, "with --min-epoch: refuse a backup below this index in that epoch (required)")
	f.DurationVar(&expiresIn, "expires-in", 10*time.Minute, "Restore decree lifetime")
	f.IntVar(&attempts, "attempts", 30, "requests before giving up, each to whichever replica the address reaches")
	for _, r := range []string{"backup-file", "decree-key", "cluster-id", "bootstrap-node", "url"} {
		_ = cmd.MarkFlagRequired(r)
	}
	// The whole key, or custodians' shares of it: exactly one.
	cmd.MarkFlagsOneRequired("recovery-key", "recovery-key-share")
	cmd.MarkFlagsMutuallyExclusive("recovery-key", "recovery-key-share")
	return cmd
}

// restoreApplied reports whether the cluster's decree record holds the
// Restore decree with this intent.
func restoreApplied(ctx context.Context, hc *http.Client, base, intent string) bool {
	records, err := fetchDecreeRecord(ctx, hc, base)
	if err != nil {
		return false
	}
	for _, r := range records {
		if r.Decree.Decree.Kind == cdsha.Restore && r.Decree.Decree.IntentID == intent {
			return true
		}
	}
	return false
}

func postRestore(hc *http.Client, url string, body []byte) (int, string, error) {
	var envelope struct {
		Decree cdsha.SignedDecree `json:"decree"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return 0, "", err
	}
	decree, err := json.Marshal(envelope.Decree)
	if err != nil {
		return 0, "", err
	}
	if len(decree) > maxRestoreDecreeBytes {
		return 0, "", errors.New("restore decree exceeds header limit")
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(restoreDecreeHeader, string(decree))
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(msg), nil
}
