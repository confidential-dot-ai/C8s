package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
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
		trustedCA          string
		recoveryKey        string
		recoveryShares     []string
		decreeKey          string
		clusterID          string
		node               string
		minEpoch, minIndex uint64
		resumeEpoch        uint64
		expiresIn          time.Duration
		attempts           int
		alone              bool
	)
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Restore a CDS cluster that lost every replica from its sealed backup",
		Long: "Reads the backup objects (kubectl get configmaps -n <decree namespace> -l " + cdsha.LabelBackup + "=<cluster> -o json),\n" +
			"opens them with the offline recovery key, and refuses a backup older than --min-epoch/--min-index\n" +
			"(compare with your own record: an older backup rolls back decrees, policy and secrets).\n" +
			"Then reads the member ID of the fresh replica on --bootstrap-node from its /ha/status over armTLS,\n" +
			"signs a Restore decree for that one process (target_member) with the decree key, and sends it with the\n" +
			"snapshot on the same attested connection; the replica starts the cluster from it and the others join.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkPinnedReplica(conn, "", "recover sends the decrypted cluster state"); err != nil {
				return err
			}
			if !cmd.Flags().Changed("min-epoch") || !cmd.Flags().Changed("min-index") {
				return errors.New("--min-epoch and --min-index are required: the oldest state you accept, from your own record of the cluster")
			}
			if resumeEpoch == 0 {
				return errors.New("--resume-epoch is required: the highest epoch you know the cluster reached (c8s cds ha decrees, or the base_epoch c8s cds ha pin-policy shows); the restored cluster resumes after it, so nodes take its next pin decree")
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
			fmt.Fprintf(cmd.OutOrStdout(), "backup: cluster=%s epoch=%d index=%d taken=%s ca=%.16s decrees=%s state=%.16s\n", m.ClusterID, m.Epoch, m.Index,
				time.UnixMilli(m.TakenAtMS).UTC().Format(time.RFC3339), m.CAFingerprint, strings.Join(m.AppliedDecrees, ","), m.StateDigest)
			if m.Epoch < minEpoch || (m.Epoch == minEpoch && m.Index < minIndex) {
				return fmt.Errorf("backup (epoch %d, index %d) is older than --min-epoch %d --min-index %d: refusing to roll the cluster back", m.Epoch, m.Index, minEpoch, minIndex)
			}
			if resumeEpoch < m.Epoch {
				return fmt.Errorf("--resume-epoch %d is below the backup's epoch %d: name the highest epoch the cluster reached", resumeEpoch, m.Epoch)
			}
			if err := cdsha.VerifyBackupSource(b, trustedCA); err != nil {
				return err
			}
			rk, err := loadRecoveryKey(recoveryKey, recoveryShares)
			if err != nil {
				return fmt.Errorf("recovery key: %w", err)
			}
			snap, err := cdsha.OpenBackup(rk, b)
			if err != nil {
				return err
			}
			if err := cdsha.ValidateRecoverySnapshot(snap, m, minEpoch, minIndex); err != nil {
				return err
			}
			dk, err := certutil.LoadECPrivateKeyFile(decreeKey)
			if err != nil {
				return fmt.Errorf("--decree-key: %w", err)
			}
			intent := "restore-" + cdsha.NewIntentID()
			expires := time.Now().Add(expiresIn).UTC().Truncate(time.Second)
			sign := func(member string) ([]byte, error) {
				sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: clusterID, IntentID: intent, Kind: cdsha.Restore, BootstrapNode: node,
					IssuedAtMS: time.Now().UnixMilli(), TargetMember: member, ResumeEpoch: resumeEpoch, SnapshotSHA256: cdsha.SnapshotSHA256(snap), ExpiresAt: expires, Alone: alone}, dk)
				if err != nil {
					return nil, err
				}
				return json.Marshal(RestoreRequest{Decree: sd, Snapshot: snap})
			}
			return deliverRestore(cmd.Context(), conn, cmd.OutOrStdout(), cmd.ErrOrStderr(), restoreTarget{clusterID: clusterID, node: node, intent: intent, attempts: attempts}, sign)
		},
	}
	cdsconn.BindFlags(cmd.Flags(), &conn)
	f := cmd.Flags()
	f.StringVar(&trustedCA, "trusted-ca-sha256", "", "CA certificate SHA-256 retained independently from the attested live cluster; NEVER copy from the backup")
	f.StringVar(&backupFile, "backup-file", "", "JSON list of the backup ConfigMaps (kubectl get configmaps -l "+cdsha.LabelBackup+"=<cluster> -o json)")
	f.StringVar(&recoveryKey, "recovery-key", "", "PEM EC private key the backups are sealed to (bundle recovery.key)")
	f.StringArrayVar(&recoveryShares, "recovery-key-share", nil, "a custodian's share of the recovery key (c8s cds ha recovery-key split); repeat for at least the threshold. Excludes --recovery-key")
	f.StringVar(&decreeKey, "decree-key", "", "PEM EC private key that signs decrees (bundle decree.key)")
	f.StringVar(&clusterID, "cluster-id", "", "cluster to restore")
	f.StringVar(&node, "bootstrap-node", "", "node whose fresh replica starts the restored cluster")
	f.Uint64Var(&minEpoch, "min-epoch", 0, "refuse a backup below this epoch (required)")
	f.Uint64Var(&minIndex, "min-index", 0, "with --min-epoch: refuse a backup below this index in that epoch (required)")
	f.Uint64Var(&resumeEpoch, "resume-epoch", 0, "the highest epoch you know the cluster reached, at least the backup's (required); the restored cluster resumes at the epoch after it")
	f.DurationVar(&expiresIn, "expires-in", 10*time.Minute, "Restore decree lifetime")
	f.IntVar(&attempts, "attempts", 30, "requests before giving up, each to whichever replica the address reaches")
	f.BoolVar(&alone, "alone", false, "restore even if the replica discovers no other replica; only when you have confirmed outside the host that no other replica of the cluster exists")
	for _, r := range []string{"trusted-ca-sha256", "backup-file", "decree-key", "cluster-id", "bootstrap-node", "url"} {
		_ = cmd.MarkFlagRequired(r)
	}
	// The whole key, or custodians' shares of it: exactly one.
	cmd.MarkFlagsOneRequired("recovery-key", "recovery-key-share")
	cmd.MarkFlagsMutuallyExclusive("recovery-key", "recovery-key-share")
	return cmd
}

// checkPinnedReplica refuses a replica endpoint that is not armTLS to a
// replica whose whole image identity an image policy pins, outside c8s_dev
// builds: the launch digest alone (TDX: the firmware) admits any guest on
// that firmware. prefix is the flags' prefix ("" or "target-"), why what the
// endpoint is trusted with.
func checkPinnedReplica(conn cdsconn.Options, prefix, why string) error {
	u, err := url.Parse(conn.URL)
	if err != nil {
		return fmt.Errorf("invalid --%surl %q", prefix, conn.URL)
	}
	if u.Scheme != "https" {
		if allowPlainHTTP {
			return nil // c8s_dev: the integration harness serves plain HTTP
		}
		return fmt.Errorf("%s: use an https --%surl pinned with --%simage-policy-file", why, prefix, prefix)
	}
	if conn.MeasurementsConfig == "" {
		return fmt.Errorf("%s: pin the replica's whole image with --%simage-policy-file; --%smeasurements pins only its launch digest", why, prefix, prefix)
	}
	pins, err := cmdsutil.ImagePolicySource{File: conn.MeasurementsConfig}.LoadValues(cmdsutil.MeasurementPins{Measurements: conn.Measurements, MeasurementsFile: conn.MeasurementsFile})
	if err != nil {
		return err
	}
	if len(pins.Images) == 0 {
		return fmt.Errorf("--%simage-policy-file pins no image", prefix)
	}
	for _, img := range pins.Images {
		switch {
		case len(img.Anchor) == 0:
			return fmt.Errorf("--%simage-policy-file: image %q has no launch-key anchor", prefix, img.Name)
		case pins.Family == teetypes.FamilyTDX && (len(img.Registers[1]) == 0 || len(img.Registers[2]) == 0):
			return fmt.Errorf("--%simage-policy-file: TDX image %q does not pin RTMR1 and RTMR2", prefix, img.Name)
		}
	}
	return nil
}

// restoreTimeout bounds one restore end to end: the replica's write deadline
// for POST /ha/restore (handleRestore), how long recover waits for that
// answer, and how long it keeps reading the outcome after a request that may
// have started a restore. Node.Restore checks the backup twice (preflight and
// apply), probes each peer and waits for leadership, which can take well over
// the other requests' timeouts.
const restoreTimeout = 5 * time.Minute

// restoreTarget is the replica a recover restores and the decree it signs.
type restoreTarget struct {
	clusterID, node, intent string
	attempts                int
}

// deliverRestore hands the Restore to the fresh replica on t.node. sign
// returns the request body for the member ID the replica reports.
//
// INVARIANT: success means the POST answered 200 or the replica's decree
// record holds t.intent. After a request that may have started the restore
// (no answer, 429, or the replica joined since), recover reads the status and
// the decree record until one says how it ended, for up to restoreTimeout,
// instead of reporting a refusal for a restore that is still running.
func deliverRestore(ctx context.Context, conn cdsconn.Options, out, errOut io.Writer, t restoreTarget, sign func(member string) ([]byte, error)) error {
	url := strings.TrimRight(conn.URL, "/") + "/ha/restore"
	var waitUntil time.Time // set once a request may have started a restore
	for i := 0; i < t.attempts || time.Now().Before(waitUntil); i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		// A fresh attested connection each time: behind a Service the
		// request lands on any replica, and only the named one restores.
		hc, err := conn.HTTPClient(ctx)
		if err != nil {
			return err
		}
		// The decree names the process this connection reaches: every
		// request of hc goes to the one attested peer its first handshake
		// verified (cdsconn), so the member ID comes from it.
		var st cdsha.Status
		if err := getJSON(ctx, hc, conn.URL, "/ha/status", 1<<16, &st); err != nil {
			fmt.Fprintf(errOut, "attempt %d: %v\n", i+1, err)
			continue
		}
		if st.ClusterID != t.clusterID || st.NodeName != t.node {
			fmt.Fprintf(errOut, "attempt %d: reached the replica of cluster %q on node %q\n", i+1, st.ClusterID, st.NodeName)
			continue
		}
		if st.Joined {
			applied, err := restoreApplied(ctx, hc, conn.URL, t.intent)
			switch {
			case applied:
				fmt.Fprintf(out, "restored on %s (the decree record holds %s)\n", t.node, t.intent)
				return nil
			case err == nil:
				return errors.New("restore refused: the replica is serving; a Restore only goes to a fresh replica after a total loss (c8s cds ha status shows the cluster)")
			}
			// Joined, but its full server does not serve the record yet.
			fmt.Fprintf(errOut, "attempt %d: the replica on %s holds a cluster; waiting for its decree record: %v\n", i+1, t.node, err)
			continue
		}
		body, err := sign(st.ID)
		if err != nil {
			return err
		}
		post := *hc
		post.Timeout = restoreTimeout
		code, msg, err := postRestore(&post, url, body)
		switch {
		case err == nil && code == http.StatusOK:
			fmt.Fprintf(out, "restored on %s (member %s): %s", t.node, st.ID, msg)
			return nil
		case err == nil && code == http.StatusMisdirectedRequest:
			// The process restarted since its status: a new member ID.
		case err != nil || code == http.StatusTooManyRequests || code == http.StatusNotFound || code == http.StatusServiceUnavailable:
			// No answer, a restore in progress, or the full server: the
			// restore may be running or done. Read how it ended.
			waitUntil = time.Now().Add(restoreTimeout)
			fmt.Fprintf(errOut, "attempt %d: %s; reading the outcome\n", i+1, postOutcome(code, msg, err))
		default:
			// A refusal, unless the replica restored in between (409:
			// it belongs to a cluster now).
			var now cdsha.Status
			if getJSON(ctx, hc, conn.URL, "/ha/status", 1<<16, &now) == nil && now.Joined {
				waitUntil = time.Now().Add(restoreTimeout)
				continue
			}
			return fmt.Errorf("restore refused (%d): %s", code, strings.TrimSpace(msg))
		}
	}
	return fmt.Errorf("no answer from the replica on %s after %d attempts", t.node, t.attempts)
}

func postOutcome(code int, msg string, err error) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("%d %s", code, strings.TrimSpace(msg))
}

// restoreApplied reports whether the cluster's decree record holds the
// Restore decree with this intent, or why the record could not be read.
func restoreApplied(ctx context.Context, hc *http.Client, base, intent string) (bool, error) {
	records, err := fetchDecreeRecord(ctx, hc, base)
	if err != nil {
		return false, err
	}
	for _, r := range records {
		if r.Decree.Decree.Kind == cdsha.Restore && r.Decree.Decree.IntentID == intent {
			return true, nil
		}
	}
	return false, nil
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
