// `ha backups`: the sealed backups a cluster's board holds, and
// `ha recover`: the cluster started again from one of them.
//
// The operator lists the backups, names one, opens it with the recovery key
// they keep offline, and hands the state to a replica that holds no cluster
// with a signed Restore decree. The board is the host's, so nothing it says
// is acted on: the backup is authenticated against the mesh CA the operator
// kept from the live cluster, and the state inside against the metadata that
// signature covers. See docs/cds-ha-backups.md.

package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsboard"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

type backupsOptions struct {
	config string
}

func newBackupsCmd() *cobra.Command {
	var o backupsOptions
	cmd := &cobra.Command{
		Use:   "backups",
		Short: "List the sealed backups a cluster's board holds",
		Long: "Lists the backups under the board the configuration names, oldest state first. Every field is\n" +
			"read from the object key, which is whoever can write to that board's word: it says which\n" +
			"backups to consider, and `ha recover` checks the one it is given.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}
	cmd.Flags().StringVar(&o.config, "config", "", "the configuration document the cluster's CDS VMs boot on (REQUIRED); it names the board")
	requireFlags(cmd, "config")
	return cmd
}

func (o backupsOptions) run(cmd *cobra.Command) error {
	c, err := readDecreeConfig(o.config)
	if err != nil {
		return err
	}
	board, err := operatorBoard(c)
	if err != nil {
		return err
	}
	listed, err := board.Backups(cmd.Context())
	if err != nil {
		return err
	}
	for _, backup := range listed {
		fmt.Fprintf(cmd.OutOrStdout(), "%q version=%d index=%d ca=%q\n",
			backup.Key, backup.Name.Version, backup.Name.Index, backup.Name.CAKeySHA256)
	}
	return nil
}

// replicaSet is the configuration's ha block: a cluster whose CDS runs as its
// singleton keeps no backups and takes no restore.
func replicaSet(c decreeConfig) (*cdsconfig.HA, error) {
	if c.parsed.HA == nil {
		return nil, errors.New("--config names no replica set: a CDS of this cluster runs as its singleton, which keeps no backups")
	}
	return c.parsed.HA, nil
}

// operatorBoard addresses the board the configuration names. Its objects are
// signed or sealed, and every reader checks what it reads, so the client
// carries no credentials.
func operatorBoard(c decreeConfig) (*cdsboard.Client, error) {
	ha, err := replicaSet(c)
	if err != nil {
		return nil, err
	}
	if !ha.Board.Names() {
		return nil, errors.New("--config names no ha.board: this cluster keeps its state in the replicas' memory and has no backup to restore from")
	}
	return cdsboard.New(ha.Board, c.parsed.ClusterID)
}

// restoreOptions start a cluster again from one of its backups.
type restoreOptions struct {
	decreeOptions
	pins   pinFlags
	target replica
	// backup is the board key of the backup to restore, as `ha backups`
	// lists it.
	backup string
	// recoveryKey is the operator's half of the key the cluster seals its
	// backups to, and trustedCAKey the mesh CA key they kept from the live
	// cluster.
	recoveryKey  string
	trustedCAKey string
	// minVersion and minIndex are the oldest state the operator accepts, from
	// their own record of the cluster, and resumeVersion the highest version
	// they know it reached.
	minVersion    uint64
	minIndex      uint64
	resumeVersion uint64
	alone         bool
	acknowledge   bool
}

func newRecoverClusterCmd() *cobra.Command {
	var o restoreOptions
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Start a cluster that lost every replica again from a sealed backup",
		Long: "Opens the backup --backup names with the recovery key, signs a Restore decree for the replica\n" +
			"--target names, and hands both to it over armTLS. That replica starts the cluster again from\n" +
			"the state, and the other replicas join it.\n\n" +
			"The state brings the allowlist, the secrets, the sandbox bindings and the node images of the\n" +
			"cluster that was. The decree brings the CDS images of the configuration the replicas boot now,\n" +
			"so a cluster-lifetime field may be written again under the same cluster id before a restore;\n" +
			"write the client and node pins again from `ha pin-policy` afterwards.\n\n" +
			"The target mints the mesh CA the restored cluster issues under, so every workload must be\n" +
			"issued again and the key in the backup stops being the cluster's. Record the new `ca` and\n" +
			"`ca_key` from `ha status`.\n\n" +
			"--min-version and --min-index are the oldest state you accept, from your own record of the\n" +
			"cluster. --trusted-ca-key-sha256 is the `ca_key` you kept from the live cluster; never read it\n" +
			"off the board. --cds-pin must name the images --image-manifest pins, so the state goes to a\n" +
			"replica attested as one of them. See docs/cds-ha-backups.md.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}
	bindPinFlags(cmd, &o.pins)
	bindTargetFlags(cmd, &o.target)
	f := cmd.Flags()
	f.StringVar(&o.config, "config", "", "the configuration document the cluster's CDS VMs boot on (REQUIRED)")
	f.StringVar(&o.operatorKey, "operator-key", "", "operator EC private key PEM file, whose public key the configuration pins (REQUIRED)")
	f.DurationVar(&o.expiresIn, "expires-in", defaultDecreeValidity, "how long the target replica may act on this Restore decree")
	f.StringVar(&o.backup, "backup", "", "board key of the backup to restore, as `c8s cds ha backups` lists it (REQUIRED)")
	f.StringVar(&o.recoveryKey, "recovery-key", "", "EC private key PEM file the cluster's backups are sealed to (REQUIRED)")
	f.StringVar(&o.trustedCAKey, "trusted-ca-key-sha256", "", "SHA-256 of the mesh CA key you kept from the live cluster, which signed the backup (REQUIRED); never from the board")
	f.Uint64Var(&o.minVersion, "min-version", 0, "refuse a backup below this cluster version (REQUIRED)")
	f.Uint64Var(&o.minIndex, "min-index", 0, "refuse a backup below this log index of --min-version (REQUIRED)")
	f.Uint64Var(&o.resumeVersion, "resume-version", 0, "the highest version you know the cluster reached, at least the backup's (REQUIRED); the restored cluster resumes above it")
	f.BoolVar(&o.alone, "alone", false, "restore even where the target replica finds no other replica (a one-replica cluster only)")
	f.BoolVar(&o.acknowledge, "i-understand-restore-loses-writes", false, "required: every write the lost cluster took after this backup is gone")
	requireFlags(cmd, "config", "operator-key", "backup", "recovery-key", "trusted-ca-key-sha256",
		"min-version", "min-index", "resume-version")
	return cmd
}

func (o restoreOptions) run(cmd *cobra.Command) error {
	if err := acknowledged(o.acknowledge, "i-understand-restore-loses-writes",
		"a restore starts the cluster again from the state of a backup, and every write the lost cluster took after it is gone"); err != nil {
		return err
	}
	if o.minVersion == 0 {
		return errors.New("--min-version 0 accepts every backup on the board: name the version your own record of the cluster holds, which is at least the 1 its Genesis produced")
	}
	c, err := readDecreeConfig(o.config)
	if err != nil {
		return err
	}
	cdsPins, err := o.signedPins(c)
	if err != nil {
		return err
	}
	state, err := o.openBackup(cmd, c)
	if err != nil {
		return err
	}
	return o.deliver(cmd, c, cdsPins, state)
}

// signedPins are the CDS images the Restore carries, which must be the
// images --cds-pin verifies the target replica against: the state holds the
// mesh CA key and every secret of the cluster, so it goes to a replica
// attested as an image the restored cluster accepts. It is judged before the
// backup is opened.
func (o restoreOptions) signedPins(c decreeConfig) (*cdsdecree.PinDocument, error) {
	cdsPins, err := o.pins.document(c.launchFile)
	if err != nil {
		return nil, err
	}
	signed, err := cdsPins.WithLaunchFile(c.launchFile)
	if err != nil {
		return nil, err
	}
	verified, err := refvalues.Load(o.target.cdsPin)
	if err != nil {
		return nil, fmt.Errorf("--cds-pin: %w", err)
	}
	return cdsPins, pinsTheSameImages(signed, verified)
}

// pinsTheSameImages is why a pin document is not the image set a decree
// carries. Entry names are the operator's, so the images are compared by
// what decides admission.
func pinsTheSameImages(signed, verified refvalues.ReferenceValues) error {
	if signed.Family != verified.Family {
		return fmt.Errorf("--cds-pin verifies the target replica on %s, and this Restore pins %s images", verified.Family, signed.Family)
	}
	missing, extra := refvalues.Diff(signed, verified)
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	return fmt.Errorf("--cds-pin verifies the target replica against another CDS image set than this Restore pins: it is missing %d of the decree's images and names %d the decree does not. Write it with the --platform, --vcpus and --image-manifest of this restore, against this --config",
		len(missing), len(extra))
}

// openBackup is the state the named backup holds: read off the board,
// authenticated against the mesh CA the operator kept, opened with their
// recovery key, and checked against the metadata that signature covers and
// the floor they named.
func (o restoreOptions) openBackup(cmd *cobra.Command, c decreeConfig) ([]byte, error) {
	key, err := o.loadRecoveryKey(c)
	if err != nil {
		return nil, err
	}
	board, err := operatorBoard(c)
	if err != nil {
		return nil, err
	}
	object, err := board.Get(cmd.Context(), o.backup, cdsha.MaxBackupObjectBytes())
	if err != nil {
		return nil, fmt.Errorf("--backup %s: %w", o.backup, err)
	}
	backup, err := cdsha.ParseBackup(object)
	if err != nil {
		return nil, err
	}
	if err := cdsha.VerifyBackupSource(backup, o.trustedCAKey); err != nil {
		return nil, err
	}
	state, err := cdsha.OpenBackup(key, backup)
	if err != nil {
		return nil, err
	}
	if err := cdsha.ValidateRecoverySnapshot(state, backup, o.minVersion, o.minIndex); err != nil {
		return nil, err
	}
	if o.resumeVersion < backup.Meta.Version {
		return nil, fmt.Errorf("--resume-version %d is below the backup's version %d: name the highest version the cluster reached", o.resumeVersion, backup.Meta.Version)
	}
	meta := backup.Meta
	fmt.Fprintf(cmd.OutOrStdout(), "%q opens: version=%d index=%d decrees=%d sealed=%s state=%q\n",
		o.backup, meta.Version, meta.Index, len(meta.AppliedDecrees),
		time.UnixMilli(meta.SealedAtMS).UTC().Format(time.RFC3339), meta.StateDigest)
	return state, nil
}

// loadRecoveryKey is the operator's half of the key this cluster's backups
// seal to. A key the configuration does not name opens no backup of it, so it
// is refused before the board is read.
func (o restoreOptions) loadRecoveryKey(c decreeConfig) (*ecdsa.PrivateKey, error) {
	ha, err := replicaSet(c)
	if err != nil {
		return nil, err
	}
	key, err := certutil.LoadECPrivateKeyFile(o.recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("--recovery-key: %w", err)
	}
	if !key.PublicKey.Equal(ha.RecoveryKey) {
		return nil, errors.New("--recovery-key is not the key this configuration seals its backups to")
	}
	return key, nil
}

// deliver signs the Restore decree for the target replica and hands it the
// state, then reports the cluster that came back.
func (o restoreOptions) deliver(cmd *cobra.Command, c decreeConfig, cdsPins *cdsdecree.PinDocument, state []byte) error {
	target, address, err := o.target.statusAtAddress(cmd.Context())
	if err != nil {
		return err
	}
	if err := checkRestoreTarget(target, c.parsed.ClusterID); err != nil {
		return err
	}
	signed, err := o.restoreDecree(cmd, c, cdsPins, target, address, state)
	if err != nil {
		return err
	}
	if o.alone {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: --alone restores even if the target replica finds no other, so a host that hides a live cluster gets a second one beside it")
	}
	fmt.Fprintf(cmd.OutOrStdout(), "restoring cluster %s on member %s at %s: Restore decree %s\n",
		c.parsed.ClusterID, target.ID, address, signed.Decree.IntentID)
	result, err := o.handOver(cmd.Context(), address, signed, state)
	if err != nil {
		return fmt.Errorf("%w\nRead `c8s cds ha decrees` for decree %s: a restore the replica committed before the connection broke is in its record", err, signed.Decree.IntentID)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "restored: the cluster is at version %d, under mesh CA %s\n", result.Version, signed.Decree.GenesisCA)
	fmt.Fprintln(cmd.ErrOrStderr(), "warning: the restored cluster issues under a mesh CA its replica minted: issue every workload again, and record the new ca and ca_key from `ha status`")
	return nil
}

// restoreDecree is the decree the target replica acts on: the state it
// restores, the images of the configuration it boots, the mesh CA that
// replica mints, the node images the state certifies, and the version the
// restored cluster resumes above.
func (o restoreOptions) restoreDecree(cmd *cobra.Command, c decreeConfig, cdsPins *cdsdecree.PinDocument, target cdsha.Status, address netip.AddrPort, state []byte) (cdsdecree.Signed, error) {
	nodePins, err := cdsha.NodeImagesIn(state)
	if err != nil {
		return cdsdecree.Signed{}, err
	}
	return o.sign(cmd, c, cdsdecree.Decree{
		Kind:          cdsdecree.Restore,
		CDSPins:       cdsPins,
		NodePins:      nodePins,
		TargetMember:  target.ID,
		TargetAddress: address.String(),
		IssuedAtMS:    time.Now().UnixMilli(),
		GenesisCA:     target.GenesisCA,
		ResumeVersion: o.resumeVersion,
		StateSHA256:   cdsha.StateSHA256(state),
		Alone:         o.alone,
	})
}

// checkRestoreTarget requires a replica of this cluster that holds none and
// reports the mesh CA it would install: a restore starts a lost cluster again
// on a replica with no state of its own, under a mesh CA that replica mints.
func checkRestoreTarget(target cdsha.Status, clusterID string) error {
	if err := checkTargetCluster(target, clusterID); err != nil {
		return err
	}
	switch {
	case target.Joined:
		return errors.New("the target replica already holds a cluster: a restore starts a lost one again")
	case target.GenesisCA == "":
		return errors.New("the target replica reports no mesh CA it would install")
	}
	return nil
}

// handOver posts the decree and the state to the replica on one attested
// connection, and answers with what the cluster made of the restore.
func (o restoreOptions) handOver(ctx context.Context, address netip.AddrPort, signed cdsdecree.Signed, state []byte) (cdsha.DecreeResult, error) {
	body, err := restoreRequest(signed, state)
	if err != nil {
		return cdsha.DecreeResult{}, err
	}
	// The replica restores while it answers, which outlasts the deadline
	// every other read of one holds to.
	client, _, err := o.target.dialWithin(ctx, restoreDeadline)
	if err != nil {
		return cdsha.DecreeResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address.String()+restorePath, bytes.NewReader(body))
	if err != nil {
		return cdsha.DecreeResult{}, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		return cdsha.DecreeResult{}, fmt.Errorf("POST %s: %w", restorePath, err)
	}
	defer response.Body.Close()
	return restoreResult(response)
}

// restoreRequest is what the operator posts: the Restore decree on one line,
// which the encoder ends, and the state behind it, so the replica authorizes
// the restore before it reads a state of that size.
func restoreRequest(signed cdsdecree.Signed, state []byte) ([]byte, error) {
	var request bytes.Buffer
	if err := json.NewEncoder(&request).Encode(signed); err != nil {
		return nil, err
	}
	if _, err := request.Write(state); err != nil {
		return nil, err
	}
	return request.Bytes(), nil
}

// restoreResult is what the replica answered: the version the restored
// cluster is at, or its refusal in the words it gave.
func restoreResult(response *http.Response) (cdsha.DecreeResult, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxReplicaReport))
	if err != nil {
		return cdsha.DecreeResult{}, fmt.Errorf("POST %s: %w", restorePath, err)
	}
	if response.StatusCode != http.StatusOK {
		return cdsha.DecreeResult{}, fmt.Errorf("the replica restored nothing (%s): %s", response.Status, bytes.TrimSpace(body))
	}
	var result cdsha.DecreeResult
	if err := json.Unmarshal(body, &result); err != nil {
		return cdsha.DecreeResult{}, fmt.Errorf("POST %s: %w", restorePath, err)
	}
	return result, nil
}
