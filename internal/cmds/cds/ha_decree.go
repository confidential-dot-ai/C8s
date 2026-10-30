package cds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// defaultDecreeValidity is how long a cluster may adopt a decree for. A
// re-signed decree leaves the host a choice among those still unexpired, so
// the window is short.
const defaultDecreeValidity = 10 * time.Minute

// newHACmd groups the operator side of a highly available CDS.
func newHACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ha",
		Short: "Operate a highly available CDS",
	}
	cmd.AddCommand(
		newDecreeCmd(),
		newStatusCmd(),
		newDecreesCmd(),
		newPinPolicyCmd(),
	)
	return cmd
}

// newDecreeCmd groups the decrees an operator signs, one subcommand per
// intent. Each kind that names the replica it is for is posted to that
// replica over the attested channel, and every kind can be written to --out
// as a file.
func newDecreeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decree",
		Short: "Sign an operator decree for a CDS cluster",
	}
	cmd.AddCommand(
		newGenesisCmd(),
		newPinsCmd(),
		newNodeImagesCmd(),
		newRotateKeyCmd(),
		newRecoverCmd(),
		newDismissRecoverCmd(),
		newAdmitCmd(),
	)
	return cmd
}

// decreeOptions are the inputs every decree command takes.
type decreeOptions struct {
	config      string
	operatorKey string
	out         string
	expiresIn   time.Duration
	baseVersion uint64
}

// decreeCmd is one kind's command: what every decree takes, plus the work of
// that kind.
func decreeCmd(use, short, long string, o *decreeOptions, run func(*cobra.Command) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:          use,
		Short:        short,
		Long:         long,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.config, "config", "", "the configuration document the cluster's CDS VMs boot on (REQUIRED)")
	f.StringVar(&o.operatorKey, "operator-key", "", "operator EC private key PEM file, whose public key the configuration pins (REQUIRED)")
	f.StringVar(&o.out, "out", "", "file to write the signed decree to, beside posting it")
	f.DurationVar(&o.expiresIn, "expires-in", defaultDecreeValidity, "how long the cluster may adopt this decree for")
	requireFlags(cmd, "config", "operator-key")
	return cmd
}

// bindBaseVersionFlag names the version a decree applies on top of, for the
// kinds that apply to a cluster that already has one.
func bindBaseVersionFlag(cmd *cobra.Command, o *decreeOptions) {
	cmd.Flags().Uint64Var(&o.baseVersion, "base-version", 0, "the version the cluster reports now (REQUIRED); the decree applies on top of it")
	requireFlags(cmd, "base-version")
}

// decreeConfig is the cluster a decree is for, as its measured configuration
// describes it. The document is the launch file every replica of the cluster
// boots, which the CDS pins bind, and it names the operator keys a decree may
// be signed with.
type decreeConfig struct {
	launchFile []byte
	parsed     *cdsconfig.Config
}

func readDecreeConfig(path string) (decreeConfig, error) {
	launchFile, err := os.ReadFile(path)
	if err != nil {
		return decreeConfig{}, fmt.Errorf("--config: %w", err)
	}
	parsed, err := cdsconfig.Parse(launchFile)
	if err != nil {
		return decreeConfig{}, fmt.Errorf("--config: %w", err)
	}
	return decreeConfig{launchFile: launchFile, parsed: parsed}, nil
}

// sign fills in what every decree carries, signs it, and writes it to --out
// where the operator named one. The signature is checked against the keys the
// configuration pins, so a key the cluster would refuse is caught here.
func (o decreeOptions) sign(cmd *cobra.Command, c decreeConfig, d cdsdecree.Decree) (cdsdecree.Signed, error) {
	if o.expiresIn <= 0 {
		return cdsdecree.Signed{}, errors.New("--expires-in must be positive: a decree no replica may adopt does nothing")
	}
	key, err := certutil.LoadECPrivateKeyFile(o.operatorKey)
	if err != nil {
		return cdsdecree.Signed{}, fmt.Errorf("--operator-key: %w", err)
	}
	d.ClusterID = c.parsed.ClusterID
	d.IntentID = cdsdecree.NewIntentID()
	d.ExpiresAt = time.Now().Add(o.expiresIn).UTC().Truncate(time.Second)
	signed, err := cdsdecree.Sign(d, key)
	if err != nil {
		return cdsdecree.Signed{}, err
	}
	if err := cdsdecree.Verify(signed, c.parsed.OperatorKeys.Keys(), d.ClusterID); err != nil {
		return cdsdecree.Signed{}, fmt.Errorf("the decree this would hand the cluster: %w", err)
	}
	if o.out == "" {
		return signed, nil
	}
	return signed, o.write(cmd, signed)
}

func (o decreeOptions) write(cmd *cobra.Command, signed cdsdecree.Signed) error {
	body, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(o.out, append(body, '\n'), 0o644); err != nil {
		return err
	}
	d := signed.Decree
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s: %s decree %s for cluster %s, adoptable until %s\n",
		o.out, d.Kind, d.IntentID, d.ClusterID, d.ExpiresAt.Format(time.RFC3339))
	return nil
}

// deliver signs a decree and posts it over the attested channel to the replica
// it names, which is the member id that replica's process minted, so no other
// replica acts on it.
func (o decreeOptions) deliver(cmd *cobra.Command, c decreeConfig, to replica, d cdsdecree.Decree) error {
	signed, err := o.sign(cmd, c, d)
	if err != nil {
		return err
	}
	delivered, address, err := to.postDecree(cmd.Context(), signed)
	if err != nil {
		return err
	}
	return reportDelivered(cmd, address, signed.Decree, delivered)
}

// deliverIssued posts a decree that starts or carries on a cluster: it records
// the operator's signing time, which is the earliest start time that cluster
// takes.
func (o decreeOptions) deliverIssued(cmd *cobra.Command, c decreeConfig, to replica, d cdsdecree.Decree) error {
	d.IssuedAtMS = time.Now().UnixMilli()
	return o.deliver(cmd, c, to, d)
}

func reportDelivered(cmd *cobra.Command, address string, d cdsdecree.Decree, delivered cdsha.Delivered) error {
	if delivered.Refused != "" {
		return fmt.Errorf("%s refused the %s decree %s: %s", address, d.Kind, delivered.Intent, delivered.Refused)
	}
	if delivered.Held {
		fmt.Fprintf(cmd.OutOrStdout(), "posted %s decree %s to %s: the replica holds it until it acts on it\n",
			d.Kind, delivered.Intent, address)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "posted %s decree %s to %s: the cluster applied it at version %d\n",
		d.Kind, delivered.Intent, address, delivered.Version)
	return nil
}

// acknowledged refuses an intent whose consequence the operator has not
// confirmed. The value is what counts: a flag cobra marks required is
// satisfied by passing it as false.
func acknowledged(confirmed bool, flag, consequence string) error {
	if confirmed {
		return nil
	}
	return fmt.Errorf("%s. Pass --%s", consequence, flag)
}

// pinFlags name the CDS guest images a decree pins the cluster to: one
// manifest per image it accepts, and the VM shapes those images may boot in.
type pinFlags struct {
	platform  string
	vcpus     []int
	manifests []string
}

func bindPinFlags(cmd *cobra.Command, p *pinFlags) {
	f := cmd.Flags()
	f.StringVar(&p.platform, "platform", "", "TEE platform the CDS VMs run on: sev-snp or tdx (REQUIRED)")
	f.IntSliceVar(&p.vcpus, "vcpus", nil, "SEV-SNP only: a vCPU count a CDS VM may boot with, one pin entry each; repeatable")
	f.StringArrayVar(&p.manifests, "image-manifest", nil, "manifest.json of a CDS guest image the cluster accepts; repeatable (REQUIRED)")
	requireFlags(cmd, "platform", "image-manifest")
}

// document is the image set the decree carries: every named image bound to the
// launch file the replicas boot, with that file elided.
func (p pinFlags) document(launchFile []byte) (*cdsdecree.PinDocument, error) {
	family, err := cdsconfig.ParsePlatform(p.platform)
	if err != nil {
		return nil, fmt.Errorf("--platform: %w", err)
	}
	set := refvalues.ReferenceValues{Family: family}
	for _, manifest := range p.manifests {
		images, err := imagePins(manifest, family, p.vcpus, launchFile)
		if err != nil {
			return nil, err
		}
		set.Images = append(set.Images, images...)
	}
	document, err := refvalues.Format(set)
	if err != nil {
		return nil, err
	}
	return cdsdecree.NewPinDocument(document)
}

// imagePins names one image's entries after its launch digest, so the entries
// of the two images an image roll accepts never collide.
func imagePins(manifest string, family teetypes.Family, vcpus []int, launchFile []byte) ([]remote.ImagePin, error) {
	document, err := cdsconfig.Pin(manifest, family, vcpus, launchFile)
	if err != nil {
		return nil, fmt.Errorf("--image-manifest %s: %w", manifest, err)
	}
	set, err := refvalues.Parse(document)
	if err != nil {
		return nil, err
	}
	for i, image := range set.Images {
		set.Images[i].Name = fmt.Sprintf("%s@%.4x", image.Name, image.Digest)
	}
	return set.Images, nil
}

// genesisOptions start a cluster on one replica that holds none.
type genesisOptions struct {
	decreeOptions
	pins          pinFlags
	target        replica
	nodes         string
	resumeVersion uint64
	alone         bool
}

func newGenesisCmd() *cobra.Command {
	var o genesisOptions
	cmd := decreeCmd("genesis", "Sign the decree that starts a cluster",
		"The replica this decree names mints the mesh CA, seeds the allowlist from the configuration's\n"+
			"workloads, and begins with the CDS and node image sets the decree carries. A cluster started\n"+
			"again under this cluster id resumes above --resume-version, so no decree of the old one applies\n"+
			"a second time and nodes keep taking the newest pin decree.",
		&o.decreeOptions, func(cmd *cobra.Command) error { return o.run(cmd) })
	bindPinFlags(cmd, &o.pins)
	bindTargetFlags(cmd, &o.target)
	f := cmd.Flags()
	f.StringVar(&o.nodes, "nodes", "", "measurements document pinning the node images the cluster certifies (default: the configuration's nodes)")
	f.Uint64Var(&o.resumeVersion, "resume-version", 0, "the highest version a cluster under this cluster id reached (REQUIRED, 0 for the first)")
	f.BoolVar(&o.alone, "alone", false, "start the cluster even where discovery finds no other replica (a one-replica cluster only)")
	requireFlags(cmd, "resume-version")
	return cmd
}

func (o genesisOptions) run(cmd *cobra.Command) error {
	c, err := readDecreeConfig(o.config)
	if err != nil {
		return err
	}
	cdsPins, err := o.pins.document(c.launchFile)
	if err != nil {
		return err
	}
	nodePins, err := o.nodePins(c)
	if err != nil {
		return err
	}
	target, address, err := o.target.statusAtAddress(cmd.Context())
	if err != nil {
		return err
	}
	if err := checkGenesisTarget(target, c.parsed.ClusterID); err != nil {
		return err
	}
	if o.alone {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: --alone starts the cluster even if the replica finds no other, so a host that hides the others gets a cluster beside them")
	}
	return o.deliverIssued(cmd, c, o.target, cdsdecree.Decree{
		Kind:          cdsdecree.Genesis,
		CDSPins:       cdsPins,
		NodePins:      nodePins,
		TargetMember:  target.ID,
		TargetAddress: address.String(),
		GenesisCA:     target.GenesisCA,
		ResumeVersion: o.resumeVersion,
		Alone:         o.alone,
	})
}

// nodePins are the node images the cluster starts out certifying. The decree
// carries them, so a cluster started again certifies the set the operator
// names now rather than the one the configuration was written with.
func (o genesisOptions) nodePins(c decreeConfig) (*cdsdecree.NodeImages, error) {
	if o.nodes == "" {
		measurements, err := refvalues.Format(c.parsed.Nodes)
		if err != nil {
			return nil, fmt.Errorf("the configuration's nodes: %w", err)
		}
		return cdsdecree.NewNodeImages(measurements)
	}
	return readNodeImages(o.nodes)
}

// The whole set the cluster is to certify, as `c8s cds config new --nodes`
// writes one.
func readNodeImages(path string) (*cdsdecree.NodeImages, error) {
	measurements, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--nodes: %w", err)
	}
	images, err := cdsdecree.NewNodeImages(measurements)
	if err != nil {
		return nil, fmt.Errorf("--nodes: %w", err)
	}
	return images, nil
}

type nodeImagesOptions struct {
	decreeOptions
	nodes string
	to    replica
}

func newNodeImagesCmd() *cobra.Command {
	var o nodeImagesOptions
	cmd := decreeCmd("node-images", "Sign the decree that replaces the node images the cluster certifies",
		"The cluster issues a leaf to a node of one of these images and to no other. The decree carries\n"+
			"the whole set: an upgrade signs the image being replaced and the one replacing it together,\n"+
			"and a second decree then names the new image alone.",
		&o.decreeOptions, func(cmd *cobra.Command) error { return o.run(cmd) })
	bindBaseVersionFlag(cmd, &o.decreeOptions)
	bindDeliveryFlags(cmd, &o.to)
	cmd.Flags().StringVar(&o.nodes, "nodes", "", "measurements document pinning the node images the cluster certifies (REQUIRED)")
	requireFlags(cmd, "nodes")
	return cmd
}

func (o nodeImagesOptions) run(cmd *cobra.Command) error {
	c, err := readDecreeConfig(o.config)
	if err != nil {
		return err
	}
	nodePins, err := readNodeImages(o.nodes)
	if err != nil {
		return err
	}
	return o.deliver(cmd, c, o.to, cdsdecree.Decree{
		Kind:        cdsdecree.SetNodeImages,
		BaseVersion: o.baseVersion,
		NodePins:    nodePins,
	})
}

// checkGenesisTarget requires a replica of this cluster that holds none, and
// that reports the mesh CA it would install.
func checkGenesisTarget(target cdsha.Status, clusterID string) error {
	if err := checkTargetCluster(target, clusterID); err != nil {
		return err
	}
	switch {
	case target.Joined:
		return errors.New("the target replica already holds a cluster: a Genesis starts one that was never started")
	case target.GenesisCA == "":
		return errors.New("the target replica reports no mesh CA it would install")
	}
	return nil
}

func checkTargetCluster(target cdsha.Status, clusterID string) error {
	if target.ClusterID != clusterID {
		return fmt.Errorf("the target replica serves cluster %q, not %q", target.ClusterID, clusterID)
	}
	if target.ID == "" {
		return errors.New("the target replica reports no member id")
	}
	return nil
}

// pinsOptions replace the images a CDS of the cluster may run.
type pinsOptions struct {
	decreeOptions
	pins pinFlags
	to   replica
}

func newPinsCmd() *cobra.Command {
	var o pinsOptions
	cmd := decreeCmd("pins", "Sign the decree that replaces the images a CDS of the cluster may run",
		"The cluster's replicas admit each other by this set, and its clients and nodes pin CDS by it. An\n"+
			"image roll signs the old and the new image together, and a second decree then names the new\n"+
			"image alone.",
		&o.decreeOptions, func(cmd *cobra.Command) error { return o.run(cmd) })
	bindBaseVersionFlag(cmd, &o.decreeOptions)
	bindPinFlags(cmd, &o.pins)
	bindDeliveryFlags(cmd, &o.to)
	return cmd
}

func (o pinsOptions) run(cmd *cobra.Command) error {
	c, err := readDecreeConfig(o.config)
	if err != nil {
		return err
	}
	cdsPins, err := o.pins.document(c.launchFile)
	if err != nil {
		return err
	}
	return o.deliver(cmd, c, o.to, cdsdecree.Decree{
		Kind:        cdsdecree.UpdateMeasurements,
		BaseVersion: o.baseVersion,
		CDSPins:     cdsPins,
	})
}

func newRotateKeyCmd() *cobra.Command {
	var (
		o           decreeOptions
		to          replica
		acknowledge bool
	)
	run := func(cmd *cobra.Command) error {
		if err := acknowledged(acknowledge, "i-understand-rotation-forks-the-cluster",
			"a RotateKey decree forks the mesh: every workload must be issued again under the new key"); err != nil {
			return err
		}
		c, err := readDecreeConfig(o.config)
		if err != nil {
			return err
		}
		return o.deliver(cmd, c, to, cdsdecree.Decree{
			Kind:        cdsdecree.RotateKey,
			BaseVersion: o.baseVersion,
		})
	}
	cmd := decreeCmd("rotate-key", "Sign the decree that mints a new mesh CA key",
		"Roll the mesh once the decree applies: every leaf under the old key stops being trusted.",
		&o, run)
	bindBaseVersionFlag(cmd, &o)
	bindDeliveryFlags(cmd, &to)
	cmd.Flags().BoolVar(&acknowledge, "i-understand-rotation-forks-the-cluster", false, "required: every leaf must be issued again under the new key")
	return cmd
}

// recoverOptions carry one surviving voter on alone.
type recoverOptions struct {
	decreeOptions
	target        replica
	resumeVersion uint64
	acknowledge   bool
}

func newRecoverCmd() *cobra.Command {
	var o recoverOptions
	cmd := decreeCmd("recover", "Sign the break-glass decree that carries a surviving voter on alone",
		"Destroy the lost VMs first: a voter that was only cut off could still serve as the old majority.\n"+
			"Follow this with rotate-key, so anything that comes back holds a retired key. The survivor\n"+
			"resumes above --resume-version, so nodes keep taking the newest pin decree.",
		&o.decreeOptions, func(cmd *cobra.Command) error { return o.run(cmd) })
	bindBaseVersionFlag(cmd, &o.decreeOptions)
	bindTargetFlags(cmd, &o.target)
	f := cmd.Flags()
	f.Uint64Var(&o.resumeVersion, "resume-version", 0, "the highest version you know the cluster reached, at least --base-version (REQUIRED)")
	f.BoolVar(&o.acknowledge, "i-understand-recover-is-break-glass", false, "required: the writes the survivor never received are gone")
	requireFlags(cmd, "resume-version")
	return cmd
}

func (o recoverOptions) run(cmd *cobra.Command) error {
	if err := acknowledged(o.acknowledge, "i-understand-recover-is-break-glass",
		"a Recover decree drops the writes the lost voters committed and the survivor never received"); err != nil {
		return err
	}
	if o.resumeVersion < o.baseVersion {
		return fmt.Errorf("--resume-version %d is below --base-version %d: name the highest version the cluster reached", o.resumeVersion, o.baseVersion)
	}
	c, err := readDecreeConfig(o.config)
	if err != nil {
		return err
	}
	target, address, err := o.target.statusAtAddress(cmd.Context())
	if err != nil {
		return err
	}
	if err := checkRecoverTarget(target, c.parsed.ClusterID); err != nil {
		return err
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "warning: follow this Recover with a rotate-key decree, so a lost replica that comes back holds a retired key")
	return o.deliverIssued(cmd, c, o.target, cdsdecree.Decree{
		Kind:          cdsdecree.Recover,
		BaseVersion:   o.baseVersion,
		TargetMember:  target.ID,
		TargetAddress: address.String(),
		ResumeVersion: o.resumeVersion,
	})
}

// checkRecoverTarget requires a surviving voter: a member without a vote may
// be missing writes the cluster committed.
func checkRecoverTarget(target cdsha.Status, clusterID string) error {
	if err := checkTargetCluster(target, clusterID); err != nil {
		return err
	}
	switch {
	case !target.Joined:
		return errors.New("the target replica holds no cluster: a Recover carries on a survivor's state")
	case !holdsAVote(target):
		return errors.New("the target replica holds no vote: name a surviving voter, whose state is the cluster's")
	}
	return nil
}

func newDismissRecoverCmd() *cobra.Command {
	var (
		o             decreeOptions
		to            replica
		recoverIntent string
	)
	run := func(cmd *cobra.Command) error {
		c, err := readDecreeConfig(o.config)
		if err != nil {
			return err
		}
		return o.deliver(cmd, c, to, cdsdecree.Decree{
			Kind:          cdsdecree.DismissRecover,
			BaseVersion:   o.baseVersion,
			RecoverIntent: recoverIntent,
		})
	}
	cmd := decreeCmd("dismiss-recover", "Sign the decree that lifts the doubt a Recover left on the cluster",
		"Sign this once the doubted member has rejoined or its VM is destroyed, so no other side of the\n"+
			"cluster can serve.",
		&o, run)
	bindBaseVersionFlag(cmd, &o)
	bindDeliveryFlags(cmd, &to)
	cmd.Flags().StringVar(&recoverIntent, "recover-intent", "", "intent id of the Recover decree the cluster reports as its doubt (REQUIRED)")
	requireFlags(cmd, "recover-intent")
	return cmd
}

// admitOptions let one unjoined replica admit the cluster's images.
type admitOptions struct {
	decreeOptions
	target replica
	joined string
}

func newAdmitCmd() *cobra.Command {
	var o admitOptions
	cmd := decreeCmd("admit", "Sign the decree that lets one unjoined replica admit the cluster's images",
		"A replica with no cluster yet admits only its own image, so a replica of a new image cannot reach\n"+
			"a leader still running the old one. The replica this decree names admits the images of the pin\n"+
			"decree the cluster applied, until the decree expires; each restart of it needs a new decree.",
		&o.decreeOptions, func(cmd *cobra.Command) error { return o.run(cmd) })
	bindTargetFlags(cmd, &o.target)
	cmd.Flags().StringVar(&o.joined, "cluster", "", "<host>[:"+strconv.Itoa(replicaPort)+"] of a replica serving the cluster, whose applied pin decree names the images (REQUIRED)")
	requireFlags(cmd, "cluster")
	return cmd
}

func (o admitOptions) run(cmd *cobra.Command) error {
	c, err := readDecreeConfig(o.config)
	if err != nil {
		return err
	}
	cdsPins, err := o.appliedPins(cmd.Context(), c)
	if err != nil {
		return err
	}
	target, err := o.target.status(cmd.Context())
	if err != nil {
		return err
	}
	if err := checkAdmitTarget(target, c.parsed.ClusterID); err != nil {
		return err
	}
	return o.deliver(cmd, c, o.target, cdsdecree.Decree{
		Kind:         cdsdecree.Admit,
		CDSPins:      cdsPins,
		TargetMember: target.ID,
	})
}

// appliedPins are the images the cluster accepts, read from a serving replica
// as the decree the cluster applied. An Admit names only those, so it cannot
// widen what the cluster already runs.
func (o admitOptions) appliedPins(ctx context.Context, c decreeConfig) (*cdsdecree.PinDocument, error) {
	object, _, err := o.servingReplica().answer(ctx, pinDecreePath, maxReplicaReport)
	if err != nil {
		return nil, err
	}
	applied, err := checkedPinDecree(object, c)
	if err != nil {
		return nil, fmt.Errorf("the pin decree %s serves: %w", o.joined, err)
	}
	return applied.decree.Decree.CDSPins, nil
}

// servingReplica is the joined replica an Admit reads the cluster's applied
// pin decree from. An image roll's pin document names the old and the new
// image, so the one --cds-pin verifies this replica and the target.
func (o admitOptions) servingReplica() replica {
	return replica{
		address:  o.joined,
		cdsPin:   o.target.cdsPin,
		verifier: o.target.verifier,
	}
}

// checkAdmitTarget requires a replica of this cluster that holds none: a
// joined replica admits by the cluster's own image set.
func checkAdmitTarget(target cdsha.Status, clusterID string) error {
	if err := checkTargetCluster(target, clusterID); err != nil {
		return err
	}
	if target.Joined {
		return errors.New("the target replica already holds a cluster, and admits by the image set the cluster applied")
	}
	return nil
}

func requireFlags(cmd *cobra.Command, names ...string) {
	for _, name := range names {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}
