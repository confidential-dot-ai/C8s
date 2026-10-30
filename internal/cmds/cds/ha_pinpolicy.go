// `ha pin-policy`: the pin decree a cluster applied, and the pin document it
// makes. A client, a node document and an Admit decree hold this cluster's
// CDS to that document, which the cluster itself serves after an image roll.

package cds

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

type pinPolicyOptions struct {
	reach     clusterReach
	out       string
	decreeOut string
}

func newPinPolicyCmd() *cobra.Command {
	var o pinPolicyOptions
	cmd := &cobra.Command{
		Use:   "pin-policy",
		Short: "Report the pin decree a cluster applied and write the pin document it makes",
		Long: "Reads the applied pin decree from the first replica of the cluster that answers, over armTLS,\n" +
			"and checks it against the configuration: a key the configuration pins signed it, it names this\n" +
			"cluster, and its entries bind the launch file the replicas boot.\n\n" +
			"--out writes the pin document the decree makes, with that launch file filled in: what a client\n" +
			"pins this CDS by, and what --cds-pin takes during a roll. --decree-out writes the signed decree\n" +
			"itself, which 'launch-config add-agent --pin-decree' takes a node document's pin from.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}
	bindReachFlags(cmd, &o.reach)
	f := cmd.Flags()
	f.StringVar(&o.out, "out", "", "file to write the pin document the decree makes to")
	f.StringVar(&o.decreeOut, "decree-out", "", "file to write the signed pin decree to")
	return cmd
}

func (o pinPolicyOptions) run(cmd *cobra.Command) error {
	c, replicas, err := o.reach.cluster(cmd.Context())
	if err != nil {
		return err
	}
	return o.report(cmd, c, replicas)
}

func (o pinPolicyOptions) report(cmd *cobra.Command, c decreeConfig, replicas []replica) error {
	address, object, err := signedStateOfAnyReplica(cmd.Context(), replicas, pinDecreePath, maxReplicaReport)
	if err != nil {
		return err
	}
	applied, err := checkedPinDecree(object, c)
	if err != nil {
		return fmt.Errorf("the pin decree replica %s serves: %w", address, err)
	}
	d := applied.decree.Decree
	fmt.Fprintf(cmd.OutOrStdout(), "replica %s serves the %s decree %s: base_version=%d images=%d\n",
		address, d.Kind, d.IntentID, d.BaseVersion, len(applied.pins.Images))
	files, err := o.filesToWrite(applied, object)
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := fileutil.WriteAtomic(file.path, file.body, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", file.path)
	}
	return nil
}

type operatorFile struct {
	path string
	body []byte
}

// Every body is rendered before any file is written.
func (o pinPolicyOptions) filesToWrite(applied appliedPinDecree, object []byte) ([]operatorFile, error) {
	var files []operatorFile
	if o.out != "" {
		document, err := refvalues.Format(applied.pins)
		if err != nil {
			return nil, err
		}
		files = append(files, operatorFile{
			path: o.out,
			body: document,
		})
	}
	if o.decreeOut != "" {
		files = append(files, operatorFile{
			path: o.decreeOut,
			body: object,
		})
	}
	return files, nil
}

// The decree as the operator signed it, and the pin set it makes with the
// launch file the replicas boot filled into every entry.
type appliedPinDecree struct {
	decree cdsdecree.Signed
	pins   refvalues.ReferenceValues
}

// Checked against the configuration, so a decree of another cluster or
// another launch file is refused here.
func checkedPinDecree(object []byte, c decreeConfig) (appliedPinDecree, error) {
	applied, err := cdsdecree.Parse(object)
	if err != nil {
		return appliedPinDecree{}, err
	}
	if err := cdsdecree.Verify(applied, c.parsed.OperatorKeys.Keys(), c.parsed.ClusterID); err != nil {
		return appliedPinDecree{}, err
	}
	if applied.Decree.CDSPins == nil {
		return appliedPinDecree{}, fmt.Errorf("a %s decree pins no CDS image", applied.Decree.Kind)
	}
	pins, err := applied.Decree.CDSPins.WithLaunchFile(c.launchFile)
	if err != nil {
		return appliedPinDecree{}, err
	}
	return appliedPinDecree{
		decree: applied,
		pins:   pins,
	}, nil
}
