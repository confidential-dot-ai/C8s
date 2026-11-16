// `ha decrees`: the record of the decrees a cluster applied, read over
// armTLS from a replica. Every record carries the result of checking its
// signature against the keys the configuration pins.

package cds

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

type decreesOptions struct {
	reach  clusterReach
	asJSON bool
}

func newDecreesCmd() *cobra.Command {
	var o decreesOptions
	cmd := &cobra.Command{
		Use:   "decrees",
		Short: "Print the decrees a cluster applied, with every operator signature checked",
		Long: "Reads the record of applied decrees from the first replica of the cluster that answers, over\n" +
			"armTLS: the record is what the replicas agree the operator decided, in the order they applied\n" +
			"it. Every record's signature is checked against the operator keys the configuration pins, and\n" +
			"a record that does not verify carries the reason.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}
	bindReachFlags(cmd, &o.reach)
	cmd.Flags().BoolVar(&o.asJSON, "json", false, "print the records as JSON, each with the result of its signature check")
	return cmd
}

func (o decreesOptions) run(cmd *cobra.Command) error {
	c, replicas, err := o.reach.cluster(cmd.Context())
	if err != nil {
		return err
	}
	return o.report(cmd, c, replicas)
}

func (o decreesOptions) report(cmd *cobra.Command, c decreeConfig, replicas []replica) error {
	address, body, err := signedStateOfAnyReplica(cmd.Context(), replicas, decreesPath, maxDecreeRecord)
	if err != nil {
		return err
	}
	var records []cdsha.DecreeRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return fmt.Errorf("the record replica %s serves: %w", address, err)
	}
	checked := checkRecords(records, c)
	if err := printRecords(cmd.OutOrStdout(), checked, o.asJSON); err != nil {
		return err
	}
	return anyUnverified(checked)
}

type appliedDecree struct {
	cdsha.DecreeRecord
	Unverified string `json:"unverified,omitempty"`
}

// Each record carries the result, so no verdict is printed beside it.
func checkRecords(records []cdsha.DecreeRecord, c decreeConfig) []appliedDecree {
	checked := make([]appliedDecree, 0, len(records))
	for _, record := range records {
		applied := appliedDecree{DecreeRecord: record}
		if err := cdsdecree.Verify(record.Decree, c.parsed.OperatorKeys.Keys(), c.parsed.ClusterID); err != nil {
			applied.Unverified = err.Error()
		}
		checked = append(checked, applied)
	}
	return checked
}

// A cluster holding a decree the operator cannot read as their own is one to
// look at before acting on it.
func anyUnverified(checked []appliedDecree) error {
	unverified := 0
	for _, applied := range checked {
		if applied.Unverified != "" {
			unverified++
		}
	}
	if unverified == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d records do not verify against the operator keys this configuration pins", unverified, len(checked))
}

func printRecords(w io.Writer, checked []appliedDecree, asJSON bool) error {
	if asJSON {
		return printJSON(w, checked)
	}
	for _, applied := range checked {
		fmt.Fprintln(w, recordLine(applied))
	}
	return nil
}

// Whatever else the decree carries is in the JSON --json prints.
func recordLine(applied appliedDecree) string {
	d := applied.Decree.Decree
	line := fmt.Sprintf("version=%d applied=%s kind=%q intent=%q base_version=%d",
		applied.Version, time.UnixMilli(applied.AtMS).UTC().Format(time.RFC3339), d.Kind, d.IntentID, d.BaseVersion)
	if applied.Unverified == "" {
		return line
	}
	return fmt.Sprintf("%s unverified=%q", line, applied.Unverified)
}
