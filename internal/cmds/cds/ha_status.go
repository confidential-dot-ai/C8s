// `ha status`: what every replica of a cluster reports about it, one line
// each, and a line for every alarm a replica raises. A status is one
// replica's own word, so the command compares them and refuses a cluster
// whose replicas do not agree.

package cds

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

type statusOptions struct {
	reach  clusterReach
	asJSON bool
}

func newStatusCmd() *cobra.Command {
	var o statusOptions
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report every replica of a cluster, and what it says is wrong",
		Long: "Reads every replica of the cluster over armTLS and prints one line per replica, then a line for\n" +
			"each alarm it raises: a replica that does not serve, one that stopped following the log, and a\n" +
			"cluster whose replicas hold different state. Only the leader knows the voter seats, the roll\n" +
			"gate and what the state digests say, so the other replicas report none of them, which the\n" +
			"line carries as -.\n\n" +
			"Every value a replica reports is quoted, because the replica is what the command audits.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}
	bindReachFlags(cmd, &o.reach)
	cmd.Flags().BoolVar(&o.asJSON, "json", false, "print each replica's whole report, as it answered it, instead of one line each")
	return cmd
}

func (o statusOptions) run(cmd *cobra.Command) error {
	c, replicas, err := o.reach.cluster(cmd.Context())
	if err != nil {
		return err
	}
	return o.report(cmd, c, replicas)
}

func (o statusOptions) report(cmd *cobra.Command, c decreeConfig, replicas []replica) error {
	reports := readReplicas(cmd.Context(), replicas)
	if err := o.print(cmd.OutOrStdout(), reports); err != nil {
		return err
	}
	return disagreement(reports, c.parsed.ClusterID)
}

type replicaReport struct {
	Address string        `json:"address"`
	Status  *cdsha.Status `json:"status,omitempty"`
	Error   string        `json:"error,omitempty"`
}

// One attested client verifies and reaches one replica.
func readReplicas(ctx context.Context, replicas []replica) []replicaReport {
	reports := make([]replicaReport, 0, len(replicas))
	for _, r := range replicas {
		reported, err := r.status(ctx)
		if err != nil {
			reports = append(reports, replicaReport{
				Address: r.address,
				Error:   err.Error(),
			})
			continue
		}
		reports = append(reports, replicaReport{
			Address: r.address,
			Status:  &reported,
		})
	}
	return reports
}

func (o statusOptions) print(w io.Writer, reports []replicaReport) error {
	if o.asJSON {
		return printJSON(w, reports)
	}
	for _, report := range reports {
		printReport(w, report)
	}
	return nil
}

// One replica's line, then one line per alarm. Every value the replica
// supplies is quoted, so nothing it reports can read as a field of its own.
func printReport(w io.Writer, report replicaReport) {
	if report.Status == nil {
		fmt.Fprintf(w, "%s unreachable\n", report.Address)
		printAlarm(w, report.Address, report.Error)
		return
	}
	reported := *report.Status
	fmt.Fprintf(w, "%s cluster=%q member=%q state=%q joined=%t serving=%t version=%d ca=%q voters=%s non_voters=%s applied=%d term=%d leader=%q roll_safe=%s checkpoint=%s\n",
		report.Address, reported.ClusterID, reported.ID, reported.State,
		reported.Joined, reported.Serving.OK, reported.Version, reported.CAFingerprint,
		reportedCount(reported.Voters), reportedCount(reported.NonVoters),
		reported.AppliedIndex, reported.Term, reported.Leader, reportedRollSafe(reported.RollSafe),
		reportedCheckpoint(reported.Checkpoint))
	for _, alarm := range alarms(reported) {
		printAlarm(w, report.Address, alarm)
	}
}

func printAlarm(w io.Writer, address, alarm string) {
	fmt.Fprintf(w, "%s ALARM: %s\n", address, alarm)
}

// In the words the replica reports them.
func alarms(reported cdsha.Status) []string {
	var raised []string
	if !reported.Serving.OK {
		raised = append(raised, "this replica does not serve its cluster: "+reported.Serving.Reason)
	}
	if reported.Stuck != "" {
		raised = append(raised, "this replica stopped following the log: "+reported.Stuck)
	}
	if safe := reported.RollSafe; safe != nil && !safe.OK {
		raised = append(raised, "no replica of this cluster may be replaced now: "+safe.Reason)
	}
	if reported.Divergence != "" {
		raised = append(raised, "the replicas of this cluster hold different state: "+reported.Divergence)
	}
	return raised
}

// None from a replica that named no seats at all.
func reportedCount(members []string) string {
	if len(members) == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", len(members))
}

// The log index and the digest, and none from a replica that recorded no
// checkpoint.
func reportedCheckpoint(point cdsha.Point) string {
	if point == (cdsha.Point{}) {
		return "-"
	}
	return fmt.Sprintf("%q", fmt.Sprintf("%d:%s", point.Index, point.State))
}

// None from a replica that does not lead and cannot know.
func reportedRollSafe(safe *cdsha.RollSafety) string {
	if safe == nil {
		return "-"
	}
	return fmt.Sprintf("%t", safe.OK)
}

// Why the operator cannot act on the replicas as one cluster. A replica that
// stopped following the log serves nothing, so it is caught here too.
func disagreement(reports []replicaReport, clusterID string) error {
	var first *replicaReport
	for i := range reports {
		report := &reports[i]
		if err := unusable(*report, clusterID); err != nil {
			return err
		}
		if first == nil {
			first = report
			continue
		}
		if err := differingState(*first, *report); err != nil {
			return err
		}
	}
	return nil
}

func unusable(report replicaReport, clusterID string) error {
	switch {
	case report.Status == nil:
		return fmt.Errorf("replica %s answered nothing: %s", report.Address, report.Error)
	case report.Status.ClusterID != clusterID:
		return fmt.Errorf("replica %s serves cluster %q, not %q", report.Address, report.Status.ClusterID, clusterID)
	case !report.Status.Serving.OK:
		return fmt.Errorf("replica %s does not serve its cluster: %s", report.Address, report.Status.Serving.Reason)
	}
	return nil
}

// The applied operator commands and the mesh CA are the cluster's, so a
// replica holding another one is a cluster no decree applies cleanly to.
func differingState(first, other replicaReport) error {
	switch {
	case other.Status.Version != first.Status.Version:
		return fmt.Errorf("replica %s has applied version %d, and replica %s version %d",
			other.Address, other.Status.Version, first.Address, first.Status.Version)
	case other.Status.CAFingerprint != first.Status.CAFingerprint:
		return fmt.Errorf("replica %s issues under mesh CA %q, and replica %s under %q",
			other.Address, other.Status.CAFingerprint, first.Address, first.Status.CAFingerprint)
	}
	return nil
}
