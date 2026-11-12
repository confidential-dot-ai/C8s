// `ha status`: what every replica of a cluster reports about it, one table row
// each, a line for every alarm a replica raises, and a line saying whether
// they describe one cluster. A status is one replica's own word, so the
// command compares them and refuses a cluster whose replicas do not agree.

package cds

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"text/tabwriter"

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
		Long: "Reads every replica of the cluster over armTLS and prints one row per replica, a line for each\n" +
			"alarm a replica raises, and a last line saying whether the replicas describe one cluster: one\n" +
			"leader, one set of voter seats and one applied version. A replica that answers nothing, that\n" +
			"does not serve, or that reports a column it cannot know carries - in that column.\n\n" +
			"--json prints each replica's whole report. Every value a replica reports is quoted, because\n" +
			"the replica is what the command audits.",
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
	printSummary(w, reports)
	return nil
}

// The cluster as its replicas describe it: one row each, the alarms they
// raise, and whether they describe one cluster.
func printSummary(w io.Writer, reports []replicaReport) {
	if len(reports) == 0 {
		return
	}
	printRows(w, reports)
	for _, report := range reports {
		for _, alarm := range alarms(report) {
			fmt.Fprintf(w, "%s ALARM: %s\n", report.Address, alarm)
		}
	}
	fmt.Fprintln(w, clusterLine(reports))
}

func printRows(w io.Writer, reports []replicaReport) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDRESS\tMEMBER\tROLE\tVOTER\tVERSION\tHEALTH")
	for _, report := range reports {
		row := rowOf(report)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			row.address, row.member, row.role, row.voter, row.version, row.health)
	}
	tw.Flush()
}

// replicaRow is one replica's row. Every value the replica supplies is
// quoted, so nothing it reports can read as a column of its own.
type replicaRow struct {
	address string
	member  string
	role    string
	voter   string
	version string
	health  string
}

func rowOf(report replicaReport) replicaRow {
	if report.Status == nil {
		return replicaRow{
			address: report.Address,
			member:  "-",
			role:    "-",
			voter:   "-",
			version: "-",
			health:  fmt.Sprintf("unreachable: %q", report.Error),
		}
	}
	reported := *report.Status
	return replicaRow{
		address: report.Address,
		member:  fmt.Sprintf("%q", reported.ID),
		role:    reportedRole(reported),
		voter:   reportedVote(reported),
		version: strconv.FormatUint(reported.Version, 10),
		health:  reportedHealth(reported),
	}
}

// Whether this replica leads, follows, or knows no leader at all.
func reportedRole(reported cdsha.Status) string {
	switch reported.Leader {
	case "":
		return "-"
	case reported.ID:
		return "leader"
	}
	return "follower"
}

// Whether this replica fills one of the voter seats it names, and none from
// one that names no seats at all.
func reportedVote(reported cdsha.Status) string {
	if len(reported.Voters) == 0 {
		return "-"
	}
	if slices.Contains(reported.Voters, reported.ID) {
		return "yes"
	}
	return "no"
}

// What the replica says of its own service, in its words where it serves
// nothing.
func reportedHealth(reported cdsha.Status) string {
	if reported.Serving.OK {
		return "serving"
	}
	return fmt.Sprintf("does not serve: %q", reported.Serving.Reason)
}

// The alarms a replica raises, in the words it reports them. What it serves
// is its row's health, so no alarm restates it.
func alarms(report replicaReport) []string {
	if report.Status == nil {
		return nil
	}
	reported := *report.Status
	var raised []string
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

// clusterLine is the answer the operator reads: the cluster the replicas
// describe together, or the first thing they do not agree on. The exit status
// is disagreement's, which holds the cluster to more than this.
func clusterLine(reports []replicaReport) string {
	answered, whole := everyReplicaAnswered(reports)
	switch {
	case !whole:
		return "the replicas do not agree: one of them answered nothing"
	case !oneOfThemLeads(answered):
		return "the replicas do not agree: they name no one leader"
	case !theyNameOneVoterSet(answered):
		return "the replicas do not agree: they name different voter seats"
	case !theyHoldOneVersion(answered):
		return "the replicas do not agree: they have applied different versions"
	}
	agreed := answered[0]
	return fmt.Sprintf("the replicas agree: leader %q, %d voter seats, version %d",
		agreed.Leader, len(agreed.Voters), agreed.Version)
}

// The statuses of every replica, and whether each of them answered one.
func everyReplicaAnswered(reports []replicaReport) ([]cdsha.Status, bool) {
	answered := make([]cdsha.Status, 0, len(reports))
	for _, report := range reports {
		if report.Status == nil {
			return nil, false
		}
		answered = append(answered, *report.Status)
	}
	return answered, true
}

// One member every replica follows, and one replica that is it.
func oneOfThemLeads(answered []cdsha.Status) bool {
	leader := answered[0].Leader
	if leader == "" {
		return false
	}
	led := false
	for _, reported := range answered {
		if reported.Leader != leader {
			return false
		}
		led = led || reported.ID == leader
	}
	return led
}

func theyNameOneVoterSet(answered []cdsha.Status) bool {
	seats := answered[0].Voters
	return !slices.ContainsFunc(answered, func(reported cdsha.Status) bool {
		return !sameMembers(reported.Voters, seats)
	})
}

func sameMembers(members, others []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(members)), slices.Sorted(slices.Values(others)))
}

func theyHoldOneVersion(answered []cdsha.Status) bool {
	version := answered[0].Version
	return !slices.ContainsFunc(answered, func(reported cdsha.Status) bool {
		return reported.Version != version
	})
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
