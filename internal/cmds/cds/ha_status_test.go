package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// A cluster whose configuration names the replica set a read command covers.
func newReplicatedCluster(t *testing.T) operatorCluster {
	t.Helper()
	c := newOperatorCluster(t)
	c.config = replicatedDocument(t, c.operatorPEM)
	writeTestFile(t, c.configPath, c.config)
	writeTestFile(t, c.cdsPinPath, []byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(c.config))))
	return c
}

func (c operatorCluster) decreed(t *testing.T) decreeConfig {
	t.Helper()
	read, err := readDecreeConfig(c.configPath)
	if err != nil {
		t.Fatal(err)
	}
	return read
}

// Each replica answers on an armTLS server of its own.
func (c operatorCluster) replicasServing(t *testing.T, replicas ...map[string]any) []replica {
	t.Helper()
	serving := make([]replica, 0, len(replicas))
	for _, routes := range replicas {
		serving = append(serving, c.replicaServing(t, routes))
	}
	return serving
}

// A port nothing answers at, as a lost VM leaves one.
func (c operatorCluster) unreachable() replica {
	return replica{
		address:  "127.0.0.1:1",
		cdsPin:   c.cdsPinPath,
		verifier: c.verifier(),
	}
}

// Every replica of the fixture follows "first", the leader of its cluster.
func (c operatorCluster) serving(member string, version uint64) cdsha.Status {
	return cdsha.Status{
		ClusterID:         c.clusterID,
		ID:                member,
		Joined:            true,
		Serving:           cdsha.Serving{OK: true},
		Version:           version,
		NodeImagesVersion: version - 1,
		State:             "Follower",
		Term:              4,
		Leader:            "first",
		AppliedIndex:      12,
		Voters:            []string{"first", "second", "third"},
		CAFingerprint:     "ca12",
	}
}

// Runs one read command's own work and answers with what it printed.
func reading(t *testing.T, run func(*cobra.Command) error) (string, error) {
	t.Helper()
	var printed bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&printed)
	cmd.SetErr(io.Discard)
	err := run(cmd)
	return printed.String(), err
}

func (c operatorCluster) reportStatus(t *testing.T, o statusOptions, replicas []replica) (string, error) {
	t.Helper()
	return reading(t, func(cmd *cobra.Command) error {
		return o.report(cmd, c.decreed(t), replicas)
	})
}

func TestStatusPrintsARowPerReplicaThenTheClusterLine(t *testing.T) {
	c := newReplicatedCluster(t)
	replicas := c.replicasServing(t,
		map[string]any{statusPath: c.serving("first", 7)},
		map[string]any{statusPath: c.serving("second", 7)},
	)

	printed, err := c.reportStatus(t, statusOptions{}, replicas)
	if err != nil {
		t.Fatalf("status on a cluster whose replicas agree: %v", err)
	}
	rows := printedRows(t, printed, 2)
	want := []printedRow{
		{
			address: replicas[0].address,
			member:  `"first"`,
			role:    "leader",
			voter:   "yes",
			version: "7",
			health:  "serving",
		},
		{
			address: replicas[1].address,
			member:  `"second"`,
			role:    "follower",
			voter:   "yes",
			version: "7",
			health:  "serving",
		},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("status printed rows %+v, want %+v", rows, want)
	}
	if last := lastLine(printed); last != `the replicas agree: leader "first", 3 voter seats, version 7` {
		t.Errorf("the cluster line is %q", last)
	}
}

func TestStatusRowCarriesWhyAReplicaServesNothing(t *testing.T) {
	c := newReplicatedCluster(t)
	stuck := c.serving("second", 7)
	stuck.Serving = cdsha.Serving{
		OK:     false,
		Reason: "this replica stopped following the log",
	}
	stuck.Stuck = "its allowlist database failed"
	replicas := c.replicasServing(t,
		map[string]any{statusPath: c.serving("first", 7)},
		map[string]any{statusPath: stuck},
	)

	printed, err := c.reportStatus(t, statusOptions{}, replicas)
	if err == nil {
		t.Fatal("a cluster with a replica that serves nothing read as one the operator may act on")
	}
	if !strings.Contains(printed, `does not serve: "this replica stopped following the log"`) {
		t.Errorf("the replica's row does not say why it serves nothing:\n%s", printed)
	}
	if !strings.Contains(printed, "ALARM: this replica stopped following the log: its allowlist database failed") {
		t.Errorf("no alarm names the fault the replica reports:\n%s", printed)
	}
}

func TestStatusQuotesWhatAReplicaReports(t *testing.T) {
	c := newReplicatedCluster(t)
	forging := c.serving("first\"\tleader\tyes\t0\tserving\nelsewhere", 7)
	replicas := c.replicasServing(t, map[string]any{statusPath: forging})

	printed, _ := c.reportStatus(t, statusOptions{}, replicas)
	row := printedRows(t, printed, 1)[0]
	if row.member != fmt.Sprintf("%q", forging.ID) {
		t.Fatalf("the member id the replica reported is not one quoted column: %+v", row)
	}
	// Every other column is what the command wrote, not what the id forged.
	if row.role != "follower" || row.voter != "no" || row.version != "7" || row.health != "serving" {
		t.Errorf("a member id the replica chose wrote columns of its own: %+v", row)
	}
}

func TestStatusReportsNoVoteFromAReplicaThatNamesNoSeats(t *testing.T) {
	c := newReplicatedCluster(t)
	unjoined := cdsha.Status{
		ClusterID: c.clusterID,
		ID:        "first",
		Serving: cdsha.Serving{
			OK:     false,
			Reason: "this replica holds no cluster",
		},
	}
	replicas := c.replicasServing(t, map[string]any{statusPath: unjoined})

	printed, _ := c.reportStatus(t, statusOptions{}, replicas)
	row := printedRows(t, printed, 1)[0]
	if row.role != "-" || row.voter != "-" {
		t.Errorf("a replica that named no seats reports a role and a vote: %+v", row)
	}
}

func TestStatusReportsADivergenceAsAnAlarm(t *testing.T) {
	c := newReplicatedCluster(t)
	leading := c.serving("first", 9)
	leading.Divergence = "member second holds another state at log index 12"
	replicas := c.replicasServing(t, map[string]any{statusPath: leading})

	printed, _ := c.reportStatus(t, statusOptions{}, replicas)
	if !strings.Contains(printed, "ALARM: the replicas of this cluster hold different state: member second holds another state") {
		t.Errorf("the divergence the leader found raises no alarm:\n%s", printed)
	}
}

func TestStatusSaysWhatTheReplicasDoNotAgreeOn(t *testing.T) {
	c := newReplicatedCluster(t)
	noLeader := c.serving("second", 7)
	noLeader.Leader = ""
	otherSeats := c.serving("second", 7)
	otherSeats.Voters = []string{"first", "second"}
	for name, replicas := range map[string]struct {
		served []map[string]any
		says   string
	}{
		"no one leader": {
			served: []map[string]any{
				{statusPath: c.serving("first", 7)},
				{statusPath: noLeader},
			},
			says: "they name no one leader",
		},
		"different voter seats": {
			served: []map[string]any{
				{statusPath: c.serving("first", 7)},
				{statusPath: otherSeats},
			},
			says: "they name different voter seats",
		},
		"different versions": {
			served: []map[string]any{
				{statusPath: c.serving("first", 7)},
				{statusPath: c.serving("second", 8)},
			},
			says: "they have applied different versions",
		},
	} {
		t.Run(name, func(t *testing.T) {
			printed, _ := c.reportStatus(t, statusOptions{}, c.replicasServing(t, replicas.served...))
			if last := lastLine(printed); !strings.Contains(last, replicas.says) {
				t.Errorf("the cluster line is %q, want it to say %q", last, replicas.says)
			}
		})
	}
}

// printedRow is one replica's row, cut at the header's columns as a reader
// sees them.
type printedRow struct {
	address string
	member  string
	role    string
	voter   string
	version string
	health  string
}

// The rows of as many replicas as the status covers.
func printedRows(t *testing.T, printed string, replicas int) []printedRow {
	t.Helper()
	lines := strings.Split(strings.TrimRight(printed, "\n"), "\n")
	if len(lines) < replicas+1 {
		t.Fatalf("status printed %d lines, want a header and %d rows:\n%s", len(lines), replicas, printed)
	}
	columns := columnStarts(t, lines[0])
	rows := make([]printedRow, 0, replicas)
	for _, line := range lines[1 : replicas+1] {
		cells := cutAt(line, columns)
		rows = append(rows, printedRow{
			address: cells[0],
			member:  cells[1],
			role:    cells[2],
			voter:   cells[3],
			version: cells[4],
			health:  cells[5],
		})
	}
	return rows
}

func columnStarts(t *testing.T, header string) []int {
	t.Helper()
	starts := make([]int, 0, 6)
	for _, column := range []string{"ADDRESS", "MEMBER", "ROLE", "VOTER", "VERSION", "HEALTH"} {
		at := strings.Index(header, column)
		if at < 0 {
			t.Fatalf("the table has no %s column: %q", column, header)
		}
		starts = append(starts, at)
	}
	return starts
}

func cutAt(line string, starts []int) []string {
	cells := make([]string, 0, len(starts))
	for i, start := range starts {
		end := len(line)
		if i+1 < len(starts) && starts[i+1] < end {
			end = starts[i+1]
		}
		if start > len(line) {
			start = len(line)
		}
		cells = append(cells, strings.TrimSpace(line[start:end]))
	}
	return cells
}

func lastLine(printed string) string {
	lines := strings.Split(strings.TrimRight(printed, "\n"), "\n")
	return lines[len(lines)-1]
}

func TestStatusRefusesReplicasThatHoldDifferentState(t *testing.T) {
	c := newReplicatedCluster(t)
	otherCA := c.serving("third", 7)
	otherCA.CAFingerprint = "ca99"
	for name, served := range map[string][]map[string]any{
		"another version": {
			{statusPath: c.serving("first", 7)},
			{statusPath: c.serving("second", 8)},
		},
		"another mesh CA": {
			{statusPath: c.serving("first", 7)},
			{statusPath: otherCA},
		},
		"another cluster": {
			{statusPath: c.serving("first", 7)},
			{statusPath: cdsha.Status{
				ClusterID: "elsewhere",
				ID:        "second",
				Joined:    true,
				Serving:   cdsha.Serving{OK: true},
			}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.reportStatus(t, statusOptions{}, c.replicasServing(t, served...)); err == nil {
				t.Fatalf("status read %s as a cluster the operator may act on", name)
			}
		})
	}
}

func TestStatusReportsAReplicaThatAnswersNothing(t *testing.T) {
	c := newReplicatedCluster(t)
	replicas := append(c.replicasServing(t, map[string]any{statusPath: c.serving("first", 7)}), c.unreachable())

	printed, err := c.reportStatus(t, statusOptions{}, replicas)
	if err == nil {
		t.Fatal("status read a cluster with an unreachable replica as a whole one")
	}
	if !strings.Contains(printed, "127.0.0.1:1") {
		t.Errorf("the unreachable replica has no row of its own:\n%s", printed)
	}
	if !strings.Contains(printed, `unreachable: "Get `) {
		t.Errorf("its row does not carry what the read reported:\n%s", printed)
	}
}

func TestStatusJSONCarriesWhatEveryReplicaAnswered(t *testing.T) {
	c := newReplicatedCluster(t)
	replicas := c.replicasServing(t, map[string]any{statusPath: c.serving("first", 7)})

	printed, err := c.reportStatus(t, statusOptions{asJSON: true}, replicas)
	if err != nil {
		t.Fatal(err)
	}
	var reports []replicaReport
	if err := json.Unmarshal([]byte(printed), &reports); err != nil {
		t.Fatalf("--json printed %q: %v", printed, err)
	}
	if len(reports) != 1 || reports[0].Status == nil || reports[0].Status.AppliedIndex != 12 {
		t.Fatalf("--json reported %+v", reports)
	}
}

func TestStatusOnNoReplicaIsNoAnswer(t *testing.T) {
	c := newReplicatedCluster(t)
	if _, err := c.reportStatus(t, statusOptions{}, nil); err != nil {
		t.Fatalf("reporting no replica = %v, want it to print nothing and say nothing", err)
	}
}

func TestTheReachResolvesTheConfigurationsReplicaEntries(t *testing.T) {
	c := newReplicatedCluster(t)
	reach := clusterReach{
		config: c.configPath,
		cdsPin: c.cdsPinPath,
	}

	_, replicas, err := reach.cluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(replicas) != 1 || replicas[0].address != "127.0.0.9:8443" {
		t.Fatalf("the reach covers %+v, want the configuration's replica entry at the replica port", replicas)
	}
	reach.urls = []string{"127.0.0.8:9443"}
	_, named, err := reach.cluster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(named) != 1 || named[0].address != "127.0.0.8:9443" {
		t.Fatalf("the reach covers %+v, want the replica --url names", named)
	}
}

func TestTheReachRefusesASingletonConfigurationWithoutAURL(t *testing.T) {
	c := newOperatorCluster(t)
	reach := clusterReach{
		config: c.configPath,
		cdsPin: c.cdsPinPath,
	}

	if _, _, err := reach.cluster(context.Background()); err == nil || !strings.Contains(err.Error(), "no replica set") {
		t.Fatalf("the reach of a singleton's configuration = %v", err)
	}
	reach.urls = []string{"127.0.0.8"}
	if _, replicas, err := reach.cluster(context.Background()); err != nil || len(replicas) != 1 {
		t.Fatalf("the reach of %v = %+v, %v", reach.urls, replicas, err)
	}
}
