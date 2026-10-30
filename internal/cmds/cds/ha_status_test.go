package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func (c operatorCluster) serving(member string, version uint64) cdsha.Status {
	return cdsha.Status{
		ClusterID:     c.clusterID,
		ID:            member,
		Joined:        true,
		Serving:       cdsha.Serving{OK: true},
		Version:       version,
		State:         "Follower",
		Term:          4,
		AppliedIndex:  12,
		Voters:        []string{"first", "second", "third"},
		CAFingerprint: "ca12",
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

func TestStatusPrintsOneLinePerReplicaAndAnAlarmBeside(t *testing.T) {
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
	lines := strings.Split(strings.TrimSpace(printed), "\n")
	if len(lines) != 4 {
		t.Fatalf("status printed %d lines, want one per replica and one per alarm:\n%s", len(lines), printed)
	}
	if !strings.Contains(lines[0], `member="first" state="Follower" joined=true serving=true version=7`) {
		t.Errorf("the serving replica's line is %q", lines[0])
	}
	if !strings.Contains(printed, "ALARM: this replica stopped following the log: its allowlist database failed") {
		t.Errorf("no alarm names the fault the replica reports:\n%s", printed)
	}
}

func TestStatusQuotesWhatAReplicaReports(t *testing.T) {
	c := newReplicatedCluster(t)
	forging := c.serving(`first" serving=false version=0 `, 7)
	replicas := c.replicasServing(t, map[string]any{statusPath: forging})

	printed, _ := c.reportStatus(t, statusOptions{}, replicas)
	line := strings.TrimSpace(printed)
	member := fmt.Sprintf("%q", forging.ID)
	if !strings.Contains(line, "member="+member) {
		t.Fatalf("the member id the replica reported is not one quoted value: %q", line)
	}
	// Outside that value, the line carries only fields the command wrote.
	if beside := strings.Replace(line, member, "", 1); strings.Contains(beside, "serving=false") {
		t.Errorf("a member id the replica chose added a field to its line: %q", line)
	}
}

func TestStatusAcceptsReplicasThatHoldOneState(t *testing.T) {
	c := newReplicatedCluster(t)
	leading := c.serving("first", 9)
	leading.State = "Leader"
	leading.RollSafe = &cdsha.RollSafety{OK: true}
	replicas := c.replicasServing(t,
		map[string]any{statusPath: leading},
		map[string]any{statusPath: c.serving("second", 9)},
	)

	printed, err := c.reportStatus(t, statusOptions{}, replicas)
	if err != nil {
		t.Fatalf("status on a cluster whose replicas agree: %v", err)
	}
	if !strings.Contains(printed, `state="Leader"`) || !strings.Contains(printed, "roll_safe=true") {
		t.Errorf("the leader's line carries neither its state nor the roll gate:\n%s", printed)
	}
	if !strings.Contains(printed, "roll_safe=-") {
		t.Errorf("a replica that does not lead reports a roll gate it cannot know:\n%s", printed)
	}
}

func TestStatusReportsNoSeatsFromAReplicaThatNamesNone(t *testing.T) {
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
	if !strings.Contains(printed, "voters=- non_voters=-") {
		t.Errorf("a replica that named no seats reports a count of them:\n%s", printed)
	}
}

func TestStatusReportsTheCheckpointAndADivergence(t *testing.T) {
	c := newReplicatedCluster(t)
	leading := c.serving("first", 9)
	leading.Checkpoint = cdsha.Point{
		Index: 12,
		State: cdsha.Digests{}.State,
	}
	leading.Divergence = "member second holds another state at log index 12"
	replicas := c.replicasServing(t, map[string]any{statusPath: leading})

	printed, _ := c.reportStatus(t, statusOptions{}, replicas)
	if !strings.Contains(printed, `checkpoint="12:`) {
		t.Errorf("the line carries no checkpoint:\n%s", printed)
	}
	if !strings.Contains(printed, "ALARM: the replicas of this cluster hold different state: member second holds another state") {
		t.Errorf("the divergence the leader found raises no alarm:\n%s", printed)
	}
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
	if !strings.Contains(printed, "127.0.0.1:1 unreachable") {
		t.Errorf("the unreachable replica has no line of its own:\n%s", printed)
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
