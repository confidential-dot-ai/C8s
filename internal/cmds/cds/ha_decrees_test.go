package cds

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// One decree as a replica serves its record of them.
func recordOf(signed cdsdecree.Signed, version uint64) cdsha.DecreeRecord {
	return cdsha.DecreeRecord{
		Decree:  signed,
		AtMS:    time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC).UnixMilli(),
		Version: version,
	}
}

func TestDecreesPrintsEveryDecreeTheClusterApplied(t *testing.T) {
	c := newReplicatedCluster(t)
	o := decreesOptions{}
	replicas := c.replicasServing(t, map[string]any{
		decreesPath: []cdsha.DecreeRecord{recordOf(c.pinDecree(t, smp2Digest), 4)},
	})

	printed, err := reading(t, func(cmd *cobra.Command) error { return o.report(cmd, c.decreed(t), replicas) })
	if err != nil {
		t.Fatalf("decrees on a record the cluster's operator signed: %v", err)
	}
	for _, want := range []string{
		"version=4",
		"applied=2026-10-30T12:00:00Z",
		`kind="UpdateMeasurements"`,
		"base_version=3",
	} {
		if !strings.Contains(printed, want) {
			t.Errorf("the record's line %q carries no %s", strings.TrimSpace(printed), want)
		}
	}
}

func TestDecreesRefusesARecordWithoutAnOperatorSignature(t *testing.T) {
	c := newReplicatedCluster(t)
	tampered := c.pinDecree(t, smp2Digest)
	tampered.Decree.BaseVersion = 99
	o := decreesOptions{}
	replicas := c.replicasServing(t, map[string]any{
		decreesPath: []cdsha.DecreeRecord{recordOf(tampered, 4)},
	})

	printed, err := reading(t, func(cmd *cobra.Command) error { return o.report(cmd, c.decreed(t), replicas) })
	if err == nil {
		t.Fatal("decrees read a record the operator never signed as the cluster's own")
	}
	if !strings.Contains(printed, "unverified=") {
		t.Errorf("the record that does not verify carries no reason:\n%s", printed)
	}
}

func TestDecreesJSONCarriesTheSignatureCheckOfEveryRecord(t *testing.T) {
	c := newReplicatedCluster(t)
	tampered := c.pinDecree(t, smp2Digest)
	tampered.Decree.BaseVersion = 99
	o := decreesOptions{asJSON: true}
	replicas := c.replicasServing(t, map[string]any{
		decreesPath: []cdsha.DecreeRecord{
			recordOf(c.pinDecree(t, smp2Digest), 4),
			recordOf(tampered, 5),
		},
	})

	printed, err := reading(t, func(cmd *cobra.Command) error { return o.report(cmd, c.decreed(t), replicas) })
	if err == nil {
		t.Fatal("decrees read a record the operator never signed as the cluster's own")
	}
	var checked []appliedDecree
	if err := json.Unmarshal([]byte(printed), &checked); err != nil {
		t.Fatalf("--json printed %q: %v", printed, err)
	}
	if len(checked) != 2 || checked[0].Unverified != "" || checked[1].Unverified == "" {
		t.Fatalf("--json reported %+v, want the second record carrying why it does not verify", checked)
	}
}

func TestDecreesReadsTheFirstReplicaThatAnswers(t *testing.T) {
	c := newReplicatedCluster(t)
	o := decreesOptions{}
	replicas := c.replicasServing(t,
		map[string]any{statusPath: c.serving("first", 4)},
		map[string]any{decreesPath: []cdsha.DecreeRecord{recordOf(c.pinDecree(t, smp2Digest), 4)}},
	)

	printed, err := reading(t, func(cmd *cobra.Command) error { return o.report(cmd, c.decreed(t), replicas) })
	if err != nil {
		t.Fatalf("decrees past a replica that serves no record: %v", err)
	}
	if !strings.Contains(printed, `kind="UpdateMeasurements"`) {
		t.Errorf("the record of the replica that answered is missing:\n%s", printed)
	}
}
