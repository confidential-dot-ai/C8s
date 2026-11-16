package cdsha

import (
	"errors"
	"testing"
)

// The cluster's agreed format only rises, and only to one this replica reads:
// a replica that met a newer entry would have to skip it.
func TestTheAgreedFormatOnlyRises(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	r.readable = Format + 1
	raise := Entry{
		Kind:      KindFormat,
		SetFormat: Format + 1,
	}
	if res := r.apply(raise); res.Stop != nil {
		t.Fatalf("raising the format answered %v", res.Stop)
	}
	if got := r.ClusterState().format(); got != Format+1 {
		t.Fatalf("the agreed format is %d", got)
	}
	lower := Entry{
		Kind:      KindFormat,
		SetFormat: baseFormat,
	}
	if res := r.apply(lower); res.Stop != nil {
		t.Fatalf("an older format answered %v", res.Stop)
	}
	if got := r.ClusterState().format(); got != Format+1 {
		t.Fatalf("the agreed format fell back to %d", got)
	}
}

// A replica too old for the format the cluster agreed on stops rather than
// write entries the others cannot apply.
func TestAFormatNewerThanThisReplicaReadsStopsIt(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	res := r.apply(Entry{
		Kind:      KindFormat,
		SetFormat: Format + 1,
	})
	if !errors.Is(res.Stop, ErrNewerFormat) {
		t.Fatalf("applying a newer agreed format answered %+v", res)
	}
	if r.Stuck() == "" || r.StuckLocal() {
		t.Fatalf("stuck %q, this replica's own fault %v", r.Stuck(), r.StuckLocal())
	}
}

// An entry left without a format is in the oldest format this release reads.
func TestAnUnsetFormatIsTheBaseFormat(t *testing.T) {
	if got := (ClusterState{}).format(); got != baseFormat {
		t.Fatalf("an unset cluster format reads as %d", got)
	}
	r := newReplica(t)
	r.genesis()
	if got := r.ClusterState().Format; got != baseFormat {
		t.Fatalf("a new cluster writes format %d", got)
	}
}
