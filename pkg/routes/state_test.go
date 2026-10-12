package routes

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func signedAt(revision uint64, notBefore time.Time, maxAge time.Duration) *Signed {
	return &Signed{
		manifest: &Manifest{Revision: revision, NotBefore: notBefore, MaxAge: maxAge},
		digest:   [32]byte{byte(revision)},
	}
}

func fetch(t *testing.T, st *State, s *Signed, now time.Time) bool {
	t.Helper()
	changed, err := st.Fetched(s, now)
	if err != nil {
		t.Fatalf("Fetched(revision %d) = %v, want nil", s.manifest.Revision, err)
	}
	return changed
}

func TestStateFutureActivation(t *testing.T) {
	var st State
	r1, r2 := signedAt(1, t0, time.Hour), signedAt(2, t0.Add(2*time.Hour), time.Hour)
	if !fetch(t, &st, r1, t0) || st.Applied() != r1 {
		t.Fatal("Fetched(due revision 1) did not apply it")
	}
	if fetch(t, &st, r2, t0.Add(30*time.Minute)) || st.Applied() != r1 || st.Pending() != r2 {
		t.Fatal("Fetched(revision 2 before its notBefore) applied it, want it staged")
	}
	if st.advance(t0.Add(time.Hour)) {
		t.Error("advance before notBefore = true, want false")
	}
	if !st.advance(t0.Add(2*time.Hour)) || st.Applied() != r2 || st.Pending() != nil {
		t.Error("advance at notBefore did not apply revision 2")
	}
}

func TestStateStagedReplaced(t *testing.T) {
	var st State
	fetch(t, &st, signedAt(1, t0, time.Hour), t0)
	fetch(t, &st, signedAt(2, t0.Add(2*time.Hour), time.Hour), t0)
	r3 := signedAt(3, t0.Add(time.Hour), time.Hour)
	fetch(t, &st, r3, t0)
	if st.Pending() != r3 {
		t.Errorf("Pending() = revision %d, want the higher revision 3", st.Pending().manifest.Revision)
	}
}

func TestStateStagedKept(t *testing.T) {
	conflict := func(revision uint64) *Signed {
		s := signedAt(revision, t0, time.Hour)
		s.digest[1] = 1
		return s
	}
	tests := []struct {
		name    string
		fetched *Signed
		want    error
	}{
		{"W4 lower revision than staged", signedAt(2, t0, time.Hour), ErrRollback},
		{"W4 applied revision", signedAt(1, t0, time.Hour), ErrRollback},
		{"W4 staged revision, other digest", conflict(3), ErrRevisionConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var st State
			r1, r3 := signedAt(1, t0, time.Hour), signedAt(3, t0.Add(2*time.Hour), time.Hour)
			fetch(t, &st, r1, t0)
			fetch(t, &st, r3, t0)
			if _, err := st.Fetched(tt.fetched, t0.Add(30*time.Minute)); !errors.Is(err, tt.want) {
				t.Fatalf("Fetched() = %v, want %v", err, tt.want)
			}
			if st.Applied() != r1 || st.Pending() != r3 || st.Status(t0.Add(time.Hour)) != Stale {
				t.Error("a rejected fetch changed the State (A6)")
			}
		})
	}
}

func TestStateStagedRefresh(t *testing.T) {
	var st State
	r1, r2 := signedAt(1, t0, time.Hour), signedAt(2, t0.Add(2*time.Hour), time.Hour)
	fetch(t, &st, r1, t0)
	fetch(t, &st, r2, t0)
	if fetch(t, &st, signedAt(2, t0.Add(2*time.Hour), time.Hour), t0.Add(50*time.Minute)) {
		t.Error("Fetched(the staged manifest) reported a change")
	}
	if st.Applied() != r1 || st.Pending() != r2 || st.Status(t0.Add(time.Hour)) != Fresh {
		t.Error("Fetched(the staged manifest) did not only renew freshness (F3)")
	}
}

func TestStateIgnoresConsumerChanges(t *testing.T) {
	var st State
	fetch(t, &st, signedAt(1, t0, time.Hour), t0)
	fetch(t, &st, signedAt(2, t0.Add(2*time.Hour), time.Hour), t0)
	st.Applied().Manifest().MaxAge = 0
	st.Pending().Manifest().NotBefore = t0
	if st.advance(t0.Add(time.Minute)) || st.Status(t0.Add(time.Minute)) != Fresh {
		t.Error("changing a returned Manifest changed the State")
	}
}

func TestStateRefreshFailure(t *testing.T) {
	var st State
	r2 := signedAt(2, t0, time.Hour)
	fetch(t, &st, r2, t0)
	if _, err := st.Fetched(signedAt(1, t0, time.Hour), t0.Add(30*time.Minute)); !errors.Is(err, ErrRollback) {
		t.Fatalf("Fetched(revision 1 after 2) = %v, want ErrRollback", err)
	}
	if st.Applied() != r2 || st.Pending() != nil {
		t.Error("a rejected fetch changed the State (A6)")
	}
	if st.Status(t0.Add(time.Hour)) != Stale {
		t.Error("Status an hour after the last accepted fetch is not Stale: a rejected fetch renewed freshness")
	}
}

func TestStateRefreshRenewsFreshness(t *testing.T) {
	var st State
	r1 := signedAt(1, t0, time.Hour)
	fetch(t, &st, r1, t0)
	if st.Status(t0.Add(59*time.Minute)) != Fresh {
		t.Error("Status before MaxAge is not Fresh")
	}
	if fetch(t, &st, r1, t0.Add(59*time.Minute)) {
		t.Error("Fetched(the applied manifest) reported a change")
	}
	if st.Status(t0.Add(90*time.Minute)) != Fresh {
		t.Error("Status after a same-revision refresh is not Fresh (F3)")
	}
}

func TestStateExpiryWhileWaiting(t *testing.T) {
	var st State
	fetch(t, &st, signedAt(1, t0, time.Hour), t0)
	r2 := signedAt(2, t0.Add(3*time.Hour), time.Hour)
	fetch(t, &st, r2, t0.Add(30*time.Minute))
	if st.Status(t0.Add(90*time.Minute)) != Stale {
		t.Error("Status an hour after the last fetch, revision 2 staged, is not Stale")
	}
	st.advance(t0.Add(3 * time.Hour))
	if st.Applied() != r2 || st.Status(t0.Add(3*time.Hour)) != Stale {
		t.Error("revision 2 applied after MaxAge without a refresh is not stale")
	}
}

func TestStateEmpty(t *testing.T) {
	var st State
	if st.Applied() != nil || st.Status(t0) != Unapplied || st.advance(t0) {
		t.Error("zero State is not Unapplied")
	}
	if fetch(t, &st, signedAt(5, t0.Add(time.Hour), time.Hour), t0) || st.Applied() != nil || st.Status(t0) != Unapplied {
		t.Error("Fetched(a future manifest) on an empty State applied it, want Unapplied (A2)")
	}
}

func TestStateStagedAppliedByFetch(t *testing.T) {
	var st State
	r1, r2 := signedAt(1, t0, time.Hour), signedAt(2, t0.Add(time.Hour), time.Hour)
	fetch(t, &st, r1, t0)
	fetch(t, &st, r2, t0)
	if !fetch(t, &st, r2, t0.Add(time.Hour)) || st.Applied() != r2 || st.Pending() != nil {
		t.Error("Fetched(the staged manifest at its notBefore) did not apply it (A4)")
	}
}
