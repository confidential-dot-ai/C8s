package getcert

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// A guest that loses its admission evidence during a renewal withdraws the
// published generation inside that request, and its retry is paced by the
// unpublished backoff.
func TestGuestEvidenceLossDuringRenewalRetriesOnUnpublishedBackoff(t *testing.T) {
	creds := publishedCredentials(t, newTestCA(t), time.Hour)
	guest := GuestConfig{
		InstanceID: testInstanceID,
		Snapshot: func(context.Context) (workloadclaims.PodClaims, error) {
			return workloadclaims.PodClaims{}, errors.New("admission evidence lost")
		},
	}
	unpublishedFirstRetry := time.Second
	cfg := config{RenewInterval: time.Hour, InitialRetryInterval: unpublishedFirstRetry, guest: &guest}
	r := newRenewer(cfg, attestclient.Client{}, allowlistclient.Client{}, creds)
	defer r.stop()
	r.unpublishedRetry.RandomizationFactor = 0

	before := time.Now()
	if err := r.renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	if creds.current != nil {
		t.Fatal("the guest kept its generation published after losing admission evidence")
	}
	if r.renewDue.Before(before.Add(unpublishedFirstRetry)) || r.renewDue.After(after.Add(unpublishedFirstRetry)) {
		t.Fatalf("next attempt due in %v, want the unpublished backoff's %v, not the failed-renewal retry from %v", time.Until(r.renewDue), unpublishedFirstRetry, renewalRetryBase)
	}
}
