package podprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// instanceSweepInterval spaces the listings of the provider's instances.
	instanceSweepInterval = time.Minute
)

// sweepInstances destroys the provider's cloud instances that no record
// owns. The record sweep cannot find them: it starts from the records. It
// creates nothing, and it runs only while the provider owns its node.
func (r *Reconciler) sweepInstances(ctx context.Context) error {
	// An empty ID would match an instance that carries no provider label.
	if r.cfg.ProviderID == "" {
		return errors.New("the provider has no ID to list instances by")
	}
	if r.ownsNode != nil {
		if err := r.ownsNode(ctx); err != nil {
			return fmt.Errorf("provider node: %w", err)
		}
	}
	instances, err := r.cloud.List(ctx, r.cfg.ProviderID)
	if err != nil {
		return err
	}
	var errs []error
	for i := range instances {
		if err := r.sweepInstance(ctx, &instances[i]); err != nil {
			errs = append(errs, fmt.Errorf("instance %s: %w", instances[i].ID, err))
		}
	}
	return errors.Join(errs...)
}

// sweepInstance destroys in when it carries this provider's labels and its
// record is absent. Any record protects its instance, whatever instance it
// names, so a record found needs no lock. Absence is decided again under the
// lock that serializes record creation and teardown, after the listing, so a
// record written meanwhile protects its instance too.
func (r *Reconciler) sweepInstance(ctx context.Context, in *instance) error {
	allocation := in.Labels[allocationLabel]
	if in.ID == "" || in.Status == "terminated" || in.Labels[providerLabel] != r.cfg.ProviderID || !allocationValue.MatchString(allocation) {
		return nil
	}
	key := recordPrefix + allocation
	if absent, err := r.recordAbsent(ctx, key); !absent {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if absent, err := r.recordAbsent(ctx, key); !absent {
		return err
	}
	return r.cloud.Delete(ctx, in.ID)
}

// recordAbsent reports whether no record exists under key. A record that
// cannot be read is not an absent one, and only the API server's own not-found
// answer is absence: a bare 404 from something in front of it is a failed read.
func (r *Reconciler) recordAbsent(ctx context.Context, key string) (bool, error) {
	_, _, err := r.loadRecord(ctx, key)
	if apierrors.ReasonForError(err) == metav1.StatusReasonNotFound {
		return true, nil
	}
	return false, err
}
