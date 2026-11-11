package podprovider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// providerLabel and allocationLabel are the labels every instance the
	// provider creates carries: its provider ID, and its record's key without
	// recordPrefix.
	providerLabel   = "podcvm-provider"
	allocationLabel = "podcvm-uid"
	recordPrefix    = "podcvm-"
	// instanceSweepInterval spaces the listings of the provider's instances.
	instanceSweepInterval = time.Minute
)

// allocationValue is the shape of an allocation label: identityKey's digest.
var allocationValue = regexp.MustCompile(`^[0-9a-f]{40}$`)

// sweepInstances destroys the provider's cloud instances that no record
// owns. The record sweep cannot find them: it starts from the records. It
// creates nothing, and it runs only while the provider owns its node.
func (r *Reconciler) sweepInstances(ctx context.Context) error {
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
// record is absent. The record is read under the lock that serializes record
// creation and teardown, after the listing, so a record written meanwhile
// protects its instance. Any record protects it, whatever instance it names;
// a record that cannot be read is not an absent one.
func (r *Reconciler) sweepInstance(ctx context.Context, in *instance) error {
	allocation := in.Labels[allocationLabel]
	if in.ID == "" || in.Status == "terminated" || in.Labels[providerLabel] != r.cfg.ProviderID || !allocationValue.MatchString(allocation) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _, err := r.loadRecord(ctx, recordPrefix+allocation)
	if !apierrors.IsNotFound(err) {
		return err
	}
	if err := r.cloud.Delete(ctx, in.ID); err != nil && !errors.Is(err, errCloudNotFound) {
		return err
	}
	return nil
}
