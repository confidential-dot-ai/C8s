package podprovider

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// instanceIntent retains one immutable Cloud create and its cleanup authority:
// the generic instance a pod record owns.
type instanceIntent struct {
	ProviderID      string        `json:"providerID"`
	CloudURL        string        `json:"cloudURL"`
	NodeName        string        `json:"nodeName"`
	Key             string        `json:"key"`
	Request         createRequest `json:"request"`
	Manifest        []byte        `json:"manifest"`
	VCPUs           int64         `json:"vCPUs"`
	MemoryMiB       int64         `json:"memoryMiB"`
	CreatedAt       time.Time     `json:"createdAt"`
	CreateAttempted bool          `json:"createAttempted,omitempty"`
	InstanceID      string        `json:"instanceID,omitempty"`
	DeleteRequested bool          `json:"deleteRequested,omitempty"`
	Deleted         bool          `json:"deleted,omitempty"`
}

// errForeignInstance reports an instance the cloud returned under the
// record's key or identity that the record did not create: another identity,
// or labels that differ from the frozen create. An answer naming no instance
// is not one: it shows nothing about the instance and is retried. Before the
// record holds an instance identity the reconciler retries a foreign instance
// as unavailable; after, it ends the pod with InstanceIdentityMismatch.
var errForeignInstance = errors.New("cloud instance is not the one the record created")

func (in *instanceIntent) owns(got *instance) error {
	if got == nil || got.ID == "" {
		return errors.New("cloud returned no instance identity")
	}
	if in.InstanceID != "" && got.ID != in.InstanceID {
		return fmt.Errorf("%w: another instance identity", errForeignInstance)
	}
	for k, value := range in.Request.Labels {
		if got.Labels[k] != value {
			return fmt.Errorf("%w: ownership labels differ from the frozen launch", errForeignInstance)
		}
	}
	return nil
}

func ensureCloudInstance(ctx context.Context, api cloudAPI, intent *instanceIntent, save func() error) (*instance, error) {
	var in *instance
	var err error
	if intent.InstanceID != "" {
		in, err = api.Get(ctx, intent.InstanceID)
		if errors.Is(err, errCloudNotFound) {
			return nil, nil
		}
	} else {
		in, err = api.Find(ctx, intent.Key)
		if err == nil && in == nil {
			if !intent.CreateAttempted {
				intent.CreateAttempted = true
				if err := save(); err != nil {
					return nil, err
				}
			}
			in, err = api.Create(ctx, intent.Key, intent.Request)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := intent.owns(in); err != nil {
		return nil, err
	}
	if intent.InstanceID == "" {
		intent.InstanceID = in.ID
		if err := save(); err != nil {
			return nil, err
		}
	}
	return in, nil
}

func removeCloudInstance(ctx context.Context, api cloudAPI, intent *instanceIntent, save func() error) (bool, error) {
	if intent.Deleted {
		return true, nil
	}
	if !intent.DeleteRequested {
		intent.DeleteRequested = true
		if err := save(); err != nil {
			return false, err
		}
	}
	var in *instance
	var err error
	if intent.InstanceID == "" {
		in, err = api.Find(ctx, intent.Key)
	} else {
		in, err = api.Get(ctx, intent.InstanceID)
	}
	if errors.Is(err, errCloudNotFound) {
		in, err = nil, nil
	}
	if err != nil {
		return false, err
	}
	if in == nil && intent.InstanceID == "" && intent.CreateAttempted {
		// An empty lookup cannot disprove an in-flight POST. Replay the exact
		// persisted request and key, however old: Cloud keeps the idempotency
		// record for the instance lifetime, so the replay returns the instance
		// the lost response named or creates the one to destroy.
		// A definitive refusal of the replay proves that Cloud holds no create
		// under the key and made none now: nothing exists to destroy.
		in, err = api.Create(ctx, intent.Key, intent.Request)
		switch {
		case createRefused(err):
			in = nil
		case err != nil:
			return false, err
		case in == nil:
			return false, errors.New("create replay returned no instance")
		}
	}
	if in != nil {
		if err := intent.owns(in); err != nil {
			return false, err
		}
	}
	if in == nil || in.Status == "terminated" {
		intent.Deleted = true
		return true, save()
	}
	if intent.InstanceID == "" {
		intent.InstanceID = in.ID
		if err := save(); err != nil {
			return false, err
		}
	}
	if err := api.Delete(ctx, intent.InstanceID); err != nil {
		return false, err
	}
	return false, nil
}
