package podprovider

import (
	"context"
	"errors"
	"time"
)

// instanceIntent retains one immutable Cloud create and its cleanup authority.
// Both static Pod records and allocation slots use this exact lifecycle. The
// signed desired Pod document is independent of a generic VM's actual launch.
type instanceIntent struct {
	ProviderID      string        `json:"providerID"`
	CloudURL        string        `json:"cloudURL"`
	CredentialHash  string        `json:"credentialHash"`
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

func (in *instanceIntent) owns(got *instance) error {
	if got == nil || got.ID == "" || (in.InstanceID != "" && got.ID != in.InstanceID) {
		return errors.New("cloud returned another or missing instance identity")
	}
	for k, value := range in.Request.Labels {
		if got.Labels[k] != value {
			return errors.New("cloud instance ownership differs from its frozen launch")
		}
	}
	return nil
}

func ensureCloudInstance(ctx context.Context, api cloudAPI, intent *instanceIntent, now time.Time, save func() error) (*instance, error) {
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
			// Never replay uncertain creates outside Cloud's known idempotency
			// retention window. Keep the intent for authoritative resolution.
			if now.Sub(intent.CreatedAt) > 24*time.Hour {
				return nil, nil
			}
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

func removeCloudInstance(ctx context.Context, api cloudAPI, intent *instanceIntent, now time.Time, save func() error) (bool, error) {
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
		if now.Sub(intent.CreatedAt) > 24*time.Hour {
			return false, errors.New("old uncertain create retained for authoritative Cloud resolution")
		}
		in, err = api.Create(ctx, intent.Key, intent.Request)
		if err != nil {
			return false, err
		}
		if in == nil {
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
