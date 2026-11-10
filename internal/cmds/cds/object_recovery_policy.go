package cds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// objectRecoveryPolicySource combines immutable approved images with a fresh
// authenticated read of the same object CDS serves. It does not deploy a
// custodian or add mutable image approval to the state format.
type objectRecoveryPolicySource struct {
	cfg    config
	store  objectstate.Store
	cipher *objectstate.Cipher
	policy objectstate.RecoveryPolicy
}

var _ objectstate.RecoveryPolicySource = (*objectRecoveryPolicySource)(nil)

// The caller must independently authenticate owner approval of these pins.
// The custodian must initialize state before releasing any recovery grants;
// absence never authorizes creation by a recipient. cfg.measuredFile is the
// authoritative launch; parsing it again gives the source its own configuration.
func newObjectRecoveryPolicySource(
	cfg config,
	store objectstate.Store,
	cipher *objectstate.Cipher,
	images []remote.ImagePin,
) (*objectRecoveryPolicySource, error) {
	if store == nil || cipher == nil || len(cfg.measuredFile) == 0 || len(cfg.measuredFile) > 1<<20 {
		return nil, errors.New("object state recovery: storage, cipher and bounded launch configuration required")
	}
	cfg.measuredFile = bytes.Clone(cfg.measuredFile)
	measured, err := cdsconfig.Parse(cfg.measuredFile)
	if err != nil {
		return nil, err
	}
	if measured.ObjectState == nil {
		return nil, errors.New("object state recovery: launch must select object state")
	}
	cfg.measured = measured
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	policy := objectstate.RecoveryPolicy{
		Revision:       "fixed",
		Images:         images,
		AttestationURL: cfg.attestationApiURL,
	}
	policy.Native, err = armtls.NewNativeVerifier(measured.ObjectState.SNPMinTCB)
	if err != nil {
		return nil, err
	}
	if err := policy.Check(objectRecoveryIdentity(cfg)); err != nil {
		return nil, err
	}
	policy.Images = cloneObjectRecoveryImages(images)

	// Only fixed authorization inputs determine the revision. ETags and normal
	// CDS state revisions change on every write and would starve grants.
	digest := sha256.New()
	encoder := json.NewEncoder(digest)
	if err := encoder.Encode([]any{
		"c8s/object-state/recovery-policy/v1",
		cfg.measuredFile,
		policy.AttestationURL,
	}); err != nil {
		return nil, err
	}
	for _, image := range policy.Images {
		if err := encoder.Encode([]any{
			image.Digest,
			image.Registers,
		}); err != nil {
			return nil, err
		}
	}
	policy.Revision = hex.EncodeToString(digest.Sum(nil))
	return &objectRecoveryPolicySource{
		cfg:    cfg,
		store:  store,
		cipher: cipher,
		policy: policy,
	}, nil
}

func (s *objectRecoveryPolicySource) Current(ctx context.Context) (objectstate.RecoveryPolicy, error) {
	ctx, cancel := context.WithTimeout(
		ctx,
		10*time.Second,
	)
	defer cancel()
	current, err := s.store.Load(ctx)
	if contextErr := ctx.Err(); contextErr != nil {
		return objectstate.RecoveryPolicy{}, contextErr
	}
	if err != nil {
		return objectstate.RecoveryPolicy{}, err
	}
	plain, err := s.cipher.Open(current.Data)
	if err != nil {
		return objectstate.RecoveryPolicy{}, err
	}
	defer clear(plain)
	view, err := readObjectView(
		s.cfg,
		plain,
	)
	if err != nil {
		return objectstate.RecoveryPolicy{}, err
	}
	defer view.Stop()
	if err := ctx.Err(); err != nil {
		return objectstate.RecoveryPolicy{}, err
	}
	policy := s.policy
	policy.Images = cloneObjectRecoveryImages(policy.Images)
	return policy, nil
}

func cloneObjectRecoveryImages(images []remote.ImagePin) []remote.ImagePin {
	cloned := make(
		[]remote.ImagePin,
		len(images),
	)
	for i, image := range images {
		cloned[i] = image
		cloned[i].Digest = bytes.Clone(image.Digest)
		cloned[i].LaunchFile = bytes.Clone(image.LaunchFile)
		if image.Registers != nil {
			cloned[i].Registers = make(
				map[int][]byte,
				len(image.Registers),
			)
			for index, register := range image.Registers {
				cloned[i].Registers[index] = bytes.Clone(register)
			}
		}
	}
	return cloned
}
