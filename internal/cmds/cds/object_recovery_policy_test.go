package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

type objectPolicyReadStore struct {
	objectstate.Store
	load func(context.Context) (objectstate.Object, error)
}

func (s objectPolicyReadStore) Load(ctx context.Context) (objectstate.Object, error) {
	return s.load(ctx)
}

func objectPolicyImages(cfg config) []remote.ImagePin {
	return []remote.ImagePin{{
		Name: "approved-cds",
		Digest: bytes.Repeat(
			[]byte{0x31},
			48,
		),
		LaunchFile: bytes.Clone(cfg.measuredFile),
		Registers: map[int][]byte{
			1: bytes.Repeat(
				[]byte{0x41},
				48,
			),
			2: bytes.Repeat(
				[]byte{0x42},
				48,
			),
		},
	}}
}

func TestObjectRecoveryPolicyFreshlyAuthenticatesCurrentState(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	var reads int
	var outage bool
	store := objectPolicyReadStore{
		Store: h.store,
		load: func(ctx context.Context) (objectstate.Object, error) {
			reads++
			if outage {
				return objectstate.Object{}, errors.New("read unavailable")
			}
			return h.store.Load(ctx)
		},
	}
	source, err := newObjectRecoveryPolicySource(
		h.cfg,
		store,
		h.cipher,
		objectPolicyImages(h.cfg),
	)
	if err != nil {
		t.Fatal(err)
	}
	before, err := source.Current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	current, err := h.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := h.cipher.Open(current.Data)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	view, err := readObjectView(
		h.cfg,
		plain,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Stop()
	view.state.Release["pending"] = objectChallenge{
		IssuedMS:  time.Now().UnixMilli(),
		ExpiresMS: time.Now().Add(time.Minute).UnixMilli(),
	}
	changed, err := view.encode()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(changed)
	sealed, err := h.cipher.Seal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CompareAndSwap(
		t.Context(),
		current.ETag,
		sealed,
	); err != nil {
		t.Fatal(err)
	}
	after, err := source.Current(t.Context())
	if err != nil || !reflect.DeepEqual(
		before,
		after,
	) || reads != 2 {
		t.Fatalf(
			"ordinary write changed policy or bypassed fresh read: %v, reads %d",
			err,
			reads,
		)
	}
	outage = true
	if _, err := source.Current(t.Context()); err == nil || reads != 3 {
		t.Fatal("read outage reused an earlier authenticated state")
	}
}

func TestObjectRecoveryPolicyRejectsUnauthenticatedOrInvalidState(t *testing.T) {
	for _, name := range []string{
		"wrong key",
		"wrong launch",
		"malformed body",
		"wrong CA",
		"wrong allowlist",
		"corrupt ciphertext",
	} {
		t.Run(
			name,
			func(t *testing.T) {
				h := newObjectAcceptance(t)
				h.stop()
				current, err := h.store.Load(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				plain, err := h.cipher.Open(current.Data)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(plain)
				var state objectImage
				if err := json.Unmarshal(
					plain,
					&state,
				); err != nil {
					t.Fatal(err)
				}
				cipher := h.cipher
				switch name {
				case "wrong key":
					cipher, err = objectCipher(
						h.cfg,
						bytes.Repeat(
							[]byte{0x99},
							32,
						),
					)
					if err != nil {
						t.Fatal(err)
					}
				case "wrong launch":
					state.Launch[0] ^= 1
				case "wrong CA":
					state.CAKey = []byte("invalid private key")
				case "wrong allowlist":
					state.AllowlistDigest[0] ^= 1
				}
				body, err := json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(body)
				if name == "malformed body" {
					body = []byte(`{"version":1,"version":1}`)
				}
				sealed, err := h.cipher.Seal(body)
				if err != nil {
					t.Fatal(err)
				}
				if name == "corrupt ciphertext" {
					sealed[len(sealed)-1] ^= 1
				}
				if _, err := h.store.CompareAndSwap(
					t.Context(),
					current.ETag,
					sealed,
				); err != nil {
					t.Fatal(err)
				}
				source, err := newObjectRecoveryPolicySource(
					h.cfg,
					h.store,
					cipher,
					objectPolicyImages(h.cfg),
				)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := source.Current(t.Context()); err == nil {
					t.Fatal("invalid current object authorized a recovery policy")
				}
			},
		)
	}
}

func TestObjectRecoveryPolicyOwnsInputsAndSnapshots(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	images := objectPolicyImages(h.cfg)
	source, err := newObjectRecoveryPolicySource(
		h.cfg,
		h.store,
		h.cipher,
		images,
	)
	if err != nil {
		t.Fatal(err)
	}
	before, err := source.Current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Mutating every caller-owned input must not alter the source's policy or
	// the launch configuration it uses when authenticating the current object.
	images[0].Digest[0] ^= 1
	images[0].LaunchFile[0] ^= 1
	images[0].Registers[1][0] ^= 1
	delete(
		images[0].Registers,
		2,
	)
	images[0].Name = "mutated"
	h.cfg.measuredFile[0] ^= 1
	h.cfg.measured.ClusterID = "other-cluster"
	h.cfg.measured.ObjectState.Bucket = "other-storage"
	after, err := source.Current(t.Context())
	if err != nil || !reflect.DeepEqual(
		before,
		after,
	) {
		t.Fatalf(
			"caller input aliases changed policy: %v",
			err,
		)
	}
	after.Images[0].Digest[0] ^= 1
	after.Images[0].LaunchFile[0] ^= 1
	after.Images[0].Registers[1][0] ^= 1
	delete(
		after.Images[0].Registers,
		2,
	)
	again, err := source.Current(t.Context())
	if err != nil || !reflect.DeepEqual(
		before,
		again,
	) {
		t.Fatalf(
			"returned snapshot aliases changed policy: %v",
			err,
		)
	}
}

func TestObjectRecoveryPolicyMissingStateAlwaysFailsClosed(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	source, err := newObjectRecoveryPolicySource(
		h.cfg,
		h.store,
		h.cipher,
		objectPolicyImages(h.cfg),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Current(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.memory.mu.Lock()
	h.memory.data = nil
	h.memory.mu.Unlock()
	if _, err := source.Current(t.Context()); !errors.Is(
		err,
		objectstate.ErrNotFound,
	) {
		t.Fatalf(
			"missing state after an authenticated read: %v",
			err,
		)
	}
	fresh, err := newObjectRecoveryPolicySource(
		h.cfg,
		h.store,
		h.cipher,
		objectPolicyImages(h.cfg),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Current(t.Context()); !errors.Is(
		err,
		objectstate.ErrNotFound,
	) {
		t.Fatalf(
			"missing state on a new source: %v",
			err,
		)
	}
}

func TestObjectRecoveryPolicyDeadlineAndCancellation(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	var calls int
	store := objectPolicyReadStore{
		Store: h.store,
		load: func(ctx context.Context) (objectstate.Object, error) {
			calls++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 10*time.Second {
				t.Error("fresh read had no bounded deadline")
			}
			// A store that ignores cancellation still cannot return authorization.
			return h.store.Load(context.Background())
		},
	}
	source, err := newObjectRecoveryPolicySource(
		h.cfg,
		store,
		h.cipher,
		objectPolicyImages(h.cfg),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Current(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := source.Current(ctx); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal("canceled call accepted current state")
	}
	if calls != 2 {
		t.Fatalf(
			"unexpected fresh reads: %d",
			calls,
		)
	}
	h.memory.mu.Lock()
	h.memory.loadBlocked = make(chan struct{})
	h.memory.mu.Unlock()
	source.store = h.store
	ctx, cancel = context.WithTimeout(
		t.Context(),
		20*time.Millisecond,
	)
	defer cancel()
	if _, err := source.Current(ctx); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatal("blocked current read ignored caller deadline")
	}
}

func TestObjectRecoveryPolicyConcurrentSnapshots(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	var reads atomic.Int64
	store := objectPolicyReadStore{
		Store: h.store,
		load: func(ctx context.Context) (objectstate.Object, error) {
			reads.Add(1)
			return h.store.Load(ctx)
		},
	}
	source, err := newObjectRecoveryPolicySource(
		h.cfg,
		store,
		h.cipher,
		objectPolicyImages(h.cfg),
	)
	if err != nil {
		t.Fatal(err)
	}
	var work sync.WaitGroup
	for range 12 {
		work.Go(func() {
			policy, err := source.Current(t.Context())
			if err != nil {
				t.Error(err)
				return
			}
			policy.Images[0].Digest[0] ^= 1
			policy.Images[0].Registers[1][0] ^= 1
		})
	}
	work.Wait()
	if reads.Load() != 12 {
		t.Fatalf(
			"concurrent calls shared a cached current read: %d",
			reads.Load(),
		)
	}
}

func TestObjectRecoveryPolicyValidatesConstruction(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	type inputs struct {
		cfg    config
		store  objectstate.Store
		cipher *objectstate.Cipher
		images []remote.ImagePin
	}
	for _, test := range []struct {
		name   string
		mutate func(*inputs)
	}{
		{
			"no store",
			func(v *inputs) { v.store = nil },
		},
		{
			"no cipher",
			func(v *inputs) { v.cipher = nil },
		},
		{
			"no launch",
			func(v *inputs) { v.cfg.measuredFile = nil },
		},
		{
			"bad launch",
			func(v *inputs) { v.cfg.measuredFile = []byte("invalid: launch") },
		},
		{
			"no images",
			func(v *inputs) { v.images = nil },
		},
		{
			"wrong launch pin",
			func(v *inputs) { v.images[0].LaunchFile[0] ^= 1 },
		},
		{
			"wrong digest",
			func(v *inputs) { v.images[0].Digest = nil },
		},
		{
			"wrong register",
			func(v *inputs) {
				v.images[0].Registers[4] = make(
					[]byte,
					48,
				)
			},
		},
		{
			"anchor",
			func(v *inputs) { v.images[0].Anchor = []byte("another binding") },
		},
		{
			"extension",
			func(v *inputs) { v.images[0].AcceptExtension = func(string) error { return nil } },
		},
		{
			"remote verifier",
			func(v *inputs) { v.cfg.attestationApiURL = "https://untrusted.example" },
		},
		{
			"bad decoder limits",
			func(v *inputs) { v.cfg.secretsMaxPaths = 0 },
		},
	} {
		t.Run(
			test.name,
			func(t *testing.T) {
				v := inputs{
					cfg:    h.cfg,
					store:  h.store,
					cipher: h.cipher,
					images: objectPolicyImages(h.cfg),
				}
				test.mutate(&v)
				if _, err := newObjectRecoveryPolicySource(
					v.cfg,
					v.store,
					v.cipher,
					v.images,
				); err == nil {
					t.Fatal("invalid recovery policy construction accepted")
				}
			},
		)
	}
}
