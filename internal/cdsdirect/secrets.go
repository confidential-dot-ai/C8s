package cdsdirect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func secretKey(path string) string { return "secret:" + path }
func holderKey(origin secrets.Origin, name string) string {
	b, _ := json.Marshal([]string{string(origin), name})
	return "holder:" + string(b)
}

func count(v *directstate.View, key string, maximum int) (int, error) {
	b, exists, err := v.Require(key)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var n int
	if decode(b, &n) != nil || n < 0 || n > maximum {
		return 0, objectwal.ErrCorrupt
	}
	return n, nil
}

// secretChange reads only this path and the quota counters it actually needs.
// Existing-path writes never update the cluster-wide count. New-path writes
// still contend on that exact quota: the pilot does not weaken its semantics.
func (s *State) secretChange(v *directstate.View, cmd secrets.Command) (map[string][]byte, secrets.Result, error) {
	var previous *secrets.SnapshotEntry
	if b, exists := v.Get(secretKey(cmd.Path)); exists {
		previous = &secrets.SnapshotEntry{}
		if decode(b, previous) != nil || previous.Path != cmd.Path {
			return nil, secrets.Result{}, objectwal.ErrCorrupt
		}
		defer clear(previous.Value)
	}
	origin, name := cmd.Origin, cmd.Name
	if cmd.Op == secrets.OpPut {
		origin, name = secrets.OriginOperator, ""
	}
	newHolder := holderKey(origin, name)
	total, held := 0, 0
	var err error
	if previous == nil {
		total, err = count(v, countKey, s.policy.SecretsMaxPaths)
		if err != nil {
			return nil, secrets.Result{}, err
		}
		held, err = count(v, newHolder, s.policy.SecretsMaxPaths)
		if err != nil {
			return nil, secrets.Result{}, err
		}
	}
	r, next := secrets.CurrentTransition(cmd, previous, total, held, s.policy.SecretsMaxPaths, s.policy.SecretsMaxPerHolder, s.policy.SecretsMaxValue)
	if next == nil {
		return nil, r, nil
	}
	defer clear(next.Value)
	writes := map[string][]byte{}
	if previous == nil {
		writes[countKey], _ = json.Marshal(total + 1)
		writes[newHolder], _ = json.Marshal(held + 1)
	} else {
		oldHolder := holderKey(previous.Origin, previous.Name)
		if oldHolder != newHolder {
			old, err := count(v, oldHolder, s.policy.SecretsMaxPaths)
			if err != nil {
				clear(r.Current)
				return nil, secrets.Result{}, err
			}
			if old < 1 {
				clear(r.Current)
				return nil, secrets.Result{}, objectwal.ErrCorrupt
			}
			held, err := count(v, newHolder, s.policy.SecretsMaxPaths)
			if err != nil {
				clear(r.Current)
				return nil, secrets.Result{}, err
			}
			writes[oldHolder], _ = json.Marshal(old - 1)
			writes[newHolder], _ = json.Marshal(held + 1)
		}
	}
	writes[secretKey(cmd.Path)], err = json.Marshal(next)
	if err != nil {
		clear(r.Current)
		return nil, secrets.Result{}, err
	}
	return writes, r, nil
}

func (s *State) Secret(ctx context.Context, path string) ([]byte, error) {
	v, err := s.store.Read(ctx, coreKey, policyKey, secretKey(path))
	if err != nil {
		return nil, err
	}
	defer v.Clear()
	if _, _, err := s.core(v); err != nil {
		return nil, err
	}
	b, exists := v.Get(secretKey(path))
	if !exists {
		return nil, secrets.ErrNotFound
	}
	var entry secrets.SnapshotEntry
	if err := decode(b, &entry); err != nil || entry.Path != path {
		clear(entry.Value)
		return nil, objectwal.ErrCorrupt
	}
	return entry.Value, nil
}

func (s *State) WriteSecret(ctx context.Context, cmd secrets.Command) (secrets.Result, error) {
	if cmd.Path == "" || len(cmd.Value) > s.policy.SecretsMaxValue {
		return secrets.Result{}, errors.New("direct state: invalid secret write")
	}
	answer, err := s.store.Update(ctx, secretKey(cmd.Path), []string{coreKey, policyKey, secretKey(cmd.Path)}, func(v *directstate.View) (map[string][]byte, any, error) {
		if _, _, err := s.core(v); err != nil {
			return nil, nil, err
		}
		writes, r, err := s.secretChange(v, cmd)
		return writes, r, err
	})
	if err != nil {
		return secrets.Result{}, fmt.Errorf("%w: %v", secrets.ErrUnavailable, err)
	}
	return answer.(secrets.Result), nil
}
