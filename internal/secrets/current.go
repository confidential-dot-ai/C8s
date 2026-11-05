package secrets

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/httputil"
)

// CurrentTransition applies the existing first-writer/overwrite and quota
// rules to one current record. The caller must atomically validate previous,
// total and held, and commit the returned record and its quota deltas. It is
// used only by the direct-state pilot; it has no shared mutable state.
func CurrentTransition(cmd Command, previous *SnapshotEntry, total, held, maxPaths, maxPerHolder, maxValue int) (Result, *SnapshotEntry) {
	failed := func(err error) (Result, *SnapshotEntry) {
		return Result{Status: httputil.StatusOf(err, sentinels)}, nil
	}
	if cmd.Path == "" || (cmd.Op != OpPutIfAbsent && cmd.Op != OpPut) {
		return failed(fmt.Errorf("invalid current secret command"))
	}
	if len(cmd.Value) > maxValue {
		return failed(fmt.Errorf("secrets: value is %d bytes, limit is %d", len(cmd.Value), maxValue))
	}
	result := Result{}
	if previous != nil {
		result.HeldExists, result.HeldOrigin = true, previous.Origin
		if cmd.Op == OpPutIfAbsent {
			result.Current = append([]byte(nil), previous.Value...)
			return result, nil
		}
	}
	by := Holder{origin: cmd.Origin, name: cmd.Name}
	if cmd.Op == OpPut {
		by = OperatorHolder()
	}
	if previous == nil {
		if err := checkCurrentRoom(total, held, by, maxPaths, maxPerHolder); err != nil {
			return failed(err)
		}
	}
	next := &SnapshotEntry{Path: cmd.Path, Value: append([]byte(nil), cmd.Value...), Origin: by.origin, Name: by.name}
	if cmd.Op == OpPutIfAbsent {
		result.Current = append([]byte(nil), cmd.Value...)
	}
	return result, next
}

func checkCurrentRoom(total, held int, by Holder, maxPaths, maxPerHolder int) error {
	if by.origin != OriginOperator && held >= maxPerHolder {
		return fmt.Errorf("%w: %s %q holds %d paths, limit is %d", ErrHolderQuota, by.origin, by.name, held, maxPerHolder)
	}
	if total >= maxPaths {
		return fmt.Errorf("%w: store holds %d paths, limit is %d", ErrStoreFull, total, maxPaths)
	}
	return nil
}
