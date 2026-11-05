package secrets

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
)

func TestCurrentTransitionsKeepTheExistingSecretAndQuotaContract(t *testing.T) {
	s := NewMemoryStore(8, 3, 32)
	random := rand.New(rand.NewPCG(1, 2))
	for i := range 500 {
		cmd := Command{Op: OpPutIfAbsent, Path: fmt.Sprintf("/path/%d", random.IntN(12)), Value: bytes.Repeat([]byte{byte(i)}, random.IntN(35)), Origin: OriginWorkload, Name: fmt.Sprint("worker-", random.IntN(3))}
		if random.IntN(3) == 0 {
			cmd.Op = OpPut
		}
		var previous *SnapshotEntry
		held := 0
		entries := s.Dump()
		for _, e := range entries {
			if e.Path == cmd.Path {
				copy := e
				previous = &copy
			}
			if e.Origin == cmd.Origin && e.Name == cmd.Name {
				held++
			}
		}
		got, next := CurrentTransition(cmd, previous, len(entries), held, 8, 3, 32)
		want := s.Apply(cmd)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("step %d response differs: current=%+v existing=%+v", i, got, want)
		}
		if next != nil {
			found := false
			for _, entry := range s.Dump() {
				if entry.Path == next.Path {
					found = reflect.DeepEqual(entry, *next)
				}
			}
			if !found {
				t.Fatalf("step %d current value/holder differs", i)
			}
		} else if !reflect.DeepEqual(entries, s.Dump()) {
			// Dump map iteration is unordered; compare by path instead.
			a, b := map[string]SnapshotEntry{}, map[string]SnapshotEntry{}
			for _, e := range entries {
				a[e.Path] = e
			}
			for _, e := range s.Dump() {
				b[e.Path] = e
			}
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("step %d refusal changed state", i)
			}
		}
	}
}
