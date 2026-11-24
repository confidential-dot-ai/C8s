package gpuattestations

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
)

const (
	sweepTimeout   = 45 * time.Second
	workerTimeout  = 35 * time.Second
	observationTTL = 90 * time.Second
)

var (
	errDiscoveryLimit = errors.New("worker inventory exceeds discovery limits")
	errSnapshotLimit  = errors.New("worker evidence exceeds snapshot limit")
)

type observation struct {
	body    []byte
	bootID  string
	expires time.Time
}

type entry struct {
	slot
	observation
	unavailable   []byte
	duplicateBoot bool
}

type snapshot struct {
	names     []string
	entries   map[string]*entry
	refreshed time.Time
	failure   string
}

func (s *snapshot) write(w io.Writer, now time.Time) {
	_, _ = io.WriteString(w, `{"workers":[`)
	for i, name := range s.names {
		if i > 0 {
			_, _ = io.WriteString(w, ",")
		}
		e := s.entries[name]
		body := e.unavailable
		if !e.duplicateBoot && now.Before(e.expires) {
			body = e.body
		}
		if _, err := w.Write(body); err != nil {
			return
		}
	}
	_, _ = io.WriteString(w, "]}")
}

func (c *collector) collect(ctx context.Context) (*snapshot, error) {
	peers, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	s := &snapshot{names: slices.Sorted(maps.Keys(peers)), entries: make(map[string]*entry, len(peers))}
	previous := c.snapshot.Load()
	total := len(`{"workers":[]}`)
	for _, name := range s.names {
		fallback, err := json.Marshal(worker{Name: name, record: record{Status: "unavailable"}})
		if err != nil {
			return nil, err
		}
		e := &entry{slot: peers[name], unavailable: fallback}
		if previous != nil {
			prior := previous.entries[name]
			if prior != nil && prior.slot == e.slot && now.Before(prior.expires) {
				e.observation = prior.observation
			}
		}
		s.entries[name] = e
		total += len(fallback) + len(e.body) + 1
	}
	if total > maxSnapshot {
		return nil, errSnapshotLimit
	}
	if err := c.readWorkers(ctx, s, total); err != nil {
		return nil, err
	}
	s.refreshed = time.Now()
	boots := make(map[string]int)
	for _, e := range s.entries {
		if !s.refreshed.Before(e.expires) {
			e.observation = observation{}
		}
		boots[e.bootID]++
	}
	for _, e := range s.entries {
		e.duplicateBoot = e.bootID != "" && boots[e.bootID] > 1
	}
	return s, nil
}

func (c *collector) readWorkers(ctx context.Context, s *snapshot, total int) error {
	start, _ := slices.BinarySearch(s.names, c.nextWorker)
	deadline, _ := ctx.Deadline()
	for offset := 0; offset < len(s.names); {
		if ctx.Err() != nil || (offset > 0 && time.Until(deadline) < workerTimeout) {
			break
		}
		var wg sync.WaitGroup
		batch := make([]*entry, 0, concurrentReads)
		for offset < len(s.names) && len(batch) < concurrentReads {
			name := s.names[(start+offset)%len(s.names)]
			offset++
			c.nextWorker = s.names[(start+offset)%len(s.names)]
			e := s.entries[name]
			if !e.address.IsValid() {
				continue
			}
			total -= len(e.body)
			batch = append(batch, e)
			wg.Go(func() { e.observation = c.observe(ctx, name, e.slot) })
		}
		wg.Wait()
		for _, e := range batch {
			total += len(e.body)
		}
		if total > maxSnapshot {
			return errSnapshotLimit
		}
	}
	return nil
}

func (c *collector) observe(ctx context.Context, name string, slot slot) observation {
	body, err := fetch(ctx, c.relay, relayURL+slot.address.String(), workloadclaims.MaxGPUAttestationBytes)
	if err != nil {
		return observation{}
	}
	r, ok := decodeRecord(body)
	if !ok {
		return observation{}
	}
	wire, err := json.Marshal(worker{Name: name, record: r})
	if err != nil {
		return observation{}
	}
	return observation{body: wire, bootID: r.BootID, expires: time.Now().Add(observationTTL)}
}
