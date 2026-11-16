package cdsha

import (
	"bytes"
	"context"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

// Memory is a Store in this process: tests, and a single replica.
type Memory struct {
	mu      sync.Mutex
	head    []byte
	entries map[cdschain.Hash][]byte
}

func NewMemory() *Memory { return &Memory{entries: map[cdschain.Hash][]byte{}} }

func (m *Memory) GetHead(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return bytes.Clone(m.head), nil
}

func (m *Memory) CASHead(_ context.Context, old, next []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if (old == nil) != (m.head == nil) || !bytes.Equal(old, m.head) {
		return ErrConflict
	}
	m.head = bytes.Clone(next)
	return nil
}

func (m *Memory) PutEntry(_ context.Context, hash cdschain.Hash, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[hash] = bytes.Clone(data)
	return nil
}

func (m *Memory) GetEntry(_ context.Context, hash cdschain.Hash) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return bytes.Clone(m.entries[hash]), nil
}
