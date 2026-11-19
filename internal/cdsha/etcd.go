package cdsha

import (
	"context"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

// Etcd keeps the chain at <prefix>head and <prefix>entries/<hash>.
type Etcd struct {
	Client *clientv3.Client
	Prefix string
}

// etcdMaxBackoff caps the client's reconnect backoff: with gRPC's default
// (up to 120 s) a store back after a long outage stays unreachable for
// minutes, and the set with it.
const etcdMaxBackoff = 2 * time.Second

// OpenEtcd connects with cfg, capping every answer and the reconnect
// backoff.
func OpenEtcd(cfg clientv3.Config, cluster string) (*Etcd, error) {
	cfg.MaxCallRecvMsgSize = MaxStoreAnswer
	b := backoff.DefaultConfig
	b.MaxDelay = etcdMaxBackoff
	cfg.DialOptions = append(cfg.DialOptions, grpc.WithConnectParams(grpc.ConnectParams{Backoff: b}))
	client, err := clientv3.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("etcd client: %w", err)
	}
	return &Etcd{Client: client, Prefix: "/cds/" + cluster + "/"}, nil
}

func (s *Etcd) entryKey(h cdschain.Hash) string { return s.Prefix + "entries/" + h.String() }

func (s *Etcd) GetHead(ctx context.Context) ([]byte, error) { return s.get(ctx, s.Prefix+"head") }

func (s *Etcd) CASHead(ctx context.Context, old, next []byte) error {
	key := s.Prefix + "head"
	cmp := clientv3.Compare(clientv3.CreateRevision(key), "=", 0)
	if old != nil {
		cmp = clientv3.Compare(clientv3.Value(key), "=", string(old))
	}
	resp, err := s.Client.Txn(ctx).
		If(cmp).
		Then(clientv3.OpPut(key, string(next))).
		Commit()
	if err != nil {
		return fmt.Errorf("etcd cas head: %w", err)
	}
	if !resp.Succeeded {
		return ErrConflict
	}
	return nil
}

func (s *Etcd) PutEntry(ctx context.Context, hash cdschain.Hash, data []byte) error {
	key := s.entryKey(hash)
	_, err := s.Client.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
		Then(clientv3.OpPut(key, string(data))).
		Commit()
	if err != nil {
		return fmt.Errorf("etcd put entry: %w", err)
	}
	return nil
}

func (s *Etcd) GetEntry(ctx context.Context, hash cdschain.Hash) ([]byte, error) {
	return s.get(ctx, s.entryKey(hash))
}

func (s *Etcd) get(ctx context.Context, key string) ([]byte, error) {
	resp, err := s.Client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("etcd get: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	return resp.Kvs[0].Value, nil
}
