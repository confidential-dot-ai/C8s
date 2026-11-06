package metadataha

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

// Etcd uses the stable v3 JSON gateway. Each CDS transaction is exactly one
// etcd Txn, with no nested transactions, leases, watches or stale-read option.
// The dedicated etcd cluster owns consensus; this adapter owns no durable state.
type Etcd struct {
	endpoints []string
	clusterID string
	client    *http.Client
	preferred atomic.Uint32
	verified  [3]atomic.Bool
}

type EtcdConfig struct {
	Endpoints []string
	// ClusterID is the canonical decimal ID from independently bootstrapped
	// member status. Never adopt a cluster identity from a data response.
	ClusterID string
	TLS       *tls.Config
}

func NewEtcd(cfg EtcdConfig) (*Etcd, error) {
	id, err := strconv.ParseUint(cfg.ClusterID, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != cfg.ClusterID || len(cfg.Endpoints) != 3 ||
		cfg.TLS == nil || cfg.TLS.InsecureSkipVerify || cfg.TLS.RootCAs == nil || len(cfg.TLS.Certificates) == 0 {
		return nil, errors.New("metadata HA requires three HTTPS members, a pinned cluster ID and verified mutual TLS")
	}
	seen := map[string]bool{}
	endpoints := make([]string, len(cfg.Endpoints))
	for i, endpoint := range cfg.Endpoints {
		endpoint = strings.TrimSuffix(endpoint, "/")
		if metadatapilot.CheckEndpoint(endpoint) != nil || seen[endpoint] {
			return nil, errors.New("metadata HA: invalid or duplicate etcd endpoint")
		}
		seen[endpoint], endpoints[i] = true, endpoint
	}
	tc := cfg.TLS.Clone()
	tc.MinVersion = tls.VersionTLS13
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tc,
		DialContext:         (&net.Dialer{Timeout: time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: time.Second, MaxConnsPerHost: 64, MaxIdleConns: 192, MaxIdleConnsPerHost: 64,
		IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 4 * time.Second, ForceAttemptHTTP2: true}
	return &Etcd{endpoints: endpoints, clusterID: cfg.ClusterID, client: &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (e *Etcd) Close() { e.client.CloseIdleConnections() }

type etcdHeader struct {
	ClusterID string `json:"cluster_id"`
	Revision  string `json:"revision"`
}
type etcdCompare struct {
	Key     []byte `json:"key"`
	Target  string `json:"target"`
	Result  string `json:"result"`
	Version string `json:"version"`
}
type etcdRange struct {
	Key          []byte `json:"key"`
	Limit        string `json:"limit"`
	Serializable bool   `json:"serializable"` // always false, including minority reads
}
type etcdPut struct {
	Key   []byte `json:"key"`
	Value []byte `json:"value"`
}
type etcdOp struct {
	Range *etcdRange `json:"request_range,omitempty"`
	Put   *etcdPut   `json:"request_put,omitempty"`
}
type etcdTxn struct {
	Compare []etcdCompare `json:"compare,omitempty"`
	Success []etcdOp      `json:"success"`
}
type etcdKV struct {
	Key     []byte `json:"key"`
	Value   []byte `json:"value"`
	Version string `json:"version"`
	Lease   string `json:"lease"`
}
type etcdRangeReply struct {
	KVs   []etcdKV `json:"kvs"`
	More  bool     `json:"more"`
	Count string   `json:"count"`
}
type etcdReplyOp struct {
	Range *etcdRangeReply `json:"response_range,omitempty"`
	Put   *struct{}       `json:"response_put,omitempty"`
}
type etcdReply struct {
	Header    etcdHeader    `json:"header"`
	Succeeded bool          `json:"succeeded"`
	Responses []etcdReplyOp `json:"responses"`
}

func recordKey(namespace, key string) []byte {
	h := sha256.Sum256([]byte(namespace))
	return []byte("/cds-current/v1/" + hex.EncodeToString(h[:]) + "/" + key)
}

// Every record's public counter is etcd's per-key version. No delete or lease
// API is exposed, so normal clients cannot manufacture delete/recreate ABA.
// Access to raw etcd administration is part of the trusted metadata boundary.
func (e *Etcd) Read(ctx context.Context, namespace string, keys []string) ([]metadatapilot.Record, error) {
	check := metadatapilot.Transaction{}
	for _, key := range keys {
		check.Checks = append(check.Checks, metadatapilot.Check{Key: key})
	}
	if err := check.Check(true); err != nil {
		return nil, err
	}
	txn := etcdTxn{}
	for _, key := range keys {
		txn.Success = append(txn.Success, etcdOp{Range: &etcdRange{Key: recordKey(namespace, key), Limit: "1"}})
	}
	reply, err := e.send(ctx, txn, true)
	if err != nil {
		return nil, err
	}
	if !reply.Succeeded || len(reply.Responses) != len(keys) {
		return nil, objectwal.ErrCorrupt
	}
	rows := make([]metadatapilot.Record, len(keys))
	for i, op := range reply.Responses {
		r := op.Range
		if r == nil || op.Put != nil || r.More || len(r.KVs) > 1 {
			return nil, objectwal.ErrCorrupt
		}
		rows[i].Key = keys[i]
		if len(r.KVs) == 0 {
			if r.Count != "" && r.Count != "0" {
				return nil, objectwal.ErrCorrupt
			}
			continue
		}
		kv := r.KVs[0]
		version, err := strconv.ParseInt(kv.Version, 10, 64)
		if err != nil || version <= 0 || strconv.FormatInt(version, 10) != kv.Version || r.Count != "1" ||
			!bytes.Equal(kv.Key, recordKey(namespace, keys[i])) || len(kv.Value) == 0 || len(kv.Value) > metadatapilot.MaxHeadBytes ||
			(kv.Lease != "" && kv.Lease != "0") {
			return nil, objectwal.ErrCorrupt
		}
		rows[i].Version, rows[i].Value = fmt.Sprintf("%016x", version), kv.Value
	}
	return rows, nil
}

func (e *Etcd) Commit(ctx context.Context, namespace string, t metadatapilot.Transaction) error {
	if err := t.Check(false); err != nil {
		return err
	}
	txn := etcdTxn{}
	for _, check := range t.Checks {
		var version uint64
		if check.Version != "" {
			version, _ = strconv.ParseUint(check.Version, 16, 64)
		}
		if version >= math.MaxInt64 {
			return errors.New("metadata HA: record version exhausted")
		}
		txn.Compare = append(txn.Compare, etcdCompare{Key: recordKey(namespace, check.Key), Target: "VERSION", Result: "EQUAL", Version: strconv.FormatUint(version, 10)})
	}
	for _, row := range t.Writes {
		txn.Success = append(txn.Success, etcdOp{Put: &etcdPut{Key: recordKey(namespace, row.Key), Value: row.Value}})
	}
	reply, err := e.send(ctx, txn, false)
	if err != nil {
		return objectwal.ErrInDoubt
	}
	if !reply.Succeeded {
		if len(reply.Responses) != 0 {
			return objectwal.ErrInDoubt
		}
		return objectwal.ErrConflict
	}
	if len(reply.Responses) != len(t.Writes) {
		return objectwal.ErrInDoubt
	}
	for _, op := range reply.Responses {
		if op.Put == nil || op.Range != nil {
			return objectwal.ErrInDoubt
		}
	}
	return nil
}

func (e *Etcd) send(ctx context.Context, txn etcdTxn, read bool) (etcdReply, error) {
	body, err := json.Marshal(txn)
	if err != nil || len(body) > metadatapilot.MaxTransactionBytes {
		return etcdReply{}, errors.New("metadata HA: invalid etcd transaction size")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	start := int(e.preferred.Load() % uint32(len(e.endpoints)))
	attempts := 1
	if read {
		attempts = len(e.endpoints)
	}
	for i := 0; i < attempts; i++ {
		index := (start + i) % len(e.endpoints)
		attemptLimit := 4 * time.Second
		if read {
			attemptLimit = 1200 * time.Millisecond
		}
		attemptCtx, stop := context.WithTimeout(ctx, attemptLimit)
		// Establish an endpoint's pinned identity with a read before sending its
		// first mutation. Credentials and addresses are immutable for this client.
		if !read && !e.verified[index].Load() {
			probe, _ := json.Marshal(etcdTxn{Success: []etcdOp{{Range: &etcdRange{Key: []byte("/cds-current/v1/.identity-probe"), Limit: "1"}}}})
			if _, err := e.exchange(attemptCtx, index, probe); err != nil {
				stop()
				return etcdReply{}, err
			}
		}
		reply, err := e.exchange(attemptCtx, index, body)
		stop()
		if err != nil {
			if errors.Is(err, objectwal.ErrCorrupt) {
				return etcdReply{}, err
			}
			e.verified[index].Store(false)
			e.preferred.CompareAndSwap(uint32(index), uint32((index+1)%len(e.endpoints)))
			continue
		}
		e.preferred.Store(uint32(index))
		return reply, nil
	}
	return etcdReply{}, errors.New("metadata HA: current quorum unavailable")
}

func (e *Etcd) exchange(ctx context.Context, index int, body []byte) (etcdReply, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoints[index]+"/v3/kv/txn", bytes.NewReader(body))
	if err != nil {
		return etcdReply{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.GetBody = nil // A mutation is sent once, including transport-level failures.
	response, err := e.client.Do(r)
	if err != nil {
		return etcdReply{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, metadatapilot.MaxTransactionBytes+1))
	if err != nil || response.StatusCode != http.StatusOK {
		return etcdReply{}, errors.New("metadata HA: member unavailable")
	}
	var reply etcdReply
	if len(data) > metadatapilot.MaxTransactionBytes || json.Unmarshal(data, &reply) != nil || reply.Header.ClusterID != e.clusterID {
		return etcdReply{}, objectwal.ErrCorrupt
	}
	revision, err := strconv.ParseInt(reply.Header.Revision, 10, 64)
	if err != nil || revision <= 0 {
		return etcdReply{}, objectwal.ErrCorrupt
	}
	e.verified[index].Store(true)
	return reply, nil
}
