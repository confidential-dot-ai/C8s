package cdsobject

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type bucket struct {
	mu      sync.Mutex
	data    map[string]objectwal.Object
	version int
	outage  atomic.Bool
}

func (b *bucket) Get(ctx context.Context, key string) (objectwal.Object, error) {
	if b.outage.Load() {
		return objectwal.Object{}, errors.New("storage unreachable")
	}
	if err := ctx.Err(); err != nil {
		return objectwal.Object{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.data[key]
	if !ok {
		return o, objectwal.ErrNotFound
	}
	o.Data = bytes.Clone(o.Data)
	return o, nil
}
func (b *bucket) Put(ctx context.Context, key string, data []byte, expected string) (string, error) {
	if b.outage.Load() {
		return "", errors.New("storage unreachable")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	old, ok := b.data[key]
	if (expected == "" && ok) || (expected != "" && (!ok || old.ETag != expected)) {
		return "", objectwal.ErrConflict
	}
	b.version++
	etag := fmt.Sprint(b.version)
	b.data[key] = objectwal.Object{Data: bytes.Clone(data), ETag: etag}
	return etag, nil
}

type fixture struct {
	operator *ecdsa.PrivateKey
	launch   cdsha.Launch
	key      []byte
	bucket   *bucket
}

const launchFile = "synthetic CDS object WAL pilot launch"

func newFixture(t testing.TB) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(launchFile))
	return &fixture{operator: key, key: bytes.Repeat([]byte{0x42}, 32), bucket: &bucket{data: map[string]objectwal.Object{}},
		launch: cdsha.Launch{ClusterID: "object-pilot", ConfigSHA256: hex.EncodeToString(hash[:]), OperatorKeys: []*ecdsa.PublicKey{&key.PublicKey}, Voters: 3}}
}
func (f *fixture) node(t testing.TB) *Node {
	t.Helper()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	hash := sha256.Sum256(f.key)
	n, err := New(t.Context(), Config{Launch: f.launch, Storage: cdsconfig.ObjectWALPilot{
		Bucket: "pilot", Region: "us-west-2", Prefix: "isolated", KeySHA256: hex.EncodeToString(hash[:])},
		Allowlist: al, Secrets: secrets.NewMemoryStore(1024, 100, 4096), Ledger: sandboxledger.New(time.Hour, 100),
		OpenStore: func(objectwal.Credentials) (objectwal.Store, error) { return f.bucket, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Provision(Provision{Key: f.key}); err != nil {
		t.Fatal(err)
	}
	return n
}
func (f *fixture) genesis(t testing.TB, n *Node) {
	t.Helper()
	document, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{Name: "pilot", Digest: bytes.Repeat([]byte{1}, refvalues.DigestSize), LaunchFile: []byte(launchFile)}}})
	if err != nil {
		t.Fatal(err)
	}
	pins, err := cdsdecree.NewPinDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilyTDX,
		Images: []remote.ImagePin{{Name: "node", Digest: bytes.Repeat([]byte{2}, refvalues.DigestSize)}}})
	if err != nil {
		t.Fatal(err)
	}
	nodePins, err := cdsdecree.NewNodeImages(nodes)
	if err != nil {
		t.Fatal(err)
	}
	d := cdsdecree.Decree{Kind: cdsdecree.Genesis, ClusterID: f.launch.ClusterID, IntentID: cdsdecree.NewIntentID(),
		ExpiresAt: time.Now().Add(time.Hour), IssuedAtMS: time.Now().UnixMilli(), TargetMember: n.id, TargetAddress: "127.0.0.1:8443",
		GenesisCA: n.Status().GenesisCA, CDSPins: pins, NodePins: nodePins}
	signed, err := cdsdecree.Sign(d, f.operator)
	if err != nil {
		t.Fatal(err)
	}
	result, err := n.TakeDecree(signed)
	if err != nil || result.Refused != "" {
		t.Fatalf("genesis: %+v %v", result, err)
	}
}

func TestSharedCDSCommandsAndWholeClusterRestart(t *testing.T) {
	f := newFixture(t)
	a, b, c := f.node(t), f.node(t), f.node(t)
	f.genesis(t, a)
	for _, n := range []*Node{a, b, c} {
		if err := n.ConfirmRead(); err != nil {
			t.Fatal(err)
		}
	}
	ca := a.Status().CAFingerprint
	for _, n := range []*Node{b, c} {
		if n.Status().CAFingerprint != ca {
			t.Fatal("replicas hold different CAs")
		}
	}

	var won atomic.Int32
	var wg sync.WaitGroup
	for _, n := range []*Node{a, b, c} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, held, err := n.Secrets().PutIfAbsent(t.Context(), "/pilot/token", []byte("synthetic-private-value"), secrets.WorkloadHolder("pilot"))
			if err != nil {
				t.Error(err)
				return
			}
			if !held.Exists {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d PutIfAbsent winners", won.Load())
	}
	payload := fmt.Sprintf(`{"iat":%d,"exp":%d,"jti":"pilot"}`, time.Now().Unix(), time.Now().Add(time.Minute).Unix())
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	if err := a.Allowlist().ConsumeToken(token); err != nil {
		t.Fatal(err)
	}
	if err := b.Allowlist().ConsumeToken(token); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("token replay: %v", err)
	}
	if !a.Bindings().Record("sandbox", "10.0.0.8") {
		t.Fatal("binding was not committed")
	}
	if err := a.wal.Load().Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Secrets().Put(t.Context(), "/pilot/after", []byte("after-snapshot")); err != nil {
		t.Fatal(err)
	}

	// None of the new nodes receives state or keys from an old process. The
	// operator supplies the same DEK, then each rebuilds from object storage.
	for range 3 {
		restarted := f.node(t)
		if err := restarted.ConfirmRead(); err != nil {
			t.Fatal(err)
		}
		if !restarted.Serving().OK || restarted.Status().CAFingerprint != ca {
			t.Fatal("CA continuity lost")
		}
		value, err := restarted.Secrets().Get(t.Context(), "/pilot/token")
		if err != nil || string(value) != "synthetic-private-value" {
			t.Fatalf("secret: %q %v", value, err)
		}
		if err := restarted.Allowlist().ConsumeToken(token); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("restart replay: %v", err)
		}
		if host, ok := restarted.Bindings().Lookup("sandbox"); !ok || host != "10.0.0.8" {
			t.Fatal("binding lost")
		}
	}
	for _, obj := range f.bucket.data {
		if bytes.Contains(obj.Data, []byte("synthetic-private-value")) || bytes.Contains(obj.Data, []byte("mesh_ca_key")) {
			t.Fatal("plaintext in object storage")
		}
	}
}

func TestStorageOutageAndWrongKeyFailClosed(t *testing.T) {
	f := newFixture(t)
	n := f.node(t)
	f.genesis(t, n)
	if err := n.ConfirmRead(); err != nil {
		t.Fatal(err)
	}
	if err := n.Provision(Provision{Key: bytes.Repeat([]byte{5}, 32)}); err == nil {
		t.Fatal("wrong key accepted")
	}
	f.bucket.outage.Store(true)
	if err := n.ConfirmRead(); err == nil {
		t.Fatal("outage read succeeded")
	}
	if n.Serving().OK {
		t.Fatal("outage left readiness enabled")
	}
	if _, ok := n.CA(); ok {
		t.Fatal("outage left issuance enabled")
	}
	f.bucket.outage.Store(false)
	if err := n.ConfirmRead(); err != nil {
		t.Fatal(err)
	}
	if !n.Serving().OK {
		t.Fatal("storage recovery did not restore service")
	}
}
