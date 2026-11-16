package volumed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type fakeIdentity struct {
	pod PodCgroup
	err error
}

func (f fakeIdentity) Resolve(workloadclaims.Peer) (PodCgroup, error) {
	return f.pod, f.err
}

type fakeDevices struct {
	// device, when set, is answered for every name — two names resolving to
	// one disk, which is what a device-conflict test needs.
	device string
	err    error
}

func (f fakeDevices) Device(name string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.device != "" {
		return f.device, nil
	}
	return "/dev/disk/by-id/virtio-c8s-vol-" + name, nil
}

// serverFixture wires a server over a real unix socket, so the connection and
// peer-credential plumbing is exercised rather than stubbed.
type serverFixture struct {
	client *http.Client
	ops    *fakeOps
	opener *Opener
	srv    *Server
}

func newServerFixture(t *testing.T, ident Identity) *serverFixture {
	t.Helper()
	ops := newOps()
	opener := testOpener(t, ops)
	srv := &Server{Identity: ident, Opener: opener, Devices: fakeDevices{}}

	sock := filepath.Join(t.TempDir(), "volumed.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, l)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	return &serverFixture{client: client, ops: ops, opener: opener, srv: srv}
}

func (f *serverFixture) post(t *testing.T, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := f.client.Post("http://volumed"+VolumePath, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func openBody(t *testing.T) OpenRequest {
	t.Helper()
	req := testRequest(t)
	return OpenRequest{Name: req.Name, Blob: req.Blob}
}

func resolvedIdentity() fakeIdentity {
	return fakeIdentity{pod: testPod(testPodUID)}
}

func TestServerOpensForAResolvedCaller(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if f.opener.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", f.opener.Len())
	}
}

// A caller the kernel cannot place in a pod is refused before anything
// privileged happens: there is no directory to mount into.
func TestServerRefusesUnresolvableCaller(t *testing.T) {
	f := newServerFixture(t, fakeIdentity{err: errors.New("no pod cgroup")})
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if f.ops.sequence() != "" {
		t.Fatalf("an unresolved caller reached the privileged steps: %q", f.ops.sequence())
	}
}

// The volume name is a label in a host-written annotation, so a caller naming
// one already open must still present its key.
func TestServerRefusesAWrongKeyForAnOpenVolume(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
		t.Fatalf("first open: status %d", got)
	}

	body := openBody(t)
	blob, err := volume.NewBlob(make([]byte, volume.KeyBytes), *body.Blob.Verity)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	body.Blob = blob

	if got := f.post(t, body).StatusCode; got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d for a wrong key", got, http.StatusForbidden)
	}
	if f.opener.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want the original 1", f.opener.Len())
	}
}

// The caller never names its own pod; a body field claiming to is rejected
// rather than ignored.
func TestServerRejectsUnknownRequestFields(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	raw := map[string]any{"name": "weights", "pod_uid": "someone-else"}
	resp := f.post(t, raw)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestServerReportsAMissingDevice(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	f.srv.Devices = fakeDevices{err: errors.New("no such serial")}
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if f.ops.sequence() != "" {
		t.Fatalf("a missing device reached the privileged steps: %q", f.ops.sequence())
	}
}

func TestServerReportsAFailedOpen(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	f.ops.failOn = "CryptOpen"
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	// The body forwards the underlying cause so the in-pod sidecar (same
	// tenant, node-local socket) can surface why a release keeps failing
	// instead of retrying blind against a generic 500.
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "CryptOpen failed") {
		t.Fatalf("500 body = %q, want it to carry the underlying cause", string(body))
	}
	if c, v, m := f.ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("a failed open leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
}

// A restarted sidecar re-sends its request; the repeat must not open a second
// mapping or fail.
func TestServerIsIdempotentForARepeatedRequest(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	for i := range 3 {
		if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
			t.Fatalf("attempt %d: status %d", i, got)
		}
	}
	if f.opener.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", f.opener.Len())
	}
	if got := f.ops.sequence(); got != "CryptOpen,VerityOpen,MountRO" {
		t.Fatalf("repeats re-ran privileged steps: %q", got)
	}
}

// A second open of a device already held answers 409: the workload backing
// off and being rescheduled is the recovery, not a retry.
func TestServerReportsAConflictingOpen(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	f.srv.Devices = fakeDevices{device: "/dev/vdb"}
	body := openBody(t)
	blob, err := volume.NewMutableBlob(mustKey(t, body))
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	body.Blob = blob
	if got := f.post(t, body).StatusCode; got != http.StatusNoContent {
		t.Fatalf("first open: status %d", got)
	}

	// Same device, another name, same mutable key: one device, one mount.
	other := openBody(t)
	otherBlob, err := volume.NewMutableBlob(mustKey(t, other))
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	other.Name = "datasets"
	other.Blob = otherBlob
	if got := f.post(t, other).StatusCode; got != http.StatusConflict {
		t.Fatalf("status = %d, want %d", got, http.StatusConflict)
	}
}

// mustKey decodes the key out of a test body so a re-moded blob opens the same
// volume.
func mustKey(t *testing.T, body OpenRequest) []byte {
	t.Helper()
	key, err := body.Blob.DecodeKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return key
}

// The node cap answers differently from a refusal: a caller turned away here
// may succeed once something else is torn down.
func TestServerReportsTheNodeMountCap(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	f.opener.MaxMounts = 1
	if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
		t.Fatalf("first open: status %d", got)
	}

	body := openBody(t)
	body.Name = "datasets"
	if got := f.post(t, body).StatusCode; got != http.StatusInsufficientStorage {
		t.Fatalf("status = %d, want %d", got, http.StatusInsufficientStorage)
	}
}

// Only POST is served; the route exists for one verb.
func TestServerServesOnlyPost(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	resp, err := f.client.Get("http://volumed" + VolumePath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("GET was served")
	}
}

func TestServerBoundsTheRequestBody(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	body := openBody(t)
	body.Name = strings.Repeat("a", maxRequestBytes)
	if got := f.post(t, body).StatusCode; got != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d for an oversized body", got, http.StatusBadRequest)
	}
}

// The open request is one document: the handler refuses anything following it
// rather than opening the volume the first document names.
func TestServerRefusesTrailingDataAfterTheRequest(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	raw, err := json.Marshal(openBody(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := f.client.Post("http://volumed"+VolumePath, "application/json", bytes.NewReader(append(bytes.Clone(raw), raw...)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if f.opener.Len() != 0 {
		t.Fatalf("opener holds %d mounts, want 0", f.opener.Len())
	}
}

func TestAcquireBoundsConcurrentOpensPerPod(t *testing.T) {
	s := &Server{}
	var releases []func()
	for i := range maxInFlightPerPod {
		release, ok := s.acquire(testPodUID)
		if !ok {
			t.Fatalf("slot %d refused below the cap", i)
		}
		releases = append(releases, release)
	}
	if _, ok := s.acquire(testPodUID); ok {
		t.Fatal("acquired past the per-pod cap")
	}
	// A different pod has its own budget.
	if _, ok := s.acquire("99999999-8888-7777-6666-555555555555"); !ok {
		t.Fatal("one pod's load blocked another")
	}
	for _, r := range releases {
		r()
	}
	if _, ok := s.acquire(testPodUID); !ok {
		t.Fatal("slots were not released")
	}
}

func TestAcquireIsRaceFree(t *testing.T) {
	s := &Server{}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if release, ok := s.acquire(testPodUID); ok {
				release()
			}
		})
	}
	wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inFlight) != 0 {
		t.Fatalf("in-flight table leaked %d entries", len(s.inFlight))
	}
}

// postClose posts the bodiless termination close.
func (f *serverFixture) postClose(t *testing.T) *http.Response {
	t.Helper()
	resp, err := f.client.Post("http://volumed"+ClosePath, "application/json", nil)
	if err != nil {
		t.Fatalf("post close: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestServerClosesTheCallingPodsVolumes(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
		t.Fatalf("open: status %d", got)
	}
	if got := f.postClose(t).StatusCode; got != http.StatusNoContent {
		t.Fatalf("close: status %d, want %d", got, http.StatusNoContent)
	}
	if f.opener.Len() != 0 {
		t.Fatalf("opener holds %d mounts, want 0", f.opener.Len())
	}
	if c, v, m := f.ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("close left crypt=%d verity=%d mounts=%d behind", c, v, m)
	}
}

// Closing with nothing open is success: teardown races pod deletion by design.
func TestServerCloseWithNothingOpenIsANoOp(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	if got := f.postClose(t).StatusCode; got != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", got, http.StatusNoContent)
	}
}

func TestServerRefusesUnresolvableCloseCaller(t *testing.T) {
	f := newServerFixture(t, fakeIdentity{err: errors.New("no pod cgroup")})
	if got := f.postClose(t).StatusCode; got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}
}

// switchIdentity is an Identity whose answer the test changes between requests.
type switchIdentity struct {
	mu  sync.Mutex
	pod PodCgroup
}

func (s *switchIdentity) Resolve(workloadclaims.Peer) (PodCgroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pod, nil
}

func (s *switchIdentity) set(pod PodCgroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pod = pod
}

// A close releases the caller's own volumes and nobody else's: the pod comes
// from peer credentials, and the request has no say.
func TestServerCloseIsScopedToTheCallingPod(t *testing.T) {
	ident := &switchIdentity{pod: testPod(testPodUID)}
	f := newServerFixture(t, ident)
	if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
		t.Fatalf("open: status %d", got)
	}
	ident.set(testPod("00000000-0000-4000-8000-000000000000"))
	if got := f.postClose(t).StatusCode; got != http.StatusNoContent {
		t.Fatalf("close: status %d", got)
	}
	if f.opener.Len() != 1 {
		t.Fatalf("another pod's close took the mount: %d mounts, want 1", f.opener.Len())
	}
}

// A restarted sidecar whose close already ran re-opens and mounts afresh.
func TestServerReopensAfterClose(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity())
	if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
		t.Fatalf("open: status %d", got)
	}
	if got := f.postClose(t).StatusCode; got != http.StatusNoContent {
		t.Fatalf("close: status %d", got)
	}
	if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
		t.Fatalf("re-open: status %d", got)
	}
	if f.opener.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", f.opener.Len())
	}
}
