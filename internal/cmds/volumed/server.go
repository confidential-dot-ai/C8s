package volumed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// VolumePath is the route the fetcher sidecar posts to.
const VolumePath = "/volume"

// ClosePath is the route the sidecar posts to at termination, releasing its
// pod's volumes before kubelet's emptyDir cleanup can delete through the live
// mount. See docs/volumes.md — teardown.
const ClosePath = "/volume/close"

// maxRequestBytes bounds a request body. It carries one key blob.
const maxRequestBytes = 64 << 10

// maxInFlightPerPod bounds concurrent opens from one pod, so a caller looping on
// the socket cannot occupy every worker.
const maxInFlightPerPod = 2

// Timeouts are this server's own, deliberately not the inventory's. Opening a
// volume reads from a host-backed device, which the host can make arbitrarily
// slow; a bound short enough for the inventory's token route would cut the
// response while the privileged work carried on, and the sidecar would retry
// into a duplicate request.
const (
	readTimeout  = 30 * time.Second
	writeTimeout = 5 * time.Minute
	idleTimeout  = 2 * time.Minute
)

// OpenRequest is the wire body. It carries no identity: which pod is asking
// comes from the kernel, and a field claiming otherwise would be the caller
// naming itself.
type OpenRequest struct {
	// Name selects the volume, and with it the device the agent will open.
	Name string      `json:"name"`
	Blob volume.Blob `json:"blob"`
}

// Identity resolves a connected process to the pod it belongs to.
type Identity interface {
	Resolve(peer workloadclaims.Peer) (PodCgroup, error)
}

// Devices maps a volume name to the block device carrying it.
type Devices interface {
	Device(name string) (string, error)
}

// Server serves VolumePath on a unix socket.
type Server struct {
	Identity Identity
	Opener   *Opener
	Devices  Devices
	Logger   *slog.Logger

	mu       sync.Mutex
	inFlight map[string]int
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// Serve runs the server on l until ctx is done.
//
// The listener is this server's own. Sharing the inventory's would put a
// wedged volume open behind the same timeouts and the same accept loop as
// sandbox-token issuance, which every confidential pod depends on to start.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	mux := http.NewServeMux()
	mux.Handle("POST "+VolumePath, http.HandlerFunc(s.handleOpen))
	mux.Handle("POST "+ClosePath, http.HandlerFunc(s.handleClose))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type connKey struct{}

func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	conn, _ := r.Context().Value(connKey{}).(net.Conn)
	peer := workloadclaims.PeerFromConn(conn)
	defer peer.Close()

	var req OpenRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if dec.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid trailing data", http.StatusBadRequest)
		return
	}

	pod, err := s.Identity.Resolve(peer)
	if err != nil {
		s.logger().Warn("volume request rejected", "reason", err)
		http.Error(w, "caller could not be resolved", http.StatusForbidden)
		return
	}

	release, ok := s.acquire(pod.UID)
	if !ok {
		http.Error(w, "too many concurrent requests", http.StatusTooManyRequests)
		return
	}
	defer release()

	device, err := s.Devices.Device(req.Name)
	if err != nil {
		s.logger().Warn("volume device unavailable", "name", req.Name, "reason", err)
		http.Error(w, "volume device is not present on this node", http.StatusNotFound)
		return
	}

	err = s.Opener.Open(r.Context(), Request{Pod: pod, Name: req.Name, Device: device, Blob: req.Blob})
	switch {
	case err == nil:
		s.logger().Info("volume opened", "pod", pod.UID, "name", req.Name)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrNotAuthorized):
		s.logger().Warn("volume request denied", "pod", pod.UID, "name", req.Name, "reason", err)
		http.Error(w, "not authorized for this volume", http.StatusForbidden)
	case errors.Is(err, ErrTooManyMounts):
		http.Error(w, "too many open volumes on this node", http.StatusInsufficientStorage)
	case errors.Is(err, ErrVolumeInUse):
		http.Error(w, "volume device is already in use", http.StatusConflict)
	default:
		// Forward the underlying cause, not just a generic 500: the caller is
		// the in-pod get-volume sidecar over a node-local socket, same tenant
		// on a single-tenant node-as-CVM, so this leaks nothing across the
		// trust boundary — and without it a systemic failure (a missing
		// cryptsetup, a verity mismatch) is invisible to the operator, who
		// sees only the sidecar giving up after every attempt.
		s.logger().Error("volume open failed", "pod", pod.UID, "name", req.Name, "error", err)
		http.Error(w, fmt.Sprintf("could not open the volume: %v", err), http.StatusInternalServerError)
	}
}

// handleClose releases every volume the calling pod holds. The caller is
// resolved from kernel peer credentials, so a pod can only ever close its own
// volumes; closing what is not open is a no-op, because teardown races pod
// deletion by design.
func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	conn, _ := r.Context().Value(connKey{}).(net.Conn)
	peer := workloadclaims.PeerFromConn(conn)
	defer peer.Close()

	pod, err := s.Identity.Resolve(peer)
	if err != nil {
		s.logger().Warn("volume close rejected", "reason", err)
		http.Error(w, "caller could not be resolved", http.StatusForbidden)
		return
	}
	release, ok := s.acquire(pod.UID)
	if !ok {
		http.Error(w, "too many concurrent requests", http.StatusTooManyRequests)
		return
	}
	defer release()
	if n := s.Opener.ClosePod(r.Context(), pod.UID); n > 0 {
		s.logger().Info("volumes closed", "pod", pod.UID, "volumes", n)
	}
	w.WriteHeader(http.StatusNoContent)
}

// acquire bounds concurrent opens per pod.
func (s *Server) acquire(podUID string) (func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight == nil {
		s.inFlight = map[string]int{}
	}
	if s.inFlight[podUID] >= maxInFlightPerPod {
		return nil, false
	}
	s.inFlight[podUID]++
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.inFlight[podUID]--; s.inFlight[podUID] <= 0 {
			delete(s.inFlight, podUID)
		}
	}, true
}
