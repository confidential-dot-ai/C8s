package podstart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

// Listen keeps the authority in a root-owned directory that workloads cannot write.
func Listen(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("pod start socket requires an absolute clean path")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !ownedByRoot(info) {
		return nil, errors.New("pod start socket directory must be root-owned and not writable by group or others")
	}
	if old, err := os.Lstat(path); err == nil {
		if old.Mode()&os.ModeSocket == 0 || !ownedByRoot(old) {
			return nil, errors.New("refusing to replace a non-root socket at the Pod start path")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

type rootPeerKey struct{}

// Serve stops accepting permissions as soon as its NRI session context ends.
func Serve(ctx context.Context, listener net.Listener, consume func(context.Context, Request) error) error {
	server := &http.Server{
		Handler:           handler(consume),
		ReadHeaderTimeout: Timeout,
		ReadTimeout:       Timeout,
		WriteTimeout:      Timeout,
		IdleTimeout:       Timeout,
		MaxHeaderBytes:    requestLimit,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, rootPeerKey{}, rootPeer(c))
		},
	}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	defer server.Close()
	err := server.Serve(listener)
	if ctx.Err() != nil && errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve Pod start permissions: %w", err)
}

func handler(consume func(context.Context, Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(rootPeerKey{}) != true {
			http.Error(w, "local root required", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/consume" || r.URL.RawQuery != "" {
			http.Error(w, "unsupported request", http.StatusBadRequest)
			return
		}
		var start Request
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, requestLimit))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&start); err != nil || start.Validate() != nil {
			http.Error(w, "invalid start request", http.StatusBadRequest)
			return
		}
		if dec.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid trailing data", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), Timeout)
		defer cancel()
		if err := consume(ctx, start); err != nil || ctx.Err() != nil {
			http.Error(w, "start not admitted", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
