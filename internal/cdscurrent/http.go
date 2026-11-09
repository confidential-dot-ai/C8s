package cdscurrent

import (
	"bytes"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/casregister"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// ServeHTTP exposes the local proof's CA, allowlist and operator secret routes.
// It does not implement issuance, decrees, pod-secret brokers or production TLS.
// Its hosting server must enforce header and body read deadlines.
func (r *Replica) ServeHTTP(
	w http.ResponseWriter,
	request *http.Request,
) {
	ctx, done, err := r.begin(request.Context())
	if err != nil {
		writeUnavailable(
			w,
			err,
		)
		return
	}
	defer done()
	request = request.Clone(ctx)
	if len(request.URL.EscapedPath()) > 4096 {
		http.Error(
			w,
			"path too long",
			http.StatusRequestURITooLong,
		)
		return
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/ca":
		v, err := r.read(ctx)
		if err != nil {
			writeUnavailable(
				w,
				err,
			)
			return
		}
		defer v.close()
		w.Header().Set(
			"Content-Type",
			"application/x-pem-file",
		)
		w.Header().Set(
			"Cache-Control",
			"no-store",
		)
		_ = pem.Encode(
			w,
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: v.ca.Cert.Raw,
			},
		)
	case request.Method == http.MethodGet && request.URL.Path == "/allowlist":
		v, err := r.read(ctx)
		if err != nil {
			writeUnavailable(
				w,
				err,
			)
			return
		}
		defer v.close()
		allowlist.Handler{Allowlist: v.al.Local()}.HandleList(
			w,
			request,
		)
	case request.Method == http.MethodPut && (request.URL.Path == "/allowlist" || strings.HasPrefix(
		request.URL.Path,
		"/secrets/",
	)):
		r.writeOperator(
			w,
			request,
		)
	default:
		http.NotFound(
			w,
			request,
		)
	}
}

func (r *Replica) writeOperator(
	w http.ResponseWriter,
	request *http.Request,
) {
	body, err := io.ReadAll(io.LimitReader(
		request.Body,
		allowlist.DefaultMaxWriteBodyBytes+1,
	))
	if err != nil {
		http.Error(
			w,
			"read request body",
			http.StatusBadRequest,
		)
		return
	}
	defer clear(body)
	if len(body) > int(allowlist.DefaultMaxWriteBodyBytes) {
		http.Error(
			w,
			"request body too large",
			http.StatusRequestEntityTooLarge,
		)
		return
	}
	var response *bufferedResponse
	defer func() {
		if response != nil {
			clear(response.body.Bytes())
		}
	}()
	_, err = r.update(
		request.Context(),
		func(v *view) error {
			attempt := request.Clone(request.Context())
			attempt.Body = io.NopCloser(bytes.NewReader(body))
			response = &bufferedResponse{header: make(http.Header)}
			authorize := func(
				req *http.Request,
				data []byte,
			) error {
				if err := r.verifier.Authorize(
					req,
					data,
				); err != nil {
					return err
				}
				token, _ := strings.CutPrefix(
					req.Header.Get("Authorization"),
					"Bearer ",
				)
				if err := v.al.Local().ConsumeToken(token); err != nil {
					if errors.Is(
						err,
						operatorauth.ErrTokenReused,
					) {
						return err
					}
					return errors.Join(
						operatorauth.ErrTokenNotRecorded,
						err,
					)
				}
				return nil
			}
			if request.URL.Path == "/allowlist" {
				allowlist.Handler{
					Allowlist:       v.al.Local(),
					WriteAuthorizer: authorize,
				}.HandleReplaceAll(
					response,
					attempt,
				)
			} else {
				secrets.OperatorHandler{
					Store:     v.secrets.Local(),
					Authorize: authorize,
				}.ServeHTTP(
					response,
					attempt,
				)
			}
			return response.err
		},
	)
	if err != nil {
		writeUnavailable(
			w,
			err,
		)
		return
	}
	if response == nil {
		writeUnavailable(
			w,
			errors.New("current CDS: missing handler result"),
		)
		return
	}
	response.publish(w)
}

// No status or response bytes reach the caller before the state is committed.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
	err    error
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}
func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	if b.body.Len()+len(p) > 128<<10 {
		b.err = ErrCapacity
		return 0, b.err
	}
	return b.body.Write(p)
}

func (b *bufferedResponse) publish(w http.ResponseWriter) {
	for key, values := range b.header {
		w.Header()[key] = append(
			[]string(nil),
			values...,
		)
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}

func writeUnavailable(
	w http.ResponseWriter,
	err error,
) {
	w.Header().Set(
		"Cache-Control",
		"no-store",
	)
	if errors.Is(
		err,
		casregister.ErrUnknown,
	) {
		w.Header().Set(
			"X-CDS-Outcome",
			"unknown",
		)
		http.Error(
			w,
			"commit outcome unknown; a timeout does not cancel the write",
			http.StatusServiceUnavailable,
		)
		return
	}
	// An aborted transform did not commit its state-dependent observation.
	uncommitted := errors.Is(
		err,
		casregister.ErrUnavailable,
	)
	if !uncommitted && errors.Is(
		err,
		ErrCapacity,
	) {
		http.Error(
			w,
			ErrCapacity.Error(),
			http.StatusInsufficientStorage,
		)
		return
	}
	w.Header().Set(
		"Retry-After",
		"1",
	)
	http.Error(
		w,
		"current state unavailable",
		http.StatusServiceUnavailable,
	)
}
