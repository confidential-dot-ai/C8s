package cds

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/internal/server"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
)

const objectRequestTimeout = 30 * time.Second

// objectServer dispatches bounded messages to request workers. The only
// shared mutable counters are atomic; each worker owns its complete view.
type objectServer struct {
	cfg          config
	store        objectstate.Store
	cipher       *objectstate.Cipher
	dependencies func(backend) (dependencies, error)
	onCA         func(*x509.Certificate)
	ctx          context.Context
	cancel       context.CancelFunc
	admit        chan objectRequest
	queue        chan objectRequest
	caUpdates    chan objectCAUpdate
	slots        chan struct{}
	dispatched   chan struct{}
	workers      sync.WaitGroup
	maintenance  sync.WaitGroup
	closed       atomic.Bool
	requests     atomic.Uint64
	commits      atomic.Uint64
	conflicts    atomic.Uint64
	unknown      atomic.Uint64
	busy         atomic.Uint64
	inflight     atomic.Int64
	pending      atomic.Int64
}

type objectRequest struct {
	r        *http.Request
	response *objectResponse
	done     chan struct{}
}

type objectCAUpdate struct {
	revision uint64
	cert     *x509.Certificate
}

func newObjectServer(
	ctx context.Context,
	cfg config,
	store objectstate.Store,
	sealed *objectstate.Cipher,
	build func(backend) (dependencies, error),
	onCA func(*x509.Certificate),
) *objectServer {
	ctx, cancel := context.WithCancel(ctx)
	s := &objectServer{
		cfg:          cfg,
		store:        store,
		cipher:       sealed,
		dependencies: build,
		onCA:         onCA,
		ctx:          ctx,
		cancel:       cancel,
		admit:        make(chan objectRequest),
		caUpdates:    make(chan objectCAUpdate),
		queue: make(
			chan objectRequest,
			cfg.measured.ObjectState.QueueCapacity,
		),
		slots: make(
			chan struct{},
			cfg.measured.ObjectState.Workers+cfg.measured.ObjectState.QueueCapacity,
		),
		dispatched: make(chan struct{}),
	}
	for range cfg.measured.ObjectState.Workers {
		s.workers.Add(1)
		go s.work()
	}
	go s.dispatch()
	return s
}

func (s *objectServer) Stop() {
	s.closed.Store(true)
	s.cancel()
	<-s.dispatched
	s.workers.Wait()
	s.maintenance.Wait()
}

// Bootstrap's control actor starts maintenance before it can stop the
// published server, so this Add cannot race Stop's Wait.
func (s *objectServer) startMaintenance() {
	s.maintenance.Add(1)
	go func() {
		defer s.maintenance.Done()
		ticker := time.NewTicker(caRenewalCheckInterval)
		defer ticker.Stop()
		for s.ctx.Err() == nil {
			if err := s.refreshCA(); err != nil && s.ctx.Err() == nil {
				slog.Warn(
					"CDS CA refresh failed",
					"error",
					err,
				)
			}
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (s *objectServer) refreshCA() error {
	request, err := http.NewRequestWithContext(
		s.ctx,
		http.MethodGet,
		"/ca",
		nil,
	)
	if err != nil {
		return err
	}
	response := newObjectResponse(int(s.cfg.measured.ObjectState.MaxBytes))
	defer func() { clear(response.body) }()
	s.ServeHTTP(
		response,
		request,
	)
	if response.code != http.StatusOK {
		return fmt.Errorf(
			"CA refresh returned HTTP %d",
			response.code,
		)
	}
	return nil
}

// The dispatcher alone sends work and closes the queue. An unbuffered
// admission transfers ownership only while it can still complete the job.
func (s *objectServer) dispatch() {
	defer close(s.dispatched)
	defer close(s.queue)
	var currentRevision uint64
	var pending objectRequest
	for {
		admit := s.admit
		var ready chan objectRequest
		if pending.done != nil {
			admit = nil
			ready = s.queue
		}
		select {
		case <-s.ctx.Done():
			if pending.done != nil {
				pending.response.fail(
					http.StatusServiceUnavailable,
					"CDS is stopping",
				)
				close(pending.done)
				s.pending.Store(0)
			}
			return
		case update := <-s.caUpdates:
			if update.revision > currentRevision {
				currentRevision = update.revision
				s.onCA(update.cert)
			}
		case pending = <-admit:
			s.pending.Store(1)
		case ready <- pending:
			pending = objectRequest{}
			s.pending.Store(0)
		}
	}
}

func (s *objectServer) publishCA(
	ctx context.Context,
	revision uint64,
	cert *x509.Certificate,
) {
	if s.onCA == nil {
		return
	}
	select {
	case s.caUpdates <- objectCAUpdate{
		revision: revision,
		cert:     cert,
	}:
	case <-ctx.Done():
	case <-s.ctx.Done():
	}
}

func (s *objectServer) work() {
	defer s.workers.Done()
	for job := range s.queue {
		func() {
			defer close(job.done)
			s.inflight.Add(1)
			defer s.inflight.Add(-1)
			defer func() {
				if recover() != nil {
					job.response.fail(
						http.StatusInternalServerError,
						"request failed",
					)
					slog.Error("object state request panicked")
				}
			}()
			s.execute(
				job.response,
				job.r,
			)
		}()
	}
}

func (s *objectServer) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	if s.closed.Load() || s.ctx.Err() != nil {
		http.Error(
			w,
			"CDS is stopping",
			http.StatusServiceUnavailable,
		)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.busy.Add(1)
		w.Header().Set(
			"Retry-After",
			"1",
		)
		http.Error(
			w,
			"CDS request capacity reached",
			http.StatusServiceUnavailable,
		)
		return
	}
	ctx, cancel := context.WithTimeout(
		r.Context(),
		objectRequestTimeout,
	)
	defer cancel()
	stop := context.AfterFunc(
		s.ctx,
		cancel,
	)
	defer stop()
	// HTTP/1 body.Close can wait behind a blocked Read. Expire the socket's
	// read deadline first so cancellation also interrupts a stalled upload.
	bodyClosed := make(chan struct{})
	closeBody := context.AfterFunc(
		ctx,
		func() {
			defer close(bodyClosed)
			_ = http.NewResponseController(w).SetReadDeadline(time.Now())
			if r.Body != nil {
				_ = r.Body.Close()
			}
		},
	)
	defer func() {
		if !closeBody() {
			<-bodyClosed
		}
	}()
	job := objectRequest{
		r:        r.WithContext(ctx),
		response: newObjectResponse(int(s.cfg.measured.ObjectState.MaxBytes)),
		done:     make(chan struct{}),
	}
	select {
	case s.admit <- job:
	case <-ctx.Done():
		http.Error(
			w,
			"CDS request canceled before admission",
			http.StatusServiceUnavailable,
		)
		return
	}
	// Accepted jobs always complete, including queued jobs during Stop.
	// Returning earlier would close r.Body beneath its worker.
	<-job.done
	defer clear(job.response.body)
	if ctx.Err() != nil || s.ctx.Err() != nil {
		job.response.fail(
			http.StatusServiceUnavailable,
			"CDS request canceled; commit outcome may be unknown",
		)
		job.response.Header().Set(
			"X-C8s-Commit-Outcome",
			"unknown",
		)
	}
	job.response.send(w)
}

func (s *objectServer) execute(
	w *objectResponse,
	r *http.Request,
) {
	s.requests.Add(1)
	if s.ctx.Err() != nil || r.Context().Err() != nil {
		w.fail(
			http.StatusServiceUnavailable,
			"request expired in queue",
		)
		return
	}
	object, err := s.store.Load(r.Context())
	if err != nil {
		s.refuse(
			w,
			err,
		)
		return
	}
	plain, err := s.cipher.Open(object.Data)
	if err != nil {
		s.refuse(
			w,
			err,
		)
		return
	}
	defer clear(plain)
	view, err := readObjectView(
		s.cfg,
		plain,
	)
	if err != nil {
		s.refuse(
			w,
			err,
		)
		return
	}
	defer view.Stop()
	// This certificate came from a committed object; a renewal below is only
	// a candidate until its conditional replacement succeeds.
	s.publishCA(
		r.Context(),
		view.state.Revision,
		view.ca.CA.Cert,
	)
	if err := view.renewCA(s.cfg.caCertValidity); err != nil {
		s.refuse(
			w,
			err,
		)
		return
	}
	if err := objectClientCertificate(
		r,
		view.ca.CA.Cert,
	); err != nil {
		w.fail(
			http.StatusForbidden,
			"client certificate is no longer authorized",
		)
		return
	}
	deps, err := s.dependencies(view)
	if err != nil {
		s.refuse(
			w,
			err,
		)
		return
	}
	logContext, publishLogs := server.DeferCommitLogs(r.Context())
	r = r.WithContext(logContext)
	deps.DeferRequestLog = true
	// No whole-handler retries: /pod-secrets can contact an external KMS.
	newRouter(deps).ServeHTTP(
		w,
		r,
	)
	if w.overflow || s.ctx.Err() != nil || r.Context().Err() != nil {
		w.fail(
			http.StatusServiceUnavailable,
			"request could not be completed",
		)
		return
	}
	if !view.dirty() && r.URL.Path != secretbroker.PodRoute {
		publishLogs()
		return
	}
	plain, err = view.encode()
	if err != nil {
		s.refuse(
			w,
			err,
		)
		return
	}
	defer clear(plain)
	ciphertext, err := s.cipher.Seal(plain)
	if err != nil {
		s.refuse(
			w,
			err,
		)
		return
	}
	_, err = s.store.CompareAndSwap(
		r.Context(),
		object.ETag,
		ciphertext,
	)
	if err != nil {
		s.refuse(
			w,
			err,
		)
		return
	}
	s.commits.Add(1)
	publishLogs()
	s.publishCA(
		r.Context(),
		view.state.Revision,
		view.ca.CA.Cert,
	)
	slog.Info(
		"CDS object state committed",
		"revision",
		view.state.Revision,
		"method",
		r.Method,
		"response_status",
		w.code,
	)
}

func (s *objectServer) refuse(
	w *objectResponse,
	err error,
) {
	switch {
	case errors.Is(
		err,
		objectstate.ErrConflict,
	):
		s.conflicts.Add(1)
		w.fail(
			http.StatusConflict,
			"state changed; reread and retry the request",
		)
		w.Header().Set(
			"X-C8s-Commit-Outcome",
			"not-committed",
		)
	case errors.Is(
		err,
		objectstate.ErrUnknown,
	):
		s.unknown.Add(1)
		w.fail(
			http.StatusServiceUnavailable,
			"commit outcome unknown; authorization may have been consumed",
		)
		w.Header().Set(
			"X-C8s-Commit-Outcome",
			"unknown",
		)
	default:
		w.fail(
			http.StatusServiceUnavailable,
			"current CDS state unavailable",
		)
	}
}

// A TLS connection may outlive a CA replacement. Verify against this request's
// authoritative root rather than trusting its handshake's VerifiedChains.
func objectClientCertificate(
	r *http.Request,
	ca *x509.Certificate,
) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	intermediates := x509.NewCertPool()
	for _, cert := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	chains, err := r.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return err
	}
	connection := new(tls.ConnectionState)
	*connection = *r.TLS
	connection.VerifiedChains = chains
	r.TLS = connection
	return nil
}

type objectResponse struct {
	header   http.Header
	code     int
	body     []byte
	max      int
	overflow bool
}

func newObjectResponse(maxBytes int) *objectResponse {
	return &objectResponse{
		header: make(http.Header),
		max:    maxBytes,
	}
}

func (w *objectResponse) Header() http.Header { return w.header }
func (w *objectResponse) WriteHeader(code int) {
	if w.code == 0 && code >= 200 {
		w.code = code
	}
}
func (w *objectResponse) Write(body []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	if len(body) > w.max-len(w.body) {
		w.overflow = true
		return 0, io.ErrShortBuffer
	}
	w.body = append(
		w.body,
		body...,
	)
	return len(body), nil
}
func (w *objectResponse) fail(
	code int,
	message string,
) {
	clear(w.body)
	w.body = nil
	w.header = make(http.Header)
	w.header.Set(
		"Cache-Control",
		"no-store",
	)
	w.code = 0
	http.Error(
		w,
		message,
		code,
	)
}
func (w *objectResponse) send(target http.ResponseWriter) {
	for key, values := range w.header {
		target.Header()[key] = slicesClone(values)
	}
	if w.code == 0 {
		w.code = http.StatusOK
	}
	target.WriteHeader(w.code)
	_, _ = io.Copy(
		target,
		bytes.NewReader(w.body),
	)
}

func slicesClone(values []string) []string {
	return append(
		[]string(nil),
		values...,
	)
}

var objectMetricDescriptors = []*prometheus.Desc{
	prometheus.NewDesc(
		"c8s_cds_object_requests_total",
		"Requests processed by object-state workers.",
		nil,
		nil,
	),
	prometheus.NewDesc(
		"c8s_cds_object_commits_total",
		"Conditional state replacements acknowledged by storage.",
		nil,
		nil,
	),
	prometheus.NewDesc(
		"c8s_cds_object_conflicts_total",
		"Conditional replacements refused because the state changed.",
		nil,
		nil,
	),
	prometheus.NewDesc(
		"c8s_cds_object_unknown_total",
		"Replacements whose commit outcome could not be established.",
		nil,
		nil,
	),
	prometheus.NewDesc(
		"c8s_cds_object_busy_total",
		"Requests refused at the bounded admission capacity.",
		nil,
		nil,
	),
	prometheus.NewDesc(
		"c8s_cds_object_queued",
		"Admitted requests waiting for an object-state worker.",
		nil,
		nil,
	),
	prometheus.NewDesc(
		"c8s_cds_object_inflight",
		"Requests currently executing in object-state workers.",
		nil,
		nil,
	),
}

func (s *objectServer) Describe(out chan<- *prometheus.Desc) {
	for _, descriptor := range objectMetricDescriptors {
		out <- descriptor
	}
}

func (s *objectServer) Collect(out chan<- prometheus.Metric) {
	counts := []uint64{
		s.requests.Load(),
		s.commits.Load(),
		s.conflicts.Load(),
		s.unknown.Load(),
		s.busy.Load(),
	}
	for index, value := range counts {
		out <- prometheus.MustNewConstMetric(
			objectMetricDescriptors[index],
			prometheus.CounterValue,
			float64(value),
		)
	}
	for index, value := range []int64{
		int64(len(s.queue)) + s.pending.Load(),
		s.inflight.Load(),
	} {
		out <- prometheus.MustNewConstMetric(
			objectMetricDescriptors[len(counts)+index],
			prometheus.GaugeValue,
			float64(value),
		)
	}
}
