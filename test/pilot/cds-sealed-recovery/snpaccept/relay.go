package snpaccept

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const MaxRelayObject = 8 << 20 // This bounded acceptance workload uses small objects.

// StorageRequest/Response transport only public metadata or WAL ciphertext.
// The host must finish its durable conditional write before sending a response.
// This exercises the real S3 adapter without granting any guest network egress.
type StorageRequest struct {
	ID     uint64 `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Match  string `json:"match,omitempty"`
	Absent string `json:"absent,omitempty"`
	Data   []byte `json:"data,omitempty"`
}
type StorageResponse struct {
	ID     uint64 `json:"id"`
	Status int    `json:"status"`
	ETag   string `json:"etag,omitempty"`
	Data   []byte `json:"data,omitempty"`
}
type storageJob struct {
	request StorageRequest
	reply   chan StorageResponse
	ctx     context.Context
}
type completion struct {
	response StorageResponse
	accepted chan bool
}

type Relay struct {
	jobs      chan storageJob
	available chan StorageRequest
	completed chan completion
	slots     chan struct{}
	sequence  atomic.Uint64
	done      chan struct{}
}

func NewRelay(ctx context.Context) *Relay {
	r := &Relay{jobs: make(chan storageJob, 32), available: make(chan StorageRequest, 32), completed: make(chan completion, 32), slots: make(chan struct{}, 32), done: make(chan struct{})}
	go func() {
		defer close(r.done)
		pending := make(map[uint64]storageJob)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-r.jobs:
				if job.ctx.Err() != nil {
					continue
				}
				pending[job.request.ID] = job
				select {
				case r.available <- job.request:
				default:
					delete(pending, job.request.ID)
					job.reply <- StorageResponse{ID: job.request.ID, Status: 503}
				}
			case c := <-r.completed:
				job, ok := pending[c.response.ID]
				if ok {
					delete(pending, c.response.ID)
					job.reply <- c.response
				}
				c.accepted <- ok
			case <-tick.C:
				for id, job := range pending {
					if job.ctx.Err() != nil {
						delete(pending, id)
					}
				}
			}
		}
	}()
	return r
}

func (r *Relay) Exchange(ctx context.Context, request StorageRequest) (StorageResponse, error) {
	select {
	case r.slots <- struct{}{}:
	default:
		return StorageResponse{}, errors.New("storage relay backpressure")
	}
	defer func() { <-r.slots }()
	timeout := 15 * time.Second
	if request.Method == "CUSTODY" {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request.ID = r.sequence.Add(1)
	job := storageJob{request, make(chan StorageResponse, 1), ctx}
	select {
	case r.jobs <- job:
	case <-ctx.Done():
		return StorageResponse{}, ctx.Err()
	case <-r.done:
		return StorageResponse{}, errors.New("relay stopped")
	}
	select {
	case response := <-job.reply:
		return response, nil
	case <-ctx.Done():
		return StorageResponse{}, ctx.Err()
	case <-r.done:
		return StorageResponse{}, errors.New("relay stopped")
	}
}

func (r *Relay) Poll(ctx context.Context) (StorageRequest, error) {
	select {
	case request := <-r.available:
		return request, nil
	case <-ctx.Done():
		return StorageRequest{}, ctx.Err()
	case <-r.done:
		return StorageRequest{}, errors.New("relay stopped")
	}
}
func (r *Relay) Complete(ctx context.Context, response StorageResponse) bool {
	c := completion{response, make(chan bool, 1)}
	select {
	case r.completed <- c:
	case <-ctx.Done():
		return false
	case <-r.done:
		return false
	}
	select {
	case ok := <-c.accepted:
		return ok
	case <-ctx.Done():
		return false
	case <-r.done:
		return false
	}
}

func (r *Relay) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	if q.Method != http.MethodGet && q.Method != http.MethodPut {
		w.WriteHeader(405)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, q.Body, MaxRelayObject))
	if err != nil {
		http.Error(w, "bounded object body required", 400)
		return
	}
	response, err := r.Exchange(q.Context(), StorageRequest{Method: q.Method, Path: q.URL.Path, Match: q.Header.Get("If-Match"), Absent: q.Header.Get("If-None-Match"), Data: b})
	if err != nil {
		http.Error(w, "durable storage relay unavailable", 503)
		return
	}
	w.Header().Set("ETag", response.ETag)
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Data)
}
