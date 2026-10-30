// Package boardtest serves the S3 requests internal/cdsboard makes, from
// memory. Each client address has its own view of the store, so one replica
// can be given a withheld object, delayed answers or a frozen listing while
// the others see the store as it is.
package boardtest

import (
	"context"
	"encoding/xml"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is a fake S3 store holding one bucket.
type Server struct {
	tls    *httptest.Server
	bucket string

	mu      sync.Mutex
	objects map[string][]byte
	views   map[string]*View
	refused bool
}

// Start serves bucket until the caller closes the server.
func Start(bucket string) *Server {
	server := &Server{
		bucket:  bucket,
		objects: make(map[string][]byte),
		views:   make(map[string]*View),
	}
	server.tls = httptest.NewTLSServer(http.HandlerFunc(server.serve))
	return server
}

func (s *Server) Close() {
	s.tls.Close()
}

// Endpoint is the store endpoint a CDS configuration names.
func (s *Server) Endpoint() string {
	return s.tls.URL
}

// Transport trusts this server's certificate.
func (s *Server) Transport() *http.Transport {
	return s.tls.Client().Transport.(*http.Transport)
}

// Put stores one object under its bucket-relative key.
func (s *Server) Put(key string, object []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = object
}

// Refuse answers every request with 503, as a store the host stops serving
// does; false serves the bucket again.
func (s *Server) Refuse(refused bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused = refused
}

func (s *Server) refuses() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

// Object returns one stored object.
func (s *Server) Object(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	object, held := s.objects[key]
	return object, held
}

// Keys are the stored keys, in the order a listing names them.
func (s *Server) Keys() []string {
	return slices.Sorted(maps.Keys(s.objectSizes()))
}

// View returns the view of the client at clientIP; a fresh one answers from
// the store as it is.
func (s *Server) View(clientIP string) *View {
	s.mu.Lock()
	defer s.mu.Unlock()
	if view, known := s.views[clientIP]; known {
		return view
	}
	view := &View{server: s}
	s.views[clientIP] = view
	return view
}

// objectSizes is one snapshot of the store, which a listing is built from.
func (s *Server) objectSizes() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	sizes := make(map[string]int64, len(s.objects))
	for key, object := range s.objects {
		sizes[key] = int64(len(object))
	}
	return sizes
}

// View is what one client address sees of the store.
type View struct {
	server *Server

	mu            sync.Mutex
	withheld      map[string]bool
	delay         time.Duration
	listingFrozen bool
	frozenKeys    []string
}

// Withhold hides keys from this client; a later call replaces the set.
func (v *View) Withhold(keys ...string) {
	withheld := make(map[string]bool, len(keys))
	for _, key := range keys {
		withheld[key] = true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.withheld = withheld
}

// Delay holds every answer to this client back by d, or until the request is
// cancelled; zero answers at once.
func (v *View) Delay(d time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.delay = d
}

// FreezeListing keeps this client's listings at the keys the store holds now.
func (v *View) FreezeListing() {
	frozen := v.server.Keys()
	v.mu.Lock()
	defer v.mu.Unlock()
	v.listingFrozen = true
	v.frozenKeys = frozen
}

func (v *View) withholds(key string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.withheld[key]
}

func (v *View) hold(ctx context.Context) {
	v.mu.Lock()
	delay := v.delay
	v.mu.Unlock()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// lists is the keys this client's listing names, out of the store's own.
func (v *View) lists(stored []string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.listingFrozen {
		return v.frozenKeys
	}
	return stored
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if s.refuses() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	view := s.View(clientIP(r))
	view.hold(r.Context())
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != s.bucket {
		http.Error(w, "no such bucket", http.StatusNotFound)
		return
	}
	switch {
	case r.Method == http.MethodGet && key == "":
		s.serveListing(w, r, view)
	case r.Method == http.MethodGet:
		s.serveObject(w, key, view)
	case r.Method == http.MethodPut && key != "":
		s.storeObject(w, r, key)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listing is the ListObjectsV2 answer.
type listing struct {
	XMLName   xml.Name `xml:"ListBucketResult"`
	Name      string   `xml:"Name"`
	Truncated bool     `xml:"IsTruncated"`
	Contents  []entry  `xml:"Contents"`
}

type entry struct {
	Key  string `xml:"Key"`
	Size int64  `xml:"Size"`
}

func (s *Server) serveListing(w http.ResponseWriter, r *http.Request, view *View) {
	maxKeys, err := strconv.Atoi(r.URL.Query().Get("max-keys"))
	if r.URL.Query().Get("list-type") != "2" || err != nil {
		http.Error(w, "unsupported listing", http.StatusBadRequest)
		return
	}
	prefix := r.URL.Query().Get("prefix")
	sizes := s.objectSizes()
	answer := listing{Name: s.bucket}
	for _, key := range view.lists(slices.Sorted(maps.Keys(sizes))) {
		if !strings.HasPrefix(key, prefix) || view.withholds(key) {
			continue
		}
		if len(answer.Contents) == maxKeys {
			answer.Truncated = true
			break
		}
		answer.Contents = append(answer.Contents, entry{
			Key:  key,
			Size: sizes[key],
		})
	}
	_ = xml.NewEncoder(w).Encode(answer)
}

func (s *Server) serveObject(w http.ResponseWriter, key string, view *View) {
	object, held := s.Object(key)
	if !held || view.withholds(key) {
		http.Error(w, "no such key", http.StatusNotFound)
		return
	}
	_, _ = w.Write(object)
}

func (s *Server) storeObject(w http.ResponseWriter, r *http.Request, key string) {
	object, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "the object did not arrive", http.StatusBadRequest)
		return
	}
	s.Put(key, object)
}

func clientIP(r *http.Request) string {
	address, _, _ := net.SplitHostPort(r.RemoteAddr)
	return address
}
