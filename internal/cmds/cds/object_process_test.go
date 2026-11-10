package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

// These processes use ordinary TLS and synthetic inventory, never native attestation.
type objectProcessInput struct {
	Document, EncryptionKey, OperatorPublicKey, InventoryPublicKey, Memory []byte
	Control                                                                string
	Credentials                                                            aws.Credentials
}

type objectProcessReady struct {
	URL         string
	Certificate []byte
}

type objectProcess struct {
	cmd          *exec.Cmd
	t            *testing.T
	done         chan error
	client       *http.Client
	url, control string
	stopOnce     sync.Once
	diagnostics  objectChildDiagnostics
}

// Only the race marker is retained; stderr itself can contain sensitive diagnostics.
type objectChildDiagnostics struct {
	tail []byte
	race atomic.Bool
}

func (d *objectChildDiagnostics) Write(p []byte) (int, error) {
	marker := []byte("WARNING: DATA RACE")
	prefix := p[:min(
		len(p),
		len(marker)-1,
	)]
	boundary := append(
		d.tail,
		prefix...,
	)
	if bytes.Contains(
		p,
		marker,
	) || bytes.Contains(
		boundary,
		marker,
	) {
		d.race.Store(true)
	}
	if len(p) >= len(marker)-1 {
		d.tail = bytes.Clone(p[len(p)-(len(marker)-1):])
	} else {
		d.tail = bytes.Clone(boundary[max(
			0,
			len(boundary)-(len(marker)-1),
		):])
	}
	return len(p), nil
}

func objectChildExitError(
	err error,
	race bool,
) error {
	if race {
		return errors.New("CDS replica subprocess reported a data race")
	}
	var exit *exec.ExitError
	if errors.As(
		err,
		&exit,
	) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGKILL {
			return nil
		}
	}
	return errors.New("CDS replica subprocess exited without the requested SIGKILL")
}

type objectFaultStore struct {
	objectstate.Store
	mu              sync.Mutex
	next            string
	entered, resume chan struct{}
	commits         atomic.Uint64
	failure         atomic.Pointer[objectStoreFailure]
}

type objectStoreFailure struct {
	Operation string `json:"operation"`
	Kind      string `json:"kind"`
	Code      string `json:"code,omitempty"`
	Status    int    `json:"status,omitempty"`
}

func (s *objectFaultStore) Load(ctx context.Context) (objectstate.Object, error) {
	object, err := s.Store.Load(ctx)
	s.recordFailure(
		"load",
		err,
	)
	return object, err
}

func (s *objectFaultStore) recordFailure(
	operation string,
	err error,
) {
	if err == nil {
		return
	}
	failure := &objectStoreFailure{
		Operation: operation,
		Kind:      "storage",
	}
	switch {
	case errors.Is(
		err,
		context.DeadlineExceeded,
	):
		failure.Kind = "timeout"
	case errors.Is(
		err,
		context.Canceled,
	):
		failure.Kind = "canceled"
	case errors.Is(
		err,
		objectstate.ErrConflict,
	):
		failure.Kind = "conflict"
	case errors.Is(
		err,
		objectstate.ErrUnknown,
	):
		failure.Kind = "unknown"
	case errors.Is(
		err,
		objectstate.ErrNotFound,
	):
		failure.Kind = "missing"
	}
	var apiError smithy.APIError
	if errors.As(
		err,
		&apiError,
	) {
		switch code := apiError.ErrorCode(); code {
		case "AccessDenied", "ExpiredToken", "InvalidAccessKeyId", "SignatureDoesNotMatch", "RequestTimeTooSkewed", "PreconditionFailed", "ConditionalRequestConflict", "SlowDown", "InternalError", "ServiceUnavailable", "RequestTimeout", "NoSuchKey", "AuthorizationHeaderMalformed", "InvalidToken", "InvalidRequest", "BadDigest", "NotImplemented":
			failure.Code = code
		default:
			failure.Code = "other"
		}
	}
	var response *smithyhttp.ResponseError
	if errors.As(
		err,
		&response,
	) {
		failure.Status = response.HTTPStatusCode()
	}
	if failure.Kind == "conflict" {
		s.failure.CompareAndSwap(
			nil,
			failure,
		)
	} else {
		s.failure.Store(failure)
	}
}

func (s *objectFaultStore) CompareAndSwap(
	ctx context.Context,
	etag string,
	data []byte,
) (string, error) {
	s.mu.Lock()
	mode, entered, resume := s.next, s.entered, s.resume
	s.next = ""
	s.mu.Unlock()
	if mode == "pause" {
		close(entered)
		select {
		case <-resume:
		case <-ctx.Done():
			return "", objectstate.ErrUnknown
		}
	}
	etag, err := s.Store.CompareAndSwap(
		ctx,
		etag,
		data,
	)
	s.recordFailure(
		"cas",
		err,
	)
	if err == nil {
		s.commits.Add(1)
		if mode == "lose-ack" {
			return "", objectstate.ErrUnknown
		}
	}
	return etag, err
}

func (s *objectFaultStore) control(
	w http.ResponseWriter,
	r *http.Request,
) {
	s.mu.Lock()
	switch r.URL.Path {
	case "/_acceptance/pause", "/_acceptance/lose-ack":
		if r.Method != http.MethodPost || s.next != "" || s.resume != nil {
			s.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			return
		}
		s.next = r.URL.Path[len("/_acceptance/"):]
		if s.next == "pause" {
			s.entered, s.resume = make(chan struct{}), make(chan struct{})
		}
	case "/_acceptance/resume":
		if r.Method != http.MethodPost || s.resume == nil {
			s.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			return
		}
		close(s.resume)
		s.resume = nil
	case "/_acceptance/entered":
		entered := s.entered
		s.mu.Unlock()
		select {
		case <-entered:
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
		return
	case "/_acceptance/error":
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(s.failure.Load())
		return
	case "/_acceptance/commits":
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(s.commits.Load())
		return
	default:
		s.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func TestObjectAcceptanceChild(t *testing.T) {
	if os.Getenv("C8S_OBJECT_ACCEPTANCE_CHILD") != "1" {
		t.Skip("subprocess entry point")
	}
	var input objectProcessInput
	if err := json.NewDecoder(io.LimitReader(
		os.Stdin,
		32<<20,
	)).Decode(&input); err != nil {
		t.Fatal(err)
	}
	h := newObjectAcceptance(t)
	h.stop()
	var err error
	h.cfg.measured, err = cdsconfig.Parse(input.Document)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.measuredFile = input.Document
	h.cipher, err = objectCipher(
		h.cfg,
		input.EncryptionKey,
	)
	clear(input.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := x509.ParsePKIXPublicKey(input.OperatorPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := x509.ParsePKIXPublicKey(input.InventoryPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	h.operator = &ecdsa.PrivateKey{PublicKey: *operator.(*ecdsa.PublicKey)}
	h.inventory.key = inventory.(*ecdsa.PublicKey)
	if input.Memory != nil {
		h.store = &acceptanceObjectStore{
			data:    input.Memory,
			version: 1,
		}
	} else {
		h.store = objectLiveStore(
			t,
			h.cfg,
			credentials.NewStaticCredentialsProvider(
				input.Credentials.AccessKeyID,
				input.Credentials.SecretAccessKey,
				input.Credentials.SessionToken,
			),
		)
	}
	faults := &objectFaultStore{Store: h.store}
	h.store = faults
	server := h.newServer(t)
	defer server.Stop()
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		if len(r.URL.Path) >= len("/_acceptance/") && r.URL.Path[:len("/_acceptance/")] == "/_acceptance/" {
			if subtle.ConstantTimeCompare(
				[]byte(r.Header.Get("X-Acceptance-Control")),
				[]byte(input.Control),
			) != 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			faults.control(
				w,
				r,
			)
			return
		}
		server.ServeHTTP(
			w,
			r,
		)
	}))
	httpServer.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequestClientCert,
	}
	httpServer.StartTLS()
	defer httpServer.Close()
	if err := json.NewEncoder(os.Stdout).Encode(objectProcessReady{
		URL:         httpServer.URL,
		Certificate: httpServer.Certificate().Raw,
	}); err != nil {
		t.Fatal(err)
	}
	<-t.Context().Done()
}

func startObjectProcess(
	t *testing.T,
	input objectProcessInput,
	clientCertificate *tls.Certificate,
) *objectProcess {
	t.Helper()
	control := make(
		[]byte,
		32,
	)
	if _, err := rand.Read(control); err != nil {
		t.Fatal(err)
	}
	input.Control = hex.EncodeToString(control)
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	cmd := exec.Command(
		os.Args[0],
		"-test.run=^TestObjectAcceptanceChild$",
		"-test.timeout=10m",
	)
	for _, variable := range os.Environ() {
		if strings.HasPrefix(
			variable,
			"GORACE=",
		) {
			continue
		}
		if !strings.HasPrefix(
			variable,
			"AWS_",
		) && !strings.HasPrefix(
			variable,
			"C8S_OBJECT_",
		) {
			cmd.Env = append(
				cmd.Env,
				variable,
			)
		}
	}
	cmd.Env = append(
		cmd.Env,
		"C8S_OBJECT_ACCEPTANCE_CHILD=1",
		"AWS_EC2_METADATA_DISABLED=true",
		"GORACE=halt_on_error=1 exitcode=66 log_path=stderr",
	)
	cmd.Stdin = bytes.NewReader(encoded)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	p := &objectProcess{
		cmd: cmd,
		t:   t,
		done: make(
			chan error,
			1,
		),
		control: input.Control,
	}
	cmd.Stderr = &p.diagnostics
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(p.kill)
	ready := make(
		chan objectProcessReady,
		1,
	)
	readError := make(
		chan error,
		1,
	)
	go func() {
		var output objectProcessReady
		if err := json.NewDecoder(io.LimitReader(
			stdout,
			16<<10,
		)).Decode(&output); err != nil {
			readError <- err
			return
		}
		ready <- output
	}()
	var output objectProcessReady
	select {
	case output = <-ready:
	case err := <-readError:
		t.Fatalf(
			"replica startup failed: %v",
			err,
		)
	case <-time.After(30 * time.Second):
		t.Fatal("replica startup exceeded 30 seconds")
	}
	cert, err := x509.ParseCertificate(output.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	tlsConfig := &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
	}
	if clientCertificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCertificate}
	}
	p.url = output.URL
	p.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 35 * time.Second,
		},
		Timeout: 40 * time.Second,
		CheckRedirect: func(
			_ *http.Request,
			_ []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}
	return p
}

func (p *objectProcess) kill() {
	p.stopOnce.Do(func() {
		if p.client != nil {
			p.client.CloseIdleConnections()
		}
		_ = p.cmd.Process.Kill()
		select {
		case err := <-p.done:
			if failure := objectChildExitError(
				err,
				p.diagnostics.race.Load(),
			); failure != nil {
				p.t.Error(failure)
			}
		case <-time.After(5 * time.Second):
			p.t.Fatalf(
				"replica PID %d did not exit after SIGKILL",
				p.cmd.Process.Pid,
			)
		}
	})
}

func (p *objectProcess) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = "", ""
	r.RequestURI = ""
	request, err := http.NewRequestWithContext(
		r.Context(),
		r.Method,
		p.url+r.URL.RequestURI(),
		r.Body,
	)
	if err == nil {
		request.Header = r.Header.Clone()
		request.Header.Set(
			"X-Acceptance-Control",
			p.control,
		)
		var response *http.Response
		response, err = p.client.Do(request)
		if err == nil {
			defer response.Body.Close()
			for name, values := range response.Header {
				w.Header()[name] = values
			}
			body, readErr := io.ReadAll(io.LimitReader(
				response.Body,
				(16<<20)+1,
			))
			if readErr != nil || len(body) > 16<<20 {
				err = errors.New("invalid fixture response body")
			} else {
				w.WriteHeader(response.StatusCode)
				_, _ = w.Write(body)
				return
			}
		}
	}
	http.Error(
		w,
		fmt.Sprintf(
			"fixture transport failed: %v",
			err,
		),
		http.StatusBadGateway,
	)
}

func processInput(
	t *testing.T,
	h *objectAcceptance,
	key []byte,
) objectProcessInput {
	t.Helper()
	operator, err := x509.MarshalPKIXPublicKey(&h.operator.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := x509.MarshalPKIXPublicKey(h.signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return objectProcessInput{
		Document:           h.cfg.measuredFile,
		EncryptionKey:      key,
		OperatorPublicKey:  operator,
		InventoryPublicKey: inventory,
	}
}

func TestObjectAcceptanceProcessHarness(t *testing.T) {
	h := newObjectAcceptance(t)
	h.stop()
	h.prepareSecret(t)
	key := make(
		[]byte,
		32,
	)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	cipher, err := objectCipher(
		h.cfg,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	object, err := h.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := h.cipher.Open(object.Data)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	input := processInput(
		t,
		h,
		key,
	)
	input.Memory, err = cipher.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &tls.Certificate{
		Certificate: [][]byte{h.leaf.Raw},
		PrivateKey:  h.leafKey,
	}
	first := startObjectProcess(
		t,
		input,
		certificate,
	)
	before := objectCall(
		first,
		http.MethodGet,
		"/ca",
		nil,
		"",
	)
	objectProcessWantStatus(
		t,
		before,
		http.StatusOK,
	)
	nonce := mintChallenge(
		t,
		first,
		"/secrets",
	)
	positive := httptest.NewRecorder()
	first.ServeHTTP(
		positive,
		h.secretRequest(
			t,
			nonce,
		),
	)
	objectProcessWantStatus(
		t,
		positive,
		http.StatusOK,
	)
	nonce = mintChallenge(
		t,
		first,
		"/secrets",
	)
	commits := objectProcessCommits(
		t,
		first,
	)
	objectControl(
		t,
		first,
		"lose-ack",
	)
	lost := httptest.NewRecorder()
	first.ServeHTTP(
		lost,
		h.secretRequest(
			t,
			nonce,
		),
	)
	objectProcessWantStatus(
		t,
		lost,
		http.StatusServiceUnavailable,
	)
	if lost.Header().Get("X-C8s-Commit-Outcome") != "unknown" || objectProcessCommits(
		t,
		first,
	) != commits+1 {
		t.Fatal("fault hook did not suppress exactly one committed mutation")
	}
	replay := httptest.NewRecorder()
	first.ServeHTTP(
		replay,
		h.secretRequest(
			t,
			nonce,
		),
	)
	objectProcessWantStatus(
		t,
		replay,
		http.StatusBadRequest,
	)
	if strings.TrimSpace(replay.Body.String()) != "invalid or expired challenge" {
		t.Fatal("consumed secret challenge did not return the route's rejection")
	}
	first.kill()
	second := startObjectProcess(
		t,
		input,
		certificate,
	)
	after := objectCall(
		second,
		http.MethodGet,
		"/ca",
		nil,
		"",
	)
	objectProcessWantStatus(
		t,
		after,
		http.StatusOK,
	)
	if !bytes.Equal(
		before.Body.Bytes(),
		after.Body.Bytes(),
	) {
		t.Fatal("subprocess fixture changed CA")
	}
	if first.cmd.Process.Pid == second.cmd.Process.Pid {
		t.Fatal("replacement reused a live process")
	}
}

func objectProcessWantStatus(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
) {
	t.Helper()
	if response.Code != status {
		t.Fatalf(
			"fixture status=%d, want %d",
			response.Code,
			status,
		)
	}
}

func TestObjectAcceptanceDiagnosticsExcludeErrorMessages(t *testing.T) {
	store := &objectFaultStore{}
	providerError := &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusConflict}},
		Err: &smithy.GenericAPIError{
			Code:    "ConditionalRequestConflict",
			Message: "sensitive provider diagnostic",
		},
	}
	store.recordFailure(
		"cas",
		errors.Join(
			objectstate.ErrUnknown,
			providerError,
		),
	)
	encoded, err := json.Marshal(store.failure.Load())
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"operation":"cas","kind":"unknown","code":"ConditionalRequestConflict","status":409}` {
		t.Fatal("storage diagnostics included an unexpected field or value")
	}
	store.recordFailure(
		"cas",
		objectstate.ErrConflict,
	)
	if store.failure.Load().Kind != "unknown" {
		t.Fatal("ordinary conflicts replaced the unknown-outcome diagnostic")
	}
	store.recordFailure(
		"load",
		&smithy.GenericAPIError{
			Code:    "unrecognized-sensitive-code",
			Message: "sensitive diagnostic",
		},
	)
	if store.failure.Load().Code != "other" {
		t.Fatal("unrecognized provider codes escaped the diagnostic allowlist")
	}
}

func TestObjectAcceptanceChildFailuresAreNotHidden(t *testing.T) {
	var diagnostics objectChildDiagnostics
	for _, part := range []string{
		"unprinted context WARNING: DA",
		"TA RACE unprinted details",
	} {
		if _, err := diagnostics.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if !diagnostics.race.Load() || len(diagnostics.tail) > len("WARNING: DATA RACE")-1 {
		t.Fatal("split race warning was missed or excess stderr was retained")
	}
	if objectChildExitError(
		nil,
		false,
	) == nil {
		t.Fatal("unexpected successful child exit was accepted")
	}
	if objectChildExitError(
		nil,
		true,
	) == nil {
		t.Fatal("child race report was ignored")
	}
}
