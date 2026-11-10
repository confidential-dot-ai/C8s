package objectstate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func testS3Config() S3Config {
	return S3Config{
		Region:        "us-east-2",
		Bucket:        "test-cds-state",
		Key:           "tenant/cluster/current",
		ExpectedOwner: "123456789012",
		MaxBytes:      1024,
		Timeout:       time.Second,
	}
}

func testS3(
	t *testing.T,
	cfg S3Config,
	transport roundTripFunc,
) *S3 {
	t.Helper()
	s, err := newS3(
		cfg,
		aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     "synthetic-access-key",
				SecretAccessKey: "synthetic-secret-key",
				Source:          "unit test",
			}, nil
		}),
		transport,
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func s3Response(
	status int,
	etag string,
	body string,
) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header: http.Header{
			"Etag":           []string{etag},
			"Content-Length": []string{strconv.Itoa(len(body))},
		},
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(strings.NewReader(body)),
	}
}

func TestS3SignsAndBindsConditionalWrites(t *testing.T) {
	var calls int
	s := testS3(
		t,
		testS3Config(),
		func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Scheme != "https" || r.URL.Host != "test-cds-state.s3.us-east-2.amazonaws.com" || r.URL.Path != "/tenant/cluster/current" {
				t.Fatalf(
					"unexpected storage destination: %s",
					r.URL,
				)
			}
			if !strings.HasPrefix(
				r.Header.Get("Authorization"),
				"AWS4-HMAC-SHA256 ",
			) {
				t.Fatal("request is not signed")
			}
			if r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
				t.Fatal("expected bucket owner was not bound")
			}
			switch calls {
			case 1:
				if r.Method != http.MethodGet {
					t.Fatal("Load did not use GET")
				}
				return s3Response(
					http.StatusOK,
					`"first"`,
					"encrypted state",
				), nil
			case 2, 3:
				if r.Method != http.MethodPut {
					t.Fatal("mutation did not use PUT")
				}
				if calls == 2 && (r.Header.Get("If-None-Match") != "*" || r.Header.Get("If-Match") != "") {
					t.Fatal("Create did not require an absent object")
				}
				if calls == 3 && (r.Header.Get("If-Match") != `"first"` || r.Header.Get("If-None-Match") != "") {
					t.Fatal("CAS did not require the exact read ETag")
				}
				if calls == 3 && !strings.Contains(
					r.Header.Get("Authorization"),
					";if-match;",
				) {
					t.Fatal("CAS precondition was not signed")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "replacement ciphertext" {
					t.Fatalf(
						"unexpected stored body: %q, %v",
						body,
						err,
					)
				}
				return s3Response(
					http.StatusOK,
					`"second"`,
					"",
				), nil
			default:
				t.Fatal("unexpected retry")
				return nil, io.ErrUnexpectedEOF
			}
		},
	)
	object, err := s.Load(context.Background())
	if err != nil || object.ETag != `"first"` || string(object.Data) != "encrypted state" {
		t.Fatalf(
			"Load = %+v, %v",
			object,
			err,
		)
	}
	etag, err := s.Create(
		context.Background(),
		[]byte("replacement ciphertext"),
	)
	if err != nil || etag != `"second"` {
		t.Fatalf(
			"Create = %q, %v",
			etag,
			err,
		)
	}
	etag, err = s.CompareAndSwap(
		context.Background(),
		object.ETag,
		[]byte("replacement ciphertext"),
	)
	if err != nil || etag != `"second"` || calls != 3 {
		t.Fatalf(
			"CAS = %q, %v; requests = %d",
			etag,
			err,
			calls,
		)
	}
}

func TestS3NeverRetriesUnknownMutation(t *testing.T) {
	tests := []struct {
		name     string
		response *http.Response
		err      error
	}{
		{
			name: "lost acknowledgement after commit",
			err:  io.ErrUnexpectedEOF,
		},
		{
			name: "server failure",
			response: s3Response(
				http.StatusServiceUnavailable,
				"",
				"<Error><Code>SlowDown</Code></Error>",
			),
		},
		{
			name: "commit response without etag",
			response: s3Response(
				http.StatusOK,
				"",
				"",
			),
		},
		{
			name: "unclassified conflict",
			response: s3Response(
				http.StatusConflict,
				"",
				"<Error><Code>Conflict</Code></Error>",
			),
		},
		{
			name: "conflict without error code",
			response: s3Response(
				http.StatusConflict,
				"",
				"",
			),
		},
		{
			name: "malformed conditional conflict",
			response: s3Response(
				http.StatusConflict,
				"",
				"<Error><Code>ConditionalRequestConflict</Code>",
			),
		},
		{
			name: "conditional conflict code with server failure",
			response: s3Response(
				http.StatusInternalServerError,
				"",
				"<Error><Code>ConditionalRequestConflict</Code></Error>",
			),
		},
		{
			name: "missing object during replacement",
			response: s3Response(
				http.StatusNotFound,
				"",
				"<Error><Code>NoSuchKey</Code></Error>",
			),
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				var calls int
				s := testS3(
					t,
					testS3Config(),
					func(*http.Request) (*http.Response, error) {
						calls++
						if calls > 1 {
							return s3Response(
								http.StatusConflict,
								"",
								"<Error><Code>ConditionalRequestConflict</Code></Error>",
							), nil
						}
						return tt.response, tt.err
					},
				)
				_, err := s.CompareAndSwap(
					context.Background(),
					`"previous"`,
					[]byte("replacement"),
				)
				if !errors.Is(
					err,
					ErrUnknown,
				) || errors.Is(
					err,
					ErrConflict,
				) || calls != 1 {
					t.Fatalf(
						"write = %v, requests = %d; unknown write must not retry",
						err,
						calls,
					)
				}
			},
		)
	}
}

func TestS3ConditionalRequestConflictIsNotRetried(t *testing.T) {
	for _, operation := range []string{"create", "replace"} {
		t.Run(
			operation,
			func(t *testing.T) {
				var calls int
				s := testS3(
					t,
					testS3Config(),
					func(*http.Request) (*http.Response, error) {
						calls++
						return s3Response(
							http.StatusConflict,
							"",
							"<Error><Code>ConditionalRequestConflict</Code></Error>",
						), nil
					},
				)
				var err error
				if operation == "create" {
					_, err = s.Create(
						t.Context(),
						[]byte("encrypted state"),
					)
				} else {
					_, err = s.CompareAndSwap(
						t.Context(),
						`"previous"`,
						[]byte("replacement"),
					)
				}
				if !errors.Is(
					err,
					ErrConflict,
				) || errors.Is(
					err,
					ErrUnknown,
				) || calls != 1 {
					t.Fatalf(
						"conditional conflict = %v after %d attempts; want definitive failure without retry",
						err,
						calls,
					)
				}
			},
		)
	}
}

func TestS3ConditionalConflictAndReadAbsence(t *testing.T) {
	var calls int
	s := testS3(
		t,
		testS3Config(),
		func(r *http.Request) (*http.Response, error) {
			calls++
			status := http.StatusPreconditionFailed
			if r.Method == http.MethodGet {
				status = http.StatusNotFound
			}
			return s3Response(
				status,
				"",
				"<Error><Message>sensitive remote error detail</Message></Error>",
			), nil
		},
	)
	_, err := s.CompareAndSwap(
		context.Background(),
		`"previous"`,
		[]byte("replacement"),
	)
	if !errors.Is(
		err,
		ErrConflict,
	) || errors.Is(
		err,
		ErrUnknown,
	) || strings.Contains(
		err.Error(),
		"sensitive",
	) {
		t.Fatalf(
			"CAS conflict = %v",
			err,
		)
	}
	_, err = s.Create(
		context.Background(),
		[]byte("initial"),
	)
	if !errors.Is(
		err,
		ErrConflict,
	) {
		t.Fatalf(
			"Create conflict = %v",
			err,
		)
	}
	_, err = s.Load(context.Background())
	if !errors.Is(
		err,
		ErrNotFound,
	) || calls != 3 {
		t.Fatalf(
			"read absence = %v, requests = %d",
			err,
			calls,
		)
	}
}

func TestS3BoundsReadWithoutContentLength(t *testing.T) {
	var consumed int
	s := testS3(
		t,
		testS3Config(),
		func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Etag": []string{`"version"`},
				},
				ContentLength: -1,
				Body: io.NopCloser(countReader{
					r: strings.NewReader(strings.Repeat(
						"x",
						4096,
					)),
					count: &consumed,
				}),
			}, nil
		},
	)
	_, err := s.Load(context.Background())
	if !errors.Is(
		err,
		ErrTooLarge,
	) || consumed != 1025 {
		t.Fatalf(
			"oversized read = %v; consumed %d bytes",
			err,
			consumed,
		)
	}
}

func TestS3BoundsSDKErrorDeserialization(t *testing.T) {
	var consumed int
	s := testS3(
		t,
		testS3Config(),
		func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusServiceUnavailable,
				Header:        make(http.Header),
				ContentLength: -1,
				Body: io.NopCloser(countReader{
					r: strings.NewReader(strings.Repeat(
						"x",
						1<<20,
					)),
					count: &consumed,
				}),
			}, nil
		},
	)
	_, err := s.Create(
		context.Background(),
		[]byte("initial"),
	)
	if !errors.Is(
		err,
		ErrUnknown,
	) || consumed > 64<<10 {
		t.Fatalf(
			"unbounded error response: %v, consumed %d bytes",
			err,
			consumed,
		)
	}
}

type countReader struct {
	r     io.Reader
	count *int
}

func (r countReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	*r.count += n
	return n, err
}

func TestS3RefusesUnboundedOrUnconditionalInput(t *testing.T) {
	var calls int
	s := testS3(
		t,
		testS3Config(),
		func(*http.Request) (*http.Response, error) {
			calls++
			return nil, io.ErrUnexpectedEOF
		},
	)
	for _, etag := range []string{
		"",
		"*",
		`W/"weak"`,
		"unquoted",
		"\"bad\r\n\"",
	} {
		_, err := s.CompareAndSwap(
			context.Background(),
			etag,
			[]byte("replacement"),
		)
		if err == nil {
			t.Fatalf(
				"accepted ETag %q",
				etag,
			)
		}
	}
	_, err := s.Create(
		context.Background(),
		make(
			[]byte,
			1025,
		),
	)
	if !errors.Is(
		err,
		ErrTooLarge,
	) || calls != 0 {
		t.Fatalf(
			"oversized create = %v; requests = %d",
			err,
			calls,
		)
	}
}

func TestS3CancellationBoundsRequest(t *testing.T) {
	var calls atomic.Int32
	cfg := testS3Config()
	cfg.Timeout = 100 * time.Millisecond
	s := testS3(
		t,
		cfg,
		func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			<-r.Context().Done()
			return nil, r.Context().Err()
		},
	)
	_, err := s.CompareAndSwap(
		context.Background(),
		`"previous"`,
		[]byte("replacement"),
	)
	if !errors.Is(
		err,
		ErrUnknown,
	) || !errors.Is(
		err,
		context.DeadlineExceeded,
	) || calls.Load() != 1 {
		t.Fatalf(
			"timed-out write = %v, requests = %d",
			err,
			calls.Load(),
		)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Create(
		ctx,
		[]byte("initial"),
	)
	if !errors.Is(
		err,
		context.Canceled,
	) || errors.Is(
		err,
		ErrUnknown,
	) || calls.Load() != 1 {
		t.Fatalf(
			"already canceled write = %v, requests = %d",
			err,
			calls.Load(),
		)
	}
}

func TestS3DoesNotFollowRedirects(t *testing.T) {
	var calls int
	s := testS3(
		t,
		testS3Config(),
		func(*http.Request) (*http.Response, error) {
			calls++
			response := s3Response(
				http.StatusTemporaryRedirect,
				"",
				"",
			)
			response.Header.Set(
				"Location",
				"https://another-storage.invalid/other",
			)
			return response, nil
		},
	)
	_, err := s.Create(
		context.Background(),
		[]byte("initial"),
	)
	if !errors.Is(
		err,
		ErrUnknown,
	) || calls != 1 {
		t.Fatalf(
			"redirected write = %v, requests = %d",
			err,
			calls,
		)
	}
}

func TestS3CredentialRetrievalHasItsOwnDeadline(t *testing.T) {
	cfg := testS3Config()
	cfg.Timeout = 100 * time.Millisecond
	finished := make(chan struct{})
	s, err := newS3(
		cfg,
		aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			defer close(finished)
			if _, ok := ctx.Deadline(); !ok {
				return aws.Credentials{}, errors.New("credential retrieval has no deadline")
			}
			<-ctx.Done()
			return aws.Credentials{}, ctx.Err()
		}),
		roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Error("request sent without credentials")
			return nil, io.ErrUnexpectedEOF
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Create(
		context.Background(),
		[]byte("initial"),
	)
	if !errors.Is(
		err,
		ErrUnknown,
	) || !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf(
			"credential timeout = %v",
			err,
		)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("credential retrieval outlived its deadline")
	}
}

func TestS3ReadsCurrentCredentialsForEveryRequest(t *testing.T) {
	var retrievals, requests int
	expired := errors.New("credential grant expired")
	keys := []string{"synthetic-first", "synthetic-renewed"}
	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		retrievals++
		if retrievals > len(keys) {
			return aws.Credentials{}, expired
		}
		return aws.Credentials{
			AccessKeyID:     keys[retrievals-1],
			SecretAccessKey: "synthetic-secret-key",
			SessionToken:    "synthetic-session-token",
			CanExpire:       true,
			Expires:         time.Now().Add(time.Hour),
		}, nil
	})
	store, err := newS3(
		testS3Config(),
		provider,
		roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if requests >= len(keys) || !strings.Contains(
				r.Header.Get("Authorization"),
				"Credential="+keys[requests]+"/",
			) {
				t.Fatal("request did not use the current credential grant")
			}
			requests++
			return s3Response(
				http.StatusOK,
				`"current"`,
				"encrypted state",
			), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	for range keys {
		if _, err := store.Load(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Load(t.Context()); !errors.Is(
		err,
		expired,
	) || requests != 2 || retrievals != 3 {
		t.Fatalf(
			"expired credentials: %v, requests=%d, retrievals=%d; want failure before dispatch",
			err,
			requests,
			retrievals,
		)
	}
}

func TestS3RejectsUnsafeConfiguration(t *testing.T) {
	tests := []func(*S3Config){
		func(c *S3Config) { c.Region = "" },
		func(c *S3Config) { c.Bucket = "arn:aws:s3:us-east-1:123456789012:accesspoint/test" },
		func(c *S3Config) { c.Key = "" },
		func(c *S3Config) {
			c.Key = strings.Repeat(
				"x",
				1025,
			)
		},
		func(c *S3Config) { c.ExpectedOwner = "not-an-owner" },
		func(c *S3Config) { c.MaxBytes = 0 },
		func(c *S3Config) { c.MaxBytes = 65 << 20 },
		func(c *S3Config) { c.Timeout = 0 },
		func(c *S3Config) { c.Timeout = 6 * time.Minute },
		func(c *S3Config) { c.Endpoint = "http://storage.invalid" },
		func(c *S3Config) { c.Endpoint = "https://credentials@storage.invalid" },
		func(c *S3Config) { c.Endpoint = "https://storage.invalid/other/path" },
		func(c *S3Config) { c.Endpoint = "https://storage.invalid?other-key" },
	}
	for i, change := range tests {
		cfg := testS3Config()
		change(&cfg)
		if err := cfg.Check(); err == nil {
			t.Fatalf(
				"unsafe configuration %d accepted",
				i,
			)
		}
	}
	if _, err := NewS3(
		testS3Config(),
		aws.AnonymousCredentials{},
	); err == nil {
		t.Fatal("anonymous credentials accepted")
	}
}
