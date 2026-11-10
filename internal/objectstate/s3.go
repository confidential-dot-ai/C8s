package objectstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type S3Config struct {
	Region        string
	Bucket        string
	Key           string
	Endpoint      string
	ExpectedOwner string
	MaxBytes      int64
	Timeout       time.Duration
}

type S3 struct {
	client    *s3.Client
	cfg       S3Config
	transport http.RoundTripper
}

var _ Store = (*S3)(nil)

var (
	bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionName = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	ownerID    = regexp.MustCompile(`^[0-9]{12}$`)
)

func NewS3(
	cfg S3Config,
	credentials aws.CredentialsProvider,
) (*S3, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           32,
		MaxIdleConnsPerHost:    16,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  cfg.Timeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 32 << 10,
	}
	return newS3(
		cfg,
		credentials,
		transport,
	)
}

func newS3(
	cfg S3Config,
	credentials aws.CredentialsProvider,
	transport http.RoundTripper,
) (*S3, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	if credentials == nil {
		return nil, errors.New("object state: S3 credentials provider is required")
	}
	switch credentials.(type) {
	case aws.AnonymousCredentials, *aws.AnonymousCredentials:
		return nil, errors.New("object state: S3 requests must be signed")
	}
	options := s3.Options{
		Region: cfg.Region,
		// The provider owns renewal; an outer cache would hide newly granted credentials.
		Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			ctx, cancel := context.WithTimeout(
				ctx,
				cfg.Timeout,
			)
			defer cancel()
			return credentials.Retrieve(ctx)
		}),
		// A lost successful write followed by a retried 412 is still unknown.
		Retryer: aws.NopRetryer{},
		HTTPClient: responseLimitClient{
			client: &http.Client{
				Transport: transport,
				Timeout:   cfg.Timeout,
				CheckRedirect: func(
					_ *http.Request,
					_ []*http.Request,
				) error {
					return http.ErrUseLastResponse
				},
			},
			maxObjectBytes: cfg.MaxBytes,
		},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
	}
	if cfg.Endpoint != "" {
		options.BaseEndpoint = aws.String(cfg.Endpoint)
		options.UsePathStyle = true
	}
	return &S3{
		client:    s3.New(options),
		cfg:       cfg,
		transport: transport,
	}, nil
}

func (s *S3) CloseIdleConnections() {
	if closer, ok := s.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Check validates the storage address and bounds without making any request.
func (cfg S3Config) Check() error {
	if !regionName.MatchString(cfg.Region) {
		return errors.New("object state: S3 region is required")
	}
	if !bucketName.MatchString(cfg.Bucket) || strings.Contains(
		cfg.Bucket,
		"..",
	) || net.ParseIP(cfg.Bucket) != nil {
		return errors.New("object state: S3 bucket must be a general purpose bucket name")
	}
	if cfg.Key == "" || len(cfg.Key) > 1024 || !utf8.ValidString(cfg.Key) || strings.ContainsRune(
		cfg.Key,
		0,
	) {
		return errors.New("object state: S3 object key must contain 1 to 1024 UTF-8 bytes")
	}
	if cfg.ExpectedOwner != "" && !ownerID.MatchString(cfg.ExpectedOwner) {
		return errors.New("object state: S3 expected owner must contain 12 digits")
	}
	if cfg.MaxBytes <= 0 || cfg.MaxBytes > 64<<20 {
		return errors.New("object state: S3 size limit must be between 1 byte and 64 MiB")
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 5*time.Minute {
		return errors.New("object state: S3 timeout must be positive and at most five minutes")
	}
	if cfg.Endpoint != "" {
		u, err := url.Parse(cfg.Endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("object state: S3 endpoint must be an HTTPS origin")
		}
	}
	return nil
}

func (s *S3) Load(ctx context.Context) (Object, error) {
	ctx, cancel := context.WithTimeout(
		ctx,
		s.cfg.Timeout,
	)
	defer cancel()
	output, err := s.client.GetObject(
		ctx,
		&s3.GetObjectInput{
			Bucket:              aws.String(s.cfg.Bucket),
			Key:                 aws.String(s.cfg.Key),
			ExpectedBucketOwner: optionalString(s.cfg.ExpectedOwner),
		},
	)
	if err != nil {
		if statusCode(err) == http.StatusNotFound {
			return Object{}, &storeError{
				op:    "read",
				kind:  ErrNotFound,
				cause: err,
			}
		}
		return Object{}, &storeError{
			op:    "read",
			cause: err,
		}
	}
	defer output.Body.Close()
	if !validETag(aws.ToString(output.ETag)) {
		return Object{}, errors.New("object state: read returned no strong ETag")
	}
	if aws.ToInt64(output.ContentLength) > s.cfg.MaxBytes {
		return Object{}, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(
		output.Body,
		s.cfg.MaxBytes+1,
	))
	if err != nil {
		clear(data)
		return Object{}, &storeError{
			op:    "read body",
			cause: err,
		}
	}
	if int64(len(data)) > s.cfg.MaxBytes {
		clear(data)
		return Object{}, ErrTooLarge
	}
	return Object{
		Data: data,
		ETag: *output.ETag,
	}, nil
}

func (s *S3) Create(
	ctx context.Context,
	data []byte,
) (string, error) {
	return s.put(
		ctx,
		&s3.PutObjectInput{IfNoneMatch: aws.String("*")},
		data,
	)
}

func (s *S3) CompareAndSwap(
	ctx context.Context,
	etag string,
	data []byte,
) (string, error) {
	if !validETag(etag) {
		return "", errors.New("object state: conditional write requires a strong ETag")
	}
	return s.put(
		ctx,
		&s3.PutObjectInput{IfMatch: aws.String(etag)},
		data,
	)
}

func (s *S3) put(
	ctx context.Context,
	input *s3.PutObjectInput,
	data []byte,
) (string, error) {
	if int64(len(data)) > s.cfg.MaxBytes {
		return "", ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	input.Bucket = aws.String(s.cfg.Bucket)
	input.Key = aws.String(s.cfg.Key)
	input.ExpectedBucketOwner = optionalString(s.cfg.ExpectedOwner)
	input.ContentType = aws.String("application/octet-stream")
	input.Body = bytes.NewReader(data)
	input.ContentLength = aws.Int64(int64(len(data)))
	ctx, cancel := context.WithTimeout(
		ctx,
		s.cfg.Timeout,
	)
	defer cancel()
	output, err := s.client.PutObject(
		ctx,
		input,
	)
	if err != nil {
		kind := ErrUnknown
		if conditionalWriteConflict(err) {
			kind = ErrConflict
		}
		return "", &storeError{
			op:    "write",
			kind:  kind,
			cause: err,
		}
	}
	if !validETag(aws.ToString(output.ETag)) {
		return "", &storeError{
			op:   "write response has no strong ETag",
			kind: ErrUnknown,
		}
	}
	return *output.ETag, nil
}

func validETag(etag string) bool {
	if len(etag) < 2 || len(etag) > 1024 || etag[0] != '"' || etag[len(etag)-1] != '"' {
		return false
	}
	for _, c := range []byte(etag[1 : len(etag)-1]) {
		if c < 0x21 || c == '"' || c == 0x7f {
			return false
		}
	}
	return true
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return aws.String(value)
}

func statusCode(err error) int {
	var responseError *smithyhttp.ResponseError
	if errors.As(
		err,
		&responseError,
	) {
		return responseError.HTTPStatusCode()
	}
	return 0
}

func conditionalWriteConflict(err error) bool {
	switch statusCode(err) {
	case http.StatusPreconditionFailed:
		return true
	case http.StatusConflict:
		// With SDK retries disabled, this is S3's failed conditional attempt.
		var apiError smithy.APIError
		return errors.As(
			err,
			&apiError,
		) && apiError.ErrorCode() == "ConditionalRequestConflict"
	default:
		return false
	}
}

// SDK error deserialization reads the body before Load can bound it.
type responseLimitClient struct {
	client         *http.Client
	maxObjectBytes int64
}

func (c responseLimitClient) Do(r *http.Request) (*http.Response, error) {
	response, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}
	limit := int64(64 << 10)
	if r.Method == http.MethodGet && response.StatusCode == http.StatusOK {
		limit = c.maxObjectBytes + 1
	}
	response.Body = limitedResponseBody{
		Reader: io.LimitReader(
			response.Body,
			limit,
		),
		Closer: response.Body,
	}
	return response, nil
}

type limitedResponseBody struct {
	io.Reader
	io.Closer
}

// Keep remote error bodies and request details out of ordinary error logs.
type storeError struct {
	op    string
	kind  error
	cause error
}

func (e *storeError) Error() string {
	if e.kind != nil {
		return fmt.Sprintf(
			"object state: %s: %s",
			e.op,
			e.kind,
		)
	}
	return "object state: " + e.op + " failed"
}

func (e *storeError) Unwrap() []error {
	var errs []error
	if e.kind != nil {
		errs = append(
			errs,
			e.kind,
		)
	}
	if e.cause != nil {
		errs = append(
			errs,
			e.cause,
		)
	}
	return errs
}
