package objectwal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// Credentials are delivered over an attested connection. The CDS process never
// loads credentials from the host environment, instance metadata or launch file.
type Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

type S3 struct {
	client      *s3.Client
	bucket      string
	credentials atomic.Pointer[Credentials]
}

type S3Config struct {
	Bucket     string
	Region     string
	Endpoint   string
	PathStyle  bool
	HTTPClient *http.Client
}

func NewS3(cfg S3Config, credentials Credentials) (*S3, error) {
	if cfg.Bucket == "" || cfg.Region == "" {
		return nil, errors.New("object WAL: S3 bucket and region are required")
	}
	s := &S3{bucket: cfg.Bucket}
	if err := s.SetCredentials(credentials); err != nil {
		return nil, err
	}
	options := s3.Options{
		Region:           cfg.Region,
		UsePathStyle:     cfg.PathStyle,
		RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			c := s.credentials.Load()
			return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Source: "attested CDS pilot provisioning"}, nil
		}),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
	}
	if cfg.Endpoint != "" {
		options.BaseEndpoint = aws.String(cfg.Endpoint)
	}
	if cfg.HTTPClient != nil {
		options.HTTPClient = cfg.HTTPClient
	}
	s.client = s3.New(options)
	return s, nil
}

func (s *S3) SetCredentials(c Credentials) error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return errors.New("object WAL: both S3 credential fields are required")
	}
	s.credentials.Store(&c)
	return nil
}

func (s *S3) Get(ctx context.Context, key string) (Object, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return Object{}, storageError(err)
	}
	defer result.Body.Close()
	data, err := io.ReadAll(io.LimitReader(result.Body, MaxObjectBytes+1))
	if err != nil {
		return Object{}, err
	}
	if len(data) > MaxObjectBytes {
		return Object{}, ErrCorrupt
	}
	return Object{Data: data, ETag: aws.ToString(result.ETag)}, nil
}

func (s *S3) Put(ctx context.Context, key string, data []byte, expected string) (string, error) {
	in := &s3.PutObjectInput{Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(data), ContentType: aws.String("application/octet-stream")}
	if expected == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = &expected
	}
	result, err := s.client.PutObject(ctx, in)
	if err != nil {
		return "", storageError(err)
	}
	if aws.ToString(result.ETag) == "" {
		return "", errors.New("object WAL: successful S3 PUT omitted its ETag")
	}
	return *result.ETag, nil
}

func storageError(err error) error {
	var api smithy.APIError
	code := "unclassified"
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return ErrNotFound
		case "PreconditionFailed", "ConditionalRequestConflict":
			return ErrConflict
		case "AccessDenied", "ExpiredToken", "InvalidToken", "InvalidAccessKeyId", "SignatureDoesNotMatch", "SlowDown", "RequestTimeout", "InternalError", "ServiceUnavailable", "InvalidRequest":
			code = api.ErrorCode() // allowlisted names only; never echo provider text
		}
	}
	// Do not include provider response bodies, request URLs or credentials in
	// public CDS responses. Keep transport/context errors classifiable locally.
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var response interface{ HTTPStatusCode() int }
	if errors.As(err, &response) {
		return fmt.Errorf("object WAL: S3 request failed (HTTP %d, %s)", response.HTTPStatusCode(), code)
	}
	return fmt.Errorf("object WAL: S3 request failed (%s, %T)", code, err)
}
