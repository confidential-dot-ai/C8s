package cds

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/confidential-dot-ai/c8s/internal/objectcustody"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

// This opt-in test qualifies real IAM session conditions using synthetic bytes;
// application recovery and native hardware custody have separate acceptance tests.
func TestObjectS3CustodyCapabilities(t *testing.T) {
	if os.Getenv("C8S_OBJECT_S3_RUN") != "1" {
		t.Skip("set C8S_OBJECT_S3_RUN=1 and explicit bucket/prefix/owner/region/profile to use live S3")
	}
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		t.Fatal("capability qualification requires an explicit owner AWS_PROFILE")
	}
	h, _ := newLiveObjectFixture(t)
	owned := *h.cfg.measured.ObjectState
	owned.Key += "-capabilities"
	storage := objectstate.S3Config{
		Region:        owned.Region,
		Bucket:        owned.Bucket,
		Key:           owned.Key,
		ExpectedOwner: owned.ExpectedBucketOwner,
		MaxBytes:      owned.MaxBytes,
		Timeout:       10 * time.Second,
	}
	ctx, cancel := context.WithTimeout(
		t.Context(),
		2*time.Minute,
	)
	defer cancel()
	owner, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithSharedConfigProfile(profile),
		awsconfig.WithRegion(owned.Region),
		awsconfig.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
		awsconfig.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }),
	)
	custodyCapabilityStatus(
		t,
		"load cleanup identity",
		err,
		http.StatusOK,
	)
	cleanup := custodyCapabilityClient(
		storage.Region,
		owner.Credentials,
	)
	issuer, err := objectcustody.NewIssuer(
		ctx,
		profile,
		storage,
		os.Getenv("C8S_OBJECT_S3_WRITER_ROLE"),
	)
	custodyCapabilityStatus(
		t,
		"configure session issuer",
		err,
		http.StatusOK,
	)
	clients := make(
		map[objectcustody.SessionPurpose]*s3.Client,
		3,
	)
	for _, purpose := range []objectcustody.SessionPurpose{
		objectcustody.SessionReader,
		objectcustody.SessionInitializer,
		objectcustody.SessionWriter,
	} {
		session, err := issuer.Issue(
			ctx,
			purpose,
		)
		custodyCapabilityStatus(
			t,
			"issue "+string(purpose),
			err,
			http.StatusOK,
		)
		provider := objectstate.NewCredentialProvider(time.Now)
		if err := provider.Install(session); err != nil {
			t.Fatal("scoped session did not pass the guest credential checks")
		}
		clients[purpose] = custodyCapabilityClient(
			storage.Region,
			provider,
		)
	}
	reader := clients[objectcustody.SessionReader]
	initializer := clients[objectcustody.SessionInitializer]
	writer := clients[objectcustody.SessionWriter]
	get := func(
		client *s3.Client,
		version *string,
	) (*s3.GetObjectOutput, error) {
		return client.GetObject(
			ctx,
			&s3.GetObjectInput{
				Bucket:              aws.String(owned.Bucket),
				Key:                 aws.String(owned.Key),
				ExpectedBucketOwner: aws.String(owned.ExpectedBucketOwner),
				VersionId:           version,
			},
		)
	}
	missing, err := get(
		reader,
		nil,
	)
	if missing != nil && missing.Body != nil {
		missing.Body.Close()
	}
	custodyCapabilityStatus(
		t,
		"reader sees missing object",
		err,
		http.StatusNotFound,
	)
	// The unique run owns this exact second key. Register cleanup before any
	// attempted write, including forbidden writes that would expose a policy bug.
	t.Cleanup(func() {
		cleanupLiveObject(
			t,
			cleanup,
			&owned,
		)
	})
	initial := []byte("synthetic-custody-capability-initial\n")
	updated := []byte("synthetic-custody-capability-updated\n")
	put := func(
		client *s3.Client,
		body []byte,
		match *string,
		absent *string,
	) (*s3.PutObjectOutput, error) {
		return client.PutObject(
			ctx,
			&s3.PutObjectInput{
				Bucket:              aws.String(owned.Bucket),
				Key:                 aws.String(owned.Key),
				ExpectedBucketOwner: aws.String(owned.ExpectedBucketOwner),
				Body:                bytes.NewReader(body),
				ContentType:         aws.String("application/octet-stream"),
				IfMatch:             match,
				IfNoneMatch:         absent,
			},
		)
	}
	_, err = put(
		reader,
		initial,
		nil,
		aws.String("*"),
	)
	custodyCapabilityStatus(
		t,
		"reader cannot create",
		err,
		http.StatusForbidden,
	)
	_, err = put(
		writer,
		initial,
		nil,
		aws.String("*"),
	)
	custodyCapabilityStatus(
		t,
		"writer cannot initialize",
		err,
		http.StatusForbidden,
	)
	_, err = put(
		writer,
		initial,
		nil,
		nil,
	)
	custodyCapabilityStatus(
		t,
		"writer cannot put unconditionally",
		err,
		http.StatusForbidden,
	)
	created, err := put(
		initializer,
		initial,
		nil,
		aws.String("*"),
	)
	custodyCapabilityStatus(
		t,
		"initializer creates conditionally",
		err,
		http.StatusOK,
	)
	if created == nil || aws.ToString(created.ETag) == "" {
		t.Fatal("conditional creation returned no ETag")
	}
	_, err = put(
		initializer,
		initial,
		nil,
		aws.String("*"),
	)
	custodyCapabilityStatus(
		t,
		"initializer cannot recreate",
		err,
		http.StatusPreconditionFailed,
	)
	_, err = put(
		initializer,
		updated,
		created.ETag,
		nil,
	)
	custodyCapabilityStatus(
		t,
		"initializer cannot replace",
		err,
		http.StatusForbidden,
	)
	_, err = put(
		initializer,
		updated,
		nil,
		nil,
	)
	custodyCapabilityStatus(
		t,
		"initializer cannot put unconditionally",
		err,
		http.StatusForbidden,
	)
	replaced, err := put(
		writer,
		updated,
		created.ETag,
		nil,
	)
	custodyCapabilityStatus(
		t,
		"writer replaces current version",
		err,
		http.StatusOK,
	)
	if replaced == nil || aws.ToString(replaced.ETag) == "" || aws.ToString(replaced.ETag) == aws.ToString(created.ETag) {
		t.Fatal("conditional replacement did not return a distinct ETag")
	}
	_, err = put(
		writer,
		initial,
		created.ETag,
		nil,
	)
	custodyCapabilityStatus(
		t,
		"writer rejects stale ETag",
		err,
		http.StatusPreconditionFailed,
	)
	version := replaced.VersionId
	if aws.ToString(version) == "" {
		version = aws.String("null")
	}
	for _, purpose := range []objectcustody.SessionPurpose{
		objectcustody.SessionReader,
		objectcustody.SessionInitializer,
		objectcustody.SessionWriter,
	} {
		client := clients[purpose]
		current, err := get(
			client,
			nil,
		)
		if err != nil && current != nil && current.Body != nil {
			current.Body.Close()
		}
		custodyCapabilityStatus(
			t,
			string(purpose)+" reads current state",
			err,
			http.StatusOK,
		)
		if current == nil || current.Body == nil {
			t.Fatal("current object returned no body")
		}
		body, readErr := io.ReadAll(io.LimitReader(
			current.Body,
			128,
		))
		current.Body.Close()
		if readErr != nil || !bytes.Equal(
			body,
			updated,
		) {
			t.Fatal("current read disagreed with acknowledged replacement")
		}
		older, err := get(
			client,
			version,
		)
		if older != nil && older.Body != nil {
			older.Body.Close()
		}
		custodyCapabilityStatus(
			t,
			string(purpose)+" cannot read versions",
			err,
			http.StatusForbidden,
		)
		_, err = client.ListObjectsV2(
			ctx,
			&s3.ListObjectsV2Input{
				Bucket:              aws.String(owned.Bucket),
				ExpectedBucketOwner: aws.String(owned.ExpectedBucketOwner),
				MaxKeys:             aws.Int32(1),
			},
		)
		custodyCapabilityStatus(
			t,
			string(purpose)+" cannot list without its prefix",
			err,
			http.StatusForbidden,
		)
		_, err = client.DeleteObject(
			ctx,
			&s3.DeleteObjectInput{
				Bucket:              aws.String(owned.Bucket),
				Key:                 aws.String(owned.Key),
				ExpectedBucketOwner: aws.String(owned.ExpectedBucketOwner),
			},
		)
		custodyCapabilityStatus(
			t,
			string(purpose)+" cannot delete",
			err,
			http.StatusForbidden,
		)
	}
	t.Log("real S3 reader, initializer and writer session conditions passed; only disposable objects were used")
}

func custodyCapabilityClient(
	region string,
	provider aws.CredentialsProvider,
) *s3.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Second
	transport.MaxConnsPerHost = 2
	transport.DisableKeepAlives = true
	return s3.New(s3.Options{
		Region:      region,
		Credentials: provider,
		Retryer:     aws.NopRetryer{},
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(
				_ *http.Request,
				_ []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
	})
}

func custodyCapabilityStatus(
	t *testing.T,
	operation string,
	err error,
	expected int,
) {
	t.Helper()
	status, code := http.StatusOK, "none"
	if err != nil {
		status, code = 0, "transport-or-local"
		var response interface{ HTTPStatusCode() int }
		if errors.As(
			err,
			&response,
		) {
			status = response.HTTPStatusCode()
		}
		var api smithy.APIError
		if errors.As(
			err,
			&api,
		) {
			switch api.ErrorCode() {
			case "AccessDenied", "NoSuchKey", "PreconditionFailed":
				code = api.ErrorCode()
			default:
				code = "other-api-error"
			}
		}
	}
	wantCode := map[int]string{
		http.StatusOK:                 "none",
		http.StatusForbidden:          "AccessDenied",
		http.StatusNotFound:           "NoSuchKey",
		http.StatusPreconditionFailed: "PreconditionFailed",
	}[expected]
	if status != expected || code != wantCode {
		t.Fatalf(
			"%s: HTTP %d, API code %s; expected HTTP %d, API code %s",
			operation,
			status,
			code,
			expected,
			wantCode,
		)
	}
}
