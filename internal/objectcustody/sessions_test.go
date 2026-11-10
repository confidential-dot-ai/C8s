package objectcustody

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

const sessionRoleARN = "arn:aws:iam::123456789012:role/cds/storage"

func sessionStorage() objectstate.S3Config {
	return objectstate.S3Config{
		Region:        "us-east-2",
		Bucket:        "cds-sessions",
		Key:           "clusters/a/current",
		ExpectedOwner: "123456789012",
		MaxBytes:      16 << 20,
		Timeout:       10 * time.Second,
	}
}

func TestSessionPolicyRestrictsEveryPurposeToItsObjectAndCondition(t *testing.T) {
	storage := sessionStorage()
	for _, purpose := range []SessionPurpose{
		SessionReader,
		SessionInitializer,
		SessionWriter,
	} {
		t.Run(
			string(purpose),
			func(t *testing.T) {
				policy, err := SessionPolicy(
					storage,
					purpose,
				)
				if err != nil {
					t.Fatal(err)
				}
				var parsed struct {
					Version   string
					Statement []sessionStatement
				}
				decoder := json.NewDecoder(strings.NewReader(policy))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&parsed); err != nil || parsed.Version != "2012-10-17" {
					t.Fatalf(
						"invalid policy document: %v",
						err,
					)
				}
				wantStatements := 2
				if purpose != SessionReader {
					wantStatements = 3
				}
				if len(parsed.Statement) != wantStatements {
					t.Fatalf(
						"extra policy permissions: %d statements",
						len(parsed.Statement),
					)
				}
				bucket := "arn:aws:s3:::" + storage.Bucket
				object := bucket + "/" + storage.Key
				conditions := map[string]string{
					"aws:ResourceAccount": storage.ExpectedOwner,
					"aws:RequestedRegion": storage.Region,
					"s3:prefix":           storage.Key,
				}
				allows := func(
					action string,
					resource string,
				) bool {
					return sessionPolicyAllows(
						t,
						parsed.Statement,
						action,
						resource,
						conditions,
					)
				}
				if !allows(
					"s3:GetObject",
					object,
				) || !allows(
					"s3:ListBucket",
					bucket,
				) || allows(
					"s3:PutObject",
					object,
				) {
					t.Fatal("read permission missing or unconditional write permitted")
				}
				for _, header := range []string{
					"s3:if-none-match",
					"s3:if-match",
				} {
					conditions[header] = "example-etag"
					want := (purpose == SessionInitializer && header == "s3:if-none-match") ||
						(purpose == SessionWriter && header == "s3:if-match")
					if allows(
						"s3:PutObject",
						object,
					) != want {
						t.Fatalf(
							"wrong conditional write permission for %s",
							header,
						)
					}
					delete(
						conditions,
						header,
					)
				}
				conditions["s3:if-match"] = "example-etag"
				conditions["s3:if-none-match"] = "*"
				for _, action := range []string{
					"s3:GetObjectVersion",
					"s3:DeleteObject",
					"s3:ListBucketVersions",
					"s3:AbortMultipartUpload",
					"s3:ListMultipartUploadParts",
					"s3:ListBucketMultipartUploads",
					"s3:CreateBucket",
					"iam:PutRolePolicy",
					"sts:AssumeRole",
				} {
					if allows(
						action,
						object,
					) || allows(
						action,
						bucket,
					) {
						t.Fatalf(
							"unrequested permission %s",
							action,
						)
					}
				}
				for _, target := range []string{
					object + "-other",
					bucket + "/clusters/b/current",
					"arn:aws:s3:::other/current",
				} {
					if allows(
						"s3:GetObject",
						target,
					) || allows(
						"s3:PutObject",
						target,
					) {
						t.Fatal("session escaped the exact object")
					}
				}
				for key, wrong := range map[string]string{
					"aws:ResourceAccount": "999999999999",
					"aws:RequestedRegion": "us-west-2",
					"s3:prefix":           "clusters/",
				} {
					original := conditions[key]
					conditions[key] = wrong
					if allows(
						"s3:ListBucket",
						bucket,
					) || (key != "s3:prefix" && (allows(
						"s3:GetObject",
						object,
					) || allows(
						"s3:PutObject",
						object,
					))) {
						t.Fatalf(
							"scope condition %s was ignored",
							key,
						)
					}
					conditions[key] = original
				}
			},
		)
	}
}

// This evaluates only the exact operators emitted here; cloud qualification
// separately verifies AWS authorization behavior against the dedicated object.
func sessionPolicyAllows(
	t *testing.T,
	statements []sessionStatement,
	action string,
	resource string,
	values map[string]string,
) bool {
	t.Helper()
	for _, statement := range statements {
		if statement.Effect != "Allow" || strings.ContainsAny(
			statement.Action,
			"*?",
		) || strings.ContainsAny(
			statement.Resource,
			"*?",
		) {
			t.Fatal("unexpected broad statement")
		}
		if statement.Action != action || statement.Resource != resource {
			continue
		}
		match := true
		for operator, expected := range statement.Condition {
			for key, want := range expected {
				value, exists := values[key]
				switch operator {
				case "StringEquals":
					match = match && exists && value == want
				case "Null":
					if want != "false" {
						t.Fatal("unexpected Null condition")
					}
					match = match && exists
				default:
					t.Fatalf(
						"unexpected condition operator %s",
						operator,
					)
				}
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestSessionPolicyRejectsAmbiguousOrUnboundedScope(t *testing.T) {
	for _, change := range []func(*objectstate.S3Config){
		func(c *objectstate.S3Config) { c.Endpoint = "https://alternate.invalid" },
		func(c *objectstate.S3Config) { c.ExpectedOwner = "" },
		func(c *objectstate.S3Config) { c.ExpectedOwner = "not-project" },
		func(c *objectstate.S3Config) { c.Region = "" },
		func(c *objectstate.S3Config) { c.Region = "cn-north-1" },
		func(c *objectstate.S3Config) { c.Region = "us-gov-west-1" },
		func(c *objectstate.S3Config) { c.Bucket = "invalid/bucket" },
		func(c *objectstate.S3Config) { c.Key = "" },
		func(c *objectstate.S3Config) { c.Key = "clusters/*/current" },
		func(c *objectstate.S3Config) { c.Key = "clusters/?/current" },
		func(c *objectstate.S3Config) { c.Key = "clusters/${aws:username}/current" },
		func(c *objectstate.S3Config) {
			c.Key = strings.Repeat(
				"a",
				1024,
			)
		},
		func(c *objectstate.S3Config) { c.Key = "clusters/\U0001f512/current" },
		func(c *objectstate.S3Config) { c.MaxBytes = 0 },
		func(c *objectstate.S3Config) { c.Timeout = 0 },
	} {
		storage := sessionStorage()
		change(&storage)
		if policy, err := SessionPolicy(
			storage,
			SessionWriter,
		); err == nil || policy != "" {
			t.Fatal("ambiguous or unsupported scope produced a session policy")
		}
	}
	if _, err := SessionPolicy(
		sessionStorage(),
		"unknown",
	); err == nil {
		t.Fatal("unknown purpose accepted")
	}
}

type assumeRoleFunc func(
	context.Context,
	*sts.AssumeRoleInput,
) (*sts.AssumeRoleOutput, error)

func (f assumeRoleFunc) AssumeRole(
	ctx context.Context,
	input *sts.AssumeRoleInput,
	_ ...func(*sts.Options),
) (*sts.AssumeRoleOutput, error) {
	return f(
		ctx,
		input,
	)
}

func sessionResponse() *sts.AssumeRoleOutput {
	return &sts.AssumeRoleOutput{Credentials: &types.Credentials{
		AccessKeyId:     aws.String("TEMPORARYACCESS"),
		SecretAccessKey: aws.String("temporary-secret"),
		SessionToken:    aws.String("temporary-token"),
		Expiration:      aws.Time(time.Now().Add(15 * time.Minute)),
	}}
}

func TestIssuerRequestsOnlyBoundedScopedSessions(t *testing.T) {
	var calls atomic.Int64
	names := make(
		chan string,
		12,
	)
	client := assumeRoleFunc(func(
		ctx context.Context,
		input *sts.AssumeRoleInput,
	) (*sts.AssumeRoleOutput, error) {
		calls.Add(1)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > sessionTimeout || aws.ToInt32(input.DurationSeconds) != 900 ||
			aws.ToString(input.RoleArn) != sessionRoleARN || len(input.PolicyArns) != 0 || len(input.Tags) != 0 {
			t.Error("STS request escaped its bounds")
		}
		want, err := SessionPolicy(
			sessionStorage(),
			SessionWriter,
		)
		if err != nil || aws.ToString(input.Policy) != want {
			t.Error("STS received the wrong session policy")
		}
		names <- aws.ToString(input.RoleSessionName)
		return sessionResponse(), nil
	})
	issuer, err := newIssuer(
		sessionStorage(),
		sessionRoleARN,
		client,
	)
	if err != nil {
		t.Fatal(err)
	}
	var work sync.WaitGroup
	for range 12 {
		work.Go(func() {
			credentials, err := issuer.Issue(
				t.Context(),
				SessionWriter,
			)
			if err != nil || credentials.AccessKeyID != "TEMPORARYACCESS" || credentials.Check(time.Now()) != nil {
				t.Errorf(
					"valid scoped session failed: %v",
					err,
				)
			}
		})
	}
	work.Wait()
	close(names)
	seen := make(map[string]bool)
	for name := range names {
		if seen[name] || !strings.HasPrefix(
			name,
			"cds-writer-",
		) || len(name) > 64 {
			t.Fatal("session name was reused or invalid")
		}
		seen[name] = true
	}
	if calls.Load() != 12 {
		t.Fatal("unexpected STS call count")
	}
	if _, err := issuer.Issue(
		t.Context(),
		"unknown",
	); err == nil || calls.Load() != 12 {
		t.Fatal("unknown purpose reached STS")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := issuer.Issue(
		ctx,
		SessionReader,
	); !errors.Is(
		err,
		context.Canceled,
	) || calls.Load() != 12 {
		t.Fatal("canceled issuance reached STS")
	}
}

func TestIssuerRejectsInvalidRoleAndSTSResults(t *testing.T) {
	for _, role := range []string{
		"",
		"arn:aws:iam::999999999999:role/cds",
		"arn:aws:iam:us-east-2:123456789012:role/cds",
		"arn:aws-cn:iam::123456789012:role/cds",
		"arn:aws:iam::123456789012:user/cds",
		"arn:aws:iam::123456789012:role/*",
	} {
		if _, err := newIssuer(
			sessionStorage(),
			role,
			nil,
		); err == nil {
			t.Fatal("invalid or cross-project role accepted")
		}
	}
	for _, mutate := range []func(*sts.AssumeRoleOutput){
		func(r *sts.AssumeRoleOutput) { r.Credentials = nil },
		func(r *sts.AssumeRoleOutput) { r.Credentials.AccessKeyId = nil },
		func(r *sts.AssumeRoleOutput) { r.Credentials.SecretAccessKey = aws.String("secret\ninvalid") },
		func(r *sts.AssumeRoleOutput) { r.Credentials.SessionToken = nil },
		func(r *sts.AssumeRoleOutput) { r.Credentials.Expiration = nil },
		func(r *sts.AssumeRoleOutput) { r.Credentials.Expiration = aws.Time(time.Now().Add(-time.Second)) },
		func(r *sts.AssumeRoleOutput) { r.Credentials.Expiration = aws.Time(time.Now().Add(2 * time.Hour)) },
	} {
		response := sessionResponse()
		mutate(response)
		issuer, err := newIssuer(
			sessionStorage(),
			sessionRoleARN,
			assumeRoleFunc(func(
				context.Context,
				*sts.AssumeRoleInput,
			) (*sts.AssumeRoleOutput, error) {
				return response, nil
			}),
		)
		if err != nil {
			t.Fatal(err)
		}
		if credentials, err := issuer.Issue(
			t.Context(),
			SessionReader,
		); err == nil || credentials != (objectstate.TemporaryCredentials{}) {
			t.Fatal("invalid STS result returned credentials")
		}
	}
}

func TestIssuerNoRetryAndCanceledResultDiscarded(t *testing.T) {
	failure := errors.New("synthetic STS outage")
	calls := 0
	issuer, err := newIssuer(
		sessionStorage(),
		sessionRoleARN,
		assumeRoleFunc(func(
			context.Context,
			*sts.AssumeRoleInput,
		) (*sts.AssumeRoleOutput, error) {
			calls++
			return nil, failure
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if credentials, err := issuer.Issue(
		t.Context(),
		SessionReader,
	); !errors.Is(
		err,
		failure,
	) || calls != 1 || credentials != (objectstate.TemporaryCredentials{}) {
		t.Fatal("failed issuance retried or returned credentials")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	issuer.client = assumeRoleFunc(func(
		context.Context,
		*sts.AssumeRoleInput,
	) (*sts.AssumeRoleOutput, error) {
		cancel()
		return sessionResponse(), nil
	})
	if credentials, err := issuer.Issue(
		ctx,
		SessionReader,
	); !errors.Is(
		err,
		context.Canceled,
	) || credentials != (objectstate.TemporaryCredentials{}) {
		t.Fatal("canceled result returned credentials")
	}
}

type sessionHTTPClient func(*http.Request) (*http.Response, error)

func (f sessionHTTPClient) Do(request *http.Request) (*http.Response, error) { return f(request) }

func ownerProfileFiles(
	t *testing.T,
	withCredentials bool,
) {
	t.Helper()
	path := t.TempDir()
	configPath := filepath.Join(
		path,
		"config",
	)
	credentialsPath := filepath.Join(
		path,
		"credentials",
	)
	if err := os.WriteFile(
		configPath,
		[]byte("[profile session-owner]\nregion = us-west-2\nendpoint_url = https://wrong.invalid\n"),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	credentials := ""
	if withCredentials {
		credentials = "[session-owner]\naws_access_key_id = PROFILEACCESS\naws_secret_access_key = profile-secret\naws_session_token = profile-token\n"
	}
	if err := os.WriteFile(
		credentialsPath,
		[]byte(credentials),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv(
		"AWS_CONFIG_FILE",
		configPath,
	)
	t.Setenv(
		"AWS_SHARED_CREDENTIALS_FILE",
		credentialsPath,
	)
	t.Setenv(
		"AWS_ACCESS_KEY_ID",
		"ENVIRONMENTACCESS",
	)
	t.Setenv(
		"AWS_SECRET_ACCESS_KEY",
		"environment-secret",
	)
	t.Setenv(
		"AWS_REGION",
		"us-west-2",
	)
	t.Setenv(
		"AWS_ENDPOINT_URL",
		"https://wrong.invalid",
	)
	t.Setenv(
		"AWS_ENDPOINT_URL_STS",
		"https://wrong.invalid",
	)
	t.Setenv(
		"AWS_EC2_METADATA_DISABLED",
		"true",
	)
}

func TestNewIssuerUsesExplicitProfileAndRegionalAWSSTS(t *testing.T) {
	ownerProfileFiles(
		t,
		true,
	)
	issuer, err := NewIssuer(
		t.Context(),
		"session-owner",
		sessionStorage(),
		sessionRoleARN,
	)
	if err != nil {
		t.Fatal(err)
	}
	options := issuer.client.(*sts.Client).Options()
	if options.Region != "us-east-2" || options.BaseEndpoint != nil || options.Retryer.MaxAttempts() != 1 {
		t.Fatal("ambient endpoint, Region or retries changed the owner request")
	}
	httpClient := options.HTTPClient.(*http.Client)
	transport := httpClient.Transport.(*http.Transport)
	if httpClient.Timeout != 10*time.Second || transport.DialContext == nil || transport.TLSHandshakeTimeout != 5*time.Second ||
		transport.ResponseHeaderTimeout != 5*time.Second || transport.MaxConnsPerHost != 2 || !transport.DisableKeepAlives {
		t.Fatal("owner session transport escaped its connection or time bounds")
	}
	var calls int
	options.HTTPClient = sessionHTTPClient(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Scheme != "https" || request.URL.Host != "sts.us-east-2.amazonaws.com" ||
			!strings.Contains(
				request.Header.Get("Authorization"),
				"Credential=PROFILEACCESS/",
			) {
			t.Fatal("session request used ambient identity or a different endpoint")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil || form.Get("Action") != "AssumeRole" || form.Get("DurationSeconds") != "900" || form.Get("RoleArn") != sessionRoleARN {
			t.Fatal("incorrect STS request encoding")
		}
		policy, err := SessionPolicy(
			sessionStorage(),
			SessionReader,
		)
		if err != nil || form.Get("Policy") != policy {
			t.Fatal("session policy was lost in the SDK request")
		}
		return &http.Response{
			StatusCode: 503,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Receiver</Type><Code>ServiceUnavailable</Code><Message>temporary</Message></Error><RequestId>test</RequestId></ErrorResponse>`,
			)),
		}, nil
	})
	issuer.client = sts.New(options)
	if _, err := issuer.Issue(
		t.Context(),
		SessionReader,
	); err == nil || calls != 1 {
		t.Fatalf(
			"SDK unexpectedly retried a failed request: calls %d, error %v",
			calls,
			err,
		)
	}
}

func TestNewIssuerRejectsImplicitOrEmptyOwnerIdentity(t *testing.T) {
	ownerProfileFiles(
		t,
		false,
	)
	for _, profile := range []string{
		"",
		" ",
		"absent-profile",
		"session-owner",
	} {
		if _, err := NewIssuer(
			t.Context(),
			profile,
			sessionStorage(),
			sessionRoleARN,
		); err == nil {
			t.Fatalf(
				"profile %q silently selected ambient credentials",
				profile,
			)
		}
	}
}
