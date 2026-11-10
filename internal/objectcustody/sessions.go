package objectcustody

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

type SessionPurpose string

const (
	SessionReader      SessionPurpose = "reader"
	SessionInitializer SessionPurpose = "initializer"
	SessionWriter      SessionPurpose = "writer"
	sessionTimeout                    = 10 * time.Second
)

type sessionStatement struct {
	Effect    string                       `json:"Effect"`
	Action    string                       `json:"Action"`
	Resource  string                       `json:"Resource"`
	Condition map[string]map[string]string `json:"Condition"`
}

// SessionPolicy narrows one role session to the current object. Conditional
// writes deliberately have no multipart exemption. The storage authority must
// not separately grant additional permissions directly to a session principal.
// Listing uses the key as a prefix, so names beginning with it are visible.
func SessionPolicy(
	storage objectstate.S3Config,
	purpose SessionPurpose,
) (string, error) {
	if err := storage.Check(); err != nil {
		return "", err
	}
	if storage.Endpoint != "" || storage.ExpectedOwner == "" ||
		strings.HasPrefix(
			storage.Region,
			"cn-",
		) || strings.HasPrefix(
		storage.Region,
		"us-gov-",
	) ||
		strings.Contains(
			storage.Region,
			"-iso",
		) {
		return "", errors.New("object custody: AWS commercial storage and an explicit project are required")
	}
	if strings.ContainsAny(
		storage.Key,
		"*?",
	) || strings.Contains(
		storage.Key,
		"${",
	) {
		return "", errors.New("object custody: session object key must be literal, without IAM wildcards or variables")
	}
	var header string
	switch purpose {
	case SessionReader:
	case SessionInitializer:
		header = "s3:if-none-match"
	case SessionWriter:
		header = "s3:if-match"
	default:
		return "", errors.New("object custody: unknown storage session purpose")
	}
	bucketARN := "arn:aws:s3:::" + storage.Bucket
	objectARN := bucketARN + "/" + storage.Key
	conditions := func() map[string]map[string]string {
		return map[string]map[string]string{"StringEquals": {
			"aws:ResourceAccount": storage.ExpectedOwner,
			"aws:RequestedRegion": storage.Region,
		}}
	}
	listCondition := conditions()
	listCondition["StringEquals"]["s3:prefix"] = storage.Key
	statements := []sessionStatement{
		{
			Effect:    "Allow",
			Action:    "s3:GetObject",
			Resource:  objectARN,
			Condition: conditions(),
		},
		{
			Effect:    "Allow",
			Action:    "s3:ListBucket",
			Resource:  bucketARN,
			Condition: listCondition,
		},
	}
	if header != "" {
		condition := conditions()
		condition["Null"] = map[string]string{header: "false"}
		statements = append(
			statements,
			sessionStatement{
				Effect:    "Allow",
				Action:    "s3:PutObject",
				Resource:  objectARN,
				Condition: condition,
			},
		)
	}
	policy, err := json.Marshal(struct {
		Version   string             `json:"Version"`
		Statement []sessionStatement `json:"Statement"`
	}{
		Version:   "2012-10-17",
		Statement: statements,
	})
	if err != nil {
		return "", err
	}
	// STS limits inline policies to 2,048 characters from its Latin-1 range.
	// A byte bound is stricter for non-ASCII keys and avoids partial policies.
	if len(policy) > 2048 {
		return "", errors.New("object custody: scoped session policy exceeds the STS size limit")
	}
	for _, character := range string(policy) {
		if character > 0xff {
			return "", errors.New("object custody: object key cannot be represented in an STS inline policy")
		}
	}
	return string(policy), nil
}

type assumeRoleClient interface {
	AssumeRole(
		context.Context,
		*sts.AssumeRoleInput,
		...func(*sts.Options),
	) (*sts.AssumeRoleOutput, error)
}

// Issuer runs in the owner's tooling, never in a CDS guest. Its source
// credentials are not the scoped sessions delivered to custody or CDS.
type Issuer struct {
	client   assumeRoleClient
	roleARN  string
	policies map[SessionPurpose]string
}

// NewIssuer uses one explicitly selected owner profile and the storage Region.
// It loads local configuration; Issue performs the STS request.
func NewIssuer(
	ctx context.Context,
	profile string,
	storage objectstate.S3Config,
	roleARN string,
) (*Issuer, error) {
	if profile == "" || strings.TrimSpace(profile) != profile {
		return nil, errors.New("object custody: an explicit owner AWS profile is required")
	}
	issuer, err := newIssuer(
		storage,
		roleARN,
		nil,
	)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(
		ctx,
		sessionTimeout,
	)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Second
	transport.MaxConnsPerHost = 2
	transport.DisableKeepAlives = true
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   sessionTimeout,
		CheckRedirect: func(
			_ *http.Request,
			_ []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}
	owner, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithSharedConfigProfile(profile),
		awsconfig.WithRegion(storage.Region),
		awsconfig.WithHTTPClient(httpClient),
		awsconfig.WithRetryer(func() aws.Retryer { return aws.NopRetryer{} }),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"object custody: load owner profile: %w",
			err,
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !hasOwnerProfileCredentials(owner.ConfigSources) || owner.Credentials == nil {
		return nil, errors.New("object custody: selected owner profile has no configured credential source")
	}
	// Copy only explicit settings so endpoint environment variables cannot
	// redirect the scoped session request away from the selected AWS Region.
	issuer.client = sts.New(sts.Options{
		Region:      storage.Region,
		Credentials: owner.Credentials,
		Retryer:     aws.NopRetryer{},
		HTTPClient:  httpClient,
	})
	return issuer, nil
}

var roleResource = regexp.MustCompile(`^role/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]{1,64}$`)

func newIssuer(
	storage objectstate.S3Config,
	roleARN string,
	client assumeRoleClient,
) (*Issuer, error) {
	policies := make(
		map[SessionPurpose]string,
		3,
	)
	for _, purpose := range []SessionPurpose{
		SessionReader,
		SessionInitializer,
		SessionWriter,
	} {
		policy, err := SessionPolicy(
			storage,
			purpose,
		)
		if err != nil {
			return nil, err
		}
		policies[purpose] = policy
	}
	role, err := arn.Parse(roleARN)
	if err != nil || role.Partition != "aws" || role.Service != "iam" || role.Region != "" ||
		role.AccountID != storage.ExpectedOwner || len(role.Resource) > 581 || !roleResource.MatchString(role.Resource) {
		return nil, errors.New("object custody: an exact IAM role in the storage project is required")
	}
	return &Issuer{
		client:   client,
		roleARN:  roleARN,
		policies: policies,
	}, nil
}

func hasOwnerProfileCredentials(sources []any) bool {
	for _, source := range sources {
		var profile *awsconfig.SharedConfig
		switch value := source.(type) {
		case awsconfig.SharedConfig:
			profile = &value
		case *awsconfig.SharedConfig:
			profile = value
		}
		if profile == nil {
			continue
		}
		for profile.Source != nil {
			profile = profile.Source
		}
		return profile.Credentials.HasKeys() || profile.CredentialSource != "" || profile.CredentialProcess != "" ||
			profile.WebIdentityTokenFile != "" || profile.LoginSession != "" || profile.SSOSession != nil || profile.SSOStartURL != ""
	}
	return false
}

func (i *Issuer) Issue(
	ctx context.Context,
	purpose SessionPurpose,
) (objectstate.TemporaryCredentials, error) {
	if i == nil || i.client == nil {
		return objectstate.TemporaryCredentials{}, errors.New("object custody: session issuer is not configured")
	}
	policy, ok := i.policies[purpose]
	if !ok {
		return objectstate.TemporaryCredentials{}, errors.New("object custody: unknown storage session purpose")
	}
	ctx, cancel := context.WithTimeout(
		ctx,
		sessionTimeout,
	)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return objectstate.TemporaryCredentials{}, err
	}
	output, err := i.client.AssumeRole(
		ctx,
		&sts.AssumeRoleInput{
			RoleArn:         aws.String(i.roleARN),
			RoleSessionName: aws.String("cds-" + string(purpose) + "-" + rand.Text()),
			DurationSeconds: aws.Int32(900),
			Policy:          aws.String(policy),
		},
	)
	if err != nil {
		return objectstate.TemporaryCredentials{}, fmt.Errorf(
			"object custody: assume scoped storage role: %w",
			err,
		)
	}
	if err := ctx.Err(); err != nil {
		return objectstate.TemporaryCredentials{}, err
	}
	if output == nil || output.Credentials == nil {
		return objectstate.TemporaryCredentials{}, errors.New("object custody: STS returned no temporary credentials")
	}
	credentials := objectstate.TemporaryCredentials{
		AccessKeyID:     aws.ToString(output.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(output.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(output.Credentials.SessionToken),
		ExpiresAt:       aws.ToTime(output.Credentials.Expiration).UTC(),
	}
	if err := credentials.Check(time.Now()); err != nil {
		return objectstate.TemporaryCredentials{}, err
	}
	return credentials, nil
}
