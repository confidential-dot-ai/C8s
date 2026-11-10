package objectstate

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

var (
	ErrCredentialsUnavailable = errors.New("object state: fresh storage credentials are unavailable")
	ErrCredentialsStale       = errors.New("object state: credential expiration did not advance")
)

// TemporaryCredentials carries a temporary session; its policy determines storage permissions.
type TemporaryCredentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// Check validates a complete temporary session without publishing it.
func (c TemporaryCredentials) Check(now time.Time) error {
	if !credentialField(
		c.AccessKeyID,
		128,
	) || !credentialField(
		c.SecretAccessKey,
		256,
	) ||
		!credentialField(
			c.SessionToken,
			16<<10,
		) || !c.ExpiresAt.After(now) ||
		c.ExpiresAt.After(now.Add(time.Hour)) {
		return errors.New("object state: malformed or expired temporary credentials")
	}
	return nil
}

func credentialField(
	value string,
	limit int,
) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

// CredentialProvider publishes immutable snapshots. Expiration remains a floor
// after credentials expire, so replay cannot reinstall an older session.
type CredentialProvider struct {
	current atomic.Pointer[TemporaryCredentials]
	clock   func() time.Time
}

var _ aws.CredentialsProvider = (*CredentialProvider)(nil)

func NewCredentialProvider(now func() time.Time) *CredentialProvider {
	return &CredentialProvider{clock: now}
}

func (p *CredentialProvider) now() time.Time {
	if p.clock != nil {
		return p.clock()
	}
	return time.Now()
}

func (p *CredentialProvider) Install(credentials TemporaryCredentials) error {
	credentials.ExpiresAt = credentials.ExpiresAt.UTC()
	if err := credentials.Check(p.now()); err != nil {
		return err
	}
	for {
		previous := p.current.Load()
		// A custodian can reseal the same session after losing its response or
		// restarting. Acknowledging that installation never extends its life.
		if previous != nil && credentials == *previous {
			return nil
		}
		if previous != nil && !credentials.ExpiresAt.After(previous.ExpiresAt) {
			return ErrCredentialsStale
		}
		if p.current.CompareAndSwap(
			previous,
			&credentials,
		) {
			return nil
		}
	}
}

func (p *CredentialProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return aws.Credentials{}, err
	}
	current := p.current.Load()
	if current == nil || !current.ExpiresAt.After(p.now()) {
		return aws.Credentials{}, ErrCredentialsUnavailable
	}
	return aws.Credentials{
		AccessKeyID:     current.AccessKeyID,
		SecretAccessKey: current.SecretAccessKey,
		SessionToken:    current.SessionToken,
		CanExpire:       true,
		Expires:         current.ExpiresAt,
		Source:          "attested object-state custody",
	}, nil
}
