package getcert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// GuestConfig is the measured guest's credential broker. HTTPClient must
// authenticate CDS with the signed launch's server pins; VolumeRoot must be
// the verified memory-backed emptyDir mounted read-only only by the mesh.
// Commit serializes its final snapshot/liveness check and publish closure
// with admission mutations. The closure performs only local filesystem work.
// The caller owns VolumeRoot and keeps it open until RunGuest returns.
type GuestConfig struct {
	CDSURL            string
	AttestationAPIURL string
	HTTPClient        *http.Client
	VolumeRoot        *os.Root
	InstanceID        string
	Snapshot          func(context.Context) (workloadclaims.PodClaims, error)
	Commit            func(workloadclaims.PodClaims, func() error) error
	Changes           <-chan struct{}
}

// RunGuest obtains and renews Pod credentials without exporting quote or
// assertion authority. It reuses the ordinary renewal, CA binding, expiry,
// policy watch and complete-generation validation. It never resumes an old
// leaf: only retained guest admission history may authorize a new generation.
func RunGuest(ctx context.Context, guest GuestConfig) (result error) {
	endpoint, err := url.Parse(guest.CDSURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || guest.HTTPClient == nil || guest.VolumeRoot == nil || guest.Snapshot == nil || guest.Commit == nil || armtls.ValidateSandboxID(guest.InstanceID) != nil {
		return fmt.Errorf("incomplete guest credential broker configuration")
	}
	volume := credentialVolume{root: guest.VolumeRoot, leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
	defer func() { result = errors.Join(result, withdrawGeneration(volume)) }()
	if err := requireGuestRoot(guest.VolumeRoot); err != nil {
		return err
	}
	bound, err := loadIssuerRecord(volume)
	if err != nil && !errors.Is(err, errNoIssuerRecord) {
		return err
	}
	if err := withdrawGeneration(volume); err != nil {
		return err
	}
	creds := &credentials{volume: volume, instanceID: guest.InstanceID, issuer: bound}
	cfg := config{
		CDSURL: guest.CDSURL, AttestationApiURL: guest.AttestationAPIURL,
		RenewInterval: time.Hour, RenewJitterPercent: defaultRenewJitterPercent,
		InitialRetryInterval: 2 * time.Second, UnnamedRenewInterval: 30 * time.Second,
		CAWatchInterval: defaultCDSWatchInterval, guest: &guest,
	}
	client := attestclient.NewClientWithHTTP(guest.CDSURL, guest.HTTPClient)
	policy := allowlistclient.NewClientWithHTTP(guest.CDSURL, guest.HTTPClient)
	if err := obtainGuestCert(ctx, guest, client, creds); err != nil {
		if errors.Is(err, errFailClosed) {
			return err
		}
		if ctx.Err() == nil {
			slog.Warn("initial Pod credential request failed; renewal will retry", "error", err)
		}
	}
	return renewLoop(ctx, cfg, client, policy, creds)
}

func obtainGuestCert(ctx context.Context, guest GuestConfig, client attestclient.Client, creds *credentials) error {
	claims, err := guest.Snapshot(ctx)
	if err != nil {
		return withdrawGuestEvidence(creds, err)
	}
	if claims.InstanceID() != guest.InstanceID {
		return withdrawGuestEvidence(creds, fmt.Errorf("pod credential snapshot changed instance"))
	}
	key, keyPEM, err := generateKey()
	if err != nil {
		return err
	}
	// A Pod CSR intentionally carries no nonce-free node evidence extension.
	csr, err := createCSR(key, "")
	if err != nil {
		return err
	}
	result, err := workloadclaims.ObtainPodCertificateContext(ctx, client, guest.AttestationAPIURL, string(csr), claims)
	if err != nil {
		return err
	}
	g, err := issuedGeneration(result.Certificate, key, keyPEM)
	if err != nil {
		return err
	}
	return guest.Commit(claims, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return creds.publish(g, time.Now())
	})
}

// Lost admission evidence differs from a transient CDS outage: no generation
// remains advertised while the guest cannot describe its sandbox. The issuer
// binding survives so recovery cannot silently adopt a different CA key.
func withdrawGuestEvidence(creds *credentials, cause error) error {
	if err := withdrawGeneration(creds.volume); err != nil {
		return errors.Join(cause, fmt.Errorf("%w: withdraw Pod credentials: %w", errFailClosed, err))
	}
	creds.current = nil
	return cause
}
