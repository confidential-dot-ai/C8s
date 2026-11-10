package cds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/objectcustody"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/google/go-sev-guest/kds"
	"github.com/spf13/cobra"
)

type objectCustodyOwnerOptions struct {
	origin, document, pins, certificate, key string
	completed, profile, role, output         string
	origins                                  []string
	renew                                    bool
}

type objectCustodyIssue func(
	context.Context,
	objectcustody.SessionPurpose,
) (objectstate.TemporaryCredentials, error)

var errObjectCustodyPartial = errors.New("object custody: some replicas are not ready")

type objectCustodyOwner struct {
	options   objectCustodyOwnerOptions
	document  *objectcustody.Config
	completed []byte
	client    func(context.Context) (*http.Client, error)
	newIssuer func(
		context.Context,
		objectstate.S3Config,
	) (objectCustodyIssue, error)
	wait func(
		context.Context,
		time.Duration,
	) error
	output, diagnostics        io.Writer
	readerExpiry, writerExpiry time.Time
}

func newObjectCustodyOwnerCommands() []*cobra.Command {
	var commands []*cobra.Command
	for _, action := range []string{
		"launch",
		"initialize",
		"provision",
	} {
		options := objectCustodyOwnerOptions{}
		command := &cobra.Command{
			Use:          action,
			Args:         cobra.NoArgs,
			SilenceUsage: true,
			RunE: func(
				command *cobra.Command,
				_ []string,
			) error {
				ctx, cancel := signal.NotifyContext(
					command.Context(),
					syscall.SIGTERM,
					syscall.SIGINT,
				)
				defer cancel()
				owner, err := loadObjectCustodyOwner(options)
				if err != nil {
					return err
				}
				owner.output, owner.diagnostics = command.OutOrStdout(), command.ErrOrStderr()
				return owner.run(
					ctx,
					action,
				)
			},
		}
		flags := command.Flags()
		flags.StringVar(
			&options.origin,
			"url",
			"",
			"direct HTTPS custody origin",
		)
		flags.StringVar(
			&options.document,
			"config",
			"",
			"exact original c8s-cds-custody/v1 launch document",
		)
		flags.StringVar(
			&options.pins,
			"custody-pins",
			"",
			"owner-approved SNP custody image measurements document",
		)
		flags.StringVar(
			&options.certificate,
			"client-cert",
			"",
			"independent owner's client certificate chain",
		)
		flags.StringVar(
			&options.key,
			"client-key",
			"",
			"independent owner's client private-key file",
		)
		for _, name := range []string{
			"url",
			"config",
			"custody-pins",
			"client-cert",
			"client-key",
		} {
			_ = command.MarkFlagRequired(name)
		}
		if action == "launch" {
			command.Short = "Read the public CDS launch from an attested custodian"
			flags.StringVar(
				&options.output,
				"output",
				"",
				"new public launch file; otherwise write to stdout",
			)
		} else {
			flags.StringVar(
				&options.completed,
				"cds-config",
				"",
				"pinned completed CDS launch returned during owner enrollment",
			)
			flags.StringVar(
				&options.profile,
				"aws-profile",
				"",
				"named independent owner AWS profile",
			)
			flags.StringVar(
				&options.role,
				"role-arn",
				"",
				"dedicated role for scoped custody and CDS sessions",
			)
			for _, name := range []string{
				"cds-config",
				"aws-profile",
				"role-arn",
			} {
				_ = command.MarkFlagRequired(name)
			}
			if action == "initialize" {
				command.Short = "Explicitly initialize one NEW cluster; never used for recovery"
			} else {
				command.Short = "Provision approved replicas and optionally renew their temporary sessions"
				flags.StringArrayVar(
					&options.origins,
					"replica",
					nil,
					"approved CDS HTTPS origin; repeat for 1..16 replicas",
				)
				flags.BoolVar(
					&options.renew,
					"renew",
					false,
					"renew every five minutes until canceled; never initialize state",
				)
				_ = command.MarkFlagRequired("replica")
			}
		}
		commands = append(
			commands,
			command,
		)
	}
	return commands
}

func readObjectCustodyFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readutil.ReadAll(
		file,
		1<<20,
	)
}

func loadObjectCustodyOwner(options objectCustodyOwnerOptions) (*objectCustodyOwner, error) {
	if !objectCustodyOrigin(options.origin) {
		return nil, errors.New("object custody: direct HTTPS custody origin required")
	}
	raw, err := readObjectCustodyFile(options.document)
	if err != nil {
		return nil, err
	}
	document, err := objectcustody.Parse(raw)
	if err != nil {
		return nil, err
	}
	pins, err := readObjectCustodyFile(options.pins)
	if err != nil {
		return nil, err
	}
	images, err := refvalues.Parse(pins)
	if err != nil || images.Family != teetypes.FamilySNP || len(images.Images) == 0 || len(images.Images) > 64 {
		return nil, errors.New("object custody: bounded native SNP custody image pins required")
	}
	digest := sha256.Sum256(raw)
	for _, image := range images.Images {
		if image.Anchor != nil || image.AcceptExtension != nil || len(image.Registers) != 0 ||
			(image.LaunchFile != nil && !bytes.Equal(
				image.LaunchFile,
				raw,
			)) ||
			(image.LaunchFileDigest != nil && !bytes.Equal(
				image.LaunchFileDigest,
				digest[:],
			)) {
			return nil, errors.New("object custody: image pins do not bind the original custody document")
		}
	}
	certificate, err := tls.LoadX509KeyPair(
		options.certificate,
		options.key,
	)
	if err != nil {
		return nil, errors.New("object custody: cannot load owner client identity")
	}
	roots := x509.NewCertPool()
	roots.AddCert(document.OwnerCA())
	intermediates := x509.NewCertPool()
	for _, der := range certificate.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("object custody: invalid owner certificate chain")
		}
		intermediates.AddCert(cert)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("object custody: invalid owner client certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, errors.New("object custody: client identity is not authorized by the measured owner CA")
	}
	owner := &objectCustodyOwner{
		options:  options,
		document: document,
		wait:     waitObjectCustodyRenewal,
		client: func(ctx context.Context) (*http.Client, error) {
			return objectCustodyOwnerClient(
				ctx,
				document,
				images.Digests(),
				certificate,
				objectCustodyNativeVerifier(teeverify.VerifyEnvelope),
			), nil
		},
		newIssuer: func(
			ctx context.Context,
			storage objectstate.S3Config,
		) (objectCustodyIssue, error) {
			issuer, err := objectcustody.NewIssuer(
				ctx,
				options.profile,
				storage,
				options.role,
			)
			if err != nil {
				return nil, errors.New("object custody: owner session issuer is unavailable")
			}
			return issuer.Issue, nil
		},
	}
	if options.completed != "" {
		owner.completed, err = readObjectCustodyFile(options.completed)
		if err != nil {
			return nil, err
		}
	}
	return owner, nil
}

// Retain the shared TLS certificate checks, but require native SNP collateral
// revocation checks before the owner sends either scoped storage session.
func objectCustodyNativeVerifier(
	verify func(
		context.Context,
		teetypes.AttestationEvidence,
		teetypes.VerifyParams,
		teeverify.Options,
	) (*teetypes.VerificationResult, error),
) localverify.VerifyFunc {
	return func(
		ctx context.Context,
		platform string,
		evidence json.RawMessage,
		params localverify.Params,
	) (*teetypes.VerificationResult, error) {
		if platform != string(teetypes.PlatformSNP) || len(params.Measurements) == 0 ||
			len(params.ExpectedReportData) != 48 || len(params.ExpectedInitDataHash) != 32 || params.AllowDebug || params.MinTCB == nil {
			return nil, errors.New("object custody: complete native custody verification policy required")
		}
		result, err := verify(
			ctx,
			teetypes.AttestationEvidence{
				Platform: teetypes.PlatformSNP,
				Evidence: evidence,
			},
			params.VerifyParams,
			teeverify.Options{
				SNP: snp.Options{
					CheckRevocations: true,
					Getter: snp.DefaultKDSGetter(
						20*time.Second,
						2*time.Second,
					),
				},
			},
		)
		if err != nil {
			return nil, err
		}
		if result == nil || !result.SignatureValid || result.Platform != teetypes.PlatformSNP || !result.CollateralVerified ||
			result.ReportDataMatch == nil || !*result.ReportDataMatch || result.InitDataMatch == nil || !*result.InitDataMatch {
			return nil, errors.New("object custody: native binding or revocation verdict missing")
		}
		if err := armtls.EnforceNonMigratable(result); err != nil {
			return nil, err
		}
		for _, digest := range params.Measurements {
			if hex.EncodeToString(digest) == result.Claims.LaunchDigest {
				return result, nil
			}
		}
		return nil, errors.New("object custody: unapproved custody image")
	}
}

func objectCustodyOwnerClient(
	parent context.Context,
	document *objectcustody.Config,
	digests [][]byte,
	certificate tls.Certificate,
	verify localverify.VerifyFunc,
) *http.Client {
	digest := sha256.Sum256(document.Document())
	tcb := kds.DecomposeTCBVersion(kds.TCBVersion(document.Parameters().TCB))
	client := localverify.NewARMTLSHTTPClient(
		digests,
		func(
			ctx context.Context,
			platform string,
			evidence json.RawMessage,
			params localverify.Params,
		) (*teetypes.VerificationResult, error) {
			if err := parent.Err(); err != nil {
				return nil, err
			}
			if platform != string(teetypes.PlatformSNP) || len(params.RuntimeExtensions) != 0 {
				return nil, errors.New("object custody: native fixed SNP custodian required")
			}
			ctx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(
				parent,
				cancel,
			)
			defer stop()
			defer cancel()
			params.ExpectedInitDataHash = digest[:]
			params.AllowDebug = false
			params.MinTCB = &teetypes.SnpTcb{
				Bootloader: tcb.BlSpl,
				Tee:        tcb.TeeSpl,
				Snp:        tcb.SnpSpl,
				Microcode:  tcb.UcodeSpl,
			}
			return verify(
				ctx,
				platform,
				evidence,
				params,
			)
		},
		30*time.Second,
	)
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	transport.TLSClientConfig.SessionTicketsDisabled = true
	transport.DisableKeepAlives = true
	transport.ResponseHeaderTimeout = 130 * time.Second
	client.Timeout = 140 * time.Second
	client.CheckRedirect = func(
		*http.Request,
		[]*http.Request,
	) error {
		return http.ErrUseLastResponse
	}
	return client
}

func (o *objectCustodyOwner) run(
	ctx context.Context,
	action string,
) error {
	if action != "launch" && action != "initialize" && action != "provision" {
		return errors.New("object custody: unsupported owner action")
	}
	if action != "launch" && (len(o.completed) == 0 || o.options.profile == "" || o.options.role == "") {
		return errors.New("object custody: completed launch and independent owner profile and role required")
	}
	if action == "provision" {
		seen := make(map[string]bool)
		if len(o.options.origins) == 0 || len(o.options.origins) > 16 {
			return errors.New("object custody: 1..16 distinct replica origins required")
		}
		for _, origin := range o.options.origins {
			if !objectCustodyOrigin(origin) || seen[origin] {
				return errors.New("object custody: distinct HTTPS replica origins required")
			}
			seen[origin] = true
		}
	}
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := o.cycle(
			ctx,
			action,
		)
		if action != "provision" || !o.options.renew {
			return err
		}
		wait := 5*time.Minute + time.Duration(rand.Int64N(int64(30*time.Second)))
		if err != nil {
			if _, err := fmt.Fprintln(
				o.diagnostics,
				"Custody renewal unavailable; retrying with bounded backoff.",
			); err != nil {
				return err
			}
			wait = backoff + time.Duration(rand.Int64N(int64(time.Second)))
			backoff = min(
				30*time.Second,
				2*backoff,
			)
		} else {
			backoff = time.Second
		}
		if err := o.wait(
			ctx,
			wait,
		); err != nil {
			return err
		}
	}
}

func (o *objectCustodyOwner) cycle(
	parent context.Context,
	action string,
) error {
	ctx, cancel := context.WithTimeout(
		parent,
		130*time.Second,
	)
	defer cancel()
	client, err := o.client(ctx)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	var info objectCustodyInfo
	if err := o.exchange(
		ctx,
		client,
		objectCustodyLaunchPath,
		nil,
		&info,
	); err != nil {
		return err
	}
	measured, err := cdsconfig.Parse(info.Launch)
	if err != nil || measured.ObjectState == nil {
		return errors.New("object custody: invalid completed launch")
	}
	launch, _, _, err := o.document.Complete(measured.ObjectState.RecoveryAuthority)
	if err != nil || !bytes.Equal(
		launch,
		info.Launch,
	) || info.Identity != objectRecoveryIdentity(config{
		measured:     measured,
		measuredFile: info.Launch,
	}) || (action != "launch" && !bytes.Equal(
		info.Launch,
		o.completed,
	)) {
		return errors.New("object custody: custodian root or completed launch differs from the owner pin")
	}
	if action == "launch" {
		if o.options.output == "" {
			_, err := o.output.Write(info.Launch)
			return err
		}
		file, err := os.OpenFile(
			o.options.output,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL,
			0644,
		)
		if err != nil {
			return err
		}
		_, err = file.Write(info.Launch)
		return errors.Join(
			err,
			file.Close(),
		)
	}
	storage := measured.ObjectState
	issue, err := o.newIssuer(
		ctx,
		objectstate.S3Config{
			Region:        storage.Region,
			Bucket:        storage.Bucket,
			Key:           storage.Key,
			Endpoint:      storage.Endpoint,
			ExpectedOwner: storage.ExpectedBucketOwner,
			MaxBytes:      storage.MaxBytes,
			Timeout:       10 * time.Second,
		},
	)
	if err != nil {
		return err
	}
	purpose := objectcustody.SessionReader
	path := objectCustodyProvisionPath
	if action == "initialize" {
		purpose = objectcustody.SessionInitializer
		path = objectCustodyInitializePath
	}
	request := objectCustodyRequest{ConfigSHA256: info.Identity.ConfigSHA256}
	request.Storage, err = issue(
		ctx,
		purpose,
	)
	if err != nil || !request.Storage.ExpiresAt.After(o.readerExpiry) {
		return errors.New("object custody: fresh reader or initializer session unavailable")
	}
	if action == "provision" {
		writer, err := issue(
			ctx,
			objectcustody.SessionWriter,
		)
		if err != nil || !writer.ExpiresAt.After(o.writerExpiry) {
			return errors.New("object custody: fresh writer session unavailable")
		}
		request.Writer, request.Origins = &writer, o.options.origins
		o.writerExpiry = writer.ExpiresAt
	}
	o.readerExpiry = request.Storage.ExpiresAt
	var result objectCustodyResult
	err = o.exchange(
		ctx,
		client,
		path,
		request,
		&result,
	)
	if err != nil && !errors.Is(
		err,
		errObjectCustodyPartial,
	) {
		if action == "initialize" {
			return errors.New("object custody: initialization outcome unknown; inspect current state before explicitly repeating initialization")
		}
		return err
	}
	if action == "provision" {
		if result.CAKeyID != "" || len(result.Ready) != len(o.options.origins) {
			return errors.New("object custody: incomplete replica results")
		}
		var failed bool
		for index, replica := range result.Ready {
			if replica.Origin != o.options.origins[index] {
				return errors.New("object custody: unexpected replica result")
			}
			failed = failed || !replica.Ready
		}
		if failed != errors.Is(
			err,
			errObjectCustodyPartial,
		) {
			return errors.New("object custody: inconsistent replica readiness")
		}
	}
	return errors.Join(
		json.NewEncoder(o.output).Encode(result),
		err,
	)
}

func (o *objectCustodyOwner) exchange(
	ctx context.Context,
	client *http.Client,
	path string,
	input any,
	output any,
) error {
	u, _ := url.Parse(o.options.origin)
	u.Path = path
	method := http.MethodGet
	var body []byte
	if input != nil {
		method = http.MethodPost
		var err error
		body, err = json.Marshal(input)
		if err != nil || len(body) > objectCustodyRequestLimit {
			clear(body)
			return errors.New("object custody: bounded owner request required")
		}
	}
	request, err := http.NewRequestWithContext(
		ctx,
		method,
		u.String(),
		bytes.NewReader(body),
	)
	if err != nil {
		return errors.New("object custody: invalid owner request")
	}
	request.GetBody = nil
	request.Header.Set(
		"Content-Type",
		"application/json",
	)
	response, err := client.Do(request)
	if err != nil {
		return errors.New("object custody: attested owner request unavailable")
	}
	defer response.Body.Close()
	partial := path == objectCustodyProvisionPath && response.StatusCode == http.StatusServiceUnavailable
	if response.StatusCode != http.StatusOK && !partial {
		return errors.New("object custody: request refused or outcome unavailable")
	}
	data, err := readutil.ReadAll(
		response.Body,
		2<<20,
	)
	if err != nil || strictjson.Validate(data) != nil {
		return errors.New("object custody: invalid bounded public response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("object custody: invalid public response")
	}
	if partial {
		return errObjectCustodyPartial
	}
	return nil
}

func waitObjectCustodyRenewal(
	ctx context.Context,
	delay time.Duration,
) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
