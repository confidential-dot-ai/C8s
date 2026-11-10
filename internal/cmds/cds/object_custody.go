package cds

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/launchbinding"
	"github.com/confidential-dot-ai/c8s/internal/objectcustody"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/spf13/cobra"
	"golang.org/x/net/netutil"
)

const (
	objectCustodyLaunchPath     = "/object-state/custody/launch"
	objectCustodyInitializePath = "/object-state/custody/initialize"
	objectCustodyProvisionPath  = "/object-state/custody/provision"
	objectCustodyRequestLimit   = 96 << 10
)

type objectCustodyInfo struct {
	Launch   []byte                       `json:"launch"`
	Identity objectstate.RecoveryIdentity `json:"identity"`
}

// Initialization and ordinary renewal use distinct scoped sessions. The owner
// pins the completed launch so a replacement chip cannot silently change roots.
type objectCustodyRequest struct {
	ConfigSHA256 string                            `json:"config_sha256"`
	Storage      objectstate.TemporaryCredentials  `json:"storage"`
	Writer       *objectstate.TemporaryCredentials `json:"writer,omitempty"`
	Origins      []string                          `json:"origins,omitempty"`
}

type objectCustodyResult struct {
	CAKeyID string                 `json:"ca_key_id,omitempty"`
	Ready   []objectCustodyReplica `json:"replicas,omitempty"`
}

type objectCustodyReplica struct {
	Origin string `json:"origin"`
	Ready  bool   `json:"ready"`
}

type objectCustodyJob struct {
	ctx        context.Context
	initialize bool
	request    objectCustodyRequest
	reply      chan objectCustodyReply
}

type objectCustodyReply struct {
	result objectCustodyResult
	err    error
}

// One actor owns provisioning for one measured cluster. No secret-bearing
// state is shared with the HTTP handlers or other cluster processes.
type objectCustodian struct {
	cfg       config
	images    []remote.ImagePin
	owner     *x509.CertPool
	material  *objectcustody.Material
	info      objectCustodyInfo
	ctx       context.Context
	cancel    context.CancelFunc
	jobs      chan objectCustodyJob
	slots     chan struct{}
	done      chan struct{}
	newStore  func(*objectstate.CredentialProvider) (objectstate.Store, error)
	provision func(
		context.Context,
		objectstate.RecoveryPolicySource,
		string,
		objectstate.TemporaryCredentials,
	) error
}

func newObjectCustodian(
	ctx context.Context,
	cfg config,
	images []remote.ImagePin,
	owner *x509.Certificate,
	material *objectcustody.Material,
) (*objectCustodian, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.measured.ObjectState == nil {
		return nil, errors.New("object custody: object-state configuration required")
	}
	if owner == nil || !owner.IsCA || material == nil || len(material.StateKey) != 32 ||
		len(material.Signer) != ed25519.PrivateKeySize || !bytes.Equal(
		material.Signer.Public().(ed25519.PublicKey),
		cfg.measured.ObjectState.RecoveryAuthority,
	) {
		return nil, errors.New("object custody: independent owner and matching hardware material required")
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &objectCustodian{
		cfg:      cfg,
		images:   cloneObjectRecoveryImages(images),
		owner:    x509.NewCertPool(),
		material: material,
		info: objectCustodyInfo{
			Launch:   bytes.Clone(cfg.measuredFile),
			Identity: objectRecoveryIdentity(cfg),
		},
		ctx:    ctx,
		cancel: cancel,
		jobs: make(
			chan objectCustodyJob,
			1,
		),
		slots: make(
			chan struct{},
			2,
		),
		done: make(chan struct{}),
	}
	c.owner.AddCert(owner)
	c.newStore = func(credentials *objectstate.CredentialProvider) (objectstate.Store, error) {
		o := cfg.measured.ObjectState
		return objectstate.NewS3(
			objectstate.S3Config{
				Region:        o.Region,
				Bucket:        o.Bucket,
				Key:           o.Key,
				Endpoint:      o.Endpoint,
				ExpectedOwner: o.ExpectedBucketOwner,
				MaxBytes:      o.MaxBytes,
				Timeout:       10 * time.Second,
			},
			credentials,
		)
	}
	c.provision = c.provisionReplica
	go c.control()
	return c, nil
}

func (c *objectCustodian) Stop() {
	c.cancel()
	<-c.done
}

func (c *objectCustodian) control() {
	defer close(c.done)
	for {
		select {
		case <-c.ctx.Done():
			return
		case job := <-c.jobs:
			result, err := c.execute(job)
			job.reply <- objectCustodyReply{
				result: result,
				err:    err,
			}
		}
	}
}

func (c *objectCustodian) execute(job objectCustodyJob) (objectCustodyResult, error) {
	if err := job.ctx.Err(); err != nil {
		return objectCustodyResult{}, err
	}
	if err := c.ctx.Err(); err != nil {
		return objectCustodyResult{}, err
	}
	if job.request.ConfigSHA256 != c.info.Identity.ConfigSHA256 {
		return objectCustodyResult{}, errors.New("object custody: completed launch changed")
	}
	if job.initialize {
		if job.request.Writer != nil || len(job.request.Origins) != 0 {
			return objectCustodyResult{}, errors.New("object custody: initialization cannot release material")
		}
	} else if job.request.Writer == nil || len(job.request.Origins) == 0 || len(job.request.Origins) > 16 {
		return objectCustodyResult{}, errors.New("object custody: bounded replica origins and writer session required")
	}
	seen := make(map[string]bool)
	for _, origin := range job.request.Origins {
		if !objectCustodyOrigin(origin) || seen[origin] {
			return objectCustodyResult{}, errors.New("object custody: distinct HTTPS origins required")
		}
		seen[origin] = true
	}
	credentials := objectstate.NewCredentialProvider(time.Now)
	if err := credentials.Install(job.request.Storage); err != nil {
		return objectCustodyResult{}, err
	}
	store, err := c.newStore(credentials)
	if err != nil {
		return objectCustodyResult{}, err
	}
	if closer, ok := store.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	sealed, err := objectCipher(
		c.cfg,
		c.material.StateKey,
	)
	if err != nil {
		return objectCustodyResult{}, err
	}
	if job.initialize {
		view, err := initializeObjectState(
			job.ctx,
			c.cfg,
			store,
			sealed,
		)
		if err != nil {
			return objectCustodyResult{}, err
		}
		defer view.Stop()
		return objectCustodyResult{CAKeyID: caKeyID(view.ca.CA.Cert)}, nil
	}
	policy, err := newObjectRecoveryPolicySource(
		c.cfg,
		store,
		sealed,
		c.images,
	)
	if err != nil {
		return objectCustodyResult{}, err
	}
	// Check current state before delivering even a storage session. Neither
	// missing state nor a stale custodian can turn renewal into initialization.
	if _, err := policy.Current(job.ctx); err != nil {
		return objectCustodyResult{}, err
	}
	// Every admitted origin gets its own bounded attempt. An unavailable
	// replica must not consume another replica's renewal budget.
	type progress struct {
		index int
		ready bool
	}
	replies := make(
		chan progress,
		len(job.request.Origins),
	)
	for index, origin := range job.request.Origins {
		go func() {
			err := c.provision(
				job.ctx,
				policy,
				origin,
				*job.request.Writer,
			)
			replies <- progress{
				index: index,
				ready: err == nil,
			}
		}()
	}
	result := objectCustodyResult{Ready: make(
		[]objectCustodyReplica,
		len(job.request.Origins),
	)}
	var failed bool
	for range job.request.Origins {
		reply := <-replies
		result.Ready[reply.index] = objectCustodyReplica{
			Origin: job.request.Origins[reply.index],
			Ready:  reply.ready,
		}
		failed = failed || !reply.ready
	}
	if failed {
		return result, errors.New("object custody: a replica is not ready")
	}
	return result, nil
}

func objectCustodyOrigin(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && len(origin) <= 2048 && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		(u.Path == "" || u.Path == "/")
}

func (c *objectCustodian) provisionReplica(
	ctx context.Context,
	policy objectstate.RecoveryPolicySource,
	origin string,
	credentials objectstate.TemporaryCredentials,
) error {
	ctx, cancel := context.WithTimeout(
		ctx,
		40*time.Second,
	)
	defer cancel()
	grant, err := objectstate.ReleaseCredentials(
		ctx,
		c.info.Identity,
		origin,
		policy,
		credentials,
		c.material.Signer,
	)
	if err != nil {
		return err
	}
	verification := armtls.Pins{Images: c.images}.VerifyPolicy(c.cfg.attestationApiURL)
	verification.RequireNonMigratable = true
	tlsConfig, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{Policy: verification})
	if err != nil {
		return err
	}
	client := armtls.HTTPClient(tlsConfig)
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(
		*http.Request,
		[]*http.Request,
	) error {
		return http.ErrUseLastResponse
	}
	if err := objectCustodyPost(
		ctx,
		client,
		origin,
		objectstate.CredentialsPath,
		grant,
	); err != nil {
		return err
	}
	// A credential refresh resumes an accepted key grant after a lost response
	// or a custodian restart; it never needs a newly sealed one-shot key grant.
	if objectCustodyReady(
		ctx,
		client,
		origin,
	) {
		return nil
	}
	key, err := objectstate.Release(
		ctx,
		c.info.Identity,
		origin,
		policy,
		objectstate.RecoveryMaterial{
			Key: c.material.StateKey,
		},
		c.material.Signer,
	)
	if err != nil {
		return err
	}
	if err := objectCustodyPost(
		ctx,
		client,
		origin,
		objectstate.GrantPath,
		key,
	); err != nil {
		return err
	}
	if !objectCustodyReady(
		ctx,
		client,
		origin,
	) {
		return errors.New("object custody: replica has not recovered")
	}
	return nil
}

func objectCustodyPost(
	ctx context.Context,
	client *http.Client,
	origin string,
	path string,
	value any,
) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	u, _ := url.Parse(origin)
	u.Path = path
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		u.String(),
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	request.Header.Set(
		"Content-Type",
		"application/json",
	)
	response, err := client.Do(request)
	if err != nil {
		return errors.New("object custody: attested grant delivery failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("object custody: grant delivery was not acknowledged")
	}
	return nil
}

func objectCustodyReady(
	ctx context.Context,
	client *http.Client,
	origin string,
) bool {
	u, _ := url.Parse(origin)
	u.Path = "/readyz"
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		u.String(),
		nil,
	)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func (c *objectCustodian) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set(
		"Cache-Control",
		"no-store",
	)
	if !c.ownerAuthorized(r) {
		http.Error(
			w,
			"independent owner certificate required",
			http.StatusUnauthorized,
		)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == objectCustodyLaunchPath {
		w.Header().Set(
			"Content-Type",
			"application/json",
		)
		_ = json.NewEncoder(w).Encode(c.info)
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != objectCustodyInitializePath && r.URL.Path != objectCustodyProvisionPath) {
		http.NotFound(
			w,
			r,
		)
		return
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		w.Header().Set(
			"Retry-After",
			"1",
		)
		http.Error(
			w,
			"custody queue is full",
			http.StatusServiceUnavailable,
		)
		return
	}
	ctx, cancel := context.WithTimeout(
		r.Context(),
		2*time.Minute,
	)
	defer cancel()
	stop := context.AfterFunc(
		c.ctx,
		cancel,
	)
	defer stop()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(10 * time.Second))
	readStopped := make(chan struct{})
	unblock := context.AfterFunc(
		ctx,
		func() {
			_ = controller.SetReadDeadline(time.Now())
			_ = r.Body.Close()
			close(readStopped)
		},
	)
	defer func() {
		if !unblock() {
			<-readStopped
		}
	}()
	body, err := io.ReadAll(http.MaxBytesReader(
		w,
		r.Body,
		objectCustodyRequestLimit,
	))
	if err != nil || strictjson.Validate(body) != nil {
		clear(body)
		http.Error(
			w,
			"invalid bounded custody request",
			http.StatusBadRequest,
		)
		return
	}
	defer clear(body)
	var request objectCustodyRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(
			w,
			"invalid custody request",
			http.StatusBadRequest,
		)
		return
	}
	job := objectCustodyJob{
		ctx:        ctx,
		initialize: r.URL.Path == objectCustodyInitializePath,
		request:    request,
		reply: make(
			chan objectCustodyReply,
			1,
		),
	}
	select {
	case c.jobs <- job:
	case <-ctx.Done():
		http.Error(
			w,
			"custody request canceled",
			http.StatusServiceUnavailable,
		)
		return
	}
	select {
	case reply := <-job.reply:
		w.Header().Set(
			"Content-Type",
			"application/json",
		)
		if reply.err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(reply.result)
	case <-ctx.Done():
		http.Error(
			w,
			"custody outcome unavailable",
			http.StatusServiceUnavailable,
		)
	}
}

func (c *objectCustodian) ownerAuthorized(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, cert := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := r.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         c.owner,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

func newObjectCustodyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "custody",
		Short: "Operate protected custody for one object-state CDS cluster",
	}
	var path, verifier, listen string
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Serve an independent owner from an approved SNP custody image",
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
			return runObjectCustody(
				ctx,
				path,
				verifier,
				listen,
			)
		},
	}
	serve.Flags().StringVar(
		&path,
		"config",
		"",
		"exact measured c8s-cds-custody/v1 launch document",
	)
	serve.Flags().StringVar(
		&verifier,
		"attestation-api-url",
		"",
		"attestation API inside this custody guest",
	)
	serve.Flags().StringVar(
		&listen,
		"listen",
		":8443",
		"custody TLS listen address",
	)
	_ = serve.MarkFlagRequired("config")
	_ = serve.MarkFlagRequired("attestation-api-url")
	cmd.AddCommand(serve)
	cmd.AddCommand(newObjectCustodyOwnerCommands()...)
	return cmd
}

func runObjectCustody(
	ctx context.Context,
	path string,
	verifier string,
	listen string,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := requireLoopbackAttestationAPI(verifier); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	raw, err := readutil.ReadAll(
		file,
		1<<20,
	)
	file.Close()
	if err != nil {
		return err
	}
	document, err := objectcustody.Parse(raw)
	if err != nil {
		return err
	}
	platform, err := launchbinding.VerifyMeasuredLaunchFile(
		ctx,
		verifier,
		raw,
	)
	if err != nil || platform != teetypes.FamilySNP {
		return errors.New("object custody: verified SNP launch required")
	}
	material, err := objectcustody.Derive(
		ctx,
		document,
	)
	if err != nil {
		return err
	}
	defer material.Clear()
	launch, measured, images, err := document.Complete(material.Signer.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	cfg := objectCustodyCDSConfig(verifier)
	cfg.measuredFile = launch
	cfg.measured = measured
	cfg.armtlsPlatform = teetypes.FamilySNP
	custodian, err := newObjectCustodian(
		ctx,
		cfg,
		images,
		document.OwnerCA(),
		material,
	)
	if err != nil {
		return err
	}
	defer custodian.Stop()
	settings := servingConfig(
		cfg,
		document.OwnerCA(),
	)
	settings.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig, certificates, err := armtls.NewServerTLSConfig(settings)
	if err != nil {
		return err
	}
	warm, stopWarmup := context.WithTimeout(
		ctx,
		30*time.Second,
	)
	err = certificates.WarmUp(warm)
	stopWarmup()
	if err != nil {
		return err
	}
	rotationDone := make(chan struct{})
	go func() {
		certificates.RunRotation(ctx)
		close(rotationDone)
	}()
	defer func() {
		cancel()
		<-rotationDone
	}()
	server := &http.Server{
		Addr:              listen,
		Handler:           custodian,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      130 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	defer server.Close()
	serverClosed := make(chan struct{})
	closeServer := context.AfterFunc(
		ctx,
		func() {
			_ = server.Close()
			close(serverClosed)
		},
	)
	defer func() {
		if !closeServer() {
			<-serverClosed
		}
	}()
	listener, err := net.Listen(
		"tcp",
		listen,
	)
	if err != nil {
		return err
	}
	err = server.ServeTLS(
		netutil.LimitListener(
			listener,
			48,
		),
		"",
		"",
	)
	if errors.Is(
		err,
		http.ErrServerClosed,
	) {
		return nil
	}
	return err
}

// Match the CDS defaults for the complete initial image and its decoder. The
// custodian exposes no host-selectable override of these state limits.
func objectCustodyCDSConfig(verifier string) config {
	return config{
		attestationApiURL:          verifier,
		caCommonName:               issuer.DefaultCACommonName,
		caCertValidity:             8760 * time.Hour,
		certTTL:                    24 * time.Hour,
		namedCertTTL:               issuer.MaxNamedLeafTTL,
		routerCertTTL:              20 * time.Second,
		allowlistNodeDelay:         30 * time.Second,
		challengeTTL:               60 * time.Second,
		maxRequestSize:             65536,
		readinessInterval:          10 * time.Second,
		minCAValidity:              time.Hour,
		armtlsCertTTL:              24 * time.Hour,
		secretsMaxPaths:            1024,
		secretsMaxPathsPerWorkload: secrets.DefaultMaxPathsPerHolder,
		secretsMaxValueBytes:       4096,
		sandboxLedgerMax:           10000,
	}
}
