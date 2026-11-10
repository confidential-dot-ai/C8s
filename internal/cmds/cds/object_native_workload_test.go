package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/sidecar"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	nativeWorkloadPrefix       = "/object-native/"
	nativeWorkloadRequestLimit = 256 << 10
	// Below the unchanged production 60-second challenge TTL. A result after
	// this monotonic deadline is inconclusive, never a replay-protection pass.
	nativeWorkloadReplayWindow = 55 * time.Second
)

type nativeWorkloadRequest struct {
	RunID         string   `json:"run_id"`
	CDSLaunch     []byte   `json:"cds_launch,omitempty"`
	CDSPins       []string `json:"cds_pins,omitempty"`
	InventoryHost string   `json:"inventory_host,omitempty"`
	Originals     []string `json:"originals,omitempty"`
	Replacements  []string `json:"replacements,omitempty"`
}

// No secret value, secret hash, private key or reusable token belongs in this
// public receipt. Operator JWT replay is a separate owner-run assertion.
type nativeWorkloadResult struct {
	RunID              string          `json:"run_id"`
	Phase              string          `json:"phase"`
	ConfigSHA256       string          `json:"config_sha256,omitempty"`
	CAKeyID            string          `json:"ca_key_id,omitempty"`
	OriginalLeafSerial string          `json:"original_leaf_serial,omitempty"`
	ReplayDeadline     time.Time       `json:"replay_deadline,omitempty"`
	Checks             map[string]bool `json:"checks,omitempty"`
}

type nativeWorkloadJob struct {
	ctx     context.Context
	action  string
	request nativeWorkloadRequest
	reply   chan nativeWorkloadReply
}

type nativeWorkloadReply struct {
	result nativeWorkloadResult
	status int
}

type nativeWorkloadReceipt struct {
	digest [32]byte
	reply  nativeWorkloadReply
}

type nativeWorkloadIssuance struct {
	started time.Time
	request types.AttestRequestBody
}

type nativeWorkloadSecret struct {
	started      time.Time
	nonce, token []byte
}

// The actor owns every protocol field. Handlers admit at most two requests:
// one executing and one queued. Secret-bearing fields never enter a receipt.
type nativeWorkload struct {
	ctx                           context.Context
	cancel                        context.CancelFunc
	done                          chan struct{}
	jobs                          chan nativeWorkloadJob
	slots                         chan struct{}
	raw                           []byte
	launch                        nativeWorkloadLaunch
	owner                         *x509.Certificate
	family                        teetypes.Family
	result                        nativeWorkloadResult
	receipts                      map[string]nativeWorkloadReceipt
	pins                          refvalues.ReferenceValues
	originals, replacements       []string
	signer                        *workloadclaims.SandboxTokenSigner
	key                           *ecdsa.PrivateKey
	csr                           string
	leaf                          *x509.Certificate
	root                          *x509.Certificate
	chain                         tls.Certificate
	public, mesh                  *http.Client
	target, control               []byte
	unusedIssuance, spentIssuance nativeWorkloadIssuance
	unusedSecret, spentSecret     nativeWorkloadSecret
}

func newNativeWorkload(
	ctx context.Context,
	raw []byte,
	launch nativeWorkloadLaunch,
	owner *x509.Certificate,
	family teetypes.Family,
) (*nativeWorkload, error) {
	if owner == nil || len(raw) == 0 {
		return nil, errors.New("native workload requires authenticated launch and owner")
	}
	ctx, cancel := context.WithCancel(ctx)
	f := &nativeWorkload{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
		jobs: make(
			chan nativeWorkloadJob,
			1,
		),
		slots: make(
			chan struct{},
			2,
		),
		raw:    bytes.Clone(raw),
		launch: launch,
		owner:  owner,
		family: family,
		result: nativeWorkloadResult{
			RunID:  launch.RunID,
			Phase:  "new",
			Checks: make(map[string]bool),
		},
		receipts: make(map[string]nativeWorkloadReceipt),
	}
	go f.run()
	return f, nil
}

func (f *nativeWorkload) stop() {
	f.cancel()
	<-f.done
}

func (f *nativeWorkload) snapshot(status int) nativeWorkloadReply {
	result := f.result
	result.Checks = maps.Clone(result.Checks)
	return nativeWorkloadReply{
		result: result,
		status: status,
	}
}

func (f *nativeWorkload) run() {
	defer close(f.done)
	defer func() {
		for _, client := range []*http.Client{
			f.public,
			f.mesh,
		} {
			if client != nil {
				client.CloseIdleConnections()
			}
		}
		clear(f.target)
		clear(f.control)
		if f.key != nil {
			f.key.D.SetInt64(0)
		}
	}()
	for {
		select {
		case <-f.ctx.Done():
			return
		case job := <-f.jobs:
			job.reply <- f.execute(job)
		}
	}
}

func (f *nativeWorkload) execute(job nativeWorkloadJob) nativeWorkloadReply {
	if job.ctx.Err() != nil {
		return f.snapshot(http.StatusServiceUnavailable)
	}
	if job.action == "result" {
		return f.snapshot(http.StatusOK)
	}
	if job.request.RunID != f.launch.RunID {
		return f.snapshot(http.StatusBadRequest)
	}
	canonical, _ := json.Marshal(job.request)
	digest := sha256.Sum256(canonical)
	if receipt, exists := f.receipts[job.action]; exists {
		if receipt.digest != digest {
			return f.snapshot(http.StatusConflict)
		}
		return receipt.reply
	}
	expected := map[string]string{
		"prepare": "new",
		"arm":     "prepared",
		"verify":  "armed",
	}
	if expected[job.action] != f.result.Phase {
		return f.snapshot(http.StatusConflict)
	}
	if job.action != "prepare" && (len(job.request.CDSLaunch) != 0 || len(job.request.CDSPins) != 0 ||
		job.request.InventoryHost != "" || len(job.request.Originals) != 0 || len(job.request.Replacements) != 0) {
		return f.snapshot(http.StatusBadRequest)
	}
	if job.action == "prepare" && !nativeWorkloadOrigins(
		job.request.Originals,
		job.request.Replacements,
	) {
		return f.snapshot(http.StatusBadRequest)
	}
	var err error
	switch job.action {
	case "prepare":
		err = f.prepare(
			job.ctx,
			job.request,
		)
	case "arm":
		err = f.arm(job.ctx)
	case "verify":
		err = f.verify(job.ctx)
	default:
		return f.snapshot(http.StatusNotFound)
	}
	status := http.StatusOK
	if err != nil {
		// A partial phase may have committed a mutation despite losing its
		// response. Retrying returns this receipt and never remints a nonce.
		f.result.Phase = "failed"
		status = http.StatusServiceUnavailable
	} else {
		f.result.Phase = map[string]string{
			"prepare": "prepared",
			"arm":     "armed",
			"verify":  "verified",
		}[job.action]
	}
	reply := f.snapshot(status)
	f.receipts[job.action] = nativeWorkloadReceipt{
		digest: digest,
		reply:  reply,
	}
	return reply
}

func nativeWorkloadOrigins(originals, replacements []string) bool {
	if len(originals) != 3 || len(replacements) != 3 {
		return false
	}
	seen := make(map[string]bool)
	for _, origins := range [][]string{
		originals,
		replacements,
	} {
		for _, origin := range origins {
			if !objectCustodyOrigin(origin) || strings.HasSuffix(
				origin,
				"/",
			) || seen[origin] {
				return false
			}
			seen[origin] = true
		}
	}
	return true
}

func (f *nativeWorkload) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(
			w,
			"owner certificate required",
			http.StatusUnauthorized,
		)
		return
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.owner)
	intermediates := x509.NewCertPool()
	for _, certificate := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := r.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		http.Error(
			w,
			"owner certificate required",
			http.StatusUnauthorized,
		)
		return
	}
	action := strings.TrimPrefix(
		r.URL.Path,
		nativeWorkloadPrefix,
	)
	if (r.Method != http.MethodPost || (action != "prepare" && action != "arm" && action != "verify")) &&
		(r.Method != http.MethodGet || action != "result") {
		http.NotFound(
			w,
			r,
		)
		return
	}
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	default:
		http.Error(
			w,
			"native fixture busy",
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
		f.ctx,
		cancel,
	)
	defer stop()
	request := nativeWorkloadRequest{}
	if action != "result" {
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(10 * time.Second))
		readDone := make(chan struct{})
		unblock := context.AfterFunc(
			ctx,
			func() {
				_ = controller.SetReadDeadline(time.Now())
				_ = r.Body.Close()
				close(readDone)
			},
		)
		defer func() {
			if !unblock() {
				<-readDone
			}
		}()
		raw, err := io.ReadAll(http.MaxBytesReader(
			w,
			r.Body,
			nativeWorkloadRequestLimit,
		))
		if err != nil || nativeWorkloadDecode(
			raw,
			&request,
		) != nil {
			http.Error(
				w,
				"invalid bounded fixture request",
				http.StatusBadRequest,
			)
			return
		}
	}
	job := nativeWorkloadJob{
		ctx:     ctx,
		action:  action,
		request: request,
		reply: make(
			chan nativeWorkloadReply,
			1,
		),
	}
	select {
	case f.jobs <- job:
	case <-ctx.Done():
		http.Error(
			w,
			"fixture unavailable",
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
		w.WriteHeader(reply.status)
		_ = json.NewEncoder(w).Encode(reply.result)
	case <-ctx.Done():
		http.Error(
			w,
			"fixture unavailable",
			http.StatusServiceUnavailable,
		)
	}
}

func nativeWorkloadDecode(
	raw []byte,
	target any,
) error {
	if err := strictjson.Validate(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func nativeWorkloadPins(
	documents []string,
	launch []byte,
) (refvalues.ReferenceValues, error) {
	var merged refvalues.ReferenceValues
	if len(documents) == 0 || len(documents) > 2 || len(launch) == 0 || len(launch) > 64<<10 {
		return merged, errors.New("native fixture requires bounded completed launch and image documents")
	}
	families := map[teetypes.Family]bool{}
	for _, document := range documents {
		if len(document) > 64<<10 {
			return merged, errors.New("native image document too large")
		}
		pins, err := refvalues.Parse([]byte(document))
		if err != nil || pins.Empty() || len(pins.Images) > 4 || families[pins.Family] ||
			(pins.Family != teetypes.FamilySNP && pins.Family != teetypes.FamilyTDX) {
			return merged, errors.New("native fixture requires distinct SNP/TDX image documents")
		}
		families[pins.Family] = true
		for _, image := range pins.Images {
			if image.Anchor != nil || image.LaunchFileDigest != nil || image.AcceptExtension != nil ||
				(len(image.LaunchFile) != 0 && !bytes.Equal(
					image.LaunchFile,
					launch,
				)) ||
				(pins.Family == teetypes.FamilySNP && len(image.Registers) != 0) ||
				(pins.Family == teetypes.FamilyTDX && (len(image.Registers) != 2 || len(image.Registers[1]) != 48 || len(image.Registers[2]) != 48)) {
				return merged, errors.New("native fixture requires exact image and launch pins")
			}
			image.LaunchFile = bytes.Clone(launch)
			merged.Images = append(
				merged.Images,
				image,
			)
		}
	}
	return merged, nil
}

func (f *nativeWorkload) prepare(
	ctx context.Context,
	request nativeWorkloadRequest,
) error {
	measured, err := cdsconfig.Parse(request.CDSLaunch)
	if err != nil || measured.ObjectState == nil || measured.Nodes.Family != f.family || measured.Nodes.Empty() {
		return errors.New("native fixture requires object-state CDS with its native node identity")
	}
	for _, image := range measured.Nodes.Images {
		if !bytes.Equal(
			image.LaunchFile,
			f.raw,
		) || image.Anchor != nil || image.LaunchFileDigest != nil ||
			(f.family == teetypes.FamilyTDX && (len(image.Registers) != 2 || len(image.Registers[1]) != 48 || len(image.Registers[2]) != 48)) {
			return errors.New("CDS must pin the exact native workload launch")
		}
	}
	host, err := workloadclaims.ParseInventoryHost(request.InventoryHost)
	if err != nil || host != request.InventoryHost || !measured.NodeCIDRs.Contains(host) {
		return errors.New("native inventory address is not in the measured CDS node bound")
	}
	pins, err := nativeWorkloadPins(
		request.CDSPins,
		request.CDSLaunch,
	)
	if err != nil {
		return err
	}
	f.pins = pins
	f.originals = append(
		[]string(nil),
		request.Originals...,
	)
	f.replacements = append(
		[]string(nil),
		request.Replacements...,
	)
	f.signer, err = workloadclaims.NewSandboxTokenSigner(host)
	if err != nil {
		return err
	}
	verification := armtls.Pins(pins.Policy()).VerifyPolicy(nativeWorkloadAPI)
	verification.RequireNonMigratable = true
	publicTLS, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{Policy: verification})
	if err != nil {
		return err
	}
	f.public = armtls.HTTPClient(publicTLS)
	f.public.CheckRedirect = nativeWorkloadNoRedirect
	if err := f.startInventory(pins); err != nil {
		return err
	}
	f.key, err = ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	if err != nil {
		return err
	}
	client := attestclient.NewClientWithHTTP(
		f.originals[0],
		f.public,
	)
	ext, err := client.AttestationExtension(
		ctx,
		nativeWorkloadAPI,
		&f.key.PublicKey,
	)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{ExtraExtensions: []pkix.Extension{ext}},
		f.key,
	)
	if err != nil {
		return err
	}
	f.csr = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))
	issuance, err := f.newIssuance(
		ctx,
		f.originals[0],
	)
	if err != nil {
		return err
	}
	raw, err := f.issue(
		ctx,
		f.originals[1],
		issuance,
	)
	if err != nil {
		return err
	}
	leaf, root, chain, err := f.checkIssued(raw)
	if err != nil {
		return err
	}
	f.leaf, f.root, f.chain = leaf, root, chain
	tlsConfig, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{Policy: verification})
	if err != nil {
		return err
	}
	tlsConfig.Certificates = []tls.Certificate{f.chain}
	f.mesh = armtls.HTTPClient(tlsConfig)
	f.mesh.CheckRedirect = nativeWorkloadNoRedirect
	for index, path := range []string{
		f.path("target"),
		f.path("control"),
	} {
		created, err := f.newSecret(
			ctx,
			f.originals[0],
		)
		if err != nil {
			return err
		}
		value, status, err := f.secret(
			ctx,
			f.originals[1],
			http.MethodPost,
			path,
			created,
		)
		clear(value)
		if err != nil || status != http.StatusCreated {
			return errors.New("native fixture secret creation failed")
		}
		fresh, err := f.newSecret(
			ctx,
			f.originals[2],
		)
		if err != nil {
			return err
		}
		value, status, err = f.secret(
			ctx,
			f.originals[0],
			http.MethodGet,
			path,
			fresh,
		)
		if err != nil || status != http.StatusOK || len(value) == 0 {
			clear(value)
			return errors.New("native fixture baseline release failed")
		}
		if index == 0 {
			f.target = value
		} else {
			f.control = value
		}
	}
	sum := sha256.Sum256(request.CDSLaunch)
	f.result.ConfigSHA256 = hex.EncodeToString(sum[:])
	f.result.CAKeyID = caKeyID(f.root)
	f.result.OriginalLeafSerial = f.leaf.SerialNumber.String()
	f.result.Checks["native_issuance"] = true
	f.result.Checks["baseline_target_and_control"] = true
	return f.checkCA(
		ctx,
		f.originals,
	)
}

func nativeWorkloadNoRedirect(
	*http.Request,
	[]*http.Request,
) error {
	return errors.New("native fixture does not follow redirects")
}

func (f *nativeWorkload) path(name string) string {
	return "/object-native/" + f.launch.RunID + "/" + name
}

func (f *nativeWorkload) token(nonce []byte) ([]byte, error) {
	digest, err := workloadclaims.RequesterKeyDigest(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	token, err := f.signer.Sign(
		f.launch.RunID,
		digest,
		nonce,
	)
	if err != nil {
		return nil, err
	}
	return json.Marshal(token)
}

func (f *nativeWorkload) newIssuance(
	ctx context.Context,
	origin string,
) (nativeWorkloadIssuance, error) {
	result := nativeWorkloadIssuance{started: time.Now()}
	client := attestclient.NewClientWithHTTP(
		origin,
		f.public,
	)
	challenge, err := client.AuthenticateContext(ctx)
	if err != nil {
		return result, err
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil || len(nonce) != 32 {
		return result, errors.New("invalid issuance challenge")
	}
	token, err := f.token(nonce)
	if err != nil {
		return result, err
	}
	bound, err := armtls.ReportDataForKey(
		&f.key.PublicKey,
		nonce,
	)
	if err != nil {
		return result, err
	}
	evidence, err := client.GenerateEvidenceContext(
		ctx,
		nativeWorkloadAPI,
		bound[:48],
	)
	if err != nil {
		return result, err
	}
	if evidence.Platform != teetypes.PlatformSNP && evidence.Platform != teetypes.PlatformTDX {
		return result, errors.New("native workload requires native evidence")
	}
	result.request = types.AttestRequestBody{
		Challenge:    challenge.Challenge,
		CSR:          f.csr,
		Evidence:     evidence.Envelope(),
		SandboxToken: token,
	}
	return result, nil
}

func (f *nativeWorkload) issue(
	ctx context.Context,
	origin string,
	issuance nativeWorkloadIssuance,
) ([]byte, error) {
	client := attestclient.NewClientWithHTTP(
		origin,
		f.public,
	)
	chain, err := client.AttestContext(
		ctx,
		issuance.request,
	)
	return []byte(chain), err
}

func (f *nativeWorkload) checkIssued(raw []byte) (*x509.Certificate, *x509.Certificate, tls.Certificate, error) {
	certs, err := certutil.ParsePEMCertificates(raw)
	if err != nil || len(certs) != 2 {
		return nil, nil, tls.Certificate{}, errors.New("native fixture expected leaf and CA")
	}
	leaf, root := certs[0], certs[1]
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	sandbox, sandboxErr := armtls.SandboxIDFromCert(leaf)
	matched, matchedErr := armtls.MatchedWorkloadFromCert(leaf)
	if err != nil || root.CheckSignatureFrom(root) != nil || !f.key.PublicKey.Equal(leaf.PublicKey) ||
		sandboxErr != nil || sandbox != f.launch.RunID || matchedErr != nil || matched == nil || matched.Name != nativeWorkloadName ||
		(f.root != nil && !bytes.Equal(
			root.RawSubjectPublicKeyInfo,
			f.root.RawSubjectPublicKeyInfo,
		)) {
		return nil, nil, tls.Certificate{}, errors.New("native fixture leaf identity or CA did not match")
	}
	return leaf, root, tls.Certificate{
		Certificate: [][]byte{
			leaf.Raw,
			root.Raw,
		},
		PrivateKey: f.key,
		Leaf:       leaf,
	}, nil
}

func (f *nativeWorkload) newSecret(
	ctx context.Context,
	origin string,
) (nativeWorkloadSecret, error) {
	result := nativeWorkloadSecret{started: time.Now()}
	var err error
	result.nonce, err = sidecar.FetchChallenge(
		ctx,
		f.mesh,
		origin,
		20*time.Second,
	)
	if err != nil || len(result.nonce) != 32 {
		return result, errors.New("native secret challenge failed")
	}
	result.token, err = f.token(result.nonce)
	return result, err
}

func (f *nativeWorkload) secret(
	ctx context.Context,
	origin, method, path string,
	request nativeWorkloadSecret,
) ([]byte, int, error) {
	req, err := sidecar.NewStoreRequest(
		ctx,
		origin,
		method,
		path,
		request.nonce,
		request.token,
	)
	if err != nil {
		return nil, 0, err
	}
	response, err := f.mesh.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	raw, err := readNativeWorkloadResponse(response)
	if err != nil {
		return nil, response.StatusCode, err
	}
	defer clear(raw)
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		if response.StatusCode == http.StatusBadRequest && string(raw) != "invalid or expired challenge\n" {
			return nil, response.StatusCode, errors.New("unexpected secret challenge refusal")
		}
		return nil, response.StatusCode, nil
	}
	var value struct {
		Value string `json:"value"`
	}
	if err := nativeWorkloadDecode(
		raw,
		&value,
	); err != nil {
		return nil, response.StatusCode, err
	}
	plain, err := base64.StdEncoding.DecodeString(value.Value)
	return plain, response.StatusCode, err
}

func readNativeWorkloadResponse(response *http.Response) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(
		response.Body,
		1<<20+1,
	))
	if len(raw) > 1<<20 {
		clear(raw)
		return nil, errors.New("native fixture response too large")
	}
	return raw, err
}

func (f *nativeWorkload) checkCA(
	ctx context.Context,
	origins []string,
) error {
	for _, origin := range origins {
		client := attestclient.NewClientWithHTTP(
			origin,
			f.public,
		)
		raw, err := client.MeshCA(ctx)
		if err != nil {
			return errors.New("native fixture CA request failed")
		}
		certs, err := certutil.ParsePEMCertificates(raw)
		if err != nil || len(certs) == 0 || !bytes.Equal(
			certs[0].RawSubjectPublicKeyInfo,
			f.root.RawSubjectPublicKeyInfo,
		) {
			return errors.New("replica changed CA identity")
		}
	}
	return nil
}

func (f *nativeWorkload) arm(ctx context.Context) error {
	var err error
	// Mint the unused nonce first. Its later success is a stronger freshness
	// control than a younger nonce that could outlive the replay.
	f.unusedIssuance, err = f.newIssuance(
		ctx,
		f.originals[0],
	)
	if err != nil {
		return err
	}
	f.spentIssuance, err = f.newIssuance(
		ctx,
		f.originals[0],
	)
	if err != nil {
		return err
	}
	raw, err := f.issue(
		ctx,
		f.originals[1],
		f.spentIssuance,
	)
	if err != nil {
		return err
	}
	if _, _, _, err := f.checkIssued(raw); err != nil {
		return err
	}
	f.unusedSecret, err = f.newSecret(
		ctx,
		f.originals[0],
	)
	if err != nil {
		return err
	}
	f.spentSecret, err = f.newSecret(
		ctx,
		f.originals[0],
	)
	if err != nil {
		return err
	}
	value, status, err := f.secret(
		ctx,
		f.originals[1],
		http.MethodGet,
		f.path("control"),
		f.spentSecret,
	)
	defer clear(value)
	if err != nil || status != http.StatusOK || !bytes.Equal(
		value,
		f.control,
	) {
		return errors.New("native secret pre-loss use failed")
	}
	if err := f.replayTimely(); err != nil {
		return err
	}
	f.result.ReplayDeadline = f.unusedIssuance.started.Add(nativeWorkloadReplayWindow)
	f.result.Checks["spent_and_unused_challenges_armed"] = true
	return nil
}

func (f *nativeWorkload) replayTimely() error {
	for _, started := range []time.Time{
		f.unusedIssuance.started,
		f.spentIssuance.started,
		f.unusedSecret.started,
		f.spentSecret.started,
	} {
		if started.IsZero() || time.Since(started) >= nativeWorkloadReplayWindow {
			return errors.New("native replay timing inconclusive")
		}
	}
	return nil
}

func (f *nativeWorkload) verify(ctx context.Context) error {
	f.public.CloseIdleConnections()
	f.mesh.CloseIdleConnections()
	if err := f.replayTimely(); err != nil {
		return err
	}
	// Before ANY successful post-loss issuance or owner policy write, exercise
	// the old leaf and persisted binding. Issuance would repair a missing ledger;
	// an owner write could repair a lost allowlist. The runner must order its JWT
	// positive control after this phase and separately prove all originals died.
	origins := f.replacements
	_, status, err := f.secret(
		ctx,
		origins[0],
		http.MethodGet,
		f.path("control"),
		f.spentSecret,
	)
	if err != nil || status != http.StatusBadRequest {
		return errors.New("spent secret challenge was not refused")
	}
	value, status, err := f.secret(
		ctx,
		origins[0],
		http.MethodGet,
		f.path("control"),
		f.unusedSecret,
	)
	defer clear(value)
	if err != nil || status != http.StatusOK || !bytes.Equal(
		value,
		f.control,
	) {
		return errors.New("unused secret challenge failed after recovery")
	}
	if err := f.replayTimely(); err != nil {
		return err
	}
	f.result.Checks["secret_replay_and_older_unused_control"] = true
	for _, origin := range origins {
		for _, name := range []string{
			"target",
			"control",
		} {
			fresh, err := f.newSecret(
				ctx,
				origin,
			)
			if err != nil {
				return err
			}
			value, status, err := f.secret(
				ctx,
				origin,
				http.MethodGet,
				f.path(name),
				fresh,
			)
			if err != nil {
				clear(value)
				return err
			}
			accepted := (name == "target" && status == http.StatusNotFound) ||
				(name == "control" && status == http.StatusOK && len(value) != 0 && bytes.Equal(
					value,
					f.control,
				))
			clear(value)
			if !accepted {
				return errors.New("old-leaf revocation or control release failed")
			}
		}
	}
	f.result.Checks["original_leaf_binding_and_revocation_on_three_replicas"] = true
	if err := f.replayTimely(); err != nil {
		return err
	}
	_, err = f.issue(
		ctx,
		origins[0],
		f.spentIssuance,
	)
	var statusError *attestclient.StatusError
	var refusal types.ErrorResponse
	if !errors.As(
		err,
		&statusError,
	) || statusError.Status != http.StatusBadRequest ||
		nativeWorkloadDecode(
			[]byte(statusError.Body),
			&refusal,
		) != nil || refusal.Error != types.ErrorCodeInvalidChallenge {
		return errors.New("spent issuance challenge was not refused specifically")
	}
	raw, err := f.issue(
		ctx,
		origins[0],
		f.unusedIssuance,
	)
	if err != nil {
		return err
	}
	if _, _, _, err := f.checkIssued(raw); err != nil {
		return err
	}
	if err := f.replayTimely(); err != nil {
		return err
	}
	f.result.Checks["issuance_replay_and_older_unused_control"] = true
	if err := f.checkCA(
		ctx,
		origins,
	); err != nil {
		return err
	}
	f.result.Checks["same_ca_on_three_replicas"] = true
	return nil
}

func nativeWorkloadJSON(
	t *testing.T,
	value any,
) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Offline admission tests, not evidence of native execution. They never replace
// a verifier or network transport in the gated guest entrypoint.
func TestNativeWorkloadBoundsAndPhases(t *testing.T) {
	ownerPEM, clientPEM, _ := ownerClientIdentity(t)
	owner, _ := certutil.ParseCertificatePEM(ownerPEM)
	client, _ := certutil.ParseCertificatePEM(clientPEM)
	launch := nativeWorkloadLaunch{RunID: strings.Repeat(
		"a",
		32,
	)}
	f, err := newNativeWorkload(
		t.Context(),
		[]byte("offline"),
		launch,
		owner,
		teetypes.FamilySNP,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.stop)
	request := func(
		method, action, body string,
		authorized bool,
	) *httptest.ResponseRecorder {
		r := httptest.NewRequest(
			method,
			nativeWorkloadPrefix+action,
			strings.NewReader(body),
		)
		if authorized {
			r.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{client},
				VerifiedChains: [][]*x509.Certificate{{
					client,
					owner,
				}},
			}
		}
		w := httptest.NewRecorder()
		f.ServeHTTP(
			w,
			r,
		)
		return w
	}
	for _, test := range []struct {
		name, method, action, body string
		authorized                 bool
		status                     int
	}{
		{
			"unauthorized",
			"POST",
			"arm",
			`{}`,
			false,
			http.StatusUnauthorized,
		},
		{
			"phase",
			"POST",
			"arm",
			`{"run_id":"` + launch.RunID + `"}`,
			true,
			http.StatusConflict,
		},
		{
			"unknown field",
			"POST",
			"prepare",
			`{"private_key":"forbidden"}`,
			true,
			http.StatusBadRequest,
		},
		{
			"duplicate",
			"POST",
			"prepare",
			`{"run_id":"a","run_id":"b"}`,
			true,
			http.StatusBadRequest,
		},
		{
			"oversized",
			"POST",
			"prepare",
			strings.Repeat(
				"x",
				nativeWorkloadRequestLimit+1,
			),
			true,
			http.StatusBadRequest,
		},
		{
			"public result",
			"GET",
			"result",
			"",
			true,
			http.StatusOK,
		},
	} {
		t.Run(
			test.name,
			func(t *testing.T) {
				if got := request(
					test.method,
					test.action,
					test.body,
					test.authorized,
				); got.Code != test.status {
					t.Fatalf(
						"status %d, want %d",
						got.Code,
						test.status,
					)
				}
			},
		)
	}
	f.slots <- struct{}{}
	f.slots <- struct{}{}
	if got := request(
		"GET",
		"result",
		"",
		true,
	); got.Code != http.StatusServiceUnavailable {
		t.Fatal("overload was admitted")
	}
	<-f.slots
	<-f.slots
	originals := []string{
		"https://one",
		"https://two",
		"https://three",
	}
	replacements := []string{
		"https://four",
		"https://five",
		"https://six",
	}
	if !nativeWorkloadOrigins(
		originals,
		replacements,
	) || nativeWorkloadOrigins(
		originals,
		originals,
	) ||
		nativeWorkloadOrigins(
			originals[:2],
			replacements,
		) {
		t.Fatal("origin bounds failed")
	}
}

func TestNativeWorkloadReplayDeadlineAndReceipts(t *testing.T) {
	launch := nativeWorkloadLaunch{RunID: strings.Repeat(
		"a",
		32,
	)}
	f := &nativeWorkload{
		launch: launch,
		result: nativeWorkloadResult{
			RunID:  launch.RunID,
			Phase:  "armed",
			Checks: map[string]bool{},
		},
		receipts: make(map[string]nativeWorkloadReceipt),
	}
	old := time.Now().Add(-time.Minute)
	f.unusedIssuance.started, f.spentIssuance.started = old, old
	f.unusedSecret.started, f.spentSecret.started = old, old
	if f.replayTimely() == nil {
		t.Fatal("expired replay accepted as conclusive")
	}
	request := nativeWorkloadRequest{RunID: launch.RunID}
	canonical, _ := json.Marshal(request)
	receipt := nativeWorkloadReply{
		status: http.StatusOK,
		result: nativeWorkloadResult{
			Phase:          "armed",
			ReplayDeadline: old,
		},
	}
	f.receipts["arm"] = nativeWorkloadReceipt{
		digest: sha256.Sum256(canonical),
		reply:  receipt,
	}
	got := f.execute(nativeWorkloadJob{
		ctx:     t.Context(),
		action:  "arm",
		request: request,
	})
	if got.status != http.StatusOK || !got.result.ReplayDeadline.Equal(old) || !f.unusedIssuance.started.Equal(old) {
		t.Fatal("arm retry changed original receipt or nonce timing")
	}
	request.Originals = []string{"https://other"}
	if got := f.execute(nativeWorkloadJob{
		ctx:     t.Context(),
		action:  "arm",
		request: request,
	}); got.status != http.StatusConflict {
		t.Fatal("arm retry changed fixed roles")
	}
	request.Originals = nil
	request.Replacements = []string{"https://other"}
	if got := f.execute(nativeWorkloadJob{
		ctx:     t.Context(),
		action:  "verify",
		request: request,
	}); got.status != http.StatusBadRequest {
		t.Fatal("verify changed replacement roles")
	}
}

func TestNativeWorkloadPinsBindCompletedLaunch(t *testing.T) {
	snp := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"snp","measurement":"` + strings.Repeat(
		"a",
		96,
	) + `"}]}`
	tdx := `{"schema_version":"1","tee":"tdx","measurements":[{"name":"tdx","mrtd":"` + strings.Repeat(
		"b",
		96,
	) + `","rtmr":[null,"` + strings.Repeat(
		"c",
		96,
	) + `","` + strings.Repeat(
		"d",
		96,
	) + `"]}]}`
	launch := []byte("exact completed CDS launch")
	pins, err := nativeWorkloadPins(
		[]string{
			snp,
			tdx,
		},
		launch,
	)
	if err != nil || len(pins.Images) != 2 {
		t.Fatalf(
			"strict mixed native pins rejected: %v",
			err,
		)
	}
	launch[0] ^= 1
	if !bytes.Equal(
		pins.Images[0].LaunchFile,
		[]byte("exact completed CDS launch"),
	) {
		t.Fatal("caller mutated completed launch pin")
	}
	for _, documents := range [][]string{
		nil,
		{
			snp,
			snp,
		},
		{strings.Replace(
			tdx,
			`,"rtmr":[null,"`+strings.Repeat(
				"c",
				96,
			)+`","`+strings.Repeat(
				"d",
				96,
			)+`"]`,
			"",
			1,
		)},
		{strings.Replace(
			tdx,
			`"]}]}`,
			`","`+strings.Repeat(
				"e",
				96,
			)+`"]}]}`,
			1,
		)},
	} {
		if _, err := nativeWorkloadPins(
			documents,
			launch,
		); err == nil {
			t.Fatal("missing, duplicate-family, firmware-only or circular RTMR3 pins accepted")
		}
	}
}

func TestNativeWorkloadCannotRepairRecoveryBeforeCheckingSecrets(t *testing.T) {
	// The synthetic transport models loss of a durable binding or policy. It
	// asserts test ordering only; no native verifier is bypassed in the guest.
	for _, lost := range []string{
		"binding",
		"revocation",
	} {
		t.Run(
			lost,
			func(t *testing.T) {
				key, err := ecdsa.GenerateKey(
					elliptic.P256(),
					rand.Reader,
				)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := workloadclaims.NewSandboxTokenSigner("192.0.2.10")
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				f := &nativeWorkload{
					launch: nativeWorkloadLaunch{RunID: strings.Repeat(
						"a",
						32,
					)},
					replacements: []string{
						"https://four",
						"https://five",
						"https://six",
					},
					key:            key,
					signer:         signer,
					control:        []byte("offline-control"),
					result:         nativeWorkloadResult{Checks: make(map[string]bool)},
					unusedIssuance: nativeWorkloadIssuance{started: now},
					spentIssuance:  nativeWorkloadIssuance{started: now},
					unusedSecret: nativeWorkloadSecret{
						started: now,
						nonce: bytes.Repeat(
							[]byte{1},
							32,
						),
					},
					spentSecret: nativeWorkloadSecret{
						started: now,
						nonce: bytes.Repeat(
							[]byte{2},
							32,
						),
					},
				}
				issuances := 0
				client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					status, body := http.StatusOK, `{"value":"`+base64.StdEncoding.EncodeToString(f.control)+`"}`
					switch {
					case request.URL.Path == "/attest":
						issuances++
						return nil, errors.New("issuance must not repair recovery before secret checks")
					case request.URL.Path == "/secrets":
						body = `{"challenge":"` + base64.StdEncoding.EncodeToString(bytes.Repeat(
							[]byte{3},
							32,
						)) + `"}`
					case request.Header.Get("X-C8s-Challenge") == base64.StdEncoding.EncodeToString(f.spentSecret.nonce):
						status, body = http.StatusBadRequest, "invalid or expired challenge\n"
					case lost == "binding":
						status, body = http.StatusForbidden, "not authorized for this secret"
					}
					return &http.Response{
						StatusCode: status,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				})}
				f.public, f.mesh = client, client
				if err := f.verify(t.Context()); err == nil || issuances != 0 {
					t.Fatalf(
						"lost %s was repaired or accepted: issuances=%d error=%v",
						lost,
						issuances,
						err,
					)
				}
			},
		)
	}
}

func TestNativeWorkloadRechecksOwnerCertificateLifetime(t *testing.T) {
	ownerPEM, clientPEM, keyPEM := ownerClientIdentity(t)
	owner, err := certutil.ParseCertificatePEM(ownerPEM)
	if err != nil {
		t.Fatal(err)
	}
	client, err := certutil.ParseCertificatePEM(clientPEM)
	if err != nil {
		t.Fatal(err)
	}
	key, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	expired := *client
	expired.NotAfter = time.Now().Add(-time.Minute)
	der, err := x509.CreateCertificate(
		rand.Reader,
		&expired,
		owner,
		client.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f, err := newNativeWorkload(
		t.Context(),
		[]byte("offline"),
		nativeWorkloadLaunch{RunID: strings.Repeat(
			"a",
			32,
		)},
		owner,
		teetypes.FamilySNP,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.stop)
	request := httptest.NewRequest(
		http.MethodGet,
		nativeWorkloadPrefix+"result",
		nil,
	)
	// Model a long-lived TLS connection whose once-verified leaf has expired.
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peer},
		VerifiedChains: [][]*x509.Certificate{{
			peer,
			owner,
		}},
	}
	response := httptest.NewRecorder()
	f.ServeHTTP(
		response,
		request,
	)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("stale handshake authorization survived certificate expiry")
	}
}

func TestNativeWorkloadRequiresSpecificSecretChallengeRefusal(t *testing.T) {
	for _, body := range []string{
		"invalid or expired challenge\n",
		"invalid path\n",
		"fixture-error-secret\n",
	} {
		f := &nativeWorkload{mesh: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		})}}
		_, status, err := f.secret(
			t.Context(),
			"https://fixture.invalid",
			http.MethodGet,
			"/fixed",
			nativeWorkloadSecret{},
		)
		if status != http.StatusBadRequest || (err == nil) != (body == "invalid or expired challenge\n") {
			t.Fatal("unrelated HTTP400 counted as a challenge replay refusal")
		}
		if err != nil && strings.Contains(
			err.Error(),
			"fixture-error-secret",
		) {
			t.Fatal("refusal reflected an upstream body")
		}
	}
}
