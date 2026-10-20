// Package podstatus serves and reads a pod CVM's status and runtime
// measurements. The guest serves them over armTLS on :8443, in place of
// cred-release. A client verifies the image and, with fresh nonce-bound
// evidence, the launch key plus every workload measured into RTMR[3] before
// trusting an answer. Requests are not client-authenticated: the status, the
// digest list and quotes are not secret.
package podstatus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	PodPath          = "/v1/pod"
	MeasurementsPath = "/v1/measurements"
	// EvidencePath takes types.NonceRequest (a 32-byte nonce) and
	// returns fresh evidence whose report data is armtls.ReportDataForKey(
	// serving cert key, nonce): SHA-384(SPKI DER || nonce), zero-padded. It
	// binds the answer to this TLS channel, so a host cannot relay the request
	// to another pod CVM launched with the same key.
	EvidencePath = "/v1/evidence"
	// KubeletCertPath is where a kubelet with no tlsCertFile writes the
	// self-signed serving certificate pod-status pins.
	KubeletCertPath = "/var/lib/kubelet/pki/kubelet.crt"
	maxBody         = 4 << 20
)

// BindingHeader names the report-data convention on /v1/evidence, so a
// client and guest built from different revisions fail with a clear error
// instead of a REPORT_DATA mismatch.
const (
	BindingHeader  = "X-C8s-Evidence-Binding"
	BindingVersion = "armtls-key-nonce/v1"
)

// EvidenceReportData is the one definition of /v1/evidence's report data,
// used by guest and client: armtls.ReportDataForKey(serving cert key,
// nonce) = SHA-384(SPKI DER || nonce), zero-padded to 64 bytes. The client
// passes all 64 bytes to the verifier as the expected REPORT_DATA.
func EvidenceReportData(servingKey crypto.PublicKey, nonce []byte) ([64]byte, error) {
	if len(nonce) != 32 {
		return [64]byte{}, fmt.Errorf("nonce must be 32 bytes, got %d", len(nonce))
	}
	return armtls.ReportDataForKey(servingKey, nonce)
}

// Measurements is the GET /v1/measurements body, in extend order.
type Measurements struct {
	Digests []string `json:"digests"`
}

// Handler serves the pod-status routes.
type Handler struct {
	UID string
	// Pods returns the kubelet's /pods body.
	Pods func(ctx context.Context) ([]byte, error)
	// Journal is the RTMR[3] journal file.
	Journal string
	// Evidence returns an evidence envelope bound to reportData (48 bytes).
	Evidence func(ctx context.Context, reportData []byte) ([]byte, error)
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case PodPath:
		if allow(w, r, http.MethodGet) {
			h.servePod(w, r)
		}
	case MeasurementsPath:
		if allow(w, r, http.MethodGet) {
			h.serveMeasurements(w)
		}
	case EvidencePath:
		if allow(w, r, http.MethodPost) {
			h.serveEvidence(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func allow(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (h Handler) servePod(w http.ResponseWriter, r *http.Request) {
	pods, err := h.Pods(r.Context())
	if err != nil {
		http.Error(w, "kubelet unavailable", http.StatusServiceUnavailable)
		return
	}
	pod, err := findPod(pods, h.UID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, pod)
}

// serveMeasurements reads the journal as the serving cert does, so both list
// the same digests. No journal means nothing was measured yet.
func (h Handler) serveMeasurements(w http.ResponseWriter) {
	digests, err := armtls.ReadRuntimeExtensions(h.Journal)
	if err != nil {
		http.Error(w, "measurements unavailable", http.StatusServiceUnavailable)
		return
	}
	if digests == nil {
		digests = []string{}
	}
	writeJSON(w, Measurements{Digests: digests})
}

func (h Handler) serveEvidence(w http.ResponseWriter, r *http.Request) {
	var req types.NonceRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || len(req.Nonce) != 32 {
		http.Error(w, "want {\"nonce\": <32 bytes, base64>}", http.StatusBadRequest)
		return
	}
	key := armtls.ServingKey(r.Context())
	if key == nil {
		http.Error(w, "no serving key for this connection", http.StatusInternalServerError)
		return
	}
	rd, err := EvidenceReportData(key, req.Nonce)
	if err != nil {
		http.Error(w, "attestation unavailable", http.StatusInternalServerError)
		return
	}
	// attestation-api zero-pads the 48 bytes back to rd's 64.
	evidence, err := h.Evidence(r.Context(), rd[:sha512.Size384])
	if err != nil {
		http.Error(w, "attestation unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(BindingHeader, BindingVersion)
	_, _ = w.Write(evidence)
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func findPod(body []byte, uid string) (*corev1.Pod, error) {
	var list corev1.PodList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("decode kubelet pods: %w", err)
	}
	for i := range list.Items {
		if string(list.Items[i].UID) == uid {
			return &list.Items[i], nil
		}
	}
	return nil, fmt.Errorf("pod %s not running yet", uid)
}

// ServeConfig configures the guest service.
type ServeConfig struct {
	ListenAddr        string
	Platform          string
	AttestationAPIURL string
	KubeletURL        string
	KubeletCert       string
	StagedPath        string
	JournalPath       string
}

// Serve confirms the measured launch key, reads the signed pod UID and
// serves until ctx is done.
func Serve(ctx context.Context, cfg ServeConfig) error {
	family, err := teetypes.ParseFamily(cfg.Platform)
	if err != nil || strings.TrimSpace(cfg.Platform) == "" {
		return fmt.Errorf("--platform must be tdx or snp (armTLS is mandatory)")
	}
	doc, err := launchconfig.LoadStaged(cfg.StagedPath)
	if err != nil {
		return err
	}
	if doc.Role != launchconfig.Pod || doc.Pod == nil {
		return fmt.Errorf("staged launch configuration is not a pod")
	}
	// Fails closed if the staged pod key is not the launch-bound one. The
	// register holds the key's seed plus whatever this guest's own journal
	// lists, so a restart after containers were measured still passes.
	if _, err := credrelease.LoadMeasuredOperatorKey(ctx, cfg.AttestationAPIURL, cfg.JournalPath); err != nil {
		return fmt.Errorf("load measured launch key: %w", err)
	}
	api := attestclient.NewClient("")
	h := Handler{
		UID:     doc.Pod.UID,
		Pods:    kubeletPods(cfg.KubeletURL, cfg.KubeletCert),
		Journal: cfg.JournalPath,
		Evidence: func(ctx context.Context, reportData []byte) ([]byte, error) {
			resp, err := api.GenerateEvidenceContext(ctx, cfg.AttestationAPIURL, reportData)
			if err != nil {
				return nil, err
			}
			return json.Marshal(resp.Envelope())
		},
	}
	return serveARMTLS(ctx, cfg, family.String(), h)
}

// maxConcurrentConns caps accepted sockets: pod-status binds every interface
// and each connection costs an armTLS handshake before any request is read.
const maxConcurrentConns = 64

// newServer builds the pod-status HTTP server. The bounds live here so they
// can be asserted; none changes a legitimate answer, so a regression is silent.
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Allow the body read, attestation, and response write.
		WriteTimeout:   50 * time.Second,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}

// serveARMTLS serves h over armTLS with a self-signed certificate whose quote
// binds its own key. The certificate lists the journal as its runtime
// extensions, so a client can replay the register from the certificate alone.
func serveARMTLS(ctx context.Context, cfg ServeConfig, platform string, h http.Handler) error {
	// The attest func reads resp.Platform, so it serves TDX despite its name.
	attestFunc := attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), cfg.AttestationAPIURL)
	return armtls.Serve(ctx, newServer(cfg.ListenAddr, h), &armtls.ServerConfig{
		Platform:             platform,
		AttestFunc:           attestFunc,
		Logger:               slog.Default(),
		MeasuredPoliciesFile: cfg.JournalPath,
	}, maxConcurrentConns)
}

// kubeletPods reads the loopback kubelet. Its serving certificate is
// self-signed, so the dial pins it to the certificate kubelet wrote to
// certFile instead of checking a chain; the file and the listener share the
// root network namespace, which the pod cannot reach. The file is read on
// every handshake, so a kubelet that regenerates its certificate is followed.
func kubeletPods(base, certFile string) func(context.Context) ([]byte, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // VerifyConnection pins the kubelet's own certificate
				MinVersion:         tls.VersionTLS12,
				VerifyConnection: func(cs tls.ConnectionState) error {
					return verifyPinnedCertificate(cs, certFile)
				},
			},
		},
	}
	return func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/pods", nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("kubelet /pods: %s", resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxBody))
	}
}

// verifyPinnedCertificate accepts a connection only when the peer's leaf is
// byte for byte the first certificate in the PEM file at certFile.
func verifyPinnedCertificate(cs tls.ConnectionState, certFile string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("kubelet presented no certificate")
	}
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read kubelet serving certificate: %w", err)
	}
	for block, rest := pem.Decode(pemBytes); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		if bytes.Equal(block.Bytes, cs.PeerCertificates[0].Raw) {
			return nil
		}
		return fmt.Errorf("kubelet certificate differs from %s", certFile)
	}
	return fmt.Errorf("%s holds no certificate", certFile)
}

// AttestConfig configures the client.
type AttestConfig struct {
	Node              string
	LaunchKeyPubPath  string
	ImageManifestPath string
	ExpectDigests     []string
	Timeout           time.Duration
}

// Report is what pod-attest proves about the pod CVM.
type Report struct {
	Image           string   `json:"image"`
	LaunchKeySHA256 string   `json:"launch_key_sha256"`
	MeasuredDigests []string `json:"measured_digests"`
	RTMR3           string   `json:"rtmr3,omitempty"`
}

// Seams for tests.
var (
	newClient   = guestverify.NewClient
	verifyFresh = guestverify.VerifyEvidence
)

// Attest verifies fresh evidence from the pod CVM and its measured digest
// list, returning the report and the verified channel for further reads.
func Attest(ctx context.Context, cfg AttestConfig) (*Report, *http.Client, error) {
	if cfg.Node == "" || cfg.LaunchKeyPubPath == "" || cfg.ImageManifestPath == "" {
		return nil, nil, errors.New("--node, --launch-key-pub and --image-manifest are required")
	}
	if cfg.Timeout <= 0 {
		return nil, nil, errors.New("--timeout must be positive")
	}
	if strings.ContainsAny(cfg.Node, "/?#@") {
		return nil, nil, fmt.Errorf("--node must be a host or IP, got %q", cfg.Node)
	}
	expect := make([]string, 0, len(cfg.ExpectDigests))
	for _, ref := range cfg.ExpectDigests {
		d, err := runtimemeasure.CanonicalDigest(ref)
		if err != nil {
			return nil, nil, fmt.Errorf("--expect-digest: %w", err)
		}
		expect = append(expect, d)
	}
	pub, err := os.ReadFile(cfg.LaunchKeyPubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("--launch-key-pub: %w", err)
	}
	// One gate for the channel and the evidence: the image the manifest pins
	// and the launch key, bound as every c8s verifier binds a node's. The
	// channel replays the list the serving certificate carries as a prefix
	// of the register; the fresh evidence replays the list read from the
	// guest.
	exp, err := guestverify.PolicyFor(cfg.ImageManifestPath, pub, nil)
	if err != nil {
		return nil, nil, err
	}
	exp = exp.WithMeasuredPolicies(nil)
	client := newClient(exp, cfg.Timeout)
	base := "https://" + hostPort(cfg.Node)
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// The first answer fixes the serving key: every connection after it,
	// here and over the returned client, must present that key. Otherwise a
	// host could answer the later reads from another pod CVM launched with
	// the same launch key, whose certificate passes the same checks.
	before, peer, err := fetchDigests(ctx, client, base)
	if err != nil {
		return nil, nil, err
	}
	if client, err = pinServingKey(client, peer); err != nil {
		return nil, nil, err
	}

	// A container may start between the quote and the list; read the list
	// on both sides of the quote and retry until they agree.
	var digests []string
	var envelope, reportData []byte
	for attempt := 0; ; attempt++ {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, nil, err
		}
		reqBody, _ := json.Marshal(types.NonceRequest{Nonce: nonce})
		var peer crypto.PublicKey
		if envelope, peer, err = postEvidence(ctx, client, base, reqBody); err != nil {
			return nil, nil, fmt.Errorf("fresh evidence: %w", err)
		}
		// The quote must bind this channel's certificate key and our nonce.
		rd, err := EvidenceReportData(peer, nonce)
		if err != nil {
			return nil, nil, err
		}
		reportData = rd[:]
		if digests, _, err = fetchDigests(ctx, client, base); err != nil {
			return nil, nil, err
		}
		if slices.Equal(before, digests) {
			break
		}
		if attempt == 2 {
			return nil, nil, errors.New("measured digests kept changing during attestation; retry")
		}
		before = digests
	}
	res, err := verifyFresh(envelope, reportData, exp.WithMeasuredPolicies(digests))
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: %w", err)
	}
	// The gate accepts any replaying prefix; here the list was read on both
	// sides of the quote and agreed, so the whole of it must replay.
	if err := runtimemeasure.VerifyBinding(res, pub, digests); err != nil {
		return nil, nil, fmt.Errorf("measured digests do not explain the attested register: %w", err)
	}
	if cfg.ExpectDigests != nil && !sameSet(expect, digests) {
		return nil, nil, fmt.Errorf("measured digests %v, expected %v", digests, expect)
	}
	sum := sha256.Sum256(pub)
	report := &Report{Image: res.Claims.LaunchDigest, LaunchKeySHA256: hex.EncodeToString(sum[:]), MeasuredDigests: digests}
	if res.Platform.HasRegisters() {
		reg, err := runtimemeasure.Binding(res)
		if err != nil {
			return nil, nil, err
		}
		report.RTMR3 = hex.EncodeToString(reg)
	}
	return report, client, nil
}

// pinServingKey returns a client that accepts only connections served with
// peer, before the checks client already makes. Every pod CVM launched with
// one launch key presents a certificate that passes those checks; the pin
// tells the attested one apart.
func pinServingKey(client *http.Client, peer crypto.PublicKey) (*http.Client, error) {
	want, err := x509.MarshalPKIXPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("pin serving key: %w", err)
	}
	base, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("pin serving key: the attested client has no TLS transport")
	}
	tr := base.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	verify := tr.TLSClientConfig.VerifyConnection
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("server presented no certificate")
		}
		got, err := x509.MarshalPKIXPublicKey(cs.PeerCertificates[0].PublicKey)
		if err != nil || !bytes.Equal(got, want) {
			return errors.New("serving key differs from the attested one: another guest answered")
		}
		if verify != nil {
			return verify(cs)
		}
		return nil
	}
	client.CloseIdleConnections()
	return &http.Client{Timeout: client.Timeout, CheckRedirect: client.CheckRedirect, Transport: tr}, nil
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// fetchDigests also returns the key of the certificate that served the list.
func fetchDigests(ctx context.Context, client *http.Client, base string) ([]string, crypto.PublicKey, error) {
	body, peer, _, err := doPeer(ctx, client, http.MethodGet, base+MeasurementsPath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("measurements: %w", err)
	}
	var m Measurements
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, fmt.Errorf("measurements: %w", err)
	}
	return m.Digests, peer, nil
}

func do(ctx context.Context, client *http.Client, method, url string, body []byte) ([]byte, error) {
	data, _, _, err := doPeer(ctx, client, method, url, body)
	return data, err
}

func postEvidence(ctx context.Context, client *http.Client, base string, reqBody []byte) ([]byte, crypto.PublicKey, error) {
	body, peer, binding, err := doPeer(ctx, client, http.MethodPost, base+EvidencePath, reqBody)
	if err != nil {
		return nil, nil, err
	}
	if binding != BindingVersion {
		return nil, nil, fmt.Errorf("guest evidence binding is %q, this client needs %q: guest and client c8s are different builds", binding, BindingVersion)
	}
	return body, peer, nil
}

// doPeer also returns the public key of the certificate the server
// presented on the connection that carried this request.
func doPeer(ctx context.Context, client *http.Client, method, url string, body []byte) ([]byte, crypto.PublicKey, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("attested request (image or channel not verified): %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, "", fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, nil, "", errors.New("response did not arrive over TLS")
	}
	return data, resp.TLS.PeerCertificates[0].PublicKey, resp.Header.Get(BindingHeader), nil
}

// Get attests the pod CVM, then returns its /v1/pod body.
func Get(ctx context.Context, cfg AttestConfig) ([]byte, error) {
	_, client, err := Attest(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	return do(ctx, client, http.MethodGet, "https://"+hostPort(cfg.Node)+PodPath, nil)
}

func hostPort(node string) string {
	if _, _, err := net.SplitHostPort(node); err == nil {
		return node
	}
	return net.JoinHostPort(strings.Trim(node, "[]"), "8443")
}
