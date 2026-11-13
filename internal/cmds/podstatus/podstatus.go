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
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/launchbinding"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
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
	assignment *assignmentService
	// Pods returns the kubelet's /pods body.
	Pods func(ctx context.Context) ([]byte, error)
	// Journal is the RTMR[3] journal file.
	Journal string
	// Evidence returns an evidence envelope bound to reportData (48 bytes).
	Evidence func(ctx context.Context, reportData []byte) ([]byte, error)
	// IdentityEnded reports whether the admission plugin ended the pod
	// identity for this boot; nil never does. An ended identity is projected
	// as failed, and a plugin that cannot answer makes the status unavailable.
	IdentityEnded func(ctx context.Context) (bool, error)
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
	case AssignNoncePath:
		if allow(w, r, http.MethodGet) {
			if h.assignment == nil {
				http.Error(w, "assignment unavailable", http.StatusServiceUnavailable)
			} else if !h.identityEnded(w, r) {
				h.assignment.serveNonce(w, r)
			}
		}
	case AssignPath:
		if allow(w, r, http.MethodPost) {
			if h.assignment == nil {
				http.Error(w, "assignment unavailable", http.StatusServiceUnavailable)
			} else if !h.identityEnded(w, r) {
				h.assignment.serveAssign(w, r)
			}
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

// identityEnded answers 503 on an assignment route of a guest whose pod
// identity the plugin ended, before any assignment check. An unassigned guest
// runs no plugin and is not asked; a plugin that cannot answer leaves the
// route to its assignment checks.
func (h Handler) identityEnded(w http.ResponseWriter, r *http.Request) bool {
	if h.IdentityEnded == nil || h.assignment.assignedUID() == "" {
		return false
	}
	if ended, err := h.IdentityEnded(r.Context()); err != nil || !ended {
		return false
	}
	http.Error(w, "pod identity ended", http.StatusServiceUnavailable)
	return true
}

func (h Handler) servePod(w http.ResponseWriter, r *http.Request) {
	var uid string
	if h.assignment != nil {
		uid = h.assignment.assignedUID()
	}
	// No kubelet runs before an assignment is recorded, so the assignment is
	// checked first: an unassigned guest answers 404, an assigned one whose
	// kubelet is not up yet 503.
	if uid == "" {
		http.Error(w, "Pod is not assigned", http.StatusNotFound)
		return
	}
	ended := false
	if h.IdentityEnded != nil {
		var err error
		if ended, err = h.IdentityEnded(r.Context()); err != nil {
			// The kubelet's cached status cannot stand in for the admission
			// plugin: without its answer the pod may be running unguarded.
			http.Error(w, "pod admission unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	pods, err := h.Pods(r.Context())
	if err != nil {
		http.Error(w, "kubelet unavailable", http.StatusServiceUnavailable)
		return
	}
	pod, err := findPod(pods, uid)
	if errors.Is(err, errKubeletBody) {
		// A body that does not parse is the kubelet's fault, not a pod that
		// is still starting; a poller must not wait on it.
		http.Error(w, "kubelet reply unreadable", http.StatusBadGateway)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	projection := ProjectPod(pod)
	if ended {
		projection = failIdentityEnded(projection)
	}
	writeJSON(w, projection)
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

// errKubeletBody marks a kubelet reply that does not decode as a pod list.
var errKubeletBody = errors.New("decode kubelet pods")

func findPod(body []byte, uid string) (*corev1.Pod, error) {
	var list corev1.PodList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("%w: %w", errKubeletBody, err)
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
// serves until ctx is done. Every failure to confirm the key exits, a register
// that replays no prefix of the journal included: a client that verifies the
// guest then sees a connection failure rather than a failed verification. The
// key confirmed here is the one every assignment's signature is checked
// against; no request triggers another attestation.
func Serve(ctx context.Context, cfg ServeConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	family, err := teetypes.ParseFamily(cfg.Platform)
	if err != nil || strings.TrimSpace(cfg.Platform) == "" {
		return fmt.Errorf("--platform must be tdx or snp (armTLS is mandatory)")
	}
	doc, err := podlaunch.LoadStaged(cfg.StagedPath)
	if err != nil {
		return err
	}
	if doc.Role != podlaunch.Pod {
		return fmt.Errorf("staged launch configuration is not a pod")
	}
	launchKeyPEM, err := loadMeasuredLaunchKey(ctx, cfg.AttestationAPIURL, cfg.JournalPath)
	if err != nil {
		return fmt.Errorf("load measured launch key: %w", err)
	}
	launchKey, err := assignmentPublicKey(launchKeyPEM)
	if err != nil {
		return fmt.Errorf("measured launch key: %w", err)
	}
	api := attestclient.NewClient("")
	pods := kubeletPods(cfg.KubeletURL, cfg.KubeletCert)
	store, err := openAssignmentStore()
	if err != nil {
		return fmt.Errorf("open assignment state: %w", err)
	}
	defer store.Close()
	runtime := guestAssignmentRuntime{journal: cfg.JournalPath}
	boundKey := func(context.Context) (*ecdsa.PublicKey, error) { return launchKey, nil }
	assignment, err := newAssignmentService(ctx, doc, store, boundKey,
		func(d *podlaunch.AssignedPod) (nodeservices.PodRuntime, error) {
			return nodeservices.RenderPodRuntime("", d)
		},
		runtime.available, runtime.apply)
	if err != nil {
		return fmt.Errorf("recover Pod assignment: %w", err)
	}
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); assignment.run(ctx) }()
	// Stop the installer before releasing the assignment store's lifetime lock.
	defer func() { cancel(); <-workerDone }()
	h := Handler{
		assignment:    assignment,
		Pods:          pods,
		Journal:       cfg.JournalPath,
		IdentityEnded: podIdentityEnded,
		Evidence: func(ctx context.Context, reportData []byte) ([]byte, error) {
			resp, err := api.GenerateEvidenceContext(ctx, cfg.AttestationAPIURL, reportData)
			if err != nil {
				return nil, err
			}
			return json.Marshal(resp.Envelope())
		},
	}
	// The provider pins the serving key an assignment arrives over, so the
	// certificate keeps one key for the process: rotation renews the
	// certificate and its quote, never the key.
	servingKey, _, err := armtls.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate serving key: %w", err)
	}
	// The certificate's quote binds its own key and lists the journal as its
	// runtime extensions, so a client can replay the register from the
	// certificate alone. The attest func reads resp.Platform, so it serves
	// TDX despite its name.
	return armtls.Serve(ctx, cfg.ListenAddr, h, &armtls.ServerConfig{
		Platform:             family.String(),
		AttestFunc:           attestclient.MakeSNPARMTLSAttestFunc(api, cfg.AttestationAPIURL),
		Key:                  servingKey,
		Logger:               slog.Default(),
		MeasuredPoliciesFile: cfg.JournalPath,
	})
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
		pods, err := readutil.ReadAll(resp.Body, maxBody)
		if err != nil {
			return nil, fmt.Errorf("kubelet /pods: %w", err)
		}
		return pods, nil
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

// loadMeasuredLaunchKey is a seam for tests.
var loadMeasuredLaunchKey = launchbinding.LoadMeasuredOperatorKey
