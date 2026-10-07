// mock-cds is a fake CDS for integration testing: it serves the production
// wire contract (armTLS, /authenticate, /attest — internal/cmds/cds) backed
// by the mock attestation-api instead of a TEE, and signs CSRs with an
// ephemeral CA. Use only in test environments.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// caOutPath is where the ephemeral CA PEM lands so the harness can anchor
// chain verification out-of-band (docker compose cp).
const caOutPath = "/ca/mock-cds-ca.pem"

// mockLaunchDigest is the launch measurement the mock attestation-api
// reports. Issuance is pinned to it the way production gates /attest on
// --measurements.
const mockLaunchDigest = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

var (
	caKey  ecdsa.PrivateKey
	caCert x509.Certificate
	caPEM  []byte
)

func init() {
	// Generate an ephemeral CA at startup.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate CA key: %v", err))
	}
	caKey = *key

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock-cds-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("failed to create CA cert: %v", err))
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("failed to parse CA cert: %v", err))
	}
	caCert = *parsed
}

type challengeStore struct {
	mu         sync.Mutex
	challenges map[string]time.Time
}

func newChallengeStore() challengeStore {
	return challengeStore{challenges: make(map[string]time.Time)}
}

func (s *challengeStore) issue() string {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	encoded := base64.StdEncoding.EncodeToString(nonce)
	s.mu.Lock()
	s.challenges[encoded] = time.Now().Add(5 * time.Minute)
	s.mu.Unlock()
	return encoded
}

func (s *challengeStore) consume(challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.challenges[challenge]
	if !ok || time.Now().After(exp) {
		return false
	}
	delete(s.challenges, challenge)
	return true
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	attestationAPIURL := os.Getenv("ATTESTATION_API_URL")
	if attestationAPIURL == "" {
		slog.Error("ATTESTATION_API_URL is required")
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(caOutPath), 0o755); err != nil {
		slog.Error("failed to create CA output directory", "error", err)
		os.Exit(1)
	}
	if err := os.WriteFile(caOutPath, caPEM, 0o644); err != nil {
		slog.Error("failed to write CA PEM", "error", err)
		os.Exit(1)
	}

	store := newChallengeStore()
	verifier := remote.NewClient(attestationAPIURL)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /authenticate", func(w http.ResponseWriter, r *http.Request) {
		challenge := store.issue()
		slog.Info("issued challenge")
		writeJSON(w, types.ChallengeResponse{Challenge: challenge})
	})
	mux.HandleFunc("POST /attest", handleAttest(&store, verifier))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Serve armTLS like production CDS: the attestation-api supplies the
	// evidence binding the serving key, and callers verify the handshake
	// against the same api.
	tlsCfg, _, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), attestationAPIURL),
		Logger:     slog.Default(),
	})
	if err != nil {
		slog.Error("armtls server config failed", "error", err)
		os.Exit(1)
	}

	slog.Info("mock cds starting (armTLS)", "port", port)
	srv := &http.Server{Addr: ":" + port, Handler: mux, TLSConfig: tlsCfg}
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func handleAttest(store *challengeStore, verifier remote.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.AttestRequestBody
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusUnprocessableEntity, types.ErrorCodeInvalidRequest, err.Error())
			return
		}

		challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
		if err != nil || !store.consume(req.Challenge) {
			writeError(w, http.StatusBadRequest, types.ErrorCodeInvalidChallenge, "invalid or expired challenge")
			return
		}

		// Parse the CSR.
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			writeError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, "invalid CSR: no PEM block")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, fmt.Sprintf("invalid CSR: %s", err))
			return
		}
		if err := csr.CheckSignature(); err != nil {
			writeError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, fmt.Sprintf("CSR signature invalid: %s", err))
			return
		}
		csrPubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			writeError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, "CSR public key must be ECDSA")
			return
		}

		// Verify the evidence binds this CSR key and the consumed challenge,
		// the same report-data check production CDS delegates to the api.
		expectedReportData, err := armtls.ReportDataForKey(csrPubKey, challengeBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
			return
		}
		verifyReq := remote.NewVerifyRequest(req.Evidence, &remote.VerifyParams{
			ExpectedReportData: expectedReportData[:sha512.Size384],
		}, false)
		verifyResp, err := verifier.VerifyEnforced(r.Context(), verifyReq)
		if err != nil {
			status, code, msg := classifyVerifyError(err)
			slog.Warn("attestation verification failed", "status", status, "error", err, "remote_addr", r.RemoteAddr)
			writeError(w, status, code, msg)
			return
		}
		if digest := strings.ToLower(verifyResp.Result.Claims.LaunchDigest); digest != mockLaunchDigest {
			slog.Warn("measurement does not match any reference value", "launch_digest", digest, "remote_addr", r.RemoteAddr)
			writeError(w, http.StatusForbidden, types.ErrorCodeMeasurementDenied, "launch measurement not allowed")
			return
		}

		// Sign the certificate with the mock CA. The armTLS extension is
		// copied from the CSR like production's issuer.SignCSR, so the leaf
		// stays re-verifiable downstream.
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		template := x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			NotBefore:    time.Now().Add(-1 * time.Minute),
			NotAfter:     time.Now().Add(30 * 24 * time.Hour), // 30 days
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     csr.DNSNames,
			IPAddresses:  csr.IPAddresses,
		}
		for _, ext := range csr.Extensions {
			if ext.Id.Equal(armtls.OIDARMTLSAttestation) {
				template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: ext.Id, Value: ext.Value})
				break
			}
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &caCert, csr.PublicKey, &caKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, types.ErrorCodeSignFailed, fmt.Sprintf("failed to sign certificate: %s", err))
			return
		}

		slog.Info("issued certificate",
			"dns_names", csr.DNSNames,
			"ip_addresses", csr.IPAddresses,
			"serial", serial.String(),
		)

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(append(certPEM, caPEM...))
	}
}

// classifyVerifyError maps a VerifyEnforced error to the status/code/message
// production CDS answers /attest with (internal/cmds/cds/attest.go): 401 bad
// signature/report-data, 422 api evidence refusal or request rejection, 502
// transport or 5xx outage.
func classifyVerifyError(err error) (int, string, string) {
	switch {
	case errors.Is(err, remote.ErrSignatureInvalid):
		return http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "attestation signature invalid"
	case errors.Is(err, remote.ErrReportDataMismatch):
		return http.StatusUnauthorized, types.ErrorCodeVerificationFailed, "challenge mismatch in attestation evidence"
	}
	var apiErr *remote.APIError
	if errors.As(err, &apiErr) && refusesEvidence(apiErr.Status) {
		return http.StatusUnprocessableEntity, types.ErrorCodeVerificationFailed, "attestation evidence rejected by attestation-api"
	}
	// The api answers its own refusals in the JSON envelope, so a non-JSON body
	// names the request rather than the evidence, and only where there is a
	// body to have named it.
	var unexpected *remote.UnexpectedError
	if errors.As(err, &unexpected) && rejectsRequest(unexpected.Status) && unexpected.Text != "" {
		return http.StatusUnprocessableEntity, types.ErrorCodeVerificationFailed, "attestation-api rejected the request"
	}
	return http.StatusBadGateway, types.ErrorCodeAttestationApiUnreachable,
		fmt.Sprintf("failed to reach attestation-api: %s", err)
}

// refusesEvidence reports whether a status names the evidence rather than the
// service; 408 and 429 are availability.
func refusesEvidence(status int) bool {
	return status >= 400 && status < 500 &&
		status != http.StatusRequestTimeout && status != http.StatusTooManyRequests
}

// rejectsRequest reports whether a status names what was sent. These are the
// statuses axum's extractors reject a body with, outside the JSON envelope.
func rejectsRequest(status int) bool {
	return status == http.StatusBadRequest ||
		status == http.StatusUnsupportedMediaType ||
		status == http.StatusUnprocessableEntity
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(types.ErrorResponse{Error: code, Message: message})
}
