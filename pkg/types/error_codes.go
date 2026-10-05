package types

// Stable HTTP error codes returned in the C8s error-envelope shape. Clients
// parse these wire-format identifiers; don't rename without a migration plan.
const (
	ErrorCodeInvalidRequest            = "invalid_request"
	ErrorCodeInvalidChallenge          = "invalid_challenge"
	ErrorCodeInvalidCSR                = "invalid_csr"
	ErrorCodeInvalidToken              = "invalid_token"
	ErrorCodeVerificationFailed        = "verification_failed"
	ErrorCodeMeasurementDenied         = "measurement_denied"
	ErrorCodeKeyBinding                = "key_binding"
	ErrorCodeCSRDenied                 = "csr_denied"
	ErrorCodeSignFailed                = "sign_failed"
	ErrorCodeTimeout                   = "timeout"
	ErrorCodeAttestationApiUnreachable = "attestation_api_unreachable"
	ErrorCodeChannelError              = "channel_error"
	ErrorCodeInternal                  = "internal"
	ErrorCodeAttestationUnavailable    = "attestation_unavailable"
	ErrorCodeBindingUnavailable        = "binding_unavailable"
	// ErrorCodeTooManyRequests: the caller holds as many sessions as one
	// client may. Retrying once the sessions it holds expire succeeds.
	ErrorCodeTooManyRequests = "too_many_requests"
	// ErrorCodeExternalTLS: attest-lb was requested on a front door whose
	// serving credential was generated outside the TEE (an operator-supplied
	// WebPKI Secret), so there is no TEE-held serving key to bind; that
	// deployment shape is attest-pq-only.
	ErrorCodeExternalTLS = "external_tls"
	// ErrorCodeSecretHolderQuota: the caller is at --secrets-max-paths-per-workload.
	ErrorCodeSecretHolderQuota = "secret_holder_quota"
	// ErrorCodeSecretStoreFull: the store is at --secrets-max-paths.
	ErrorCodeSecretStoreFull = "secret_store_full"
)

// ErrorResponse is the body a C8s service returns with a non-2xx status: one
// of the codes above plus a human-readable message.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
