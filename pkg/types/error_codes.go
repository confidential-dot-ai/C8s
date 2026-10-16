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
	// ErrorCodeTunnelBusy: every tunnel slot on the router is in use, or this
	// client address holds its share of them (503). Retry after one of the
	// client's requests completes.
	ErrorCodeTunnelBusy = "tunnel_busy"
	// ErrorCodeExternalTLS: attest-lb was requested on a front door whose
	// serving credential was generated outside the TEE (an operator-supplied
	// WebPKI Secret), so there is no TEE-held serving key to bind; that
	// deployment shape is attest-pq-only.
	ErrorCodeExternalTLS = "external_tls"
	// ErrorCodeSecretHolderQuota: the caller is at --secrets-max-paths-per-workload.
	ErrorCodeSecretHolderQuota = "secret_holder_quota"
	// ErrorCodeSecretStoreFull: the store is at --secrets-max-paths.
	ErrorCodeSecretStoreFull = "secret_store_full"
	// ErrorCodeRoutesUnavailable: no route manifest is applied yet, so the
	// automated ingress service refuses attested sessions (route policy A2).
	// A retry succeeds after the operator writes a manifest and the router
	// fetches it.
	ErrorCodeRoutesUnavailable = "routes_unavailable"
	// ErrorCodeRoutesStale: the applied route manifest is stale, so the
	// automated ingress service refuses new attested sessions (route policy
	// F2).
	ErrorCodeRoutesStale = "routes_stale"
)

// ErrorResponse is the body a C8s service returns with a non-2xx status: one
// of the codes above plus a human-readable message.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
