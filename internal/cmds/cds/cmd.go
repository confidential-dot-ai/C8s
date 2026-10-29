// Package cds implements the Certificate Distribution Service subcommand:
// the C8s trust root (attestation, mesh CA, leaf signing).
package cds

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsca"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdslaunch"
	"github.com/confidential-dot-ai/c8s/internal/cmds/verify"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

const (
	defaultHTTPReadTimeout       = 10 * time.Second
	defaultHTTPReadHeaderTimeout = 5 * time.Second
	defaultHTTPWriteTimeout      = 10 * time.Second
	defaultHTTPIdleTimeout       = 20 * time.Second
	defaultHTTPMaxHeaderBytes    = 1 << 20
)

// NewCmd returns the cobra subcommand.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "cds",
		Short: "Run the Certificate Distribution Service (CDS)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMeasuredConfig(cmd.Context(), cfg)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&cfg.configPath, "config", "", "path to the CDS configuration document (c8s-cds/v1) this VM was launched with (REQUIRED). CDS serves the cluster it describes only if a verified self-report binds the file byte for byte")
	flags.StringVar(&cfg.host, "host", "0.0.0.0", "")
	flags.IntVarP(&cfg.port, "port", "p", 8443, "")
	flags.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")

	flags.StringVar(&cfg.attestationApiURL, "attestation-api-url", "", "URL of this VM's own attestation-api (REQUIRED); it must name a loopback address")
	flags.StringVar(&cfg.caCommonName, "ca-common-name", issuer.DefaultCACommonName, "common name for the in-memory generated mesh CA")
	flags.DurationVar(&cfg.caCertValidity, "ca-cert-validity", 8760*time.Hour, "validity period of each in-memory mesh CA certificate; past half of it CDS renews the certificate under the same key")

	flags.Int64Var(&cfg.jwtClockSkew, "jwt-clock-skew", 30, "operator JWT clock skew tolerance in seconds; without --allowlist-persistent, CDS also refuses operator-token requests (allowlist, routes, secrets) for this long after it starts")
	flags.DurationVar(&cfg.certTTL, "cert-ttl", 24*time.Hour, "")
	flags.DurationVar(&cfg.namedCertTTL, "named-cert-ttl", issuer.MaxNamedLeafTTL, "upper bound on the TTL of a leaf carrying a matched-workload stamp — the documented stale-identity bound for a named leaf (never applied to membership-only leaves). Must be positive and may only shorten the built-in ceiling, never raise it")
	flags.DurationVar(&cfg.challengeTTL, "challenge-ttl", 60*time.Second, "")
	flags.DurationVar(&cfg.requestTimeout, "request-timeout", 5*time.Second, "per-request /attest timeout (0 disables)")
	flags.Int64Var(&cfg.maxRequestSize, "max-request-size", 65536, "max request body bytes on /attest, /authenticate and the workload secret routes")
	flags.DurationVar(&cfg.readTimeout, "read-timeout", defaultHTTPReadTimeout, "HTTP server read timeout")
	flags.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", defaultHTTPReadHeaderTimeout, "HTTP server read-header timeout")
	flags.DurationVar(&cfg.writeTimeout, "write-timeout", defaultHTTPWriteTimeout, "HTTP server write timeout")
	flags.DurationVar(&cfg.idleTimeout, "idle-timeout", defaultHTTPIdleTimeout, "HTTP server idle timeout")
	flags.IntVar(&cfg.maxHeaderBytes, "max-header-bytes", defaultHTTPMaxHeaderBytes, "maximum HTTP request header bytes")

	flags.BoolVar(&cfg.sanValidation, "san-validation", true, "require CSR IP SANs to equal the request source IP (false rejects CSRs carrying IP SANs)")
	flags.StringVar(&cfg.allowedCNPattern, "allowed-cn-pattern", "", "regex the CSR Subject CN must match in full (empty disables)")
	flags.DurationVar(&cfg.readinessInterval, "readiness-interval", 10*time.Second, "")
	flags.DurationVar(&cfg.minCAValidity, "min-ca-validity", time.Hour, "/readyz fails when the current mesh CA certificate has less than this remaining lifetime")
	flags.StringVar(&cfg.allowlistDB, "allowlist-db", "", "Path to the allowlist SQLite database")
	flags.BoolVar(&cfg.allowlistPersistent, "allowlist-persistent", false, "whether --allowlist-db is on durable storage; false makes CDS warn at startup that operator-added digests, the allowlist history, spent operator tokens, the route manifest and the mesh CA do not survive a restart")

	flags.Float64Var(&cfg.rateLimit, "rate-limit", 10, "max requests per second per source IP on attestation endpoints")
	flags.IntVar(&cfg.rateBurst, "rate-burst", 20, "max burst size per source IP")
	flags.IntVar(&cfg.rateLimiterMax, "rate-limiter-max-entries", 10000, "max entries in the per-IP rate limiter; once full, a new source evicts the least recently seen one")
	flags.DurationVar(&cfg.rateLimiterEvictInterval, "rate-limiter-evict-interval", time.Minute, "interval for per-IP rate limiter eviction sweep")
	flags.DurationVar(&cfg.rateLimiterIdleTimeout, "rate-limiter-idle-timeout", 5*time.Minute, "idle duration before a per-IP rate limiter entry is evicted")

	flags.IntVar(&cfg.secretsMaxPaths, "secrets-max-paths", 1024, "max distinct secret paths held in memory across every workload")
	flags.IntVar(&cfg.secretsMaxPathsPerWorkload, "secrets-max-paths-per-workload", secrets.DefaultMaxPathsPerHolder, "max secret paths one allowlist entry may hold")
	flags.IntVar(&cfg.secretsMaxValueBytes, "secrets-max-value-bytes", 4096, "max bytes in one secret value")
	flags.IntVar(&cfg.sandboxLedgerMax, "sandbox-ledger-max-entries", 10000, "max sandbox-to-inventory bindings held in memory")

	flags.DurationVar(&cfg.armtlsCertTTL, "armtls-cert-ttl", 24*time.Hour, "")

	for _, name := range []string{
		"config",
		"attestation-api-url",
		"allowlist-db",
	} {
		_ = cmd.MarkFlagRequired(name)
	}

	// `c8s cds verify` — a shorthand for `c8s verify --kind cds`, sharing the
	// same implementation. Running CDS (the server) stays `c8s cds`.
	//
	// Mode is intentionally left at auto: resolveMode derives it from --kind
	// (cds → armtls-cert, lb → discovery), so `c8s cds verify --kind lb` targets
	// the LB's discovery doc. Presetting Mode: "armtls-cert" here would shadow
	// that and make --kind lb dial for the embedded armTLS extension the LB
	// front door never serves.
	cmd.AddCommand(verify.NewCmd(verify.Defaults{
		Use:         "verify [target]",
		Short:       "Verify a CDS endpoint's TEE attestation",
		Kind:        "cds",
		DefaultPort: 8443,
	}))

	cmd.AddCommand(cdsca.NewCmd())
	cmd.AddCommand(cdslaunch.NewCmd())
	cmd.AddCommand(newHACmd())

	return cmd
}

type config struct {
	configPath          string
	host                string
	port                int
	logLevel            string
	attestationApiURL   string
	caCommonName        string
	caCertValidity      time.Duration
	jwtClockSkew        int64
	certTTL             time.Duration
	namedCertTTL        time.Duration
	challengeTTL        time.Duration
	requestTimeout      time.Duration
	maxRequestSize      int64
	readTimeout         time.Duration
	readHeaderTimeout   time.Duration
	writeTimeout        time.Duration
	idleTimeout         time.Duration
	maxHeaderBytes      int
	sanValidation       bool
	allowedCNPattern    string
	readinessInterval   time.Duration
	minCAValidity       time.Duration
	allowlistDB         string
	allowlistPersistent bool
	armtlsPlatform      teetypes.Family
	armtlsCertTTL       time.Duration

	rateLimit                float64
	rateBurst                int
	rateLimiterMax           int
	rateLimiterEvictInterval time.Duration
	rateLimiterIdleTimeout   time.Duration

	secretsMaxPaths            int
	secretsMaxPathsPerWorkload int
	secretsMaxValueBytes       int
	sandboxLedgerMax           int

	// measured is the configuration document this VM was launched with: every
	// per-cluster setting CDS serves.
	measured *cdsconfig.Config
}
