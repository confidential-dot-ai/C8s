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
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
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
	cfg := builtInConfig()
	cmd := &cobra.Command{
		Use:   "cds",
		Short: "Run the Certificate Distribution Service (CDS)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMeasuredConfig(cmd.Context(), cfg)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&cfg.configPath, "config", "", "path to the CDS configuration document (c8s-cds/v1) this VM was launched with (REQUIRED). CDS serves the cluster it describes only if a verified self-report binds the file byte for byte")
	flags.StringVar(&cfg.host, "host", "0.0.0.0", "listen address; auto selects this VM's primary IPv4 address")
	flags.IntVarP(&cfg.port, "port", "p", 8443, "listen port")
	flags.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")

	flags.StringVar(&cfg.attestationApiURL, "attestation-api-url", "", "URL of this VM's own attestation-api (REQUIRED); it must name a loopback address")

	flags.Int64Var(&cfg.jwtClockSkew, "jwt-clock-skew", 30, "operator JWT clock skew tolerance in seconds; without --allowlist-persistent, CDS also refuses operator-token requests (allowlist, routes, secrets) for this long after it starts")
	flags.DurationVar(&cfg.routerCertTTL, "router-cert-ttl", 20*time.Second, "TTL of a leaf issued to a router sandbox; must be shorter than --allowlist-node-delay, so every router advertises an allowlist write before it takes effect")
	flags.DurationVar(&cfg.allowlistNodeDelay, "allowlist-node-delay", 30*time.Second, "how long after it is written an allowlist write takes effect on nodes; a write replaced before then never does")
	flags.Int64Var(&cfg.maxRequestSize, "max-request-size", 65536, "max request body bytes on /attest, /authenticate and the workload secret routes")

	flags.BoolVar(&cfg.sanValidation, "san-validation", true, "require CSR IP SANs to equal the request source IP (false rejects CSRs carrying IP SANs)")
	flags.StringVar(&cfg.allowlistDB, "allowlist-db", "", "Path to the allowlist SQLite database")
	flags.BoolVar(&cfg.allowlistPersistent, "allowlist-persistent", false, "whether --allowlist-db is on durable storage; false makes CDS warn at startup that operator-added digests, the allowlist history, spent operator tokens, the route manifest and the mesh CA do not survive a restart")

	cmdsutil.RequireFlags(cmd, "config", "attestation-api-url", "allowlist-db")

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

// builtInConfig holds the server settings no launch chooses; NewCmd's flags
// set the rest.
func builtInConfig() config {
	return config{
		caCommonName:             issuer.DefaultCACommonName,
		caCertValidity:           issuer.DefaultCAValidity,
		namedCertTTL:             issuer.MaxNamedLeafTTL,
		challengeTTL:             60 * time.Second,
		requestTimeout:           5 * time.Second,
		readTimeout:              defaultHTTPReadTimeout,
		readHeaderTimeout:        defaultHTTPReadHeaderTimeout,
		writeTimeout:             defaultHTTPWriteTimeout,
		idleTimeout:              defaultHTTPIdleTimeout,
		maxHeaderBytes:           defaultHTTPMaxHeaderBytes,
		allowedCNPattern:         "",
		readinessInterval:        10 * time.Second,
		minCAValidity:            time.Hour,
		armtlsCertTTL:            24 * time.Hour,
		rateLimit:                10,
		rateBurst:                20,
		rateLimiterMax:           10000,
		rateLimiterEvictInterval: time.Minute,
		rateLimiterIdleTimeout:   5 * time.Minute,

		// INVARIANT: unchanged across releases; every replica of a cluster holds the same.
		certTTL:                    24 * time.Hour,
		secretsMaxPaths:            1024,
		secretsMaxPathsPerWorkload: secrets.DefaultMaxPathsPerHolder,
		secretsMaxValueBytes:       4096,
		sandboxLedgerMax:           10000,
	}
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
	routerCertTTL       time.Duration
	allowlistNodeDelay  time.Duration
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

	// measured is the configuration document this VM was launched with, and
	// measuredFile the bytes its launch bound and a cluster's decrees pin.
	measured     *cdsconfig.Config
	measuredFile []byte
}
