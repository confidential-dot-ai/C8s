package nodecredential

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// DefaultNodeKeyPath is where the node key lives on a node image.
const DefaultNodeKeyPath = "/var/lib/c8s/node-credential/node-key.pem"

type config struct {
	cdsURL                 string
	cdsMeasurements        string
	cdsRTMRs               string
	measurementsConfig     string
	measurementsConfigJSON string
	attestationApiURL      string
	nodeKeyPath            string
	apiServer              string
	apiCASHA256            string
	measuredPoliciesFile   string
	printNodeName          bool
}

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// NewCmd returns the node-credential subcommand.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "node-credential",
		Short: "Kubelet credential plugin: attest this node to CDS for its join token",
		Long: `node-credential is the exec credential plugin of a hosted cluster node's
bootstrap kubeconfig. The kubelet runs it with provideClusterInfo, and it:

  1. checks that the cluster the kubelet is about to trust is the pinned API
     server hostname on 443 with exactly the pinned CA,
  2. attests the node to CDS over armTLS, holding CDS to its pins, with
     evidence bound to the node key,
  3. prints the ExecCredential with the minutes-long token CDS minted.

The node key is made on first use and kept: the node's name is derived from
it. --print-node-name prints that name, for the kubelet's --hostname-override.
See docs/node-tokens.md.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.printNodeName {
				name, err := NodeName(cfg.nodeKeyPath)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), name)
				return err
			}
			obtain, err := newObtain(cfg)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), requestTimeout)
			defer cancel()
			pins := Pins{APIServer: cfg.apiServer, CASHA256: cfg.apiCASHA256}
			return credential(ctx, os.Getenv(ExecInfoEnv), pins, cfg.nodeKeyPath, cfg.attestationApiURL, obtain, cmd.OutOrStdout())
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	cmdsutil.BindImagePolicyFlags(flags, &cfg.measurementsConfig, &cfg.measurementsConfigJSON, "pins CDS; excludes --cds-measurements and --cds-rtmrs")
	flags.StringVar(&cfg.cdsURL, "cds-url", "", "https URL of the cluster's CDS, reached over armTLS")
	flags.StringVar(&cfg.cdsMeasurements, "cds-measurements", "", "comma-separated SHA-384 hex launch measurements CDS must present (required unless a measurements config pins CDS)")
	flags.StringVar(&cfg.cdsRTMRs, "cds-rtmrs", "", "comma-separated TDX RTMR pins <index>=<sha384-hex> CDS must additionally satisfy")
	flags.StringVar(&cfg.attestationApiURL, "attestation-api-url", "", "URL of the node-local attestation-api (http://127.0.0.1:8400, or unix:// plus its socket path)")
	flags.StringVar(&cfg.nodeKeyPath, "node-key", DefaultNodeKeyPath, "path of the node key, made on first use with mode 0600")
	flags.StringVar(&cfg.apiServer, "api-server", "", "hostname of the cluster's API server, which the token is minted for")
	flags.StringVar(&cfg.apiCASHA256, "api-ca-sha256", "", "SHA-256 hex of the cluster CA certificate the API server must chain to")
	flags.StringVar(&cfg.measuredPoliciesFile, "measured-policies-file", "", "the node's journal of policies extended into TDX RTMR[3], listed with TDX evidence (empty lists none)")
	flags.BoolVar(&cfg.printNodeName, "print-node-name", false, "print the node name derived from the node key, making the key if needed, and exit")
	return cmd
}

// newObtain builds the CDS call from the flags, refusing anything that would
// let the node attest to an unpinned CDS or join an unpinned server.
func newObtain(cfg config) (obtainFunc, error) {
	if cfg.apiServer == "" || cfg.apiCASHA256 == "" {
		return nil, errors.New("--api-server and --api-ca-sha256 are required")
	}
	if !sha256Hex.MatchString(cfg.apiCASHA256) {
		return nil, fmt.Errorf("--api-ca-sha256 %q is not 64 hex characters", cfg.apiCASHA256)
	}
	u, err := url.Parse(cfg.cdsURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("--cds-url %q must be an https URL (armTLS)", cfg.cdsURL)
	}
	if err := cmdsutil.ValidateAttestationAPIURL("--attestation-api-url", cfg.attestationApiURL); err != nil {
		return nil, err
	}
	source := cmdsutil.ImagePolicySource{File: cfg.measurementsConfig, JSON: cfg.measurementsConfigJSON}
	policy, err := source.Load(cmdsutil.MeasurementPinsFromStrings(cfg.cdsMeasurements, cfg.cdsRTMRs, "cds-"))
	if err != nil {
		return nil, err
	}
	// A node hands CDS its evidence and takes back its join credential, so an
	// unpinned CDS is never acceptable here, unlike for a pod's leaf.
	if len(policy.Measurements)+len(policy.Images) == 0 {
		return nil, errors.New("CDS is unpinned: set --cds-measurements or a measurements config")
	}
	httpClient, err := armtls.NewVerifyingHTTPClient(armtls.Pins(policy), cfg.attestationApiURL)
	if err != nil {
		return nil, fmt.Errorf("cds armTLS client: %w", err)
	}
	client := attestclient.NewClientWithHTTP(cfg.cdsURL, httpClient)
	if cfg.measuredPoliciesFile != "" {
		client.MeasuredPolicies = armtls.NewJournal(cfg.measuredPoliciesFile)
	}
	return func(ctx context.Context, attestationApiURL string, nodeKey *ecdsa.PublicKey, audience string) (types.NodeTokenResponse, error) {
		return client.ObtainNodeToken(ctx, attestationApiURL, nodeKey, audience)
	}, nil
}
