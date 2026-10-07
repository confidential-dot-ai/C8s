package getkubeconfig

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
)

// NewCmd builds the `get-kubeconfig` subcommand: the operator-side client that
// obtains an admin kubeconfig from a measured TDX or SNP CVM by attesting the
// node, confirming it was launched to trust the operator's key (RTMR[3]), and
// exchanging a CSR for a signed client cert over the cred-release endpoint.
func NewCmd() *cobra.Command {
	var (
		cfg  Config
		node string
		vmi  string
	)
	cmd := &cobra.Command{
		Use:   "get-kubeconfig",
		Short: "Attest a c8s CVM and obtain an operator or log-reader kubeconfig via the measured image + operator-key gate",
		Long: "get-kubeconfig attests a measured c8s CVM and enforces its full\n" +
			"measured identity. The build-artifact manifest selects the platform:\n" +
			"on TDX the image tuple (MRTD, RTMR[1], RTMR[2]) plus the RTMR[3] chain\n" +
			"seeded by the operator's key and extended by the expected workload\n" +
			"images; on SEV-SNP the pinned per-SMP launch digest plus the\n" +
			"operator-key HOSTDATA binding. It then exchanges a CSR for a\n" +
			"short-lived kube client cert over the cred-release endpoint and writes\n" +
			"a kubeconfig. Fresh attestation uses the authenticated armTLS release\n" +
			"endpoint; the guest raw attester can remain on loopback. Verification\n" +
			"runs in-process (attestation-go).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.OperatorKeyPath == "" || cfg.ImageManifestPath == "" || cfg.OutPath == "" {
				return fmt.Errorf("--operator-key, --image-manifest and --out are required")
			}
			// Validate locally so a typo fails before the attest round-trip;
			// the server rejects unknown roles the same way.
			if _, err := credrelease.ParseRole(cfg.Role); err != nil {
				return fmt.Errorf("--role: %w", err)
			}
			// --vmi resolves a KubeVirt guest to the address --node would have
			// been given; --node <host> fills the release and apiserver URLs
			// with standard ports. Explicit URLs override these defaults.
			// --attest-url selects a separate legacy attestation endpoint.
			if vmi != "" {
				ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
				defer cancel()
				addr, err := resolveVMIAddress(ctx, vmi)
				if err != nil {
					return fmt.Errorf("resolve --vmi %q: %w", vmi, err)
				}
				node = addr
			}
			if node != "" {
				if cfg.ReleaseBaseURL == "" {
					cfg.ReleaseBaseURL = fmt.Sprintf("https://%s:8443", node)
				}
				if cfg.APIServerURL == "" {
					cfg.APIServerURL = fmt.Sprintf("https://%s:6443", node)
				}
			}
			if cfg.ReleaseBaseURL == "" || cfg.APIServerURL == "" {
				return fmt.Errorf("set --node or --vmi, or both --release-url and --apiserver-url")
			}
			return Run(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&node, "node", "", "guest host/IP; fills --release-url/--apiserver-url with standard ports (8443/6443)")
	f.StringVar(&vmi, "vmi", "", "guest as KubeVirt VMI [namespace/]name; resolves its address through the current kubeconfig and uses it as --node (namespace defaults to the kubeconfig context's)")
	f.StringVar(&cfg.AttestURL, "attest-url", "", "optional legacy attestation-api /attest URL; default: operator-authenticated attestation over --release-url")
	f.StringVar(&cfg.ReleaseBaseURL, "release-url", "", "cred-release HTTPS base URL (overrides --node)")
	f.StringVar(&cfg.APIServerURL, "apiserver-url", "", "apiserver URL for the kubeconfig (overrides --node)")
	f.StringVar(&cfg.OperatorKeyPath, "operator-key", "", "operator ECDSA private key PEM (its public half is bound into RTMR[3]) (required)")
	f.StringVar(&cfg.ImageManifestPath, "image-manifest", "", "an explicitly selected, provenanced build-artifact manifest carrying the expected guest image's measured identity — TDX: mrtd/rtmr1/rtmr2; SNP: snp_variants. Its shape selects the platform, and the gate pins every value (required)")
	f.StringArrayVar(&cfg.WorkloadImages, "workload-image", nil, "digest-pinned image ref (\"sha256:<hex>\" or \"name@sha256:<hex>\"; tags rejected) the node's measurer is expected to have extended into RTMR[3]; repeatable, in first-extend order. Omit if the node runs no measured workloads. TDX only — SNP has no runtime-extend register")
	f.StringVar(&cfg.Role, "role", credrelease.RoleOperator, "identity the released cert carries: operator (tenant workloads cluster-wide, bounded so it cannot reach the node's guards) or log-reader (pods and their logs only; hand the file on to someone who should not hold the operator role)")
	f.StringVar(&cfg.ContextName, "context", "c8s", "kubeconfig cluster/context/user name")
	f.StringVar(&cfg.TLSServerName, "tls-server-name", "c8s-cvm", "kubeconfig tls-server-name — pins apiserver cert verification to this SAN (the image bakes it into tls-san) instead of the dialed IP. Empty to omit")
	f.StringVar(&cfg.OutPath, "out", "", "output kubeconfig path (required)")
	f.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "per-step network timeout")
	f.DurationVar(&cfg.ReleaseWait, "release-wait", 2*time.Minute, "how long to retry refused connections to cred-release during attestation and credential release; 0 fails on the first refused dial")
	cmd.MarkFlagsMutuallyExclusive("node", "vmi")
	return cmd
}
