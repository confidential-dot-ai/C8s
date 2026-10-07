//go:build !c8s_node

package main

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/controller"
)

var operatorCmd = &cobra.Command{
	Use:   "operator",
	Short: "Run the c8s controller-manager and admission webhook",
	Long: `Runs the controller-runtime manager that mirrors per-pod attestation
state into ConfidentialWorkload status. Also hosts the mutating admission
webhook that injects get-cert bootstrap and renewal containers into pods opted
in via annotation.

Pod-to-pod mTLS is handled by the node-level armtls-mesh DaemonSet, not
by this command.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		policyJSON, err := operatorMeasurementsPolicy(cdsMeasurementsConfig, cdsMeasurements, cdsRTMRs)
		if err != nil {
			return err
		}
		return controller.Run(cmd.Context(), controller.Options{
			MetricsAddr:               metricsAddr,
			HealthAddr:                healthAddr,
			LeaderElection:            leaderElection,
			LeaderElectionID:          "c8s-operator.confidential.ai",
			LeaderElectionNS:          leaderElectionNS,
			DisableStatusMirror:       !statusMirrorEnabled,
			GetCertImage:              getCertImage,
			CDSURL:                    cdsURL,
			AttestationApiURL:         attestationApiURL,
			CDSMeasurements:           cdsMeasurements,
			CDSRTMRs:                  cdsRTMRs,
			CDSMeasurementsConfigJSON: policyJSON,
			ExcludeNamespaces:         excludeNamespaces,
			WebhookConfigName:         webhookConfigName,
			WebhookServiceName:        webhookServiceName,
			WebhookServiceNamespace:   webhookServiceNamespace,
			CertFSGroup:               certFSGroup,
			CertRenewInterval:         certRenewInterval,
			GetCertRunAsUser:          getCertRunAsUser,
			GetCertRunAsGroup:         getCertRunAsGroup,
			GetCertRunAsNonRoot:       getCertRunAsNonRoot,
			WorkloadClaimsHostDir:     workloadClaimsHostDir,
		})
	},
}

var (
	metricsAddr             string
	healthAddr              string
	leaderElection          bool
	leaderElectionNS        string
	statusMirrorEnabled     bool
	getCertImage            string
	cdsURL                  string
	attestationApiURL       string
	cdsMeasurements         []string
	cdsMeasurementsConfig   string
	cdsRTMRs                []string
	webhookConfigName       string
	webhookServiceName      string
	webhookServiceNamespace string
	excludeNamespaces       []string
	certFSGroup             int64
	certRenewInterval       time.Duration
	getCertRunAsUser        int64
	getCertRunAsGroup       int64
	getCertRunAsNonRoot     bool

	workloadClaimsHostDir string
)

func init() {
	operatorCmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address for Prometheus metrics")
	operatorCmd.Flags().StringVar(&healthAddr, "health-probe-bind-address", ":8081", "address for health/readyz probes")
	operatorCmd.Flags().BoolVar(&leaderElection, "leader-elect", true, "enable leader election for HA")
	operatorCmd.Flags().StringVar(&leaderElectionNS, "leader-election-namespace", "c8s-system", "namespace holding the leader-election Lease")
	operatorCmd.Flags().BoolVar(&statusMirrorEnabled, "status-mirror-enabled", true, "enable CRD-backed ConfidentialWorkload status mirror controller")
	operatorCmd.Flags().StringVar(&getCertImage, "get-cert-image", "", "image reference the admission webhook injects for get-cert containers (empty = webhook disabled)")
	operatorCmd.Flags().StringVar(&cdsURL, "cds-url", "", "CDS Service URL the injected get-cert containers POST to")
	operatorCmd.Flags().StringVar(&attestationApiURL, "attestation-api-url", "", "attestation-api endpoint (empty = no verification)")
	operatorCmd.Flags().StringSliceVar(&cdsMeasurements, "cds-measurements", nil, "SHA-384 hex launch measurement(s) the injected secret fetcher requires CDS to present (repeatable; empty pins none)")
	cmdsutil.BindImagePolicyFlags(operatorCmd.Flags(), &cdsMeasurementsConfig, nil, "", "propagates the complete CDS identity policy to injected sidecars; excludes --cds-measurements and --cds-rtmrs")
	operatorCmd.Flags().StringSliceVar(&cdsRTMRs, "cds-rtmrs", nil, "TDX RTMR pin(s) <index>=<sha384-hex> the injected sidecars additionally hold CDS to (repeatable; ignored for SNP evidence, empty pins no registers)")
	operatorCmd.Flags().StringSliceVar(&excludeNamespaces, "exclude-namespaces", nil, "extra namespaces the startup reinject sweep skips (mirrors webhook.extraExcluded)")
	operatorCmd.Flags().StringVar(&webhookConfigName, "webhook-config-name", "", "MutatingWebhookConfiguration to patch caBundle (empty = skip)")
	operatorCmd.Flags().StringVar(&webhookServiceName, "webhook-service-name", "", "webhook Service name (defaults to c8s)")
	operatorCmd.Flags().StringVar(&webhookServiceNamespace, "webhook-service-namespace", "", "webhook Service namespace (defaults to --leader-election-namespace)")
	operatorCmd.Flags().Int64Var(&certFSGroup, "cert-fs-group", 65532, "fsGroup applied to injected pods when unset (-1 disables mutation)")
	operatorCmd.Flags().DurationVar(&certRenewInterval, "get-cert-renew-interval", 2*time.Hour, "renewal interval for injected workload certificates")
	operatorCmd.Flags().Int64Var(&getCertRunAsUser, "get-cert-run-as-user", 65532, "runAsUser for injected get-cert containers")
	operatorCmd.Flags().Int64Var(&getCertRunAsGroup, "get-cert-run-as-group", 65532, "runAsGroup for injected get-cert containers")
	operatorCmd.Flags().BoolVar(&getCertRunAsNonRoot, "get-cert-run-as-non-root", true, "set runAsNonRoot for injected get-cert containers")
	operatorCmd.Flags().StringVar(&workloadClaimsHostDir, "workload-claims-host-dir", "", "host directory holding the nri-image-policy inventory socket (node-CVM); when set, NRI mounts it into c8s-cert so get-cert redeems a sandbox token there (docs/armtls.md)")
	rootCmd.AddCommand(operatorCmd)
}

// operatorMeasurementsPolicy preserves each image's runtime and operator-key
// bindings instead of flattening independently authorized server identities.
func operatorMeasurementsPolicy(path string, digests, rtmrs []string) (string, error) {
	if path == "" {
		return "", nil
	}
	pins, err := (cmdsutil.ImagePolicySource{File: path}).LoadValues(
		cmdsutil.MeasurementPins{Measurements: digests, Registers: rtmrs, Prefix: "cds-"})
	if err != nil {
		return "", err
	}
	encoded, err := refvalues.Format(pins)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
