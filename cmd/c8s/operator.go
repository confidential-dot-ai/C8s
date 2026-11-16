//go:build !c8s_node

package main

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/controller"
)

var operatorCmd = &cobra.Command{
	Use:   "operator",
	Short: "Run the c8s controller-manager and admission webhook",
	Long: `Runs the controller-runtime manager that mirrors per-pod attestation
state into ConfidentialWorkload status. Also hosts the admission webhooks that
inject the C8s platform containers into a pod and reject a pod whose final
shape is not the injected one.

Every pod the webhooks are called for is injected: its own mesh endpoint
carries its traffic, and the namespaces outside that are the webhook
configurations' own.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return controller.Run(cmd.Context(), controller.Options{
			MetricsAddr:              metricsAddr,
			HealthAddr:               healthAddr,
			LeaderElection:           leaderElection,
			LeaderElectionID:         "c8s-operator.confidential.ai",
			LeaderElectionNS:         leaderElectionNS,
			DisableStatusMirror:      !statusMirrorEnabled,
			GetCertImage:             getCertImage,
			MeshImage:                meshImage,
			AttestationApiURL:        attestationApiURL,
			ExcludeNamespaces:        excludeNamespaces,
			ConfidentialNodeSelector: confidentialNodeLabels,
			WebhookConfigName:        webhookConfigName,
			WebhookServiceName:       webhookServiceName,
			WebhookServiceNamespace:  webhookServiceNamespace,
			WebhookHost:              webhookHost,
			Kubeconfig:               kubeconfig,
			CertFSGroup:              certFSGroup,
			CertRenewInterval:        certRenewInterval,
			WorkloadClaimsHostDir:    workloadClaimsHostDir,
			PodCVMProviderConfig:     podCVMProviderConfig,
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
	meshImage               string
	attestationApiURL       string
	webhookConfigName       string
	webhookServiceName      string
	webhookServiceNamespace string
	webhookHost             string
	kubeconfig              string
	excludeNamespaces       []string
	confidentialNodeLabels  map[string]string
	certFSGroup             int64
	certRenewInterval       time.Duration

	workloadClaimsHostDir string
	podCVMProviderConfig  string
)

func init() {
	operatorCmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address for Prometheus metrics")
	operatorCmd.Flags().StringVar(&healthAddr, "health-probe-bind-address", ":8081", "address for health/readyz probes")
	operatorCmd.Flags().BoolVar(&leaderElection, "leader-elect", true, "enable leader election for HA")
	operatorCmd.Flags().StringVar(&leaderElectionNS, "leader-election-namespace", "c8s-system", "namespace holding the leader-election Lease")
	operatorCmd.Flags().BoolVar(&statusMirrorEnabled, "status-mirror-enabled", true, "enable CRD-backed ConfidentialWorkload status mirror controller")
	operatorCmd.Flags().StringVar(&getCertImage, "get-cert-image", "", "image reference the admission webhook injects for get-cert containers (empty = webhook disabled)")
	operatorCmd.Flags().StringVar(&meshImage, "mesh-image", "", "armtls-mesh image the webhook injects as the pod mesh endpoint; required with --get-cert-image, which it is one shape with")
	operatorCmd.Flags().StringVar(&attestationApiURL, "attestation-api-url", "", "attestation-api endpoint the injected sidecars attest through (empty = attestation-api.sock in --workload-claims-host-dir)")
	operatorCmd.Flags().StringSliceVar(&excludeNamespaces, "exclude-namespaces", nil, "additional namespaces the startup reinject sweep and workload-service reconciler skip")
	operatorCmd.Flags().StringToStringVar(&confidentialNodeLabels, "confidential-node-selector", nil, "label=value a confidential node of this platform carries, repeated per label (mirrors confidentialNodeSelector); the webhook selects them on every injected pod (empty = the pod's own placement)")
	operatorCmd.Flags().StringVar(&webhookConfigName, "webhook-config-name", "c8s-pod-injector", "MutatingWebhookConfiguration to patch caBundle; the pod validator's configuration is named beside it (empty = skip; default is the name c8s worker control-plane render emits)")
	operatorCmd.Flags().StringVar(&webhookServiceName, "webhook-service-name", "", "Service the API server reaches the webhook through; the serving certificate names it. With --get-cert-image and --webhook-config-name set, this or --webhook-host is required, not both")
	operatorCmd.Flags().StringVar(&webhookServiceNamespace, "webhook-service-namespace", "", "webhook Service namespace (defaults to --leader-election-namespace)")
	operatorCmd.Flags().StringVar(&webhookHost, "webhook-host", "", "host the API server reaches the webhook at from outside the cluster; requires --get-cert-image and --mesh-image; the serving certificate names it and the webhook binds it, in place of the Service")
	operatorCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "the cluster's kubeconfig file (empty = the in-cluster service account)")
	operatorCmd.Flags().Int64Var(&certFSGroup, "cert-fs-group", 65532, "fsGroup applied to an injected pod that sets no fsGroup; must be 0 or more with --mesh-image")
	operatorCmd.Flags().DurationVar(&certRenewInterval, "get-cert-renew-interval", 2*time.Hour, "renewal interval for injected workload certificates")
	operatorCmd.Flags().StringVar(&workloadClaimsHostDir, "workload-claims-host-dir", "/run/nri-image-policy", "host directory holding the nri-image-policy inventory socket (node-CVM), required for injected c8s-cert; NRI mounts it so get-cert redeems a sandbox token there (docs/armtls.md); default is the worker image's fixed directory")
	operatorCmd.Flags().StringVar(&podCVMProviderConfig, "pod-cvm-provider-config", "", "trusted JSON configuration for the Pod CVM virtual-node provider (empty = disabled)")
	rootCmd.AddCommand(operatorCmd)
}
