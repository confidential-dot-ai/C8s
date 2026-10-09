// Package controller hosts the controller-runtime manager, the slim
// ConfidentialWorkload status-mirror reconciler, and the admission webhook.
package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/confidential-dot-ai/c8s/api/v1alpha2"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Options configures the controller-manager runtime.
type Options struct {
	MetricsAddr      string
	HealthAddr       string
	LeaderElection   bool
	LeaderElectionID string
	LeaderElectionNS string

	// DisableStatusMirror skips the CRD-backed ConfidentialWorkload status
	// mirror controller. Pod injection does not depend on CRDs.
	DisableStatusMirror bool

	// MeshImage is the armtls-mesh image the admission webhook injects as the
	// pod's mesh endpoint. Empty leaves the node DaemonSet as the mesh. See
	// webhook.Config.
	MeshImage string

	// GetCertImage is the c8s multi-mode binary image the admission webhook
	// injects for get-cert bootstrap and renewal. Empty disables pod injection.
	GetCertImage string

	// CDSURL points at the CDS Service in-cluster (the URL the
	// injected get-cert containers POST evidence + CSR to).
	CDSURL string

	// AttestationApiURL points at the attestation-api.
	AttestationApiURL string

	// CDSMeasurements are the launch measurements the injected secret fetcher
	// requires CDS to present. Empty pins none.
	CDSMeasurements []string

	// CDSRTMRs are the TDX RTMR pins (<index>=<sha384-hex>) the injected
	// sidecars additionally hold CDS to. Ignored for SNP evidence.
	CDSRTMRs []string

	// CDSMeasurementsConfigJSON retains the complete identity policy for injected clients.
	CDSMeasurementsConfigJSON string

	// WebhookConfigName is the MutatingWebhookConfiguration to patch. The pod
	// validator's configuration is named beside it (validatorConfigName).
	WebhookConfigName string

	WebhookServiceName      string
	WebhookServiceNamespace string

	CertFSGroup         int64
	CertRenewInterval   time.Duration
	GetCertRunAsUser    int64
	GetCertRunAsGroup   int64
	GetCertRunAsNonRoot bool

	// ExcludeNamespaces are namespaces the startup reinject sweep and the
	// workload-service reconciler skip, on top of the release namespace and
	// the kube-system family. Mirrors webhook.extraExcluded so the sweep,
	// the reconciler, and the webhook config agree.
	ExcludeNamespaces []string

	// WorkloadClaimsHostDir, when set (node-CVM), is the nri-image-policy inventory
	// socket directory: that plugin NRI-mounts it into c8s-cert and the webhook
	// injects the get-cert workload-digest claim (docs/armtls.md). See webhook.Config.
	WorkloadClaimsHostDir string

	// MeshOutboundPort enables the MeshEgressReconciler when non-zero and is
	// its Port; MeshExcludeSourceNamespaces is its Excluded set.
	MeshOutboundPort            int32
	MeshExcludeSourceNamespaces []string
}

var scheme = runtime.NewScheme()

// newDirectClient builds a cache-bypassing client from the manager's REST
// config + scheme (the manager cache is either not started yet, or must not
// grow informers for one-shot work). A package var so tests can substitute a
// fake client.
var newDirectClient = func(mgr manager.Manager) (client.Client, error) {
	return client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
}

// webhookCertDir is where the webhook serving certs are written —
// controller-runtime's default in production, overridable in tests.
var webhookCertDir = webhook.DefaultCertDir

// Production wiring hoisted to vars so Run's error paths are testable.
var (
	getKubeConfig      = ctrl.GetConfigOrDie
	newManager         = ctrl.NewManager
	newDiscoveryClient = discovery.NewDiscoveryClientForConfig
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
}

// Run boots the manager and blocks until ctx is cancelled or the manager exits.
func Run(ctx context.Context, opts Options) error {
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	logger := ctrl.Log.WithName("c8s-operator")

	config := getKubeConfig()
	mgr, err := newManager(config, managerOptions(opts))
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// The discovery client is only needed (and only fails Run) when the
	// status-mirror controller is enabled.
	var dc serverResourcesForGroupVersion
	if !opts.DisableStatusMirror {
		d, err := newDiscoveryClient(config)
		if err != nil {
			return fmt.Errorf("create discovery client: %w", err)
		}
		dc = d
	}

	if err := setupManager(ctx, mgr, dc, opts, logger); err != nil {
		return err
	}

	logger.Info("starting manager",
		"metrics", opts.MetricsAddr,
		"health", opts.HealthAddr,
		"leaderElection", opts.LeaderElection)

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("manager exited: %w", err)
	}
	return nil
}

// managerOptions is the single source of the manager configuration Run uses;
// factored out so tests can build a manager with the same cache/label scoping.
func managerOptions(opts Options) ctrl.Options {
	return ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: opts.MetricsAddr},
		HealthProbeBindAddress:  opts.HealthAddr,
		LeaderElection:          opts.LeaderElection,
		LeaderElectionID:        opts.LeaderElectionID,
		LeaderElectionNamespace: opts.LeaderElectionNS,
		Cache: cache.Options{
			// managedFields routinely dominate cached object size and nothing
			// here reads them.
			DefaultTransform: cache.TransformStripManagedFields(),
			// The workload-service reconciler only lists and owns Services it
			// labeled itself; don't cache every Service in the cluster. A
			// foreign Service is invisible through this cache — CreateOrUpdate
			// then tries Create and the reconciler maps AlreadyExists to its
			// not-adopting skip. NetworkPolicies are deliberately not scoped
			// the same way: the mesh-egress reconciler's sources are user
			// objects, so it has to see every policy.
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Service{}: {
					Label: labels.SelectorFromSet(labels.Set{managedByLabel: managedByValue}),
				},
			},
		},
	}
}

// setupManager wires all controllers, the webhook, and the startup runnables
// onto mgr. dc may be nil when opts.DisableStatusMirror is set.
func setupManager(ctx context.Context, mgr manager.Manager, dc serverResourcesForGroupVersion, opts Options, logger logr.Logger) error {
	if opts.DisableStatusMirror {
		logger.Info("status-mirror controller disabled by configuration")
	} else {
		available, err := confidentialWorkloadCRDAvailable(dc)
		if err != nil {
			return fmt.Errorf("discover ConfidentialWorkload CRD: %w", err)
		}
		if available {
			if err := (&ConfidentialWorkloadReconciler{
				Client: mgr.GetClient(),
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("setup ConfidentialWorkload reconciler: %w", err)
			}
			logger.Info("status-mirror controller enabled")
		} else {
			logger.Info("status-mirror controller disabled; ConfidentialWorkload CRD not found")
		}
	}

	excluded := excludedNamespaceSet(opts.LeaderElectionNS, opts.ExcludeNamespaces)

	// Headless-Service provisioning: one Service per annotated workload so
	// in-cluster clients (router) can dial pod IPs by DNS and get the
	// node mesh's attested mTLS — the mesh cannot intercept Service VIPs.
	// Gated on get-cert injection: without it no pod carries the cw label
	// the Service selects on.
	if opts.GetCertImage != "" {
		for _, kind := range workloadServiceKinds {
			if err := (&WorkloadServiceReconciler{
				Client:   mgr.GetClient(),
				Scheme:   mgr.GetScheme(),
				Recorder: mgr.GetEventRecorder("c8s-operator"),
				Kind:     kind,
				Excluded: excluded,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("setup workload-service reconciler (%s): %w", kind, err)
			}
		}
	}

	// Mesh egress companions. Not gated on injection: the mesh intercepts
	// every pod's egress, not only injected pods'.
	if opts.MeshOutboundPort != 0 {
		if err := (&MeshEgressReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorder("c8s-operator"),
			Port:     opts.MeshOutboundPort,
			Excluded: namespaceSet(opts.MeshExcludeSourceNamespaces),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("setup mesh-egress reconciler: %w", err)
		}
	}

	// Admission webhooks — the platform containers a pod gets, and the shape
	// it is admitted with.
	if opts.MeshImage != "" && opts.GetCertImage == "" {
		return fmt.Errorf("--mesh-image needs --get-cert-image: the mesh endpoint is injected with the credential containers it reads from")
	}

	if opts.GetCertImage != "" {
		if err := bootstrapWebhookPKI(ctx, mgr, opts); err != nil {
			return fmt.Errorf("bootstrap webhook PKI: %w", err)
		}
		if err := webhook.Register(mgr, webhook.Config{
			GetCertImage:              opts.GetCertImage,
			MeshImage:                 opts.MeshImage,
			CDSURL:                    opts.CDSURL,
			AttestationApiURL:         opts.AttestationApiURL,
			CDSMeasurements:           opts.CDSMeasurements,
			CDSRTMRs:                  opts.CDSRTMRs,
			CDSMeasurementsConfigJSON: opts.CDSMeasurementsConfigJSON,
			CertFSGroup:               new(opts.CertFSGroup),
			CertRenewInterval:         opts.CertRenewInterval,
			GetCertRunAsUser:          new(opts.GetCertRunAsUser),
			GetCertRunAsGroup:         new(opts.GetCertRunAsGroup),
			GetCertRunAsNonRoot:       new(opts.GetCertRunAsNonRoot),
			WorkloadClaimsHostDir:     opts.WorkloadClaimsHostDir,
		}); err != nil {
			return fmt.Errorf("register webhook: %w", err)
		}
		logger.Info("pod-admission webhooks enabled",
			"image", opts.GetCertImage,
			"mesh_image", opts.MeshImage,
			"cds_url", opts.CDSURL)

		// One-shot startup sweep: delete cw-annotated pods that were admitted
		// while the webhook was down (so never injected) and let their owners
		// recreate them through admission. Runs whenever the webhook does.
		// Leader-only runnable. failurePolicy=Fail means a recreated pod that
		// races a not-yet-ready webhook is retried, not let through. Uses a direct
		// client, not the manager cache: a single cluster-wide List + targeted
		// Deletes at startup must not pin a cluster-wide pod informer for the
		// operator's lifetime.
		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
			return runReinjectSweep(ctx, mgr, excluded)
		})); err != nil {
			return fmt.Errorf("add reinject sweep: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readyz: %w", err)
	}
	return nil
}

// runReinjectSweep is the reinject-sweep runnable body; a named function so
// its client-build failure path is testable without starting the manager.
func runReinjectSweep(ctx context.Context, mgr manager.Manager, excluded map[string]struct{}) error {
	c, err := newDirectClient(mgr)
	if err != nil {
		return fmt.Errorf("build sweep client: %w", err)
	}
	return reinjectSweep(ctx, c, excluded)
}

type serverResourcesForGroupVersion interface {
	ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error)
}

func confidentialWorkloadCRDAvailable(dc serverResourcesForGroupVersion) (bool, error) {
	resources, err := dc.ServerResourcesForGroupVersion(v1alpha2.GroupVersion.String())
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if resources == nil {
		return false, nil
	}
	for _, resource := range resources.APIResources {
		if resource.Name == "confidentialworkloads" && resource.Kind == "ConfidentialWorkload" {
			return true, nil
		}
	}
	return false, nil
}

// bootstrapWebhookPKI mints a fresh CA + serving cert for the admission
// webhook and patches the CA bundle onto the MutatingWebhookConfiguration
// so the API server trusts the webhook.
//
// The CA is ephemeral — re-minted on every operator restart — but long-lived
// (webhook.WebhookCATTL), so the patched bundle stays stable while short-lived
// serving leaves rotate under it. A rotator runnable re-mints the leaf before
// it expires; without it the leaf's ~30-day validity would lapse and, with a
// fail-closed webhook, block all in-scope Pod creation until a restart.
func bootstrapWebhookPKI(ctx context.Context, mgr ctrl.Manager, opts Options) error {
	if opts.WebhookConfigName == "" {
		return nil
	}

	svcName := opts.WebhookServiceName
	svcNS := opts.WebhookServiceNamespace
	if svcNS == "" {
		svcNS = opts.LeaderElectionNS
	}
	if svcName == "" {
		return fmt.Errorf("webhook-service-name is required when webhook-config-name is set")
	}

	hostnames := []string{
		fmt.Sprintf("%s.%s.svc", svcName, svcNS),
		fmt.Sprintf("%s.%s.svc.cluster.local", svcName, svcNS),
	}

	ca, err := issuer.NewCA(fmt.Sprintf("%s webhook", svcName), webhook.WebhookCATTL)
	if err != nil {
		return fmt.Errorf("mint webhook CA: %w", err)
	}
	if err := webhook.BootstrapServingCert(ca, hostnames, webhookCertDir); err != nil {
		return err
	}

	// Manager's cache hasn't started yet, so we can't use mgr.GetClient().
	// A direct client tied to the manager's REST config + scheme is the
	// right primitive here — one Update, no informers needed.
	c, err := newDirectClient(mgr)
	if err != nil {
		return fmt.Errorf("build bootstrap client: %w", err)
	}
	caPEM := certutil.EncodeCertPEM(ca.Cert.Raw)
	if err := webhook.PatchCABundle(ctx, c, opts.WebhookConfigName, caPEM); err != nil {
		return err
	}
	if err := webhook.PatchValidatingCABundle(ctx, c, validatorConfigName(opts.WebhookConfigName), caPEM); err != nil {
		return err
	}

	// Keep the leaf fresh in-process. The CA is stable, so the patched bundle
	// keeps validating rotated leaves without a re-patch.
	rotator := webhookCertRotator(ca, hostnames, webhookCertDir, webhook.ServingTLSTTL,
		mgr.GetLogger().WithName("webhook-cert-rotator"))
	if err := mgr.Add(manager.RunnableFunc(rotator)); err != nil {
		return fmt.Errorf("add webhook cert rotator: %w", err)
	}
	return nil
}

// The chart names the two webhook configurations beside each other, so the
// operator is told one name and derives the other.
const (
	injectorConfigSuffix  = "-pod-injector"
	validatorConfigSuffix = "-pod-validator"
)

func validatorConfigName(injectorName string) string {
	return strings.TrimSuffix(injectorName, injectorConfigSuffix) + validatorConfigSuffix
}

// webhookCertRotator re-issues the webhook serving leaf before it expires.
// It re-mints at ~2/3 of the leaf TTL so a failed attempt has ~1/3 TTL of
// runway (the previous leaf stays valid) to retry on a short interval. The CA
// is unchanged, so no caBundle re-patch is needed.
func webhookCertRotator(ca *issuer.CA, hostnames []string, certDir string, leafTTL time.Duration, logger logr.Logger) manager.RunnableFunc {
	return func(ctx context.Context) error {
		interval := leafTTL * 2 / 3
		retry := time.Hour
		if retry >= interval {
			retry = interval / 2
		}
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-timer.C:
				if err := webhook.BootstrapServingCert(ca, hostnames, certDir); err != nil {
					logger.Error(err, "webhook serving-cert rotation failed; retrying soon", "retry", retry)
					timer.Reset(retry)
					continue
				}
				logger.Info("rotated webhook serving cert", "next", interval)
				timer.Reset(interval)
			}
		}
	}
}
