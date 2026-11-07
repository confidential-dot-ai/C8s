package routes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	pkgroutes "github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	"github.com/confidential-dot-ai/c8s/pkg/workloadname"
)

// Pod annotations that ask `c8s routes sync` for a route.
const (
	// RouteHostAnnotation names the request host that routes to the pod.
	RouteHostAnnotation = "confidential.ai/route-host"
	// RouteWorkloadAnnotation names the allowlist workload the router
	// requires in the pod's leaf.
	RouteWorkloadAnnotation = "confidential.ai/route-workload"
	// RoutePortAnnotation picks the Service port when the pod's Service
	// has more than one.
	RoutePortAnnotation = "confidential.ai/route-port"
)

// errUnchanged tells edit that the stored manifest already holds the change.
var errUnchanged = errors.New("route manifest unchanged")

// newKubeClient builds a clientset from kubeconfig, or from the default
// loading rules when it is empty. A seam for tests.
var newKubeClient = func(kubeconfig string) (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

func newSyncCmd(o *options) *cobra.Command {
	var (
		kubeconfig, namespace, selector, suffix string
		maxAge, interval                        time.Duration
		revision                                uint64
		dryRun, newManifest                     bool
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Route annotated pods to their Services and store the next revision when that changes",
		Long: `List pods annotated ` + RouteHostAnnotation + `=<host> and
` + RouteWorkloadAnnotation + `=<allowlist workload>, and route each host,
path / by prefix, to the ClusterIP of the pod's Service (the Service of the
pod's name the Pod CVM provider maintains) with --workload set to the
annotated workload. A pod that carries ` + workloadclaims.AnnotationWorkloadID + `=<id>
also pins the route to that assigned workload ID, so the router reaches only
the pod CVM whose leaf CDS stamped with it. ` + RoutePortAnnotation + ` picks the Service port when it
has more than one.

sync owns every host ending in --host-suffix: it replaces their routes with
the listed ones and removes hosts no pod claims. It leaves other hosts as they
are. A pod whose host lies outside the suffix is skipped. When two pods claim
one host, the oldest wins. When the owned hosts already route as listed,
sync writes nothing; otherwise it stores the next revision as 'add' does,
verified against --operator-keys and signed with --operator-key.

--interval repeats the sync until interrupted.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			suffix = strings.ToLower(suffix)
			if !strings.HasPrefix(suffix, ".") || pkgroutes.CheckHost(strings.TrimPrefix(suffix, ".")) != nil {
				return fmt.Errorf("--host-suffix %q: pass a DNS suffix beginning with a dot, such as .agents.example.com", suffix)
			}
			kube, err := newKubeClient(kubeconfig)
			if err != nil {
				return err
			}
			var newMaxAge time.Duration
			if newManifest {
				newMaxAge = maxAge
			}
			once := func() error {
				want, err := desiredRoutes(ctx(cmd), kube, namespace, selector, suffix, cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				return o.edit(cmd, dryRun, newMaxAge, revision, func(m *pkgroutes.Manifest) (string, error) {
					return syncHosts(m, suffix, want)
				})
			}
			if interval <= 0 {
				return once()
			}
			for {
				if err := once(); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "sync: %v\n", err)
				}
				select {
				case <-ctx(cmd).Done():
					return nil
				case <-time.After(interval):
				}
			}
		},
	}
	f := cmd.Flags()
	f.StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig of the cluster; default the standard loading rules")
	f.StringVarP(&namespace, "namespace", "n", "", "namespace to list pods in; default all namespaces")
	f.StringVarP(&selector, "selector", "l", "", "label selector that narrows the listed pods")
	f.StringVar(&suffix, "host-suffix", "", "DNS suffix, beginning with a dot, of the hosts sync owns (required)")
	f.DurationVar(&maxAge, "max-age", 24*time.Hour, "maxAgeSeconds of a manifest --new starts")
	f.BoolVar(&newManifest, "new", false, "start a new manifest when CDS stores none")
	f.DurationVar(&interval, "interval", 0, "repeat the sync at this interval until interrupted")
	bindRevisionFlag(f, &revision)
	f.BoolVar(&dryRun, "dry-run", false, "fetch the stored manifest from CDS and print the new one without storing it")
	_ = cmd.MarkFlagRequired("host-suffix")
	return cmd
}

// desiredRoutes lists the annotated pods and returns one route per host
// under suffix. Pods it cannot route are reported to warn and skipped.
func desiredRoutes(ctx context.Context, kube kubernetes.Interface, namespace, selector, suffix string, warn io.Writer) (map[string]pkgroutes.Route, error) {
	pods, err := kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	items := pods.Items
	// Oldest first, so the oldest claim of a host wins.
	slices.SortFunc(items, func(a, b corev1.Pod) int {
		if c := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); c != 0 {
			return c
		}
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	want := map[string]pkgroutes.Route{}
	for _, pod := range items {
		host := strings.ToLower(pod.Annotations[RouteHostAnnotation])
		if host == "" || !pod.DeletionTimestamp.IsZero() {
			continue
		}
		name := pod.Namespace + "/" + pod.Name
		skip := func(format string, args ...any) {
			fmt.Fprintf(warn, "skipping pod %s: %s\n", name, fmt.Sprintf(format, args...))
		}
		if !strings.HasSuffix(host, suffix) || pkgroutes.CheckHost(host) != nil {
			skip("host %q is not a host under %s", host, suffix)
			continue
		}
		if _, taken := want[host]; taken {
			skip("host %s is already routed to an older pod", host)
			continue
		}
		workload := pod.Annotations[RouteWorkloadAnnotation]
		if workload == "" {
			skip("no %s annotation", RouteWorkloadAnnotation)
			continue
		}
		assigned := pod.Annotations[workloadclaims.AnnotationWorkloadID]
		if assigned != "" && !workloadname.Valid(assigned) {
			skip("%s %q is not a valid workload name", workloadclaims.AnnotationWorkloadID, assigned)
			continue
		}
		svc, err := kube.CoreV1().Services(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			skip("no Service: %v", err)
			continue
		}
		port, err := servicePort(svc, pod.Annotations[RoutePortAnnotation])
		if err != nil {
			skip("%v", err)
			continue
		}
		want[host] = pkgroutes.Route{Path: "/", Match: pkgroutes.MatchPrefix, Backend: pkgroutes.Backend{
			Address: net.JoinHostPort(svc.Spec.ClusterIP, strconv.Itoa(int(port))), Workload: workload,
			AssignedWorkloadID: assigned,
		}}
	}
	return want, nil
}

func servicePort(svc *corev1.Service, annotated string) (int32, error) {
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return 0, errors.New("the pod's Service has no ClusterIP")
	}
	if annotated == "" {
		if len(svc.Spec.Ports) != 1 {
			return 0, fmt.Errorf("the pod's Service has %d ports; pick one with %s", len(svc.Spec.Ports), RoutePortAnnotation)
		}
		return svc.Spec.Ports[0].Port, nil
	}
	for _, p := range svc.Spec.Ports {
		if strconv.Itoa(int(p.Port)) == annotated {
			return p.Port, nil
		}
	}
	return 0, fmt.Errorf("the pod's Service has no port %s", annotated)
}

// syncHosts makes the hosts under suffix route exactly as want, or returns
// errUnchanged when they already do.
func syncHosts(m *pkgroutes.Manifest, suffix string, want map[string]pkgroutes.Route) (string, error) {
	have := map[string]pkgroutes.Host{}
	for host, h := range m.Hosts {
		if strings.HasSuffix(host, suffix) {
			have[host] = h
		}
	}
	wantHosts := map[string]pkgroutes.Host{}
	for host, r := range want {
		wantHosts[host] = pkgroutes.Host{Routes: []pkgroutes.Route{r}}
	}
	if equalHosts(have, wantHosts) {
		return "", errUnchanged
	}
	for host := range have {
		delete(m.Hosts, host)
	}
	maps.Copy(m.Hosts, wantHosts)
	return fmt.Sprintf("synced %d hosts under %s", len(wantHosts), suffix), nil
}

// equalHosts compares routes by the fields a manifest carries; parsed
// backends also hold derived trust anchors.
func equalHosts(a, b map[string]pkgroutes.Host) bool {
	strip := func(in map[string]pkgroutes.Host) map[string][]pkgroutes.Route {
		out := map[string][]pkgroutes.Route{}
		for host, h := range in {
			for _, r := range h.Routes {
				b := r.Backend
				out[host] = append(out[host], pkgroutes.Route{Path: r.Path, Match: r.Match, Backend: pkgroutes.Backend{Address: b.Address, Workload: b.Workload, AssignedWorkloadID: b.AssignedWorkloadID, ServerName: b.ServerName, CA: b.CA}})
			}
		}
		return out
	}
	return reflect.DeepEqual(strip(a), strip(b))
}
