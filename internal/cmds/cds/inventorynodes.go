package cds

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// buildInventoryHosts resolves the sandbox-digests dial bound: the operator's
// explicit CIDRs when given, else one host route per node derived live from
// the cluster's node objects.
func buildInventoryHosts(ctx context.Context, cidrs []string, kubeconfig string) (workloadclaims.InventoryHosts, error) {
	if len(cidrs) > 0 {
		return workloadclaims.ParseInventoryHosts(cidrs)
	}
	return watchNodeInventoryHosts(ctx, kubeconfig)
}

// nodeCacheSyncTimeout bounds the startup wait for the first node list; a
// package var so tests can shorten it.
var nodeCacheSyncTimeout = 90 * time.Second

// newInClusterKubeClientset is a package var so tests can substitute a fake clientset.
var newInClusterKubeClientset = func() (kubernetes.Interface, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("k8s in-cluster config: %w", err)
	}
	return kubernetes.NewForConfig(restCfg)
}

// newKubeClientsetFromFile uses only the explicitly selected kubeconfig.
func newKubeClientsetFromFile(kubeconfig string) (kubernetes.Interface, error) {
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load node inventory kubeconfig: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("create node inventory client: %w", err)
	}
	return clientset, nil
}

// watchNodeInventoryHosts keeps the dial bound current with the node list: a
// node added after CDS starts becomes dialable without a restart, and a
// removed node stops being dialable. The API server only hints at addresses —
// what answers must still pass mutually-attested ARmTLS on a privileged port
// (docs/armtls.md). Without in-cluster config (local dev) the bound stays
// empty and every sandbox token is refused, matching the previous posture.
func watchNodeInventoryHosts(ctx context.Context, kubeconfig string) (workloadclaims.InventoryHosts, error) {
	hosts := &workloadclaims.NodeHosts{}
	var clientset kubernetes.Interface
	var err error
	if kubeconfig != "" {
		clientset, err = newKubeClientsetFromFile(kubeconfig)
		if err != nil {
			return nil, err
		}
	} else {
		clientset, err = newInClusterKubeClientset()
	}
	if err != nil {
		slog.Warn("--sandbox-inventory-cidr not set and no in-cluster config: CDS will refuse any request carrying a sandbox token", "error", err)
		return hosts, nil
	}

	factory := informers.NewSharedInformerFactory(clientset, 0)
	nodes := factory.Core().V1().Nodes()
	informer := nodes.Informer()
	lister := nodes.Lister()

	// Recompute the whole bound from the store on any event; node objects are
	// few and the derivation is trivial, so there is nothing incremental to
	// get wrong. Exclusions are logged on first sight only — node heartbeats
	// fire UpdateFunc constantly, and on a misconfigured cluster an undeduped
	// warning every few seconds is noise, not signal.
	var mu sync.Mutex
	reported := map[string]bool{}
	resync := func() {
		nodeList, err := lister.List(labels.Everything())
		if err != nil {
			slog.Error("node inventory sync", "error", err)
			return
		}
		excluded := hosts.SetNodes(nodeList)
		mu.Lock()
		for _, e := range excluded {
			if !reported[e] {
				reported[e] = true
				slog.Warn("node address inside the pod range excluded from the sandbox-digests bound: node and pod addresses are not separable there", "node", e)
			}
		}
		mu.Unlock()
	}
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { resync() },
		UpdateFunc: func(_, _ any) { resync() },
		DeleteFunc: func(any) { resync() },
	}); err != nil {
		return nil, fmt.Errorf("node informer: add event handler: %w", err)
	}

	syncCtx, cancel := context.WithTimeout(ctx, nodeCacheSyncTimeout)
	defer cancel()
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(syncCtx.Done(), informer.HasSynced) {
		return nil, fmt.Errorf("node list did not sync within %s: CDS bounds the sandbox-digests callback with it unless --sandbox-inventory-cidr is set, and needs get/list/watch on nodes to read it", nodeCacheSyncTimeout)
	}
	resync()
	slog.Info("sandbox-digests callback bound to the live node list (--sandbox-inventory-cidr unset)")
	return hosts, nil
}
