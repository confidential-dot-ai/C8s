package getkubeconfig

import (
	"context"
	"fmt"
	"net"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// vmiGVR is KubeVirt's VirtualMachineInstance resource. The dynamic client
// keeps the KubeVirt API types out of the module graph.
var vmiGVR = schema.GroupVersionResource{
	Group:    "kubevirt.io",
	Version:  "v1",
	Resource: "virtualmachineinstances",
}

// resolveVMIAddress is a seam for tests.
var resolveVMIAddress = resolveVMI

// newVMIClient builds a dynamic client from the current kubeconfig context
// and reports that context's namespace. A seam for tests.
var newVMIClient = func() (dynamic.Interface, string, error) {
	kubeCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})
	namespace, _, err := kubeCfg.Namespace()
	if err != nil {
		return nil, "", fmt.Errorf("namespace from kubeconfig: %w", err)
	}
	restCfg, err := kubeCfg.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("load kubeconfig: %w", err)
	}
	client, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, "", fmt.Errorf("build kubernetes client: %w", err)
	}
	return client, namespace, nil
}

// resolveVMI returns the first reported interface address of the KubeVirt
// guest "name" or "namespace/name", looked up through the current kubeconfig
// context, which also supplies the namespace when the ref carries none. The
// guest's name is neither a DNS host nor an IP on the operator's machine, and
// resolving at call time means a restarted VMI cannot leave a stale entry
// behind.
func resolveVMI(ctx context.Context, ref string) (string, error) {
	namespace, name, hasNamespace := strings.Cut(ref, "/")
	if !hasNamespace {
		namespace, name = "", ref
	}
	if name == "" || (hasNamespace && namespace == "") {
		return "", fmt.Errorf("ref %q is not name or namespace/name", ref)
	}

	client, contextNamespace, err := newVMIClient()
	if err != nil {
		return "", err
	}
	if namespace == "" {
		namespace = contextNamespace
	}
	vmi, err := client.Resource(vmiGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get virtualmachineinstance %s/%s: %w", namespace, name, err)
	}
	return vmiAddress(vmi)
}

// vmiAddress returns the guest's first non-empty status interface address. A
// booting VMI reports no status.interfaces, an empty list, or entries without
// an ipAddress yet; all of those are "no reported address", not lookup errors.
// The address is cluster-reported data that ends up in the kubeconfig, so
// anything but an IP is refused.
func vmiAddress(vmi *unstructured.Unstructured) (string, error) {
	ifaces, _, err := unstructured.NestedSlice(vmi.Object, "status", "interfaces")
	if err != nil {
		return "", fmt.Errorf("read status.interfaces of %s/%s: %w", vmi.GetNamespace(), vmi.GetName(), err)
	}
	for _, entry := range ifaces {
		iface, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		ip, _ := iface["ipAddress"].(string)
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			if len(ip) > 64 {
				ip = ip[:64]
			}
			return "", fmt.Errorf("guest %s/%s reports address %q, which is not an IP", vmi.GetNamespace(), vmi.GetName(), ip)
		}
		return ip, nil
	}
	return "", fmt.Errorf("guest %s/%s has no reported address", vmi.GetNamespace(), vmi.GetName())
}
