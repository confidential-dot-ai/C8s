package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
)

// Sentences about the per-pod mesh: the endpoint the webhook puts in every
// member pod, and the name resolution a member pod keeps. Traffic between
// pods uses the hello and datagram sentences of mesh.go; a pod in an exempt
// namespace is not a member, so its plaintext is what a member's endpoint
// refuses.
func registerPodMesh(sc *godog.ScenarioContext) {
	sc.Step(`^"([^"]*)" carries a mesh endpoint ahead of its other containers$`, carriesMeshEndpoint)
	sc.Step(`^"([^"]*)" resolves the name of the cluster's API Service$`, resolvesAPIService)
	sc.Step(`^the answer holds the address of the cluster's API Service$`, answerHoldsAPIService)
}

// meshEndpointContainer is the name the webhook gives the endpoint.
const meshEndpointContainer = "c8s-mesh"

// carriesMeshEndpoint: the pod's first init container is the endpoint, a
// native sidecar, so it starts before get-cert and every workload container
// and runs through the workload's life.
func carriesMeshEndpoint(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if !p.deployed {
		return fmt.Errorf("%q has not been deployed", name)
	}
	out, err := kubectl(nil, "-n", p.namespace, "get", "pod", p.name, "-o", "jsonpath={.spec.initContainers}")
	if err != nil {
		return err
	}
	var inits []struct {
		Name          string `json:"name"`
		RestartPolicy string `json:"restartPolicy"`
	}
	if strings.TrimSpace(out) != "" {
		if err := json.Unmarshal([]byte(out), &inits); err != nil {
			return fmt.Errorf("the init containers of %q: %w", name, err)
		}
	}
	if len(inits) == 0 || inits[0].Name != meshEndpointContainer {
		names := make([]string, len(inits))
		for i, c := range inits {
			names[i] = c.Name
		}
		return fmt.Errorf("the first init container of %q is not the mesh endpoint: %v", name, names)
	}
	if inits[0].RestartPolicy != "Always" {
		return fmt.Errorf("the mesh endpoint of %q is not a native sidecar (restartPolicy %q)", name, inits[0].RestartPolicy)
	}
	return nil
}

func resolvesAPIService(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	host, err := w.be.call("api_service_name")
	if err != nil {
		return err
	}
	w.mesh.answer, err = w.exec(p, "nslookup "+host+" 2>&1")
	return err
}

func answerHoldsAPIService(ctx context.Context) error {
	w := getWorld(ctx)
	a, err := w.lastAnswer()
	if err != nil {
		return err
	}
	addr, err := kubectl(nil, "-n", "default", "get", "svc", "kubernetes", "-o", "jsonpath={.spec.clusterIP}")
	if err != nil {
		return err
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return fmt.Errorf("harness: the cluster's API Service has no ClusterIP")
	}
	if a.rc != 0 || !strings.Contains(a.out, addr) {
		return fmt.Errorf("the answer does not hold %s (exit %d):\n%s", addr, a.rc, a.out)
	}
	return nil
}
