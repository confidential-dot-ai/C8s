package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// Sentences about the per-pod mesh: the endpoint the webhook puts in every
// member pod, the TCP and UDP it carries or drops between pods, and the
// name resolution a member pod keeps. A pod in an exempt namespace is not a
// member, so its plaintext is what a member's endpoint refuses.
func registerPodMesh(sc *godog.ScenarioContext) {
	sc.Step(`^"([^"]*)" serves a hello API$`, servesHello)
	sc.Step(`^"([^"]*)" receives datagrams on (a port of its own|port 53)$`, receivesDatagrams)
	sc.Step(`^"([^"]*)" is in an exempt namespace$`, inExemptNamespace)
	sc.Step(`^"([^"]*)" carries a mesh endpoint ahead of its other containers$`, carriesMeshEndpoint)
	sc.Step(`^"([^"]*)" requests a hello from "([^"]*)"$`, requestsHello)
	sc.Step(`^"([^"]*)" sends a UDP datagram to( port 53 of)? "([^"]*)"$`, sendsDatagram)
	sc.Step(`^"([^"]*)" resolves the name of the cluster's API Service$`, resolvesAPIService)
	sc.Step(`^"([^"]*)" receives (the hello|no hello)$`, receivesHello)
	sc.Step(`^the datagram (reaches|does not reach) "([^"]*)"$`, datagramReaches)
	sc.Step(`^the answer holds the address of the cluster's API Service$`, answerHoldsAPIService)
}

// The tenant image is images/tenant-app, on python:3.12-alpine: its busybox
// has no httpd and its nc no UDP mode, so the hello API (c8s-hello-api) and
// datagrams (c8s-udp-listen, c8s-udp-send) are the image's own programs.
const (
	helloPort    = 40080
	datagramPort = 40053
	hello        = "hello"
	// secondContainer is the fixture's name for a pod's second container.
	secondContainer = "c2"
	// datagramQuiet is how long a dropped datagram is waited for.
	datagramQuiet = 10 * time.Second
)

// podMeshState is the last request a pod made and the datagram last sent.
type podMeshState struct {
	answer  *execResult
	payload string
}

// execResult is what a pod's command printed and how it exited.
type execResult struct {
	out string
	rc  int
}

func servesHello(ctx context.Context, name string) error {
	p, err := getWorld(ctx).undeployed(name)
	if err != nil {
		return err
	}
	p.containers[0].command = []string{"c8s-hello-api", strconv.Itoa(helloPort), hello}
	p.hello = helloPort
	return nil
}

// receivesDatagrams makes the pod print each datagram it receives on the
// port to the log of its listener container, the first unless the first
// serves a hello API.
func receivesDatagrams(ctx context.Context, name, which string) error {
	p, err := getWorld(ctx).undeployed(name)
	if err != nil {
		return err
	}
	port := datagramPort
	if which == "port 53" {
		port = 53
		p.opts = append(p.opts, "--add-capability", "NET_BIND_SERVICE")
	}
	listen := []string{"c8s-udp-listen", strconv.Itoa(port)}
	p.listener = p.first
	if p.hello == 0 {
		p.containers[0].command = listen
	} else {
		p.listener = secondContainer
		p.containers = append(p.containers, &container{ref: p.containers[0].ref, command: listen})
	}
	p.datagram = port
	return nil
}

func inExemptNamespace(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	return w.elsewhere(p, "exempt_namespace")
}

// elsewhere moves the pod into the namespace the backend function names;
// its name takes the scenario's suffix so scenarios never collide there,
// and the pod is deleted after the scenario, since deleting the scenario
// namespace will not take it.
func (w *world) elsewhere(p *pod, fn string) error {
	ns, err := w.be.call(fn)
	if err != nil {
		return err
	}
	if p.namespace != w.namespace {
		return fmt.Errorf("%q is already placed in namespace %q", p.name, p.namespace)
	}
	p.namespace = ns
	p.name += "-" + w.suffix()
	w.onUndo(func() error {
		_, err := kubectl(nil, "-n", p.namespace, "delete", "pod", p.name, "--ignore-not-found", "--wait=false")
		return err
	})
	return nil
}

// meshEndpointContainer is the name the webhook gives the endpoint.
const meshEndpointContainer = "c8s-mesh"

// meshLogs is the endpoint log of every deployed pod that runs one.
func (w *world) meshLogs() []godog.Attachment {
	var logs []godog.Attachment
	for _, name := range slices.Sorted(maps.Keys(w.pods)) {
		p := w.pods[name]
		if !p.deployed {
			continue
		}
		out, err := kubectl(nil, "-n", p.namespace, "logs", p.name, "-c", meshEndpointContainer, "--tail=200")
		if err != nil {
			continue
		}
		logs = append(logs, godog.Attachment{FileName: name + "-" + meshEndpointContainer + ".log", MediaType: "text/plain", Body: []byte(out)})
	}
	return logs
}

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
	w.podMesh.answer, err = w.exec(p, "nslookup "+host+" 2>&1")
	return err
}

// exec runs a shell script in the pod's first container and reports what it
// printed and its exit status, which a failing command does not turn into
// an error here.
func (w *world) exec(p *pod, script string) (*execResult, error) {
	out, err := w.podExec(p, p.first, "sh", "-c", script+"; echo \"rc=$?\"")
	if err != nil {
		return nil, err
	}
	idx := strings.LastIndex(out, "rc=")
	if idx < 0 {
		return nil, fmt.Errorf("the command in %q printed no exit status:\n%s", p.name, out)
	}
	rc, err := strconv.Atoi(strings.TrimSpace(out[idx+3:]))
	if err != nil {
		return nil, fmt.Errorf("exit status of the command in %q: %w", p.name, err)
	}
	return &execResult{out: out[:idx], rc: rc}, nil
}

// address is the running pod's first address.
func (w *world) address(p *pod) (string, error) {
	addrs, _, err := w.podIPs(p)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("%q has no pod address; the scenario must say it is running", p.name)
	}
	return addrs[0], nil
}

func requestsHello(ctx context.Context, src, dest string) error {
	w := getWorld(ctx)
	p, err := w.pod(src)
	if err != nil {
		return err
	}
	d, err := w.pod(dest)
	if err != nil {
		return err
	}
	if d.hello == 0 {
		return fmt.Errorf("%q serves no hello API", dest)
	}
	ip, err := w.address(d)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(d.hello))
	w.podMesh.answer, err = w.exec(p, fmt.Sprintf("wget -qO- -T 5 http://%s/ 2>&1", addr))
	return err
}

func sendsDatagram(ctx context.Context, src, to53, dest string) error {
	w := getWorld(ctx)
	p, err := w.pod(src)
	if err != nil {
		return err
	}
	d, err := w.pod(dest)
	if err != nil {
		return err
	}
	port := d.datagram
	if to53 != "" {
		port = 53
	}
	if port == 0 {
		return fmt.Errorf("%q receives no datagrams", dest)
	}
	ip, err := w.address(d)
	if err != nil {
		return err
	}
	w.podMesh.payload = fmt.Sprintf("datagram-%s-%d", w.suffix(), time.Now().UnixNano())
	_, err = w.exec(p, strings.Join([]string{"c8s-udp-send", ip, strconv.Itoa(port), w.podMesh.payload}, " "))
	return err
}

func (w *world) lastAnswer() (*execResult, error) {
	if w.podMesh.answer == nil {
		return nil, fmt.Errorf("no request has been made")
	}
	return w.podMesh.answer, nil
}

func receivesHello(ctx context.Context, name, what string) error {
	a, err := getWorld(ctx).lastAnswer()
	if err != nil {
		return err
	}
	got := strings.Contains(a.out, hello)
	if what == "the hello" && !got {
		return fmt.Errorf("%q received no hello (exit %d):\n%s", name, a.rc, a.out)
	}
	if what == "no hello" && got {
		return fmt.Errorf("%q received the hello:\n%s", name, a.out)
	}
	return nil
}

func datagramReaches(ctx context.Context, what, name string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if w.podMesh.payload == "" {
		return fmt.Errorf("no datagram has been sent")
	}
	if p.listener == "" {
		return fmt.Errorf("%q receives no datagrams", name)
	}
	received := func() (bool, error) {
		out, err := kubectl(nil, "-n", p.namespace, "logs", p.name, "-c", p.listener)
		return strings.Contains(out, w.podMesh.payload), err
	}
	if what == "reaches" {
		ok, err := poll(15*time.Second, received)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("the datagram did not reach %q within 15s", name)
		}
		return nil
	}
	time.Sleep(datagramQuiet)
	got, err := received()
	if err != nil {
		return err
	}
	if got {
		return fmt.Errorf("the datagram reached %q", name)
	}
	return nil
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
