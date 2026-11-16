package routing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// AgentIndex maps agent labels to the addresses of the pods that claim them,
// for the routes a pattern rule gives. It is built from Kubernetes data the
// router does not trust: a wrong address costs a refused dial, because the
// dial requires the label of the peer's own client document digest in its
// leaf. It is safe for concurrent use.
type AgentIndex struct {
	mu      sync.RWMutex
	pods    map[string]agentPod            // by namespace/name
	byLabel map[string]map[string]struct{} // label -> pod keys
}

type agentPod struct {
	label   string
	created time.Time
	// endpoints maps an application port to the host:port it is published on.
	endpoints map[uint16]string
}

// NewAgentIndex returns an empty index.
func NewAgentIndex() *AgentIndex {
	return &AgentIndex{pods: map[string]agentPod{}, byLabel: map[string]map[string]struct{}{}}
}

// Update indexes pod by what it publishes, or forgets it when it publishes
// no usable agent.
func (x *AgentIndex) Update(pod *corev1.Pod) {
	key := pod.Namespace + "/" + pod.Name
	a, ok := agentOf(pod)
	x.mu.Lock()
	defer x.mu.Unlock()
	x.forgetLocked(key)
	if !ok {
		return
	}
	x.pods[key] = a
	if x.byLabel[a.label] == nil {
		x.byLabel[a.label] = map[string]struct{}{}
	}
	x.byLabel[a.label][key] = struct{}{}
}

// Delete forgets the pod namespace/name.
func (x *AgentIndex) Delete(key string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.forgetLocked(key)
}

func (x *AgentIndex) forgetLocked(key string) {
	old, ok := x.pods[key]
	if !ok {
		return
	}
	delete(x.pods, key)
	delete(x.byLabel[old.label], key)
	if len(x.byLabel[old.label]) == 0 {
		delete(x.byLabel, old.label)
	}
}

// Lookup returns the address that serves port for the agent label. When
// several pods claim the label, the oldest one that publishes port wins, so
// every request picks the same pod while it lasts.
func (x *AgentIndex) Lookup(label string, port uint16) (string, bool) {
	if x == nil {
		return "", false
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	var best agentPod
	var bestKey string
	for key := range x.byLabel[label] {
		a := x.pods[key]
		if _, ok := a.endpoints[port]; !ok {
			continue
		}
		if bestKey == "" || a.created.Before(best.created) || a.created.Equal(best.created) && key < bestKey {
			best, bestKey = a, key
		}
	}
	if bestKey == "" {
		return "", false
	}
	return best.endpoints[port], true
}

// podEndpoint is one entry of the pod CVM provider's endpoints annotation.
type podEndpoint struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// agentOf reads the agent a pod publishes: the label of its client document
// and the addresses the pod CVM provider published for its application
// ports. A pod that is terminating, not Ready, or lacks either annotation
// publishes none.
func agentOf(pod *corev1.Pod) (agentPod, bool) {
	if pod.DeletionTimestamp != nil || !podReady(pod) {
		return agentPod{}, false
	}
	doc, err := base64.StdEncoding.DecodeString(pod.Annotations[workloadclaims.AnnotationClientDocument])
	if err != nil || len(doc) == 0 {
		return agentPod{}, false
	}
	var published []podEndpoint
	if json.Unmarshal([]byte(pod.Annotations[workloadclaims.AnnotationPodCVMEndpoints]), &published) != nil {
		return agentPod{}, false
	}
	endpoints := map[uint16]string{}
	for _, e := range published {
		n, ok := strings.CutPrefix(e.Name, workloadclaims.PodCVMAppEndpointPrefix)
		port, err := strconv.ParseUint(n, 10, 16)
		if !ok || err != nil || port == 0 || e.Host == "" || e.Port < 1 || e.Port > 65535 {
			continue
		}
		endpoints[uint16(port)] = net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	}
	if len(endpoints) == 0 {
		return agentPod{}, false
	}
	h := sha256.Sum256(doc)
	return agentPod{label: armtls.AgentLabel(h[:]), created: pod.CreationTimestamp.Time, endpoints: endpoints}, true
}

func podReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
