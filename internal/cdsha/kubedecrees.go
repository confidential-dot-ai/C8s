package cdsha

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Decrees reach the replicas as ConfigMaps the operator applies. Their
// contents are untrusted hints: every decree is checked against the operator
// key by every replica that applies it.
const (
	LabelDecree = "c8s.confidential.ai/cds-decree"
	keyDecree   = "decree"
	keyStatus   = "status"
)

// DecreeName is the decree object for one intent.
func DecreeName(clusterID, intentID string) string { return "cds-decree-" + clusterID + "-" + intentID }

// NewIntentID is a random intent id; lowercase because it ends up in DecreeName,
// which must be an RFC 1123 subdomain.
func NewIntentID() string { return strings.ToLower(rand.Text()) }

// DecreeStatus is written by the leader when it applies or rejects a decree.
type DecreeStatus struct {
	AppliedEpoch   *uint64 `json:"applied_epoch,omitempty"`
	RejectedReason string  `json:"rejected_reason,omitempty"`
}

// PendingDecree is a decree object; it is pending while it has no status.
type PendingDecree struct {
	Name   string
	Decree SignedDecree
	Err    error         // set when the object does not parse
	Status *DecreeStatus // nil while pending
}

// KubeDecrees reads decrees from a namespace the operator credential may
// write; on a locked node image the CDS namespace is not one.
type KubeDecrees struct {
	Client    kubernetes.Interface
	Namespace string
	ClusterID string
	// Timeout bounds every API request (0: DefaultTiming.Apply). The leader
	// must not wait without bound on an API server that accepts and never
	// answers.
	Timeout time.Duration
}

func (s KubeDecrees) cms() corev1client.ConfigMapInterface {
	return deadlineConfigMaps{s.Client.CoreV1().ConfigMaps(s.Namespace), cmp.Or(s.Timeout, DefaultTiming.Apply)}
}

// deadlineConfigMaps gives each request KubeDecrees makes its own deadline.
// rest.Config.Timeout would do the same, but the in-cluster clientset also
// serves watches, which it would cut.
type deadlineConfigMaps struct {
	corev1client.ConfigMapInterface
	timeout time.Duration
}

func (c deadlineConfigMaps) Get(ctx context.Context, name string, o metav1.GetOptions) (*corev1.ConfigMap, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.ConfigMapInterface.Get(ctx, name, o)
}

func (c deadlineConfigMaps) List(ctx context.Context, o metav1.ListOptions) (*corev1.ConfigMapList, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.ConfigMapInterface.List(ctx, o)
}

func (c deadlineConfigMaps) Create(ctx context.Context, cm *corev1.ConfigMap, o metav1.CreateOptions) (*corev1.ConfigMap, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.ConfigMapInterface.Create(ctx, cm, o)
}

func (c deadlineConfigMaps) Update(ctx context.Context, cm *corev1.ConfigMap, o metav1.UpdateOptions) (*corev1.ConfigMap, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.ConfigMapInterface.Update(ctx, cm, o)
}

func (c deadlineConfigMaps) Delete(ctx context.Context, name string, o metav1.DeleteOptions) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.ConfigMapInterface.Delete(ctx, name, o)
}

// ListDecrees lists this cluster's decree objects and their status.
func (s KubeDecrees) ListDecrees(ctx context.Context) ([]PendingDecree, error) {
	list, err := s.cms().List(ctx, metav1.ListOptions{LabelSelector: LabelDecree + "=" + s.ClusterID})
	if err != nil {
		return nil, err
	}
	var out []PendingDecree
	for _, cm := range list.Items {
		p := PendingDecree{Name: cm.Name}
		if raw := cm.Data[keyStatus]; raw != "" {
			// An unreadable status still marks the decree used.
			p.Status = &DecreeStatus{}
			_ = json.Unmarshal([]byte(raw), p.Status)
		}
		p.Err = json.Unmarshal([]byte(cm.Data[keyDecree]), &p.Decree)
		out = append(out, p)
	}
	return out, nil
}

// SetDecreeStatus records the outcome of a decree.
func (s KubeDecrees) SetDecreeStatus(ctx context.Context, name string, st DecreeStatus) error {
	cm, err := s.cms().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[keyStatus] = string(body)
	_, err = s.cms().Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// DecreeConfigMap renders a decree object for the CLI.
func DecreeConfigMap(namespace string, sd SignedDecree) (*corev1.ConfigMap, error) {
	body, err := json.Marshal(sd)
	if err != nil {
		return nil, err
	}
	name := DecreeName(sd.Decree.ClusterID, sd.Decree.IntentID)
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return nil, fmt.Errorf("decree object name %q: %s", name, strings.Join(errs, "; "))
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{LabelDecree: sd.Decree.ClusterID},
		},
		Data: map[string]string{keyDecree: string(body)},
	}, nil
}
