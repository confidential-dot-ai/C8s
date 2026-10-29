package cdsha

import (
	"context"
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// DecreeStatus is written by the leader when it applies or rejects a decree.
type DecreeStatus struct {
	AppliedEpoch   *uint64 `json:"applied_epoch,omitempty"`
	RejectedReason string  `json:"rejected_reason,omitempty"`
}

// PendingDecree is a decree object without a status.
type PendingDecree struct {
	Name   string
	Decree SignedDecree
	Err    error // set when the object does not parse
}

// KubeDecrees reads decrees from a namespace the operator credential may
// write; on a locked node image the CDS namespace is not one.
type KubeDecrees struct {
	Client    kubernetes.Interface
	Namespace string
	ClusterID string
}

func (s KubeDecrees) cms() corev1client.ConfigMapInterface {
	return s.Client.CoreV1().ConfigMaps(s.Namespace)
}

// PendingDecrees lists this cluster's decree objects without a status.
func (s KubeDecrees) PendingDecrees(ctx context.Context) ([]PendingDecree, error) {
	list, err := s.cms().List(ctx, metav1.ListOptions{LabelSelector: LabelDecree + "=" + s.ClusterID})
	if err != nil {
		return nil, err
	}
	var out []PendingDecree
	for _, cm := range list.Items {
		if cm.Data[keyStatus] != "" {
			continue
		}
		p := PendingDecree{Name: cm.Name}
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
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DecreeName(sd.Decree.ClusterID, sd.Decree.IntentID),
			Namespace: namespace,
			Labels:    map[string]string{LabelDecree: sd.Decree.ClusterID},
		},
		Data: map[string]string{keyDecree: string(body)},
	}, nil
}
