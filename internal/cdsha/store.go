package cdsha

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Labels and keys of the ConfigMaps standing in for the CDSEpoch and
// CDSDecree CRDs. Their contents are untrusted hints (O6, T1).
const (
	LabelDecree = "c8s.confidential.ai/cds-decree"
	keyRecord   = "record"
	keyDecree   = "decree"
	keyStatus   = "status"
)

// EpochName is the CDSEpoch object for a cluster (O1, CI3).
func EpochName(clusterID string) string { return "cds-epoch-" + clusterID }

// DecreeName is the CDSDecree object for one intent.
func DecreeName(clusterID, intentID string) string { return "cds-decree-" + clusterID + "-" + intentID }

// DecreeStatus is written only by the writer (O9).
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

// Store persists public HA objects. CDSEpoch lives in Namespace (the CDS
// namespace, writable by the CDS ServiceAccount). Decrees live in
// DecreeNamespace, which the operator credential can write: on a locked node
// image the CDS namespace is privileged and operators cannot write there.
type Store struct {
	Client          kubernetes.Interface
	Namespace       string
	DecreeNamespace string // defaults to Namespace
	ClusterID       string
}

func (s Store) cms() corev1client.ConfigMapInterface {
	return s.Client.CoreV1().ConfigMaps(s.Namespace)
}

func (s Store) decreeCMs() corev1client.ConfigMapInterface {
	ns := s.DecreeNamespace
	if ns == "" {
		ns = s.Namespace
	}
	return s.Client.CoreV1().ConfigMaps(ns)
}

// Version identifies the stored CDSEpoch object a write is based on.
type Version struct {
	Exists          bool
	ResourceVersion string
}

// GetEpoch returns the stored record (nil when absent or unparsable) and the
// version to base a write on. A parse error still returns the version, so a
// writer can overwrite garbage.
func (s Store) GetEpoch(ctx context.Context) (*SignedRecord, Version, error) {
	cm, err := s.cms().Get(ctx, EpochName(s.ClusterID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, Version{}, nil
	}
	if err != nil {
		return nil, Version{}, err
	}
	v := Version{Exists: true, ResourceVersion: cm.ResourceVersion}
	var rec SignedRecord
	if err := json.Unmarshal([]byte(cm.Data[keyRecord]), &rec); err != nil {
		return nil, v, fmt.Errorf("parse %s: %w", cm.Name, err)
	}
	return &rec, v, nil
}

// PutEpoch creates or replaces the record based on v. Update carries the
// resourceVersion read before, so a concurrent honest writer fails (W6).
func (s Store) PutEpoch(ctx context.Context, rec SignedRecord, v Version) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: EpochName(s.ClusterID), Namespace: s.Namespace, ResourceVersion: v.ResourceVersion},
		Data:       map[string]string{keyRecord: string(body)},
	}
	if !v.Exists {
		_, err = s.cms().Create(ctx, cm, metav1.CreateOptions{})
	} else {
		_, err = s.cms().Update(ctx, cm, metav1.UpdateOptions{})
	}
	return err
}

// PendingDecrees lists decree objects of this cluster without a status.
func (s Store) PendingDecrees(ctx context.Context) ([]PendingDecree, error) {
	list, err := s.decreeCMs().List(ctx, metav1.ListOptions{LabelSelector: LabelDecree + "=" + s.ClusterID})
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
func (s Store) SetDecreeStatus(ctx context.Context, name string, st DecreeStatus) error {
	cm, err := s.decreeCMs().Get(ctx, name, metav1.GetOptions{})
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
	_, err = s.decreeCMs().Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// DecreeConfigMap renders a decree object for the CLI (O8, C1).
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
