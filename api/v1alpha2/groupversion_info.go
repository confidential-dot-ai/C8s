// Package v1alpha2 contains the confidential.ai/v1alpha2 CRD types.
//
// The cluster runs without these CRDs installed. They exist as a UX overlay
// for `kubectl get td` / `kubectl get cwl` and to mirror per-pod attestation
// state into a status surface. Sidecar injection, cert issuance, and image
// policy enforcement do not consult these types — the webhook keys off pod
// annotations and Trust Authority / the NRI plugin hold the actual gates.
//
// +kubebuilder:object:generate=true
// +groupName=confidential.ai
package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion = schema.GroupVersion{Group: "confidential.ai", Version: "v1alpha2"}

	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	AddToScheme = SchemeBuilder.AddToScheme
)

// addKnownTypes registers this group-version's types with a scheme. This is the
// apimachinery builder that controller-runtime's scheme.Builder deprecation
// points at: the whole reason for that deprecation is to keep api packages
// importable without dragging in controller-runtime, so the type list lives
// here rather than behind a Register call in the types file.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&ConfidentialWorkload{},
		&ConfidentialWorkloadList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
