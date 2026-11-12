package workloadclaims

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateWorkloadLabelRequiresMatchingAnnotation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		labels, ann map[string]string
		wantErr     bool
	}{
		{"no label", nil, map[string]string{AnnotationWorkloadID: "api"}, false},
		{"label matches annotation", map[string]string{AnnotationWorkloadID: "api"}, map[string]string{AnnotationWorkloadID: "api"}, false},
		{"label without annotation", map[string]string{AnnotationWorkloadID: "api"}, nil, true},
		{"label differs from annotation", map[string]string{AnnotationWorkloadID: "other"}, map[string]string{AnnotationWorkloadID: "api"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWorkloadLabel(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels, Annotations: tc.ann}})
			if tc.wantErr != (err != nil) || (err != nil && !strings.Contains(err.Error(), "must match")) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
