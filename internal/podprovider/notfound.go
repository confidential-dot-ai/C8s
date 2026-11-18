package podprovider

import (
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// notFound is the API server's own not-found answer for a built-in kind. A 404
// with no Status body, as something in front of it answers, is a failure.
func notFound(err error) bool {
	return apierrors.ReasonForError(err) == metav1.StatusReasonNotFound && !apierrors.IsUnexpectedServerError(err)
}

// ignoreNotFound is nil for an object that is already gone.
func ignoreNotFound(err error) error {
	if notFound(err) {
		return nil
	}
	return err
}
