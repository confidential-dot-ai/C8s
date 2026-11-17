package podprovider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// bare404 is a real client's error for a 404 with no Status body.
func bare404(t *testing.T) error {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(corev1.SchemeGroupVersion.WithKind("Secret"), meta.RESTScopeNamespace)
	c, err := client.New(&rest.Config{Host: srv.URL}, client.Options{Scheme: scheme.Scheme, Mapper: mapper})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Get(t.Context(), client.ObjectKey{Namespace: "any", Name: "any"}, &corev1.Secret{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("the client reports a bare 404 as %v", err)
	}
	return err
}

// failReads answers every read of a T with err.
func failReads[T client.Object](r *Reconciler, err error) {
	r.client = interceptor.NewClient(r.client.(client.WithWatch), interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(T); ok {
			return err
		}
		return c.Get(ctx, key, obj, opts...)
	}})
}

func TestNotFoundIsTheAPIServersOwnAnswer(t *testing.T) {
	r, _ := fixtureReconciler(t, fixturePod())
	missing := r.client.Get(t.Context(), client.ObjectKey{Namespace: r.cfg.Namespace, Name: "missing"}, &corev1.Secret{})
	if !notFound(missing) {
		t.Fatalf("the API server's not-found answer %v is not absence", missing)
	}
	if err := bare404(t); notFound(err) {
		t.Fatalf("a bare 404 %v is absence", err)
	}
	if notFound(nil) {
		t.Fatal("no error is absence")
	}
}

// The record sweep destroys the instance of a record whose pod is gone. A pod
// read that fails is not a pod that is gone.
func TestRecordSweepKeepsAnInstanceWhosePodReadAnswersABare404(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	runToRunning(t, r, pod)
	failReads[*corev1.Pod](r, bare404(t))
	err := r.sweep(t.Context())
	if rec := getRecord(t, r, pod); err == nil || cloud.deleteCalls != 0 || rec.Deleted {
		t.Fatalf("sweep error %v, cloud deletes %d, record deleted %t", err, cloud.deleteCalls, rec.Deleted)
	}
}

// A deleted pod with no record owns no instance and is released at once. A
// record read that fails is not a missing record: the pod keeps its finalizer
// until its instance is destroyed.
func TestDeletionKeepsThePodWhenItsRecordReadAnswersABare404(t *testing.T) {
	pod := fixturePod()
	r, cloud := fixtureReconciler(t, pod)
	runToRunning(t, r, pod)
	if err := r.client.Delete(t.Context(), getPod(t, r, pod)); err != nil {
		t.Fatal(err)
	}
	stored := r.client
	failReads[*corev1.Secret](r, bare404(t))
	err := reconcile(t, r, pod)
	r.client = stored
	if live := getPod(t, r, pod); err == nil || !controllerutil.ContainsFinalizer(live, finalizer) || cloud.deleteCalls != 0 {
		t.Fatalf("reconcile error %v, finalizers %v, cloud deletes %d", err, live.Finalizers, cloud.deleteCalls)
	}
	// With the record readable again the instance is destroyed first.
	if err := reconcile(t, r, pod); err != nil || cloud.deleteCalls != 1 {
		t.Fatalf("reconcile error %v, cloud deletes %d", err, cloud.deleteCalls)
	}
}

// A write that fails has not happened: the deletion is retried, not taken as
// finished because the object was already gone.
func TestDeletionRetriesAWriteThatAnswersABare404(t *testing.T) {
	for name, fail := range map[string]func(error) interceptor.Funcs{
		"terminal status": func(err error) interceptor.Funcs {
			return interceptor.Funcs{SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
				return err
			}}
		},
		"finalizer release": func(err error) interceptor.Funcs {
			return interceptor.Funcs{Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				return err
			}}
		},
		"pod removal": func(err error) interceptor.Funcs {
			return interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.Pod); ok {
					return err
				}
				return c.Delete(ctx, obj, opts...)
			}}
		},
		"record removal": func(err error) interceptor.Funcs {
			return interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return err
				}
				return c.Delete(ctx, obj, opts...)
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			runToRunning(t, r, pod)
			if err := r.client.Delete(t.Context(), getPod(t, r, pod)); err != nil {
				t.Fatal(err)
			}
			cloud.in.Status = "terminated"
			refused := bare404(t)
			r.client = interceptor.NewClient(r.client.(client.WithWatch), fail(refused))
			var err error
			for range 4 {
				if err = reconcile(t, r, pod); err != nil {
					break
				}
			}
			if !errors.Is(err, refused) {
				t.Fatalf("deletion ended with %v", err)
			}
		})
	}
}
