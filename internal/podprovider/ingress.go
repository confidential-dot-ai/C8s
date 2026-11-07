package podprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ingressManager names the provider in the EndpointSlices it writes, so the
// EndpointSlice controller leaves them alone.
const ingressManager = "c8s-pod-cvm-provider"

// ingressReconciler gives each pod CVM with published application endpoints
// a selector-less ClusterIP Service of the pod's name and one EndpointSlice
// pointing at the pod's Cloud endpoints. Both are owned by the Pod, so
// Kubernetes collects them with it. In-cluster clients, the router among
// them, then reach a pod CVM at an in-cluster address.
//
// It reads only what the provider already published: the endpoints
// annotation and the Ready condition.
type ingressReconciler struct {
	client     client.Client
	nodeName   string
	providerID string
}

func (r *ingressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, req.NamespacedName, pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if pod.Spec.NodeName != r.nodeName {
		return ctrl.Result{}, nil
	}
	var apps []endpoint
	if pod.DeletionTimestamp.IsZero() {
		if raw := pod.Annotations[endpointsAnnotation]; raw != "" {
			if err := json.Unmarshal([]byte(raw), &apps); err != nil {
				return ctrl.Result{}, r.withdraw(ctx, pod)
			}
		}
	}
	svc, slice, err := r.desired(pod, apps)
	if err != nil || svc == nil {
		return ctrl.Result{}, errors.Join(err, r.withdraw(ctx, pod))
	}
	if err := r.apply(ctx, pod, svc, func(cur client.Object) bool {
		c := cur.(*corev1.Service)
		if reflect.DeepEqual(c.Spec.Ports, svc.Spec.Ports) && c.Spec.Selector == nil {
			return false
		}
		c.Spec.Ports, c.Spec.Selector = svc.Spec.Ports, nil
		return true
	}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.apply(ctx, pod, slice, func(cur client.Object) bool {
		c := cur.(*discoveryv1.EndpointSlice)
		if reflect.DeepEqual(c.Ports, slice.Ports) && reflect.DeepEqual(c.Endpoints, slice.Endpoints) && c.AddressType == slice.AddressType {
			return false
		}
		c.Ports, c.Endpoints, c.AddressType = slice.Ports, slice.Endpoints, slice.AddressType
		return true
	})
}

// desired returns the Service and EndpointSlice for the pod's application
// endpoints, or nil when it publishes none.
func (r *ingressReconciler) desired(pod *corev1.Pod, apps []endpoint) (*corev1.Service, *discoveryv1.EndpointSlice, error) {
	if len(apps) == 0 {
		return nil, nil, nil
	}
	host := apps[0].Host
	var svcPorts []corev1.ServicePort
	var slicePorts []discoveryv1.EndpointPort
	for _, ep := range apps {
		port, err := strconv.Atoi(strings.TrimPrefix(ep.Name, appEndpointPrefix))
		if err != nil || !strings.HasPrefix(ep.Name, appEndpointPrefix) || port < 1 || port > 65535 {
			return nil, nil, errors.New("pod CVM endpoint is not a declared application port")
		}
		// One EndpointSlice carries one set of ports for all its addresses.
		// A pod CVM has one public address; refuse anything else.
		if ip, err := netip.ParseAddr(ep.Host); err != nil || !ip.Is4() || ep.Host != host || ep.Port < 1 || ep.Port > 65535 {
			return nil, nil, errors.New("pod CVM endpoints do not share one IPv4 address")
		}
		svcPorts = append(svcPorts, corev1.ServicePort{Name: ep.Name, Protocol: corev1.ProtocolTCP, Port: int32(port), TargetPort: intstr.FromInt32(int32(port))})
		slicePorts = append(slicePorts, discoveryv1.EndpointPort{Name: ptr(ep.Name), Protocol: ptr(corev1.ProtocolTCP), Port: ptr(int32(ep.Port))})
	}
	meta := func(labels map[string]string) metav1.ObjectMeta {
		labels[ownerLabel] = r.providerID
		return metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace, Labels: labels, OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID, Controller: ptr(true),
		}}}
	}
	svc := &corev1.Service{ObjectMeta: meta(map[string]string{}), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Ports: svcPorts}}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  meta(map[string]string{discoveryv1.LabelServiceName: pod.Name, discoveryv1.LabelManagedBy: ingressManager}),
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       slicePorts,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{host}, Conditions: discoveryv1.EndpointConditions{Ready: ptr(podReady(pod))}}},
	}
	return svc, slice, nil
}

// apply creates want, or updates the object of its name when this Pod
// controls it and update reports a change. It never adopts an object the Pod
// does not control, such as a tenant's own Service of the same name.
func (r *ingressReconciler) apply(ctx context.Context, pod *corev1.Pod, want client.Object, update func(client.Object) bool) error {
	cur := want.DeepCopyObject().(client.Object)
	err := r.client.Get(ctx, client.ObjectKeyFromObject(want), cur)
	if apierrors.IsNotFound(err) {
		return r.client.Create(ctx, want)
	}
	if err != nil {
		return err
	}
	if !metav1.IsControlledBy(cur, pod) {
		return errors.New("refusing to adopt an object of the pod's name that the pod does not own")
	}
	if !update(cur) {
		return nil
	}
	return r.client.Update(ctx, cur)
}

// withdraw deletes the Service and EndpointSlice this Pod controls.
func (r *ingressReconciler) withdraw(ctx context.Context, pod *corev1.Pod) error {
	var errs []error
	for _, obj := range []client.Object{&corev1.Service{}, &discoveryv1.EndpointSlice{}} {
		err := r.client.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, obj)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err == nil && metav1.IsControlledBy(obj, pod) {
			err = client.IgnoreNotFound(r.client.Delete(ctx, obj, client.Preconditions{UID: ptr(obj.GetUID())}))
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func podReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func ptr[T any](v T) *T { return &v }
