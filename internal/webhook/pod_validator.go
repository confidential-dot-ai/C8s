// The validating admission webhook. The mutating webhook can be deleted,
// reordered behind another mutator or raced, so a pod in scope is admitted only
// when its final shape is the one the injector builds.

package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var errUninjectedPod = errors.New("pod does not carry the c8s injected shape")

type podValidator struct {
	decoder admission.Decoder
	cfg     Config
}

func (v *podValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	l := log.FromContext(ctx).WithValues("pod", req.Name, "ns", req.Namespace)

	pod := &corev1.Pod{}
	if err := v.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// An ephemeral container changes no injected container, so the only
	// decision is whether it may reach what they hold.
	if req.SubResource == "ephemeralcontainers" {
		if err := rejectEphemeralReach(pod); err != nil {
			l.Info("denying ephemeral container", "reason", err.Error())
			return admission.Errored(http.StatusBadRequest, err)
		}
		return admission.Allowed("ephemeral container reaches no c8s material")
	}

	// The one place this holds, since the mutator rebuilds the label it
	// stamps: a pod carrying the label the managed Services select on, without
	// the matching annotation, is refused in or out of scope.
	if err := validateWorkloadLabel(pod); err != nil {
		l.Info("denying pod", "reason", err.Error())
		return admission.Errored(http.StatusBadRequest, err)
	}
	if !v.cfg.inScope(pod) {
		return admission.Allowed("outside the injector's scope")
	}
	if req.Operation == admissionv1.Update {
		metadataOnly, err := v.isMetadataOnlyUpdate(req, pod)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		if metadataOnly {
			return admission.Allowed("pod spec unchanged")
		}
	}
	if err := validateFinalSpec(pod, req.Namespace, v.cfg); err != nil {
		l.Info("denying pod", "reason", err.Error())
		return admission.Errored(http.StatusBadRequest, err)
	}
	return admission.Allowed("pod carries the injected c8s shape")
}

// isMetadataOnlyUpdate reports whether this update leaves the pod spec as
// admitted. The shape is re-derived from live configuration, so an operator
// image bump must not deny every metadata write on the pods admitted before
// it; a spec change, like every CREATE, is judged in full.
func (v *podValidator) isMetadataOnlyUpdate(req admission.Request, pod *corev1.Pod) (bool, error) {
	if len(req.OldObject.Raw) == 0 {
		return false, nil
	}
	old := &corev1.Pod{}
	if err := v.decoder.DecodeRaw(req.OldObject, old); err != nil {
		return false, err
	}
	return reflect.DeepEqual(old.Spec, pod.Spec), nil
}

// validateFinalSpec rebuilds the injected shape from the pod's own request and
// requires the pod to carry it: a pod that reached the API server uninjected,
// with a weakened platform container, or with something of the injector's
// occupied is refused.
func validateFinalSpec(pod *corev1.Pod, namespace string, cfg Config) error {
	inj, err := parseAnnotations(pod, namespace)
	if err != nil {
		return err
	}
	if err := rejectReservedResources(pod, inj, cfg); err != nil {
		return err
	}
	injected := pod.DeepCopy()
	mutatePod(injected, inj, cfg)
	if err := matchesInjectedContainers(injected.Spec.InitContainers, pod.Spec.InitContainers); err != nil {
		return err
	}
	return matchesWorkloadMounts(injected.Spec.Containers, pod.Spec.Containers)
}

// matchesInjectedContainers requires the pod's init containers to be the
// rebuilt ones: the platform containers in the injector's order, each equal to
// what the injector builds, followed by the pod's own.
func matchesInjectedContainers(want, got []corev1.Container) error {
	if err := matchesContainerOrder(want, got); err != nil {
		return err
	}
	for i := range want {
		if !workloadclaims.IsInjectedContainerName(want[i].Name) {
			continue
		}
		if err := matchesInjectedContainer(want[i], got[i]); err != nil {
			return err
		}
	}
	return nil
}

// matchesWorkloadMounts requires each workload container to hold the mounts the
// injector gave it of the volumes C8s owns: the released secrets read-only, the
// opened volumes as the daemon presents them, and no credential volume.
func matchesWorkloadMounts(want, got []corev1.Container) error {
	if err := matchesContainerOrder(want, got); err != nil {
		return err
	}
	for i := range want {
		wantOwned := c8sMounts(want[i].VolumeMounts)
		gotOwned := c8sMounts(got[i].VolumeMounts)
		if !reflect.DeepEqual(wantOwned, gotOwned) {
			return fmt.Errorf("%w: container %q has c8s volumeMounts %+v, want %+v",
				errUninjectedPod, want[i].Name, gotOwned, wantOwned)
		}
	}
	return nil
}

// c8sMounts are the mounts of the volumes the injector owns on this pod.
func c8sMounts(mounts []corev1.VolumeMount) []corev1.VolumeMount {
	owned := make([]corev1.VolumeMount, 0, len(mounts))
	for _, m := range mounts {
		if m.Name == certVolumeName || m.Name == secretsVolumeName || strings.HasPrefix(m.Name, volume.KubeVolumePrefix) {
			owned = append(owned, m)
		}
	}
	return owned
}

func matchesContainerOrder(want, got []corev1.Container) error {
	if len(want) == len(got) && slices.EqualFunc(want, got, sameContainerName) {
		return nil
	}
	return fmt.Errorf("%w: containers are %v, want %v",
		errUninjectedPod, containerNames(got), containerNames(want))
}

func sameContainerName(a, b corev1.Container) bool {
	return a.Name == b.Name
}

// matchesInjectedContainer compares every field of a platform container the
// injector sets, plus the ones that would otherwise run code in it or carry
// data out of it: a lifecycle hook, an envFrom source, a declared port, a block
// device, a terminal, a termination message naming a credential file. Resources
// are left out: a LimitRange owns them.
func matchesInjectedContainer(want, got corev1.Container) error {
	for _, check := range []func() error{
		func() error { return matchesField(want.Name, "image", want.Image, got.Image) },
		func() error {
			return matchesField(want.Name, "imagePullPolicy", want.ImagePullPolicy, got.ImagePullPolicy)
		},
		func() error { return matchesField(want.Name, "command", want.Command, got.Command) },
		func() error { return matchesField(want.Name, "args", want.Args, got.Args) },
		func() error { return matchesField(want.Name, "workingDir", want.WorkingDir, got.WorkingDir) },
		func() error { return matchesField(want.Name, "env", want.Env, got.Env) },
		func() error { return matchesField(want.Name, "envFrom", want.EnvFrom, got.EnvFrom) },
		func() error { return matchesField(want.Name, "ports", want.Ports, got.Ports) },
		func() error { return matchesField(want.Name, "volumeMounts", want.VolumeMounts, got.VolumeMounts) },
		func() error { return matchesField(want.Name, "volumeDevices", want.VolumeDevices, got.VolumeDevices) },
		func() error { return matchesField(want.Name, "lifecycle", want.Lifecycle, got.Lifecycle) },
		func() error { return matchesField(want.Name, "restartPolicy", want.RestartPolicy, got.RestartPolicy) },
		func() error {
			return matchesField(want.Name, "securityContext", want.SecurityContext, got.SecurityContext)
		},
		func() error { return matchesField(want.Name, "startupProbe", want.StartupProbe, got.StartupProbe) },
		func() error {
			return matchesField(want.Name, "readinessProbe", want.ReadinessProbe, got.ReadinessProbe)
		},
		func() error { return matchesField(want.Name, "livenessProbe", want.LivenessProbe, got.LivenessProbe) },
		func() error { return matchesField(want.Name, "stdin", want.Stdin, got.Stdin) },
		func() error { return matchesField(want.Name, "tty", want.TTY, got.TTY) },
		func() error {
			return matchesField(want.Name, "terminationMessagePath", want.TerminationMessagePath, got.TerminationMessagePath)
		},
		func() error {
			return matchesField(want.Name, "terminationMessagePolicy", want.TerminationMessagePolicy, got.TerminationMessagePolicy)
		},
	} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// matchesField reports the difference in one field of a platform container.
func matchesField(container, field string, want, got any) error {
	if reflect.DeepEqual(want, got) {
		return nil
	}
	return fmt.Errorf("%w: container %q has %s %+v, want %+v",
		errUninjectedPod, container, field, got, want)
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}
