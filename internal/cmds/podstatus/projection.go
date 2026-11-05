package podstatus

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodProjection is the /v1/pod response: the pod's identity and the kubelet's
// progress fields, and nothing else. It is a dedicated type rather than a
// trimmed Pod so the response cannot carry what the pod object accretes: no
// spec, labels or annotations, no addresses, no image or container IDs, and
// no reason or message text, which kubelet fills from termination files and
// log output. Names and types are those of a v1 Pod, so a client may decode
// the response into one.
type PodProjection struct {
	Metadata PodMetadata `json:"metadata"`
	Status   PodStatus   `json:"status"`
}

// PodMetadata identifies the pod.
type PodMetadata struct {
	UID       string `json:"uid,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// PodStatus is the kubelet's progress: phase, conditions and per-container
// states, without the text fields.
type PodStatus struct {
	Phase                 corev1.PodPhase   `json:"phase,omitempty"`
	StartTime             *metav1.Time      `json:"startTime,omitempty"`
	Conditions            []PodCondition    `json:"conditions,omitempty"`
	InitContainerStatuses []ContainerStatus `json:"initContainerStatuses,omitempty"`
	ContainerStatuses     []ContainerStatus `json:"containerStatuses,omitempty"`
}

// PodCondition is a pod condition without its reason and message.
type PodCondition struct {
	Type               corev1.PodConditionType `json:"type"`
	Status             corev1.ConditionStatus  `json:"status"`
	LastTransitionTime *metav1.Time            `json:"lastTransitionTime,omitempty"`
}

// ContainerStatus is a container's progress without its image, IDs or
// resource view.
type ContainerStatus struct {
	Name         string          `json:"name"`
	Ready        bool            `json:"ready"`
	Started      *bool           `json:"started,omitempty"`
	RestartCount int32           `json:"restartCount"`
	State        *ContainerState `json:"state,omitempty"`
	LastState    *ContainerState `json:"lastState,omitempty"`
}

// ContainerState carries at most one member.
type ContainerState struct {
	Waiting    *struct{}            `json:"waiting,omitempty"`
	Running    *ContainerRunning    `json:"running,omitempty"`
	Terminated *ContainerTerminated `json:"terminated,omitempty"`
}

// ContainerRunning is a running state's start time.
type ContainerRunning struct {
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
}

// ContainerTerminated is a terminated state's exit and times, without the
// reason, message and container ID.
type ContainerTerminated struct {
	ExitCode   int32        `json:"exitCode"`
	Signal     int32        `json:"signal,omitempty"`
	StartedAt  *metav1.Time `json:"startedAt,omitempty"`
	FinishedAt *metav1.Time `json:"finishedAt,omitempty"`
}

// ProjectPod builds the /v1/pod response from the kubelet's pod object.
func ProjectPod(pod *corev1.Pod) PodProjection {
	out := PodProjection{
		Metadata: PodMetadata{UID: string(pod.UID), Namespace: pod.Namespace, Name: pod.Name},
		Status:   PodStatus{Phase: pod.Status.Phase, StartTime: pod.Status.StartTime},
	}
	for _, c := range pod.Status.Conditions {
		out.Status.Conditions = append(out.Status.Conditions, PodCondition{
			Type: c.Type, Status: c.Status, LastTransitionTime: timeOrNil(c.LastTransitionTime),
		})
	}
	out.Status.InitContainerStatuses = projectContainers(pod.Status.InitContainerStatuses)
	out.Status.ContainerStatuses = projectContainers(pod.Status.ContainerStatuses)
	return out
}

func projectContainers(in []corev1.ContainerStatus) []ContainerStatus {
	var out []ContainerStatus
	for _, c := range in {
		out = append(out, ContainerStatus{
			Name: c.Name, Ready: c.Ready, Started: c.Started, RestartCount: c.RestartCount,
			State:     projectState(c.State),
			LastState: projectState(c.LastTerminationState),
		})
	}
	return out
}

// projectState keeps one member. Kubelet sets exactly one; if several are
// set, the one furthest along is served.
func projectState(s corev1.ContainerState) *ContainerState {
	switch {
	case s.Terminated != nil:
		return &ContainerState{Terminated: &ContainerTerminated{
			ExitCode: s.Terminated.ExitCode, Signal: s.Terminated.Signal,
			StartedAt: timeOrNil(s.Terminated.StartedAt), FinishedAt: timeOrNil(s.Terminated.FinishedAt),
		}}
	case s.Running != nil:
		return &ContainerState{Running: &ContainerRunning{StartedAt: timeOrNil(s.Running.StartedAt)}}
	case s.Waiting != nil:
		return &ContainerState{Waiting: &struct{}{}}
	}
	return nil
}

func timeOrNil(t metav1.Time) *metav1.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
