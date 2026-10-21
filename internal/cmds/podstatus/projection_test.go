package podstatus

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// sentinel marks every field the status service must not serve. It is placed
// where kubelet puts text it copied from the pod's spec, termination files
// and log output, and where it records addresses and image identities.
const sentinel = "SENTINEL"

func leakyPod() corev1.Pod {
	t0 := metav1.NewTime(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	t1 := metav1.NewTime(t0.Add(time.Minute))
	started := true
	return corev1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "app", Namespace: "tenant", UID: "u1",
			Labels:      map[string]string{"app": sentinel},
			Annotations: map[string]string{"note": sentinel},
			Finalizers:  []string{sentinel},
		},
		Spec: corev1.PodSpec{
			NodeName: sentinel,
			Containers: []corev1.Container{{
				Name: "app", Image: sentinel, Args: []string{sentinel},
				Env: []corev1.EnvVar{{Name: "SECRET", Value: sentinel}},
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning, Reason: sentinel, Message: sentinel,
			PodIP: sentinel, HostIP: sentinel, NominatedNodeName: sentinel,
			PodIPs:    []corev1.PodIP{{IP: sentinel}},
			StartTime: &t0,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
				LastTransitionTime: t1, Reason: sentinel, Message: sentinel,
			}},
			InitContainerStatuses: []corev1.ContainerStatus{{
				Name: "init", Ready: true, RestartCount: 2,
				Image: sentinel, ImageID: sentinel, ContainerID: sentinel,
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
					ExitCode: 0, StartedAt: t0, FinishedAt: t1,
					Reason: sentinel, Message: sentinel, ContainerID: sentinel,
				}},
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
					ExitCode: 137, Signal: 9, Reason: sentinel, Message: sentinel, ContainerID: sentinel,
				}},
			}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "app", Ready: true, Started: &started, RestartCount: 0,
				Image: sentinel, ImageID: sentinel, ContainerID: sentinel,
				State:                corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: t1}},
				LastTerminationState: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: sentinel, Message: sentinel}},
			}},
		},
	}
}

// keyPaths lists every JSON key path in v, with array indices removed, so a
// response can be compared against the projection's field table.
func keyPaths(prefix string, v any, into map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			into[p] = true
			keyPaths(p, child, into)
		}
	case []any:
		for _, child := range x {
			keyPaths(prefix, child, into)
		}
	}
}

func containerStatusPaths(list string) []string {
	var out []string
	for _, f := range []string{"", ".name", ".ready", ".started", ".restartCount", ".state", ".lastState"} {
		out = append(out, list+f)
	}
	for _, s := range []string{".state", ".lastState"} {
		for _, f := range []string{".waiting", ".running", ".running.startedAt", ".terminated", ".terminated.exitCode", ".terminated.signal", ".terminated.startedAt", ".terminated.finishedAt"} {
			out = append(out, list+s+f)
		}
	}
	return out
}

// The pod route serves a fixed projection: the pod's identity and the
// kubelet's progress fields, with nothing kubelet copied from the spec,
// termination files, logs or the node's addresses.
func TestPodRouteServesOnlyTheStatusProjection(t *testing.T) {
	pod := leakyPod()
	list, err := json.Marshal(corev1.PodList{Items: []corev1.Pod{pod}})
	if err != nil {
		t.Fatal(err)
	}
	h := Handler{UID: "u1", Pods: func(ctx context.Context) ([]byte, error) { return list, nil }}
	rec := serve(h, http.MethodGet, PodPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if strings.Contains(body, sentinel) {
		t.Fatalf("response carries a field the projection excludes:\n%s", body)
	}

	allowed := map[string]bool{}
	for _, p := range append([]string{
		"metadata", "metadata.uid", "metadata.namespace", "metadata.name",
		"status", "status.phase", "status.startTime",
		"status.conditions", "status.conditions.type", "status.conditions.status", "status.conditions.lastTransitionTime",
	}, append(containerStatusPaths("status.initContainerStatuses"), containerStatusPaths("status.containerStatuses")...)...) {
		allowed[p] = true
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	keyPaths("", raw, got)
	var extra []string
	for p := range got {
		if !allowed[p] {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)
	if len(extra) != 0 {
		t.Fatalf("response carries keys outside the projection: %v", extra)
	}

	// The projection keeps v1 Pod names and types, so a client decodes it as one.
	var back corev1.Pod
	if err := json.Unmarshal(rec.Body.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Name != "app" || back.Namespace != "tenant" || string(back.UID) != "u1" || back.Status.Phase != corev1.PodRunning {
		t.Fatalf("identity and phase: %+v", back.ObjectMeta)
	}
	if back.Status.StartTime == nil || !back.Status.StartTime.Equal(pod.Status.StartTime) {
		t.Fatalf("startTime = %v", back.Status.StartTime)
	}
	if c := back.Status.Conditions; len(c) != 1 || c[0].Type != corev1.PodReady || c[0].Status != corev1.ConditionTrue || !c[0].LastTransitionTime.Equal(&pod.Status.Conditions[0].LastTransitionTime) {
		t.Fatalf("conditions = %+v", c)
	}
	init := back.Status.InitContainerStatuses
	if len(init) != 1 || init[0].Name != "init" || !init[0].Ready || init[0].RestartCount != 2 || init[0].Started != nil {
		t.Fatalf("init status = %+v", init)
	}
	if tm := init[0].State.Terminated; tm == nil || tm.ExitCode != 0 || tm.StartedAt.IsZero() || tm.FinishedAt.IsZero() {
		t.Fatalf("init state = %+v", init[0].State)
	}
	if tm := init[0].LastTerminationState.Terminated; tm == nil || tm.ExitCode != 137 || tm.Signal != 9 {
		t.Fatalf("init lastState = %+v", init[0].LastTerminationState)
	}
	app := back.Status.ContainerStatuses
	if len(app) != 1 || app[0].Name != "app" || app[0].Started == nil || !*app[0].Started || app[0].State.Running == nil || app[0].State.Running.StartedAt.IsZero() {
		t.Fatalf("app status = %+v", app)
	}
	if app[0].LastTerminationState.Waiting == nil || app[0].LastTerminationState.Running != nil || app[0].LastTerminationState.Terminated != nil {
		t.Fatalf("app lastState = %+v", app[0].LastTerminationState)
	}

	// Literal shapes the field table fixes: waiting is an empty object, a
	// zero exit code is still reported, and a zero restart count too.
	for _, want := range []string{`"waiting":{}`, `"exitCode":0`, `"restartCount":0`} {
		if !strings.Contains(body, want) {
			t.Errorf("response lacks %s:\n%s", want, body)
		}
	}
}

// Fields the kubelet has not filled yet are omitted rather than served as
// zero values, and a container state with no member is omitted.
func TestProjectionOmitsAbsentFields(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", UID: "u1"}}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app"}}
	body, err := json.Marshal(ProjectPod(&pod))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"metadata":{"uid":"u1","name":"app"},"status":{"containerStatuses":[{"name":"app","ready":false,"restartCount":0}]}}`
	if string(body) != want {
		t.Fatalf("projection = %s\nwant         %s", body, want)
	}
}

// A state that names several members, which kubelet never emits, is served
// as the one furthest along, so the response still carries at most one.
func TestProjectionKeepsOneStateMember(t *testing.T) {
	s := corev1.ContainerState{
		Waiting:    &corev1.ContainerStateWaiting{},
		Running:    &corev1.ContainerStateRunning{},
		Terminated: &corev1.ContainerStateTerminated{ExitCode: 1},
	}
	body, err := json.Marshal(projectState(s))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"terminated":{"exitCode":1}}`; string(body) != want {
		t.Fatalf("state = %s, want %s", body, want)
	}
	if projectState(corev1.ContainerState{}) != nil {
		t.Fatal("empty state must project to nothing")
	}
}
