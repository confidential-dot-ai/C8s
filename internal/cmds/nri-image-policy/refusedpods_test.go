package nriimagepolicy

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// The delete names the refused pod instance, so a replacement that reuses the
// name stays.
func TestNodeDeleteNamesTheRefusedPodInstance(t *testing.T) {
	pod := meshPod("tenant", "inference-0", testNetNS)
	pod.Uid = refusedPodUID
	client := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: pod.GetNamespace(),
		Name:      pod.GetName(),
		UID:       types.UID(pod.GetUid()),
	}})

	if err := deletePodInstance(context.Background(), client.CoreV1(), pod); err != nil {
		t.Fatalf("delete the refused pod: %v", err)
	}

	actions := client.Actions()
	if len(actions) != 1 {
		t.Fatalf("the enforcer made %d API calls, want one delete: %+v", len(actions), actions)
	}
	deletion, isDelete := actions[0].(k8stesting.DeleteActionImpl)
	if !isDelete || deletion.GetNamespace() != pod.GetNamespace() || deletion.GetName() != pod.GetName() {
		t.Fatalf("the enforcer called %+v, want a delete of %s/%s", actions[0], pod.GetNamespace(), pod.GetName())
	}
	precondition := deletion.GetDeleteOptions().Preconditions
	if precondition == nil || precondition.UID == nil || string(*precondition.UID) != refusedPodUID {
		t.Errorf("the delete carries preconditions %+v, want the refused pod's UID", precondition)
	}
}

const nodeAPIServer = "https://10.0.0.1:6443"

func nodeKubeconfigFile(t *testing.T, auth *clientcmdapi.AuthInfo) string {
	t.Helper()
	document := clientcmdapi.NewConfig()
	document.Clusters["node"] = &clientcmdapi.Cluster{Server: nodeAPIServer}
	document.AuthInfos["node"] = auth
	document.Contexts["node"] = &clientcmdapi.Context{Cluster: "node", AuthInfo: "node"}
	document.CurrentContext = "node"
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*document, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// The enforcer speaks to the API server its credentials name, not one its
// environment names.
func TestNodeCredentialsComeFromTheFileAlone(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.1.1.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	pods, err := nodePodClient(nodeKubeconfigFile(t, &clientcmdapi.AuthInfo{Token: "node"}))
	if err != nil {
		t.Fatalf("nodePodClient: %v", err)
	}
	if host := pods.RESTClient().Get().URL().Host; host != "10.0.0.1:6443" {
		t.Errorf("the client speaks to %q, want the API server the credentials name", host)
	}
}

func TestNodeCredentialsRefuseACredentialHelper(t *testing.T) {
	for name, auth := range map[string]*clientcmdapi.AuthInfo{
		"an exec helper": {Exec: &clientcmdapi.ExecConfig{
			APIVersion:      "client.authentication.k8s.io/v1",
			Command:         "/usr/local/bin/host-command",
			InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		}},
		"an auth provider": {AuthProvider: &clientcmdapi.AuthProviderConfig{Name: "host-provider"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := nodePodClient(nodeKubeconfigFile(t, auth))
			if err == nil || !strings.Contains(err.Error(), "credential helper") {
				t.Fatalf("err = %v, want the credential helper refused", err)
			}
		})
	}
}

func TestRefusedPodGone(t *testing.T) {
	pods := schema.GroupResource{Resource: "pods"}
	for name, err := range map[string]error{
		"the delete lands":                nil,
		"the pod is gone already":         apierrors.NewNotFound(pods, "inference-0"),
		"another instance holds the name": apierrors.NewConflict(pods, "inference-0", errors.New("the UID in the precondition does not match")),
	} {
		t.Run(name, func(t *testing.T) {
			if !refusedPodGone(err) {
				t.Errorf("refusedPodGone(%v) = false, want true", err)
			}
		})
	}
	t.Run("the API server refuses the delete", func(t *testing.T) {
		refused := apierrors.NewForbidden(pods, "inference-0", errors.New("not a pod of this node"))
		if refusedPodGone(refused) {
			t.Errorf("refusedPodGone(%v) = true, want false", refused)
		}
	})
}

// loggedLines reports lines as they are logged, so a test can wait for one.
type loggedLines struct {
	lines chan slog.Record
}

func (h loggedLines) Enabled(context.Context, slog.Level) bool { return true }
func (h loggedLines) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h loggedLines) WithGroup(string) slog.Handler            { return h }

func (h loggedLines) Handle(_ context.Context, record slog.Record) error {
	h.lines <- record
	return nil
}

func loggingPlugin() (*plugin, chan slog.Record) {
	p, _ := newCachedPlugin(&config{Policy: enforcing}, anyAllowlist(nil))
	lines := make(chan slog.Record, 8)
	p.logger = slog.New(loggedLines{lines: lines})
	return p, lines
}

func awaitPodNamed(t *testing.T, lines chan slog.Record, message string, pod *api.PodSandbox) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case line := <-lines:
			if line.Message == message {
				assertNamesPod(t, recordAttrs(line), pod)
				return
			}
		case <-deadline:
			t.Fatalf("the plugin never logged %q", message)
		}
	}
}

// A refused pod this node cannot delete is a line an operator acts on.
func TestARefusedPodNamesItselfWhenTheDeleteFails(t *testing.T) {
	pod := meshPod("tenant", "inference-0", testNetNS)
	p, lines := loggingPlugin()
	p.deletePod = func(context.Context, *api.PodSandbox) error {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, pod.GetName(), errors.New("not a pod of this node"))
	}

	p.removePodWithoutIdentity(pod, errRecoveryRefusedPod)
	awaitPodNamed(t, lines, podNotDeletedMessage, pod)
}

// So is a refused pod on a guest that holds no node identity.
func TestARefusedPodNamesItselfWithoutANodeIdentity(t *testing.T) {
	pod := meshPod("tenant", "inference-0", testNetNS)
	p, lines := loggingPlugin()

	p.removePodWithoutIdentity(pod, errRecoveryRefusedPod)
	awaitPodNamed(t, lines, podWithoutIdentityMessage, pod)
}

// A delete the API server is slow to answer does not hold up the NRI callback.
func TestARefusedPodDeleteRunsOffTheCallback(t *testing.T) {
	refused := meshPod("tenant", "inference-0", testNetNS)
	refused.Uid = refusedPodUID
	p, _ := newCachedPlugin(&config{Policy: enforcing}, anyAllowlist(nil))
	p.SetReady()
	answered := make(chan struct{})
	p.deletePod = func(context.Context, *api.PodSandbox) error {
		<-answered
		return nil
	}

	recovered := make(chan error, 1)
	go func() {
		_, err := p.Synchronize(context.Background(), []*api.PodSandbox{refused}, nil)
		recovered <- err
	}()
	select {
	case err := <-recovered:
		if err != nil {
			t.Fatalf("Synchronize: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Synchronize waited for the delete")
	}
	close(answered)
}

// A Pod guest enforces its one assigned pod and holds no node identity.
func TestOnlyANodeEnforcerDeletesARefusedPod(t *testing.T) {
	if node := testPlugin(t, &config{}); node.deletePod == nil {
		t.Error("a node enforcer deletes no pod it refuses for life")
	}
	if guest := testPlugin(t, &config{Pod: &podConfig{}}); guest.deletePod != nil {
		t.Error("a Pod guest holds a node delete")
	}
}
