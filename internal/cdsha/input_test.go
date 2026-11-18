package cdsha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	ktesting "k8s.io/client-go/testing"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

func inputStore(t *testing.T, s *set) (*Kube, *fake.Clientset) {
	t.Helper()
	client := fake.NewClientset()
	store := &Kube{ConfigMaps: client.CoreV1().ConfigMaps("c8s-cds"), Cluster: "lane"}
	for _, e := range s.chainOf(0) {
		raw, _ := e.Encode()
		if err := store.PutEntry(context.Background(), e.Hash(), raw); err != nil {
			t.Fatal(err)
		}
	}
	head, _ := json.Marshal(s.node(0).State().Head)
	if err := store.CASHead(context.Background(), nil, head); err != nil {
		t.Fatal(err)
	}
	s.node(0).setStore(store)
	return store, client
}

func setInput(t *testing.T, store *Kube, raw []byte) {
	t.Helper()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-input"},
		BinaryData: map[string][]byte{"entry": raw},
	}
	if _, err := store.ConfigMaps.Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		if _, err := store.ConfigMaps.Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInputPolicyAndHistoricalRetry(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	store, client := inputStore(t, s)
	p := inputPoller{name: "policy-input"}
	e, policy := s.policyEntry(s.node(0).State().Head, "app")
	raw, _ := e.Encode()
	// The limit covers the entire encoded file, including JSON whitespace.
	raw = append(raw, bytes.Repeat([]byte{' '}, MaxKubeEntry-len(raw))...)
	setInput(t, store, raw)
	client.ClearActions()
	for range 3 {
		if got, retry := p.poll(context.Background(), s.node(0).Replica); got.outcome != "confirmed" || retry {
			t.Fatalf("poll = %+v, retry=%v", got, retry)
		}
	}
	if state := s.node(0).State(); state.Head.Seq != 1 || !bytes.Equal(state.Policy, policy) {
		t.Fatalf("policy was not applied once: %+v", state.Head)
	}
	later, _ := s.policyEntry(s.node(0).State().Head, "new")
	if _, done, err := s.node(0).Submit(context.Background(), later); err != nil || !done {
		t.Fatalf("later write: %v, done=%v", err, done)
	}
	// A new poller models a consumer restart; old input must not reactivate policy.
	p = inputPoller{name: "policy-input"}
	if got, _ := p.poll(context.Background(), s.node(0).Replica); got.outcome != "confirmed" || s.node(0).State().Head.Hash != later.Hash() {
		t.Fatalf("historical retry: %+v", got)
	}
	client.PrependReactor("get", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.(ktesting.GetAction).GetName() == "cds-lane-head" {
			return true, nil, errors.New("a cached result must not submit again")
		}
		return false, nil, nil
	})
	if got, retry := p.poll(context.Background(), s.node(0).Replica); got.outcome != "confirmed" || retry {
		t.Fatalf("confirmed input was resubmitted: %+v", got)
	}
	for _, action := range client.Actions() {
		if a, ok := action.(interface{ GetName() string }); ok && a.GetName() == "policy-input" && action.GetVerb() != "get" {
			t.Fatalf("consumer modified its input: %v", action)
		}
		if a, ok := action.(interface{ GetObject() runtime.Object }); ok && a.GetObject().(*corev1.ConfigMap).Name == "policy-input" {
			t.Fatalf("consumer wrote its input: %v", action)
		}
		if action.GetVerb() == "list" || action.GetVerb() == "watch" {
			t.Fatalf("unexpected broad input access: %v", action)
		}
	}
}

func TestInputRefusesInvalidArtifacts(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	store, _ := inputStore(t, s)
	head := s.node(0).State().Head
	e, _ := s.policyEntry(head, "app")
	raw, _ := e.Encode()
	badSig := e
	badSig.Sig = "bad"
	bad, _ := badSig.Encode()
	body, _ := e.Decode()
	body.Cluster = "other"
	foreign, _ := s.sign(body).Encode()
	genesis, _ := s.genesis.Encode()
	keys, _ := s.entry(head, 0).Encode()
	for name, data := range map[string][]byte{
		"signature": bad,
		"cluster":   foreign,
		"genesis":   genesis,
		"keys":      keys,
		"trailing":  append(bytes.Clone(raw), []byte(` {}`)...),
		"unknown":   append([]byte(`{"unknown":1,`), raw[1:]...),
		"duplicate": append([]byte(`{"sig":"other",`), raw[1:]...),
		"oversize":  bytes.Repeat([]byte{' '}, MaxKubeEntry+1),
	} {
		t.Run(name, func(t *testing.T) {
			setInput(t, store, data)
			p := inputPoller{name: "policy-input"}
			if got, retry := p.poll(context.Background(), s.node(0).Replica); got.outcome != "invalid" || retry {
				t.Fatalf("poll = %+v, retry=%v", got, retry)
			}
			if s.node(0).State().Head != head {
				t.Fatal("invalid input changed accepted state")
			}
		})
	}
	setInput(t, store, raw)
	cm, _ := store.ConfigMaps.Get(context.Background(), "policy-input", metav1.GetOptions{})
	cm.Data = map[string]string{"entry": string(raw)}
	if _, err := store.ConfigMaps.Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	p := inputPoller{name: "policy-input"}
	if got, _ := p.poll(context.Background(), s.node(0).Replica); got.reason != "input_shape_or_size" {
		t.Fatalf("accepted ambiguous input: %+v", got)
	}
}

func TestInputRetriesLagAndUsesReplacementStore(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	store, _ := inputStore(t, s)
	first, _ := s.policyEntry(s.node(0).State().Head, "first")
	b, _ := first.Decode()
	second, _ := s.policyEntry(cdschain.Head{V: b.V, Cluster: b.Cluster, Seq: b.Seq, Hash: first.Hash()}, "second")
	raw, _ := second.Encode()
	setInput(t, store, raw)
	p := inputPoller{name: "policy-input"}
	if got, retry := p.poll(context.Background(), s.node(0).Replica); got.outcome != "unconfirmed" || !retry {
		t.Fatalf("lag was terminal: %+v, retry=%v", got, retry)
	}
	if _, _, err := s.node(0).Submit(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if got, retry := p.poll(context.Background(), s.node(0).Replica); got.outcome != "confirmed" || retry {
		t.Fatalf("unchanged input did not recover: %+v, retry=%v", got, retry)
	}
	// Credential replacement swaps the Kube client; the next poll must use it.
	replacement, _ := inputStore(t, s)
	third := s.routes(s.node(0).State().Head, 1)
	raw, _ = third.Encode()
	setInput(t, replacement, raw)
	if got, _ := p.poll(context.Background(), s.node(0).Replica); got.outcome != "confirmed" || s.node(0).State().Head.Hash != third.Hash() {
		t.Fatalf("replacement store was ignored: %+v", got)
	}
}

type unavailableInput struct {
	corev1client.ConfigMapInterface
	polled chan struct{}
}

func (c unavailableInput) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.ConfigMap, error) {
	if name == "policy-input" {
		select {
		case c.polled <- struct{}{}:
		default:
		}
	}
	return nil, context.DeadlineExceeded
}

func TestInputWaitsForServingAndCancels(t *testing.T) {
	s := newSet(t, 1)
	p := inputPoller{name: "policy-input"}
	if got, retry := p.poll(context.Background(), s.node(0).Replica); got.reason != "replica_not_serving" || !retry {
		t.Fatalf("pending replica consumed input: %+v", got)
	}
	s.bootstrap()
	polled := make(chan struct{}, 1)
	s.node(0).setStore(&Kube{ConfigMaps: unavailableInput{polled: polled}, Cluster: "lane"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.node(0).consumeInput(ctx, "policy-input"); close(done) }()
	<-polled
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("input backoff ignored cancellation")
	}
}

func TestInputConfiguration(t *testing.T) {
	cfg := Config{Cluster: "lane", InputConfigMap: "policy-input", StoreTimeout: time.Second}
	if err := validateInput(cfg, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Bad_Name", "cds-lane-head", "cds-lane-e-" + strings.Repeat("a", 64)} {
		bad := cfg
		bad.InputConfigMap = name
		if err := validateInput(bad, nil); err == nil {
			t.Errorf("accepted input name %q", name)
		}
	}
	if err := validateInput(cfg, NewMemory()); err == nil {
		t.Fatal("accepted non-Kubernetes store")
	}
	cfg.StoreTimeout = 0
	if err := validateInput(cfg, nil); err == nil {
		t.Fatal("accepted unbounded input calls")
	}
}

func TestInputRetriesUncertainCommit(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	store, client := inputStore(t, s)
	e, _ := s.policyEntry(s.node(0).State().Head, "app")
	raw, _ := e.Encode()
	setInput(t, store, raw)
	client.PrependReactor("update", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		obj := a.(ktesting.UpdateAction).GetObject()
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), obj, "c8s-cds"); err != nil {
			return true, nil, err
		}
		return true, nil, errors.New("lost write response")
	})
	p := inputPoller{name: "policy-input"}
	if got, retry := p.poll(context.Background(), s.node(0).Replica); got.outcome != "unconfirmed" || !retry {
		t.Fatalf("uncertain commit cached: %+v, retry=%v", got, retry)
	}
	if got, retry := p.poll(context.Background(), s.node(0).Replica); got.outcome != "confirmed" || retry {
		t.Fatalf("unchanged artifact did not confirm: %+v, retry=%v", got, retry)
	}
	if s.node(0).State().Head.Seq != 1 {
		t.Fatal("retry appended the entry twice")
	}
}

func TestInputCacheUsesPreSubmissionHead(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	store, _ := inputStore(t, s)
	head := s.node(0).State().Head
	e, _ := s.policyEntry(head, "app")
	raw, _ := e.Encode()
	setInput(t, store, raw)
	p := inputPoller{name: "policy-input"}
	if got, _ := p.poll(context.Background(), s.node(0).Replica); got.outcome != "confirmed" || p.last.head != head {
		t.Fatalf("result cached under a later head: %+v", got)
	}
	if got, _ := p.poll(context.Background(), s.node(0).Replica); got.outcome != "confirmed" || p.last.head != s.node(0).State().Head {
		t.Fatalf("cache did not reach the current head: %+v", got)
	}
	// Same body, different signature has the same entry hash, but is a conflict.
	body, _ := e.Decode()
	raw, _ = s.sign(body).Encode()
	setInput(t, store, raw)
	if got, _ := p.poll(context.Background(), s.node(0).Replica); got.outcome != "conflicting" {
		t.Fatalf("new signature bypassed validation: %+v", got)
	}
}
