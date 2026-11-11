package podprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// labelled is a running instance carrying the provider and allocation labels
// of the record key.
func labelled(id, provider, key string) instance {
	return instance{ID: id, Status: "running", Labels: map[string]string{providerLabel: provider, allocationLabel: strings.TrimPrefix(key, recordPrefix)}}
}

func TestInstanceSweepLeavesALaunchedPodsInstance(t *testing.T) {
	pod := fixturePod()
	r, cloud, _ := fixture(t, pod)
	runToRunning(t, r, pod)
	if err := r.sweepInstances(t.Context()); err != nil {
		t.Fatal(err)
	}
	if cloud.deleteCalls != 0 || cloud.createCalls != 1 {
		t.Fatalf("deletes %d creates %d: the sweep touched an instance its record owns", cloud.deleteCalls, cloud.createCalls)
	}
}

func TestInstanceSweepDestroysOnlyARecordlessInstanceOfItsOwn(t *testing.T) {
	const provider = "test-provider"
	orphan := identityKey(provider, "a pod whose record is gone")
	for name, tc := range map[string]struct {
		in      instance
		prepare func(*testing.T, *Reconciler, string)
		deleted bool
		fails   bool
	}{
		"no record":                 {in: labelled("i-orphan", provider, orphan), deleted: true},
		"another provider":          {in: labelled("i-other", "other-provider", orphan)},
		"no allocation label":       {in: instance{ID: "i-bare", Status: "running", Labels: map[string]string{providerLabel: provider}}},
		"malformed allocation":      {in: instance{ID: "i-odd", Status: "running", Labels: map[string]string{providerLabel: provider, allocationLabel: "../" + strings.Repeat("a", 37)}}},
		"terminated":                {in: instance{ID: "i-ended", Status: "terminated", Labels: labelled("", provider, orphan).Labels}},
		"no identity":               {in: labelled("", provider, orphan)},
		"record naming no instance": {in: labelled("i-unrecorded", provider, identityKey(provider, string(fixturePod().UID))), prepare: writeRecord},
		"unreadable record":         {in: labelled("i-unreadable", provider, orphan), prepare: writeUnreadableRecord, fails: true},
		"failed record read":        {in: labelled("i-unread", provider, orphan), prepare: failRecordReads, fails: true},
	} {
		t.Run(name, func(t *testing.T) {
			pod := fixturePod()
			r, cloud := fixtureReconciler(t, pod)
			// The record is written while the listing is in flight: the sweep
			// reads records only afterwards.
			cloud.list = func() ([]instance, error) {
				if tc.prepare != nil {
					tc.prepare(t, r, orphan)
				}
				return []instance{tc.in}, nil
			}
			err := r.sweepInstances(t.Context())
			if (err != nil) != tc.fails {
				t.Fatalf("sweep error %v", err)
			}
			if got := slices.Contains(cloud.deleted, tc.in.ID); got != tc.deleted || cloud.createCalls != 0 || len(cloud.deleted) > 1 {
				t.Fatalf("deleted %v creates %d, want deletion %t and no create", cloud.deleted, cloud.createCalls, tc.deleted)
			}
		})
	}
}

func writeRecord(t *testing.T, r *Reconciler, _ string) {
	t.Helper()
	rec, _, err := r.ensureRecord(t.Context(), fixturePod())
	if err != nil || rec.InstanceID != "" {
		t.Fatalf("record %v, error %v", rec, err)
	}
}

func writeUnreadableRecord(t *testing.T, r *Reconciler, key string) {
	t.Helper()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key, Namespace: r.cfg.Namespace}, Data: map[string][]byte{"state.json": []byte("{")}}
	if err := r.client.Create(t.Context(), secret); err != nil {
		t.Fatal(err)
	}
}

func failRecordReads(t *testing.T, r *Reconciler, _ string) {
	t.Helper()
	r.client = interceptor.NewClient(r.client.(client.WithWatch), interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
		return errors.New("api server unavailable")
	}})
}

func TestInstanceSweepWaitsForTheProvidersNode(t *testing.T) {
	r, cloud := fixtureReconciler(t, fixturePod())
	cloud.list = func() ([]instance, error) {
		t.Error("instances listed without the provider's node")
		return nil, nil
	}
	r.ownsNode = func(context.Context) error { return errors.New("node is not this provider's") }
	if err := r.sweepInstances(t.Context()); err == nil || len(cloud.deleted) != 0 {
		t.Fatalf("error %v, deleted %v", err, cloud.deleted)
	}
}

func TestInstanceSweepRetriesAnOrphanUntilItIsGone(t *testing.T) {
	r, cloud := fixtureReconciler(t, fixturePod())
	orphan := labelled("i-orphan", r.cfg.ProviderID, identityKey(r.cfg.ProviderID, "gone"))
	cloud.list = func() ([]instance, error) { return []instance{orphan}, nil }
	for range 2 {
		if err := r.sweepInstances(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// Cloud lists a terminated instance no longer; the sweep then asks nothing.
	cloud.list = func() ([]instance, error) { return nil, nil }
	if err := r.sweepInstances(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cloud.deleted, []string{"i-orphan", "i-orphan"}) {
		t.Fatalf("deleted %v", cloud.deleted)
	}
}

func TestCloudListFollowsEveryPageOfTheProvidersInstances(t *testing.T) {
	pages := map[string]string{
		"":    `{"items":[{"id":"i-one"}],"nextPageToken":"two"}`,
		"two": `{"items":[{"id":"i-two"},{"id":"i-three"}]}`,
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/v1/instances" || !slices.Equal(q["label"], []string{"podcvm-provider=a provider&id"}) || q.Has("status") {
			t.Errorf("wrong listing %s %s", r.Method, r.URL)
		}
		_, _ = io.WriteString(w, pages[q.Get("pageToken")])
	}))
	defer srv.Close()
	c := newCloudClient(&Config{CloudURL: srv.URL, token: "test"})
	c.http.Transport = srv.Client().Transport
	got, err := c.List(t.Context(), "a provider&id")
	if err != nil || len(got) != 3 || got[0].ID != "i-one" || got[2].ID != "i-three" {
		t.Fatalf("instances %v, error %v", got, err)
	}
	pages["two"] = `{"items":[],"nextPageToken":"two"}`
	if _, err := c.List(t.Context(), "a provider&id"); err == nil {
		t.Fatal("a listing that repeats its page token never ends")
	}
	pages["two"] = `{`
	if got, err := c.List(t.Context(), "a provider&id"); err == nil || got != nil {
		t.Fatalf("a failed page returned %v", got)
	}
}
