package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const createBody = `{"image":"c8s-pod@1","tee":"tdx","labels":{"podcvm-provider":"p","podcvm-uid":"u"},"network":{"ingress":[{"name":"pod-status","port":8443}]}}`

// request sends one call and decodes a JSON answer into out when given.
func request(t *testing.T, h http.Handler, method, path, key, body string, out any) int {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer token")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s answered %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code
}

type listing struct {
	Items []instance `json:"items"`
}

func TestCreateIsIdempotentAndDeleteTerminates(t *testing.T) {
	h := new(cloud).handler()
	var first, second, found listing
	if code := request(t, h, "POST", "/v1/instances", "key-1", createBody, &first); code != http.StatusCreated {
		t.Fatalf("create answered %d", code)
	}
	request(t, h, "POST", "/v1/instances", "key-1", createBody, &second)
	if len(first.Items) != 1 || second.Items[0].ID != first.Items[0].ID {
		t.Fatalf("a replayed create answered %+v after %+v", second.Items, first.Items)
	}
	in := first.Items[0]
	if in.Status != "running" || in.Boot.Count != 1 || in.Image.Family != "c8s-pod" || len(in.Endpoints) != 1 {
		t.Fatalf("created instance: %+v", in)
	}
	request(t, h, "GET", "/v1/instances?idempotencyKey=key-2", "", "", &found)
	if len(found.Items) != 0 {
		t.Fatalf("a lookup under another key found %+v", found.Items)
	}
	if code := request(t, h, "DELETE", "/v1/instances/"+in.ID, "", "", nil); code != http.StatusAccepted {
		t.Fatalf("delete answered %d", code)
	}
	var got instance
	request(t, h, "GET", "/v1/instances/"+in.ID, "", "", &got)
	if got.Status != "terminated" {
		t.Fatalf("a deleted instance reports %q", got.Status)
	}
}

func TestBehaviourShapesTheAnswers(t *testing.T) {
	h := new(cloud).handler()
	set := func(b string) {
		t.Helper()
		if code := request(t, h, "PUT", "/control/behaviour", "", b, nil); code != http.StatusOK {
			t.Fatalf("behaviour %s answered %d", b, code)
		}
	}
	set(`{"create":{"status":403,"code":"quota_exceeded"}}`)
	var refusal map[string]string
	if code := request(t, h, "POST", "/v1/instances", "key-1", createBody, &refusal); code != http.StatusForbidden || refusal["code"] != "quota_exceeded" {
		t.Fatalf("a refused create answered %d %v", code, refusal)
	}
	set(`{"status":"starting","bootCount":2,"foreignLabels":true}`)
	var created listing
	request(t, h, "POST", "/v1/instances", "key-1", createBody, &created)
	in := created.Items[0]
	if in.Status != "starting" || in.Boot.Count != 2 || in.Labels["podcvm-provider"] != "another-provider" {
		t.Fatalf("reported instance: %+v", in)
	}
	set(`{"gone":true}`)
	if code := request(t, h, "GET", "/v1/instances/"+in.ID, "", "", nil); code != http.StatusNotFound {
		t.Fatalf("a gone instance answered %d", code)
	}
	set(`{"outage":true}`)
	if code := request(t, h, "GET", "/v1/instances?pageSize=1", "", "", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("an outage answered %d", code)
	}
	set(`{"lingering":true}`)
	request(t, h, "DELETE", "/v1/instances/"+in.ID, "", "", nil)
	var held []instance
	request(t, h, "GET", "/control/instances", "", "", &held)
	if len(held) != 1 || held[0].Status != "terminating" {
		t.Fatalf("a lingering delete left %+v", held)
	}
	var calls []call
	request(t, h, "GET", "/control/calls", "", "", &calls)
	if len(calls) != 5 || calls[0].IdempotencyKey != "key-1" || calls[0].Method != "POST" {
		t.Fatalf("recorded calls: %+v", calls)
	}
}
