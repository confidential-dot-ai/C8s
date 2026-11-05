package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-sealed-recovery/snpaccept"
)

func TestPipeCommitSurvivesProcessStateLoss(t *testing.T) {
	db := filepath.Join(t.TempDir(), "metadata.sqlite")
	key := strings.Repeat("ab", 32)
	request := func(method string, tx metadatapilot.Transaction) snpaccept.StorageRequest {
		data, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		path := metadatapilot.StateReadPath
		if method == "STATE_COMMIT" {
			path = metadatapilot.StateCommitPath
		}
		return snpaccept.StorageRequest{ID: 1, Method: method, Path: "/pilot/owned/metadata" + path, Data: data}
	}
	exchange := func(q snpaccept.StorageRequest) snpaccept.StorageResponse {
		var in, out bytes.Buffer
		if err := json.NewEncoder(&in).Encode(q); err != nil {
			t.Fatal(err)
		}
		// Each exchange opens and closes a fresh service with a fresh private
		// transport token. Only the durable metadata file survives.
		if err := serve(db, "owned", &in, &out); err != nil {
			t.Fatal(err)
		}
		var result snpaccept.StorageResponse
		if err := json.NewDecoder(&out).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	q := request("STATE_COMMIT", metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: key}}, Writes: []metadatapilot.Record{{Key: key, Version: "0000000000000001", Value: []byte("opaque encrypted state")}}})
	if got := exchange(q); got.Status != 204 {
		t.Fatalf("commit: %d", got.Status)
	}
	if got := exchange(q); got.Status != 412 {
		t.Fatalf("replay: %d", got.Status)
	}
	read := request("STATE_READ", metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: key}}})
	got := exchange(read)
	var records []metadatapilot.Record
	if got.Status != 200 || json.Unmarshal(got.Data, &records) != nil || len(records) != 1 || records[0].Version != "0000000000000001" || string(records[0].Value) != "opaque encrypted state" {
		t.Fatalf("cold read: %d %s", got.Status, got.Data)
	}
	for _, mutation := range []func(*snpaccept.StorageRequest){
		func(q *snpaccept.StorageRequest) { q.Path = "/pilot/other/metadata" + metadatapilot.StateReadPath },
		func(q *snpaccept.StorageRequest) { q.Method = "GET" },
		func(q *snpaccept.StorageRequest) { q.Match = "old" },
		func(q *snpaccept.StorageRequest) { q.ID = 0 },
	} {
		bad := read
		mutation(&bad)
		if got := exchange(bad); got.Status != http.StatusBadRequest {
			t.Fatalf("scope accepted: %d", got.Status)
		}
	}
	rollback := request("STATE_COMMIT", metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: key, Version: "0000000000000001"}}, Writes: []metadatapilot.Record{{Key: key, Version: "0000000000000001", Value: []byte("old ciphertext")}}})
	if got := exchange(rollback); got.Status != 400 {
		t.Fatalf("nonmonotonic version accepted: %d", got.Status)
	}
}

func TestPipeRejectsExtraJSON(t *testing.T) {
	if err := serve(filepath.Join(t.TempDir(), "state"), "owned", strings.NewReader("{} {}\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("multiple messages accepted")
	}
}
