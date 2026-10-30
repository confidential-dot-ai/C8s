//go:build integration

// The board client against a real object store: the lane
// (test/integration/cdsboard/run.sh) runs an S3-compatible store, puts its
// certificate where this client's system roots read it, and names it in the
// environment. What is under test is the requests this client makes, which a
// store other than the one in test code answers.
package cdsboard

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
)

// The board of the lane's cluster: the directory an operator leaves decrees
// in, and the one decree this lane writes there. A run overwrites what the
// last one left, as an operator who uploads a decree twice does.
const (
	laneDecrees   = "decrees"
	laneDecreeKey = laneDecrees + "/lane.json"
	laneDecree    = `{"decree":{"kind":"Genesis"}}`
)

// anotherCluster is a cluster whose board lies in the same store, under its
// own path.
const anotherCluster = "another-cluster"

// theLanesStore is the store the lane runs, named as a cluster's
// configuration names it, and the cluster whose board lies in it.
func theLanesStore(t *testing.T) (cdsconfig.Board, string) {
	t.Helper()
	board := cdsconfig.Board{
		Endpoint: os.Getenv("C8S_BOARD_ENDPOINT"),
		Bucket:   os.Getenv("C8S_BOARD_BUCKET"),
		Prefix:   os.Getenv("C8S_BOARD_PREFIX"),
	}
	cluster := os.Getenv("C8S_BOARD_CLUSTER")
	if board.Endpoint == "" || board.Bucket == "" || cluster == "" {
		t.Fatal("this lane runs against the store C8S_BOARD_ENDPOINT, C8S_BOARD_BUCKET and C8S_BOARD_CLUSTER name; test/integration/cdsboard/run.sh starts one and sets them")
	}
	return board, cluster
}

// laneClient addresses the board of the lane's own cluster as a replica of it
// does: over HTTPS, with the system roots and no credentials.
func laneClient(t *testing.T) *Client {
	t.Helper()
	board, cluster := theLanesStore(t)
	return clientFor(t, board, cluster)
}

func clientFor(t *testing.T, board cdsconfig.Board, cluster string) *Client {
	t.Helper()
	client, err := New(board, cluster)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// An operator leaves a decree in the store and the cluster's replicas read
// it: a listing of the cluster's own decrees, then the object itself, whole.
func TestARealStoreCarriesTheDecreesOfACluster(t *testing.T) {
	client := laneClient(t)
	ctx := context.Background()

	if err := client.Put(ctx, laneDecreeKey, []byte(laneDecree)); err != nil {
		t.Fatalf("Put %s: %v", laneDecreeKey, err)
	}
	listed, err := client.List(ctx, laneDecrees)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := Object{
		Key:  laneDecreeKey,
		Size: int64(len(laneDecree)),
	}
	if !containsObject(listed, want) {
		t.Fatalf("List = %+v, want it to name %+v", listed, want)
	}
	read, err := client.Get(ctx, laneDecreeKey, maxDecreeBytes)
	if err != nil || !bytes.Equal(read, []byte(laneDecree)) {
		t.Fatalf("Get %s = %q, %v", laneDecreeKey, read, err)
	}
}

// Every cluster's board lies under its own path of one bucket, so a replica
// reads the decrees of its own cluster and never another's.
func TestARealStoreKeepsTheBoardsOfTwoClustersApart(t *testing.T) {
	ctx := context.Background()
	board, _ := theLanesStore(t)
	ours := laneClient(t)
	theirs := clientFor(t, board, anotherCluster)

	if err := theirs.Put(ctx, laneDecreeKey, []byte(laneDecree)); err != nil {
		t.Fatalf("Put %s: %v", laneDecreeKey, err)
	}
	if err := ours.Put(ctx, laneDecreeKey, []byte(laneDecree)); err != nil {
		t.Fatalf("Put %s: %v", laneDecreeKey, err)
	}
	listed, err := ours.List(ctx, laneDecrees)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("this cluster's board names %+v, want its own decree alone", listed)
	}
}

// A board holds no object the operator did not leave there: a replica reads
// the board at every cycle, and reads nothing from one it has not written to.
func TestARealStoreAnswersForWhatItDoesNotHold(t *testing.T) {
	client := laneClient(t)

	_, err := client.Get(context.Background(), laneDecrees+"/never-written.json", maxDecreeBytes)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get of an object the store does not hold = %v, want it to hold nothing there", err)
	}
}

func containsObject(listed []Object, want Object) bool {
	for _, object := range listed {
		if object == want {
			return true
		}
	}
	return false
}
