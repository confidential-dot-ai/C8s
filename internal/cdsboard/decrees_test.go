package cdsboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsboard/boardtest"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// testIntent is a decree's name, as `c8s cds ha decree` writes one.
const testIntent = "5kx7ay3mqz2bd4nf6pvtwjhrgs"

// decreeObject is one signed decree as the operator uploads it.
func decreeObject(t *testing.T, intent string) []byte {
	t.Helper()
	object, err := json.Marshal(cdsdecree.Signed{
		Decree: cdsdecree.Decree{
			ClusterID: testClusterID,
			IntentID:  intent,
			Kind:      cdsdecree.RotateKey,
			ExpiresAt: time.Now().Add(time.Hour),
		},
		Signature: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	return object
}

// holds puts one of this cluster's objects on the board.
func holds(board *boardtest.Server, key string, object []byte) {
	board.Put(testPrefix+"/"+testClusterID+"/"+key, object)
}

// One cycle answers with the signed decrees the board holds, and passes over
// every object that is none: the store is outside the trust boundary, so what
// it serves beside them is no decree of the cluster's.
func TestOneCycleReadsTheSignedDecreesTheBoardHolds(t *testing.T) {
	board := startBoard(t)
	client := testClient(t, board)
	holds(board, "decrees/"+testIntent+".json", decreeObject(t, testIntent))
	holds(board, "decrees/junk.json", []byte("{"))
	holds(board, "decrees/big.json", bytes.Repeat([]byte("x"), maxDecreeBytes+1))

	decrees, err := client.Decrees(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	if len(decrees) != 1 || decrees[0].Decree.IntentID != testIntent {
		t.Fatalf("the cycle read %+v", decrees)
	}
}

// A board holding more objects than a cycle reads still hands the cluster
// decrees: whoever can write to the store could otherwise leave objects on it
// until no decree of the operator is read at all.
func TestABoardOverTheCyclesBoundStillHandsOutDecrees(t *testing.T) {
	board := startBoard(t)
	client := testClient(t, board)
	for i := range maxObjectsPerCycle + 10 {
		holds(board, fmt.Sprintf("decrees/%03d.json", i), decreeObject(t, fmt.Sprintf("decree%020d", i)))
	}

	decrees, err := client.Decrees(context.Background())

	if err != nil {
		t.Fatal(err)
	}
	if len(decrees) != maxObjectsPerCycle {
		t.Fatalf("the cycle read %d decrees of a board holding %d", len(decrees), maxObjectsPerCycle+10)
	}
}

// A listed object the store does not serve is one the cluster could not read:
// a decree gone since the listing is no decree, and a store that fails is
// reported rather than answered as a board holding fewer decrees.
func TestAnObjectTheStoreDoesNotServeIsNoDecree(t *testing.T) {
	board := startBoard(t)
	client := testClientFrom(t, board, "127.0.0.2")
	holds(board, "decrees/"+testIntent+".json", decreeObject(t, testIntent))
	board.View("127.0.0.2").Withhold(testPrefix + "/" + testClusterID + "/decrees/" + testIntent + ".json")

	decrees, err := client.Decrees(context.Background())

	if err != nil || len(decrees) != 0 {
		t.Fatalf("the cycle read %+v: %v", decrees, err)
	}
}
