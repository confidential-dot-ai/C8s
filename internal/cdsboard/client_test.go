package cdsboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsboard/boardtest"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

const (
	testBucket    = "c8s-boards"
	testPrefix    = "boards"
	testClusterID = "acme-prod"
	testDecreeKey = "decrees/5kx7.json"
)

func startBoard(t *testing.T) *boardtest.Server {
	t.Helper()
	board := boardtest.Start(testBucket)
	t.Cleanup(board.Close)
	return board
}

func testBoard(board *boardtest.Server) cdsconfig.Board {
	return cdsconfig.Board{
		Endpoint: board.Endpoint(),
		Bucket:   testBucket,
		Prefix:   testPrefix,
	}
}

func testClient(t *testing.T, board *boardtest.Server) *Client {
	t.Helper()
	client, err := newClient(testBoard(board), testClusterID, board.Transport())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// testClientFrom dials from clientIP, which the fake board reads as the
// client's identity.
func testClientFrom(t *testing.T, board *boardtest.Server, clientIP string) *Client {
	t.Helper()
	bound := board.Transport().Clone()
	bound.DialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientIP)}}).DialContext
	client, err := newClient(testBoard(board), testClusterID, bound)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// testClientOf answers every request with handler, as a store the host runs
// would.
func testClientOf(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	store := httptest.NewTLSServer(handler)
	t.Cleanup(store.Close)
	client, err := newClient(cdsconfig.Board{
		Endpoint: store.URL,
		Bucket:   testBucket,
		Prefix:   testPrefix,
	}, testClusterID, store.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestPutGetAndListOneClustersObjects(t *testing.T) {
	board := startBoard(t)
	client := testClient(t, board)
	decree := []byte(`{"intent":"genesis"}`)
	if err := client.Put(context.Background(), testDecreeKey, decree); err != nil {
		t.Fatal(err)
	}
	stored, held := board.Object("boards/acme-prod/" + testDecreeKey)
	if !held || !bytes.Equal(stored, decree) {
		t.Fatalf("the object under the cluster's own path = %q, %v", stored, held)
	}
	got, err := client.Get(context.Background(), testDecreeKey, 4096)
	if err != nil || !bytes.Equal(got, decree) {
		t.Fatalf("Get = %q, %v", got, err)
	}
	board.Put("boards/acme-prod/backups/one.sealed", []byte("sealed"))
	board.Put("boards/other-prod/"+testDecreeKey, []byte("another cluster's decree"))
	objects, err := client.List(context.Background(), "decrees")
	if err != nil {
		t.Fatal(err)
	}
	want := []Object{{
		Key:  testDecreeKey,
		Size: int64(len(decree)),
	}}
	if len(objects) != 1 || objects[0] != want[0] {
		t.Fatalf("List = %+v, want %+v", objects, want)
	}
}

func TestGetReportsAnObjectTheStoreDoesNotHold(t *testing.T) {
	client := testClient(t, startBoard(t))
	_, err := client.Get(context.Background(), testDecreeKey, 4096)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
}

func TestGetRefusesAnObjectOverItsBound(t *testing.T) {
	board := startBoard(t)
	board.Put("boards/acme-prod/"+testDecreeKey, bytes.Repeat([]byte("a"), 4096))
	object, err := testClient(t, board).Get(context.Background(), testDecreeKey, 1024)
	if object != nil || !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("Get = %d bytes, %v", len(object), err)
	}
}

func TestEveryCallRefusesAKeyOutsideTheClustersPath(t *testing.T) {
	for _, key := range []string{
		"",
		"/decrees/5kx7.json",
		"../other-prod/decrees/5kx7.json",
		"decrees/../../other-prod/5kx7.json",
		"decrees//5kx7.json",
		"decrees/5kx7 copy.json",
	} {
		t.Run(key, func(t *testing.T) {
			board := startBoard(t)
			client := testClient(t, board)
			if _, err := client.Get(context.Background(), key, 4096); err == nil {
				t.Error("Get read it")
			}
			if err := client.Put(context.Background(), key, []byte("object")); err == nil {
				t.Error("Put wrote it")
			}
			if _, err := client.List(context.Background(), key); err == nil {
				t.Error("List listed it")
			}
			if keys := board.Keys(); len(keys) != 0 {
				t.Fatalf("the store holds %v", keys)
			}
		})
	}
}

// A directory the client cannot list whole is refused: a listing in part
// would hide the objects beyond the bound.
// A key the store itself would refuse is refused here, where the cluster's
// own path is still part of it.
func TestEveryCallRefusesAKeyOverTheStoresKeyLength(t *testing.T) {
	board := startBoard(t)
	client := testClient(t, board)
	key := strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 100)+"/", 11), "/")
	if _, err := client.Get(context.Background(), key, 4096); err == nil {
		t.Error("Get read it")
	}
	if err := client.Put(context.Background(), key, []byte("object")); err == nil {
		t.Error("Put wrote it")
	}
	if keys := board.Keys(); len(keys) != 0 {
		t.Fatalf("the store holds %v", keys)
	}
}

func TestListRefusesADirectoryOverItsKeyBound(t *testing.T) {
	board := startBoard(t)
	for i := range maxListKeys + 5 {
		board.Put(fmt.Sprintf("boards/acme-prod/backups/%04d.sealed", i), []byte("sealed"))
	}
	objects, err := testClient(t, board).List(context.Background(), "backups")
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("List = %d objects, %v, want the key bound refused", len(objects), err)
	}
}

func TestListRefusesAFloodedListing(t *testing.T) {
	client := testClientOf(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<ListBucketResult>")
		for i := range 20000 {
			fmt.Fprintf(w, "<Contents><Key>boards/acme-prod/backups/%06d.sealed</Key><Size>7</Size></Contents>", i)
		}
		fmt.Fprint(w, "</ListBucketResult>")
	})
	_, err := client.List(context.Background(), "backups")
	if !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("List = %v, want the listing bound", err)
	}
}

// A listing names only what this client can address: another cluster's keys
// and keys it could not read back are left out.
func TestListPassesOverTheKeysItCannotAddress(t *testing.T) {
	client := testClientOf(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<ListBucketResult>`+
			`<Contents><Key>boards/other-prod/decrees/5kx7.json</Key><Size>7</Size></Contents>`+
			`<Contents><Key>boards/acme-prod/decrees/../../escape.json</Key><Size>7</Size></Contents>`+
			`<Contents><Key>boards/acme-prod/decrees/5kx7.json</Key><Size>7</Size></Contents>`+
			`</ListBucketResult>`)
	})
	objects, err := client.List(context.Background(), "decrees")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].Key != testDecreeKey {
		t.Fatalf("List = %+v, want this cluster's one key", objects)
	}
}

func TestEveryCallRefusesAStoreThatRedirects(t *testing.T) {
	client := testClientOf(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://s3.example.org/elsewhere", http.StatusTemporaryRedirect)
	})
	if _, err := client.Get(context.Background(), testDecreeKey, 4096); err == nil {
		t.Error("Get followed the redirect")
	}
	if err := client.Put(context.Background(), testDecreeKey, []byte("object")); err == nil {
		t.Error("Put followed the redirect")
	}
}

func TestAWithheldObjectIsMissingForThatClientOnly(t *testing.T) {
	board := startBoard(t)
	board.Put("boards/acme-prod/"+testDecreeKey, []byte("decree"))
	board.View("127.0.0.2").Withhold("boards/acme-prod/" + testDecreeKey)
	if _, err := testClientFrom(t, board, "127.0.0.2").Get(context.Background(), testDecreeKey, 4096); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the withholding client read it: %v", err)
	}
	if _, err := testClientFrom(t, board, "127.0.0.1").Get(context.Background(), testDecreeKey, 4096); err != nil {
		t.Fatalf("the other client lost it: %v", err)
	}
}

func TestAFrozenListingHidesALaterWrite(t *testing.T) {
	board := startBoard(t)
	blind := testClientFrom(t, board, "127.0.0.2")
	sighted := testClientFrom(t, board, "127.0.0.1")
	board.View("127.0.0.2").FreezeListing()
	if err := sighted.Put(context.Background(), testDecreeKey, []byte("decree")); err != nil {
		t.Fatal(err)
	}
	stale, err := blind.List(context.Background(), "decrees")
	if err != nil || len(stale) != 0 {
		t.Fatalf("the frozen listing = %+v, %v", stale, err)
	}
	fresh, err := sighted.List(context.Background(), "decrees")
	if err != nil || len(fresh) != 1 {
		t.Fatalf("the live listing = %+v, %v", fresh, err)
	}
}

func TestADelayedClientRunsOutOfTime(t *testing.T) {
	board := startBoard(t)
	board.Put("boards/acme-prod/"+testDecreeKey, []byte("decree"))
	board.View("127.0.0.2").Delay(time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := testClientFrom(t, board, "127.0.0.2").Get(ctx, testDecreeKey, 4096); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get = %v, want the caller's deadline", err)
	}
}
