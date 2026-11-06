package cdsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

func testHAWire(recoveryPEM string) haWire {
	return haWire{
		Replicas: []string{
			"cds.acme.example",
			"10.0.0.7",
		},
		Voters: 3,
		Board: boardWire{
			Endpoint: "https://s3.acme.example",
			Bucket:   "c8s-boards",
			Prefix:   "boards/eu",
		},
		RecoveryKey: recoveryPEM,
	}
}

func testHADocument(t *testing.T, operatorPEM, anchorPEM, recoveryPEM string) wire {
	t.Helper()
	document := testDocument(t, operatorPEM, anchorPEM)
	block := testHAWire(recoveryPEM)
	document.HA = &block
	return document
}

func TestParseReturnsTheReplicaSet(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	recovery, recoveryPEM := testKey(t)
	cfg, err := Parse(render(t, testHADocument(t, operatorPEM, anchorPEM, recoveryPEM)))
	if err != nil {
		t.Fatal(err)
	}
	ha := cfg.HA
	if ha == nil {
		t.Fatal("the document's ha block is not parsed")
	}
	if len(ha.Replicas) != 2 || ha.Replicas[0] != "cds.acme.example" || ha.Replicas[1] != "10.0.0.7" {
		t.Fatalf("replicas = %v", ha.Replicas)
	}
	if ha.Voters != 3 {
		t.Fatalf("voters = %d", ha.Voters)
	}
	want := Board{
		Endpoint: "https://s3.acme.example",
		Bucket:   "c8s-boards",
		Prefix:   "boards/eu",
	}
	if ha.Board != want {
		t.Fatalf("board = %+v, want %+v", ha.Board, want)
	}
	if !ha.RecoveryKey.Equal(recovery) {
		t.Fatal("the recovery key is not the document's key")
	}
}

// A cluster takes its decrees over the attested channel alone unless its
// block names a board, so a replica set with neither a board nor a key to
// seal a backup to parses.
func TestParseAcceptsAReplicaSetWithNoBoard(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	document := testDocument(t, operatorPEM, anchorPEM)
	wire := testHAWire("")
	wire.Board = boardWire{}
	document.HA = &wire

	cfg, err := Parse(render(t, document))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HA == nil || cfg.HA.Board != (Board{}) || cfg.HA.RecoveryKey != nil {
		t.Fatalf("ha = %+v, want a replica set with no board", cfg.HA)
	}
}

// Without an ha block a cluster's CDS runs as the singleton.
func TestParseLeavesTheSingletonWithoutAnHABlock(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	cfg, err := Parse(render(t, testDocument(t, operatorPEM, anchorPEM)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HA != nil {
		t.Fatalf("ha = %+v, want the singleton", cfg.HA)
	}
}

func TestParseRefusesEachMalformedHAField(t *testing.T) {
	tests := []struct {
		name   string
		change func(*haWire)
		want   string
	}{
		{"no replica", func(h *haWire) { h.Replicas = nil }, "ha.replicas"},
		{"the same replica twice", func(h *haWire) { h.Replicas = []string{"cds.acme.example", "cds.acme.example"} }, "twice"},
		{"a replica port", func(h *haWire) { h.Replicas = []string{"cds.acme.example:8444"} }, "port"},
		{"a replica URL", func(h *haWire) { h.Replicas = []string{"https://cds.acme.example"} }, "ha.replicas"},
		{"a replica wildcard", func(h *haWire) { h.Replicas = []string{"*.acme.example"} }, "ha.replicas"},
		{"an IPv6 replica", func(h *haWire) { h.Replicas = []string{"fd00::7"} }, "ha.replicas"},
		{"an empty replica", func(h *haWire) { h.Replicas = []string{""} }, "ha.replicas"},
		{"no voter", func(h *haWire) { h.Voters = 0 }, "ha.voters"},
		{"an even voter count", func(h *haWire) { h.Voters = 4 }, "ha.voters"},
		{"more voters than seats", func(h *haWire) { h.Voters = cdsdecree.MaxVoterSeats + 2 }, "ha.voters"},
		{"a plain HTTP board", func(h *haWire) { h.Board.Endpoint = "http://s3.acme.example" }, "ha.board"},
		{"no bucket", func(h *haWire) { h.Board.Bucket = "" }, "ha.board"},
		{"a prefix above the bucket", func(h *haWire) { h.Board.Prefix = "../boards" }, "ha.board"},
		{"a recovery key and no board", func(h *haWire) { h.Board = boardWire{} }, "ha.recoveryKey"},
		{"a recovery key that is not a key", func(h *haWire) { h.RecoveryKey = "not a key" }, "ha.recoveryKey"},
	}
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	_, recoveryPEM := testKey(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			document := testHADocument(t, operatorPEM, anchorPEM, recoveryPEM)
			tc.change(document.HA)
			_, err := Parse(render(t, document))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// The recovery key seals the backups with a scheme that holds for P-256
// alone, so another curve is refused at launch rather than at the first
// backup.
func TestParseRefusesARecoveryKeyOffP256(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	_, recoveryPEM := testKey(t)
	document := testHADocument(t, operatorPEM, anchorPEM, recoveryPEM)
	document.HA.RecoveryKey = testP384KeyPEM(t)
	if _, err := Parse(render(t, document)); err == nil {
		t.Fatal("Parse accepted a recovery key the backups cannot seal to")
	}
}

// An unknown field inside the block is a setting CDS does not define.
func TestParseRefusesAnUndeclaredHAField(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	_, recoveryPEM := testKey(t)
	var document map[string]any
	if err := yaml.Unmarshal(render(t, testHADocument(t, operatorPEM, anchorPEM, recoveryPEM)), &document); err != nil {
		t.Fatal(err)
	}
	block, ok := document["ha"].(map[string]any)
	if !ok {
		t.Fatalf("the rendered ha block is %T", document["ha"])
	}
	block["seats"] = 5
	data, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted a setting the ha block does not define")
	}
}

func TestFormatWritesAnHABlockParseAccepts(t *testing.T) {
	_, operatorPEM := testKey(t)
	_, anchorPEM := testKey(t)
	recovery, _ := testKey(t)
	document := testDocumentFor(t, operatorPEM, anchorPEM)
	document.HA = HA{
		Replicas: []string{"cds.acme.example"},
		Voters:   1,
		Board: Board{
			Endpoint: "https://s3.acme.example",
			Bucket:   "c8s-boards",
		},
		RecoveryKey: recovery,
	}
	data, err := Format(document)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("Format wrote an ha block Parse refuses: %v", err)
	}
	if cfg.HA == nil || cfg.HA.Voters != 1 || cfg.HA.Board != document.HA.Board {
		t.Fatalf("ha = %+v, want the document's block", cfg.HA)
	}
	if !cfg.HA.RecoveryKey.Equal(recovery) {
		t.Fatal("the formatted recovery key is not the document's key")
	}
}

// Format writes only what Parse accepts back, the ha block included.
func TestFormatRefusesAReplicaSetParseWouldRefuse(t *testing.T) {
	recovery, _ := testKey(t)
	for name, change := range map[string]func(*HA){
		"a recovery key and no board": func(h *HA) { h.Board = Board{} },
		"an even voter count":         func(h *HA) { h.Voters = 4 },
		"no replica":                  func(h *HA) { h.Replicas = nil },
		"a replica with a port":       func(h *HA) { h.Replicas = []string{"cds.acme.example:8444"} },
		"a plain HTTP board":          func(h *HA) { h.Board.Endpoint = "http://s3.acme.example" },
	} {
		t.Run(name, func(t *testing.T) {
			_, operatorPEM := testKey(t)
			_, anchorPEM := testKey(t)
			document := testDocumentFor(t, operatorPEM, anchorPEM)
			document.HA = HA{
				Replicas: []string{"cds.acme.example"},
				Voters:   1,
				Board: Board{
					Endpoint: "https://s3.acme.example",
					Bucket:   "c8s-boards",
				},
				RecoveryKey: recovery,
			}
			change(&document.HA)
			if _, err := Format(document); err == nil {
				t.Fatal("Format wrote an ha block Parse refuses")
			}
		})
	}
}

// testP384KeyPEM is a public key off the curve the backups seal to.
func testP384KeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := recoveryKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pemBytes
}
