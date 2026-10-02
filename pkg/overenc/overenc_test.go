package overenc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

var update = flag.Bool("update", false, "regenerate testdata/attest_pq_channel_vectors.json")

func testTranscriptHash(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, sha512.Size384)
}

func testSessionID(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, SessionIDBytes)
}

// channelPair returns an agreed (server, client) channel pair.
func channelPair(t *testing.T) (server, client *Channel) {
	t.Helper()
	ck, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, serverSS, err := Encapsulate(ck.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	clientSS, err := ck.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	th, id := testTranscriptHash(0xA5), testSessionID(0x0F)
	serverCh, err := NewServerChannel(serverSS, th, id)
	if err != nil {
		t.Fatal(err)
	}
	clientCh, err := NewClientChannel(clientSS, th, id)
	if err != nil {
		t.Fatal(err)
	}
	return serverCh, clientCh
}

func TestXWingChannelRoundTrip(t *testing.T) {
	server, client := channelPair(t)

	rec, err := client.SealRequest([]byte("hello pq"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 1 {
		t.Fatalf("first request Seq = %d, want 1", rec.Seq)
	}
	got, err := server.OpenRequest(rec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello pq" {
		t.Fatalf("OpenRequest = %q, want %q", got, "hello pq")
	}

	resp, err := server.SealResponse([]byte("pong"), rec.Seq)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := client.OpenResponse(resp, rec.Seq)
	if err != nil || string(got2) != "pong" {
		t.Fatalf("OpenResponse = %q, %v", got2, err)
	}

	if !bytes.Equal(server.Exporter(), client.Exporter()) {
		t.Fatal("exporters differ between the two ends")
	}
	if len(server.Exporter()) != ExporterBytes {
		t.Fatalf("exporter = %d bytes, want %d", len(server.Exporter()), ExporterBytes)
	}
}

func TestChannelRejectsMismatchedTranscript(t *testing.T) {
	ck, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, serverSS, err := Encapsulate(ck.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	clientSS, err := ck.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	id := testSessionID(0x0F)
	serverCh, err := NewServerChannel(serverSS, testTranscriptHash(0x5A), id)
	if err != nil {
		t.Fatal(err)
	}
	clientCh, err := NewClientChannel(clientSS, testTranscriptHash(0xA5), id)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := clientCh.SealRequest([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCh.OpenRequest(rec); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("OpenRequest with mismatched transcript = %v, want %v", err, ErrAuthenticationFailed)
	}
}

func TestDecapsulateWrongCiphertextFailsChannel(t *testing.T) {
	ck, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, serverSS, err := Encapsulate(ck.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	// Tamper one ciphertext byte: implicit rejection yields a different secret,
	// never an error, so the divergence must surface as AEAD failure.
	tampered := bytes.Clone(ct)
	tampered[0] ^= 0xff
	clientSS, err := ck.Decapsulate(tampered)
	if err != nil {
		t.Fatalf("Decapsulate(tampered) = %v, want implicit rejection", err)
	}
	if bytes.Equal(clientSS, serverSS) {
		t.Fatal("tampered ciphertext decapsulated to the server's secret")
	}
	th, id := testTranscriptHash(0xA5), testSessionID(0x0F)
	serverCh, _ := NewServerChannel(serverSS, th, id)
	clientCh, _ := NewClientChannel(clientSS, th, id)
	rec, err := clientCh.SealRequest([]byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCh.OpenRequest(rec); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("OpenRequest = %v, want %v", err, ErrAuthenticationFailed)
	}
}

func TestOpenRequestRejectsReplayedRecord(t *testing.T) {
	server, client := channelPair(t)

	rec, err := client.SealRequest([]byte("transfer $100"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.OpenRequest(rec); err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	// Resubmitting the exact same authenticated record must not decrypt to a
	// second backend action.
	if _, err := server.OpenRequest(rec); !errors.Is(err, ErrReplayedRecord) {
		t.Fatalf("replayed record: OpenRequest = %v, want %v", err, ErrReplayedRecord)
	}
	// A fresh, distinct record from the same channel still opens.
	rec2, err := client.SealRequest([]byte("transfer $200"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.OpenRequest(rec2); err != nil {
		t.Fatalf("distinct record rejected: %v", err)
	}
}

func TestReplayWindow(t *testing.T) {
	server, client := channelPair(t)

	// Seal replayWindow+2 requests, deliver the newest first, then the rest in
	// reverse order: everything inside the window opens, the two oldest fall
	// out of it.
	total := replayWindow + 2
	recs := make([]Record, total)
	for i := range recs {
		rec, err := client.SealRequest([]byte("m"))
		if err != nil {
			t.Fatal(err)
		}
		recs[i] = rec
	}
	if _, err := server.OpenRequest(recs[total-1]); err != nil {
		t.Fatalf("newest record: %v", err)
	}
	for i := total - 2; i >= 2; i-- {
		if _, err := server.OpenRequest(recs[i]); err != nil {
			t.Fatalf("in-window record seq %d: %v", recs[i].Seq, err)
		}
	}
	for _, old := range recs[:2] {
		if _, err := server.OpenRequest(old); !errors.Is(err, ErrReplayedRecord) {
			t.Fatalf("out-of-window record seq %d: OpenRequest = %v, want %v", old.Seq, err, ErrReplayedRecord)
		}
	}
}

func TestResponseMustEchoRequestSequence(t *testing.T) {
	server, client := channelPair(t)

	// Two concurrent requests; the terminator crosses the responses.
	recA, err := client.SealRequest([]byte("request A"))
	if err != nil {
		t.Fatal(err)
	}
	recB, err := client.SealRequest([]byte("request B"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.OpenRequest(recA); err != nil {
		t.Fatal(err)
	}
	if _, err := server.OpenRequest(recB); err != nil {
		t.Fatal(err)
	}
	respA, err := server.SealResponse([]byte("response A"), recA.Seq)
	if err != nil {
		t.Fatal(err)
	}
	respB, err := server.SealResponse([]byte("response B"), recB.Seq)
	if err != nil {
		t.Fatal(err)
	}

	// Swapped wholesale: the echoed sequence exposes it before decryption.
	if _, err := client.OpenResponse(respB, recA.Seq); !errors.Is(err, ErrSequenceInvalid) {
		t.Fatalf("swapped response: OpenResponse = %v, want %v", err, ErrSequenceInvalid)
	}
	// Swapped with the seq field forged to match: the AAD kills it.
	forged := Record{Seq: recA.Seq, CT: respB.CT}
	if _, err := client.OpenResponse(forged, recA.Seq); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("forged-seq response: OpenResponse = %v, want %v", err, ErrAuthenticationFailed)
	}
	// The honest pairing still opens.
	if got, err := client.OpenResponse(respA, recA.Seq); err != nil || string(got) != "response A" {
		t.Fatalf("honest response: %q, %v", got, err)
	}
	if got, err := client.OpenResponse(respB, recB.Seq); err != nil || string(got) != "response B" {
		t.Fatalf("honest response: %q, %v", got, err)
	}
}

func TestDirectionSeparation(t *testing.T) {
	_, client := channelPair(t)
	rec, err := client.SealRequest([]byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	// A request record reflected back to the client must not open as a
	// response: the directions use distinct keys and AAD tags.
	if _, err := client.OpenResponse(rec, rec.Seq); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("reflected request: OpenResponse = %v, want %v", err, ErrAuthenticationFailed)
	}
}

func TestSequenceZeroRejected(t *testing.T) {
	server, client := channelPair(t)
	if _, err := server.SealResponse([]byte("m"), 0); !errors.Is(err, ErrSequenceInvalid) {
		t.Fatalf("SealResponse(seq 0) = %v, want %v", err, ErrSequenceInvalid)
	}
	rec, err := client.SealRequest([]byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	rec.Seq = 0
	if _, err := server.OpenRequest(rec); !errors.Is(err, ErrSequenceInvalid) {
		t.Fatalf("OpenRequest(seq 0) = %v, want %v", err, ErrSequenceInvalid)
	}
}

func TestOpenRequestRejectsTamperedRecord(t *testing.T) {
	server, client := channelPair(t)
	valid, err := client.SealRequest([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		rec  Record
	}{
		{name: "ciphertext nil", rec: Record{Seq: valid.Seq, CT: nil}},
		{name: "ciphertext 1 byte", rec: Record{Seq: valid.Seq, CT: []byte{0x00}}},
		{name: "ciphertext truncated", rec: Record{Seq: valid.Seq, CT: valid.CT[:len(valid.CT)-1]}},
		{name: "sequence shifted", rec: Record{Seq: valid.Seq + 1, CT: valid.CT}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := server.OpenRequest(tt.rec); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("OpenRequest = %v, want %v", err, ErrAuthenticationFailed)
			}
		})
	}

	// A forgery must not disturb the replay window: the genuine record still opens.
	forged := Record{Seq: valid.Seq, CT: bytes.Clone(valid.CT)}
	forged.CT[0] ^= 0xff
	if _, err := server.OpenRequest(forged); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("OpenRequest(forged) = %v, want %v", err, ErrAuthenticationFailed)
	}
	if _, err := server.OpenRequest(valid); err != nil {
		t.Fatalf("genuine record rejected after a forgery reused its sequence: %v", err)
	}
}

func TestKeyAgreementRejectsWrongSizes(t *testing.T) {
	ck, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, ss, err := Encapsulate(ck.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		run     func() error
		wantErr string
	}{
		{
			name: "encapsulation key short",
			run: func() error {
				_, _, err := Encapsulate(make([]byte, 10))
				return err
			},
			wantErr: "encapsulation key must be 1216 bytes, got 10",
		},
		{
			name: "ciphertext short",
			run: func() error {
				_, err := ck.Decapsulate(make([]byte, 10))
				return err
			},
			wantErr: "ciphertext must be 1120 bytes, got 10",
		},
		{
			name: "seed short",
			run: func() error {
				_, err := NewClientKeyFromSeed(make([]byte, 16))
				return err
			},
			wantErr: "seed",
		},
		{
			name: "transcript hash short",
			run: func() error {
				_, err := NewServerChannel(ss, make([]byte, 32), testSessionID(0x0F))
				return err
			},
			wantErr: "identity transcript hash must be 48 bytes, got 32",
		},
		{
			name: "shared secret short",
			run: func() error {
				_, err := NewClientChannel(make([]byte, 16), testTranscriptHash(0xA5), testSessionID(0x0F))
				return err
			},
			wantErr: "shared secret must be 32 bytes, got 16",
		},
		{
			name: "session id short",
			run: func() error {
				_, err := NewServerChannel(ss, testTranscriptHash(0xA5), make([]byte, 8))
				return err
			},
			wantErr: "session id must be 16 bytes, got 8",
		},
	}
	_ = ct
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// channelVectors is the cross-language golden vector for the complete channel
// derivation: X-Wing decapsulation from a fixed seed and recorded ciphertext,
// the identity transcript, the HKDF key schedule, and one sealed record per
// direction. c8s-verify-js/test/vectors.test.ts consumes the identical file.
type channelVectors struct {
	Description       string              `json:"description"`
	FrontDoorMode     types.FrontDoorMode `json:"front_door_mode"`
	XWingSeed         string              `json:"xwing_seed_hex"`
	XWingEK           string              `json:"xwing_ek_hex"`
	XWingCT           string              `json:"xwing_ct_hex"`
	SharedSecret      string              `json:"shared_secret_hex"`
	LeafDER           string              `json:"leaf_der_hex"`
	CADER             string              `json:"ca_der_hex"`
	Nonce             string              `json:"nonce_hex"`
	SessionID         string              `json:"session_id_hex"`
	TranscriptHash    string              `json:"transcript_hash_hex"`
	C2SKey            string              `json:"c2s_key_hex"`
	S2CKey            string              `json:"s2c_key_hex"`
	C2SIV             string              `json:"c2s_iv_hex"`
	S2CIV             string              `json:"s2c_iv_hex"`
	Exporter          string              `json:"exporter_hex"`
	RequestSeq        uint64              `json:"request_seq"`
	RequestPlaintext  string              `json:"request_plaintext_hex"`
	RequestCT         string              `json:"request_ct_hex"`
	ResponseSeq       uint64              `json:"response_seq"`
	ResponsePlaintext string              `json:"response_plaintext_hex"`
	ResponseCT        string              `json:"response_ct_hex"`
}

const channelVectorsPath = "testdata/attest_pq_channel_vectors.json"

// TestChannelGoldenVectors pins the canonical contract: everything downstream
// of the recorded X-Wing ciphertext is deterministic, so the whole pipeline is
// reproduced from the vector file and compared byte for byte. Run with
// -update after a deliberate contract change to regenerate the file (and
// update the copy consumed by c8s-verify-js).
func TestChannelGoldenVectors(t *testing.T) {
	if *update {
		writeChannelVectors(t)
	}
	raw, err := os.ReadFile(filepath.Clean(channelVectorsPath))
	if err != nil {
		t.Fatalf("read %s (generate with -update): %v", channelVectorsPath, err)
	}
	var v channelVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	ck, err := NewClientKeyFromSeed(mustHex(t, v.XWingSeed))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ck.EncapsulationKey()); got != v.XWingEK {
		t.Fatalf("encapsulation key from seed = %s, want %s", got, v.XWingEK)
	}
	ss, err := ck.Decapsulate(mustHex(t, v.XWingCT))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ss); got != v.SharedSecret {
		t.Fatalf("shared secret = %s, want %s", got, v.SharedSecret)
	}

	th, err := IdentityTranscriptHash(v.FrontDoorMode, ck.EncapsulationKey(), mustHex(t, v.XWingCT),
		mustHex(t, v.SessionID), mustHex(t, v.Nonce), mustHex(t, v.LeafDER), mustHex(t, v.CADER), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(th); got != v.TranscriptHash {
		t.Fatalf("transcript hash = %s, want %s", got, v.TranscriptHash)
	}

	keys, err := deriveKeys(ss, th)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name string
		got  []byte
		want string
	}{
		{"c2s key", keys.c2sKey, v.C2SKey},
		{"s2c key", keys.s2cKey, v.S2CKey},
		{"c2s iv", keys.c2sIV, v.C2SIV},
		{"s2c iv", keys.s2cIV, v.S2CIV},
		{"exporter", keys.exporter, v.Exporter},
	} {
		if got := hex.EncodeToString(check.got); got != check.want {
			t.Fatalf("%s = %s, want %s", check.name, got, check.want)
		}
	}

	client, err := NewClientChannel(ss, th, mustHex(t, v.SessionID))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerChannel(ss, th, mustHex(t, v.SessionID))
	if err != nil {
		t.Fatal(err)
	}
	req, err := client.SealRequest(mustHex(t, v.RequestPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	if req.Seq != v.RequestSeq || hex.EncodeToString(req.CT) != v.RequestCT {
		t.Fatalf("request record = seq %d ct %s, want seq %d ct %s",
			req.Seq, hex.EncodeToString(req.CT), v.RequestSeq, v.RequestCT)
	}
	if _, err := server.OpenRequest(req); err != nil {
		t.Fatal(err)
	}
	resp, err := server.SealResponse(mustHex(t, v.ResponsePlaintext), req.Seq)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Seq != v.ResponseSeq || hex.EncodeToString(resp.CT) != v.ResponseCT {
		t.Fatalf("response record = seq %d ct %s, want seq %d ct %s",
			resp.Seq, hex.EncodeToString(resp.CT), v.ResponseSeq, v.ResponseCT)
	}
	if _, err := client.OpenResponse(resp, req.Seq); err != nil {
		t.Fatal(err)
	}
}

// writeChannelVectors regenerates the vector file. Only the server-side
// encapsulation draws randomness; everything else is derived.
func writeChannelVectors(t *testing.T) {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	ck, err := NewClientKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	ct, ss, err := Encapsulate(ck.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	leafDER, caDER := []byte("leaf-der"), []byte("ca-der")
	nonce := bytes.Repeat([]byte{0x33}, 32)
	sessionID := bytes.Repeat([]byte{0x44}, SessionIDBytes)
	th, err := IdentityTranscriptHash("cds", ck.EncapsulationKey(), ct, sessionID, nonce, leafDER, caDER, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := deriveKeys(ss, th)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientChannel(ss, th, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerChannel(ss, th, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	reqPT, respPT := []byte("golden request"), []byte("golden response")
	req, err := client.SealRequest(reqPT)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.SealResponse(respPT, req.Seq)
	if err != nil {
		t.Fatal(err)
	}
	v := channelVectors{
		Description:       "c8s attest-pq v1 channel golden vector: X-Wing decapsulation from seed, identity transcript, HKDF schedule, one record per direction. Shared verbatim with c8s-verify-js.",
		FrontDoorMode:     "cds",
		XWingSeed:         hex.EncodeToString(seed),
		XWingEK:           hex.EncodeToString(ck.EncapsulationKey()),
		XWingCT:           hex.EncodeToString(ct),
		SharedSecret:      hex.EncodeToString(ss),
		LeafDER:           hex.EncodeToString(leafDER),
		CADER:             hex.EncodeToString(caDER),
		Nonce:             hex.EncodeToString(nonce),
		SessionID:         hex.EncodeToString(sessionID),
		TranscriptHash:    hex.EncodeToString(th),
		C2SKey:            hex.EncodeToString(keys.c2sKey),
		S2CKey:            hex.EncodeToString(keys.s2cKey),
		C2SIV:             hex.EncodeToString(keys.c2sIV),
		S2CIV:             hex.EncodeToString(keys.s2cIV),
		Exporter:          hex.EncodeToString(keys.exporter),
		RequestSeq:        req.Seq,
		RequestPlaintext:  hex.EncodeToString(reqPT),
		RequestCT:         hex.EncodeToString(req.CT),
		ResponseSeq:       resp.Seq,
		ResponsePlaintext: hex.EncodeToString(respPT),
		ResponseCT:        hex.EncodeToString(resp.CT),
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(channelVectorsPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
