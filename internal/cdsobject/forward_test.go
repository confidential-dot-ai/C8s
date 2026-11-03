package cdsobject

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func TestForwardAuthenticationFencingAndDuplicateReceipt(t *testing.T) {
	f := newFixture(t)
	n := f.nodeConfig(t, func(c *Config) {
		c.WALOptions.Writer = &objectwal.WriterConfig{ID: "writer", Address: "127.0.0.1:8443", Forward: func(context.Context, objectwal.Owner, objectwal.ForwardRequest) error {
			return errors.New("unexpected forward")
		}}
	})
	f.genesis(t, n)
	stats := n.WALStats()
	payload, _ := json.Marshal(cdsha.Entry{Kind: cdsha.KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/forwarded", Value: []byte("private")}})
	message := objectwal.ForwardRequest{Owner: stats.Writer, After: stats.Applied, Entries: []objectwal.Entry{{ID: "unique-request", Payload: payload}}}
	body, _ := json.Marshal(message)
	send := func(body []byte, key *[32]byte) int {
		r := httptest.NewRequest(http.MethodPost, ForwardPath, bytes.NewReader(body))
		if key != nil {
			r.Header.Set("Authorization", forwardAuth+hex.EncodeToString(forwardMAC(key, body)))
		}
		w := httptest.NewRecorder()
		n.ServeForward(w, r)
		return w.Code
	}
	other := f.launch
	other.ClusterID = "another-cluster"
	for _, key := range []*[32]byte{nil, new([32]byte), deriveForwardKey(f.key, other)} {
		if code := send(body, key); code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated append: %d", code)
		}
	}
	if n.WALStats().Applied != stats.Applied {
		t.Fatal("unauthenticated command entered the WAL")
	}
	for range 2 {
		if code := send(body, n.forwardKey.Load()); code != http.StatusNoContent {
			t.Fatalf("authenticated append or duplicate: %d", code)
		}
	}
	if n.WALStats().Applied != stats.Applied+1 {
		t.Fatal("duplicate receipt appended twice")
	}
	value, err := n.Secrets().Get(t.Context(), "/forwarded")
	if err != nil || string(value) != "private" {
		t.Fatalf("forwarded command: %q %v", value, err)
	}
	message.Owner.Epoch++
	body, _ = json.Marshal(message)
	if code := send(body, n.forwardKey.Load()); code != http.StatusConflict {
		t.Fatalf("obsolete owner accepted: %d", code)
	}
}

func TestForwardIngressBackpressureAndMeasuredAddress(t *testing.T) {
	f := newFixture(t)
	n := f.node(t)
	body := []byte(`{}`)
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, ForwardPath, bytes.NewReader(body))
		r.Header.Set("Authorization", forwardAuth+hex.EncodeToString(forwardMAC(n.forwardKey.Load(), body)))
		return r
	}
	for range cap(n.incoming) {
		n.incoming <- struct{}{}
	}
	w := httptest.NewRecorder()
	n.ServeForward(w, request())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request capacity: %d", w.Code)
	}
	for range cap(n.incoming) {
		<-n.incoming
	}
	n.incomingBytes.Store(maxIncomingBytes)
	w = httptest.NewRecorder()
	n.ServeForward(w, request())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("byte capacity: %d", w.Code)
	}
	n.incomingBytes.Store(0)
	r := request()
	r.ContentLength = maxForwardBody + 1
	w = httptest.NewRecorder()
	n.ServeForward(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit: %d", w.Code)
	}
	peer := &Node{cfg: Config{Address: "127.0.0.1:8443", PeerHosts: []string{"127.0.0.1", "127.0.0.2"}}}
	if err := peer.checkPeer(t.Context(), "127.0.0.2:8443"); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"127.0.0.3:8443", "127.0.0.2:443", "169.254.169.254:8443", "attacker.example:8443", "[::1]:8443"} {
		if err := peer.checkPeer(t.Context(), address); !errors.Is(err, objectwal.ErrRequestMismatch) {
			t.Fatalf("accepted peer %s", address)
		}
	}
}
