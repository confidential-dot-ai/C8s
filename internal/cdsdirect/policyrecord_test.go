package cdsdirect

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestCompactPolicyPreservesCurrentVersionDigestAndHistory(t *testing.T) {
	s, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Local().StartJournal(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := s.Local().ReplaceAll(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema}, allowlist.OperatorWrite{}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := policyBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	var p policyRecord
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	image, err := p.open()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(image)
	cold, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	if err := cold.Restore(image, p.Digest); err != nil {
		t.Fatal(err)
	}
	before, v1, err := s.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	after, v2, err := cold.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	h1, err := s.History()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := cold.History()
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(h1, h2) || s.Digest() != cold.Digest() {
		t.Fatal("compact policy changed an observable result")
	}
	if len(b) >= len(image) {
		t.Fatal("sparse SQLite image did not compact")
	}
}

func TestCompactPolicyRefusesCorruptionUnknownEncodingAndExpansion(t *testing.T) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write(bytes.Repeat([]byte{0}, directstate.MaxValueBytes+1))
	_ = w.Close()
	for _, p := range []policyRecord{
		{Encoding: "unknown", Image: []byte("data")},
		{Encoding: "gzip", Image: []byte("not gzip")},
		{Encoding: "gzip", Image: b.Bytes()},
		{Encoding: "gzip", Image: b.Bytes()[:len(b.Bytes())-1]},
	} {
		if v, err := p.open(); !errors.Is(err, objectwal.ErrCorrupt) || v != nil {
			t.Fatalf("unbounded or corrupt policy accepted: %v", err)
		}
	}
}
