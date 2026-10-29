package cds

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// testSnapshot encodes a snapshot of header (the JSON header fields) over
// an empty allowlist, with the digests and chain a replica would write.
func testSnapshot(t *testing.T, header map[string]any) []byte {
	t.Helper()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	image, err := al.Dump()
	if err != nil {
		t.Fatal(err)
	}
	encode := func() []byte {
		h, err := json.Marshal(header)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		zw, err := zstd.NewWriter(&b)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = zw.Write(append(h, '\n'))
		_, _ = zw.Write(image)
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	d, err := cdsha.ContentDigests(encode())
	if err != nil {
		t.Fatal(err)
	}
	header["digests"] = d
	header["chain"] = cdsha.Point{Index: 0, Chain: strings.Repeat("0", 64)}
	return encode()
}
