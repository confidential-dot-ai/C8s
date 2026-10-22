package volume

import (
	"bytes"
	"testing"
)

func TestFormatValidation(t *testing.T) {
	mutable := func(f *Format) Blob {
		b, err := NewMutableBlob(testKey())
		if err != nil {
			t.Fatal(err)
		}
		b.Format = f
		return b
	}
	ok := map[string]*Format{
		"blank":                {FS: "ext4", When: FormatBlank},
		"no filesystem, owned": {FS: "ext4", When: FormatNoFilesystem, RootOwner: "65532:65532"},
		"absent keeps today's": nil,
	}
	for name, f := range ok {
		if err := mutable(f).Validate(); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
	bad := map[string]*Format{
		"other fs":          {FS: "xfs", When: FormatBlank},
		"no when":           {FS: "ext4"},
		"unknown when":      {FS: "ext4", When: "always"},
		"owner not uid:gid": {FS: "ext4", When: FormatBlank, RootOwner: "nobody"},
		"owner negative":    {FS: "ext4", When: FormatBlank, RootOwner: "-1:0"},
		"owner too large":   {FS: "ext4", When: FormatBlank, RootOwner: "4294967296:0"},
	}
	for name, f := range bad {
		if err := mutable(f).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	immutable := validBlob(t)
	immutable.Format = &Format{FS: "ext4", When: FormatBlank}
	if err := immutable.Validate(); err == nil {
		t.Error("an immutable blob accepted a format")
	}
}

func TestFormatRoundTrips(t *testing.T) {
	raw := []byte(`{"type":"c8s.volume/v1","key":"` + mustMutable(t).Key + `","mutable":true,"format":{"fs":"ext4","when":"blank","root_owner":"1000:1000"}}`)
	b, err := DecodeBlob(raw)
	if err != nil {
		t.Fatal(err)
	}
	if b.Format == nil || *b.Format != (Format{FS: "ext4", When: FormatBlank, RootOwner: "1000:1000"}) {
		t.Fatalf("format = %+v", b.Format)
	}
}

func mustMutable(t *testing.T) Blob {
	t.Helper()
	b, err := NewMutableBlob(testKey())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// One secret always derives the same key, so every open of the cache after
// the first finds the filesystem it wrote; another secret derives another.
func TestNewCacheBlob(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, CacheSecretBytes)
	a, err := NewCacheBlob(secret, "65532:65532")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCacheBlob(secret, "65532:65532")
	if err != nil {
		t.Fatal(err)
	}
	if a.Key != b.Key {
		t.Fatal("one secret derived two keys")
	}
	if !a.Mutable || a.Format == nil || a.Format.When != FormatNoFilesystem || a.Format.RootOwner != "65532:65532" {
		t.Fatalf("cache blob = %+v", a)
	}
	key, err := a.DecodeKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(key, secret) {
		t.Fatal("the secret is used as the key rather than derived from")
	}
	other, err := NewCacheBlob(bytes.Repeat([]byte{8}, CacheSecretBytes), "")
	if err != nil {
		t.Fatal(err)
	}
	if other.Key == a.Key {
		t.Fatal("two secrets derived one key")
	}
	if _, err := NewCacheBlob(secret[:16], ""); err == nil {
		t.Fatal("accepted a short secret")
	}
}
