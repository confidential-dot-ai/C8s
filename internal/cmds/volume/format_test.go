package volume

import "testing"

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
		"ext4":                 {FS: "ext4"},
		"ext4, owned":          {FS: "ext4", RootOwner: "65532:65532"},
		"absent keeps today's": nil,
	}
	for name, f := range ok {
		if err := mutable(f).Validate(); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
	bad := map[string]*Format{
		"other fs":          {FS: "xfs"},
		"no fs":             {},
		"owner not uid:gid": {FS: "ext4", RootOwner: "nobody"},
		"owner negative":    {FS: "ext4", RootOwner: "-1:0"},
		"owner too large":   {FS: "ext4", RootOwner: "4294967296:0"},
	}
	for name, f := range bad {
		if err := mutable(f).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	immutable := validBlob(t)
	immutable.Format = &Format{FS: "ext4"}
	if err := immutable.Validate(); err == nil {
		t.Error("an immutable blob accepted a format")
	}
}

func TestFormatRoundTrips(t *testing.T) {
	b, err := NewMutableBlob(testKey())
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"type":"c8s.volume/v1","key":"` + b.Key + `","mutable":true,"format":{"fs":"ext4","root_owner":"1000:1000"}}`)
	got, err := DecodeBlob(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format == nil || *got.Format != (Format{FS: "ext4", RootOwner: "1000:1000"}) {
		t.Fatalf("format = %+v", got.Format)
	}
}
