package credvolume

import "testing"

// The three reader paths must name three different files in one directory, so
// one pointer covers the whole generation.
func TestFor(t *testing.T) {
	if _, err := For("/run/certs/tls.crt", "/run/keys/tls.key", "/run/certs/ca.crt"); err == nil {
		t.Error("paths in two directories were accepted")
	}
	if _, err := For("/run/certs/tls.crt", "/run/certs/tls.crt", "/run/certs/ca.crt"); err == nil {
		t.Error("two paths naming one file were accepted")
	}
	volume, err := For("/run/certs/tls.crt", "/run/certs/tls.key", "/run/certs/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	if volume.PointerPath() != "/run/certs/current" {
		t.Errorf("PointerPath = %q", volume.PointerPath())
	}
}
