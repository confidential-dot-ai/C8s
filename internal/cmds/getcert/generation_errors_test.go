package getcert

import (
	"crypto/x509/pkix"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// diskVolume is a credential volume on an ordinary directory: these cases
// exercise volume state, not the RAM-backed check run applies.
func diskVolume(t *testing.T) credentialVolume {
	t.Helper()
	dir := t.TempDir()
	v, err := credentialVolumeFor(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func writeVolumeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// blockRemoval makes path a non-empty directory, which a withdrawal cannot remove.
func blockRemoval(t *testing.T, path string) {
	t.Helper()
	writeVolumeFile(t, filepath.Join(path, "held"), "held")
}

func TestPublishRefusesCorruptVolume(t *testing.T) {
	for name, tt := range map[string]struct {
		corrupt func(*testing.T, credentialVolume)
		want    string
	}{
		"pointer is a regular file": {func(t *testing.T, v credentialVolume) { writeVolumeFile(t, v.pointerPath(), "1") }, "read generation pointer"},
		"foreign generation entry": {func(t *testing.T, v credentialVolume) {
			writeVolumeFile(t, filepath.Join(v.generationsPath(), "junk"), "")
		}, `holds "junk"`},
		"generations is a file":    {func(t *testing.T, v credentialVolume) { writeVolumeFile(t, v.generationsPath(), "") }, "read generations directory"},
		"issuer record unwritable": {func(t *testing.T, v credentialVolume) { blockRemoval(t, v.issuerPath()) }, "write issuer record"},
	} {
		t.Run(name, func(t *testing.T) {
			v := diskVolume(t)
			tt.corrupt(t, v)
			creds := &credentials{volume: v, instanceID: testInstanceID}
			g, err := issueFor(newTestCA(t), creds, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			err = creds.publish(g, time.Now())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("publish = %v, want %q", err, tt.want)
			}
			if creds.current != nil {
				t.Fatal("a refused generation became current")
			}
			for _, name := range v.names() {
				if _, err := os.Lstat(filepath.Join(v.dir, name)); !os.IsNotExist(err) {
					t.Fatalf("refused publication created reader %q: %v", name, err)
				}
			}
		})
	}
}

func TestPublishRefusesReadOnlyVolume(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	for name, readOnly := range map[string]func(credentialVolume) string{
		"volume":      func(v credentialVolume) string { return v.dir },
		"generations": func(v credentialVolume) string { return v.generationsPath() },
	} {
		t.Run(name, func(t *testing.T) {
			v := diskVolume(t)
			if err := os.Mkdir(v.generationsPath(), 0o755); err != nil {
				t.Fatal(err)
			}
			if name == "volume" {
				if err := os.Remove(v.generationsPath()); err != nil {
					t.Fatal(err)
				}
			}
			dir := readOnly(v)
			if err := os.Chmod(dir, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			creds := &credentials{volume: v, instanceID: testInstanceID}
			g, err := issueFor(newTestCA(t), creds, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := publishGeneration(v, g); err == nil || !strings.Contains(err.Error(), "create generation") {
				t.Fatalf("publishGeneration = %v, want a create failure", err)
			}
		})
	}
}

func TestStoredGenerationRejectsDamagedSet(t *testing.T) {
	ca := newTestCA(t)
	key, keyPEM := testKey(t)
	chain := ca.mustIssue(t, &key.PublicKey, testInstanceID, time.Hour)
	caPEM := ca.pem(t)
	for name, tt := range map[string]struct {
		files map[string]string
		want  string
	}{
		"missing key":     {map[string]string{"tls.crt": chain, "ca.crt": caPEM}, "read published generation"},
		"missing CA":      {map[string]string{"tls.crt": chain, "tls.key": string(keyPEM)}, "read published generation"},
		"unparsable key":  {map[string]string{"tls.crt": chain, "tls.key": "key", "ca.crt": caPEM}, "published generation key"},
		"unparsable leaf": {map[string]string{"tls.crt": "leaf", "tls.key": string(keyPEM), "ca.crt": caPEM}, "generation leaf"},
	} {
		t.Run(name, func(t *testing.T) {
			v := diskVolume(t)
			for file, data := range tt.files {
				writeVolumeFile(t, filepath.Join(v.generationsPath(), "1", file), data)
			}
			if err := os.Symlink(filepath.Join(generationsSubdir, "1"), v.pointerPath()); err != nil {
				t.Fatal(err)
			}
			if _, err := storedGeneration(v); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("storedGeneration = %v, want %q", err, tt.want)
			}
		})
	}
	v := diskVolume(t)
	writeVolumeFile(t, v.pointerPath(), "1")
	if _, err := storedGeneration(v); err == nil || !strings.Contains(err.Error(), "read generation pointer") {
		t.Fatalf("a regular-file pointer was followed: %v", err)
	}
}

func TestIssuerRecordUnreadableFailsClosed(t *testing.T) {
	v := diskVolume(t)
	blockRemoval(t, v.issuerPath())
	if _, err := loadIssuerRecord(v); err == nil || !strings.Contains(err.Error(), "read issuer record") {
		t.Fatalf("loadIssuerRecord = %v", err)
	}
	if _, err := loadCredentials(v, testInstanceID); !errors.Is(err, errFailClosed) {
		t.Fatalf("unreadable issuer record did not fail closed: %v", err)
	}
}

func TestWithdrawalFailureIsReported(t *testing.T) {
	ca := newTestCA(t)
	t.Run("pointer", func(t *testing.T) {
		v := diskVolume(t)
		blockRemoval(t, v.pointerPath())
		if err := withdrawGeneration(v); err == nil || !strings.Contains(err.Error(), "withdraw generation") {
			t.Fatalf("withdrawGeneration = %v", err)
		}
	})
	t.Run("unreadable generation at load", func(t *testing.T) {
		v := diskVolume(t)
		if err := writeIssuerRecord(v, issuerKeyID(strings.Repeat("ab", 32))); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(generationsSubdir, "1"), v.pointerPath()); err != nil {
			t.Fatal(err)
		}
		blockRemoval(t, filepath.Join(v.dir, v.keyName))
		if _, err := loadCredentials(v, testInstanceID); err == nil || !strings.Contains(err.Error(), "withdraw generation") {
			t.Fatalf("loadCredentials = %v", err)
		}
	})
	t.Run("unusable generation at adoption", func(t *testing.T) {
		v := diskVolume(t)
		creds := &credentials{volume: v, instanceID: testInstanceID}
		g, err := issueFor(ca, creds, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := creds.publish(g, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(v.dir, v.keyName)); err != nil {
			t.Fatal(err)
		}
		blockRemoval(t, filepath.Join(v.dir, v.keyName))
		creds.instanceID = "another-instance"
		if err := creds.adoptStoredGeneration(time.Now()); err == nil || !strings.Contains(err.Error(), "withdraw generation") {
			t.Fatalf("adoptStoredGeneration = %v", err)
		}
	})
}

func TestRestartAdoptsValidGeneration(t *testing.T) {
	v := diskVolume(t)
	creds := &credentials{volume: v, instanceID: testInstanceID}
	g, err := issueFor(newTestCA(t), creds, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.publish(g, time.Now()); err != nil {
		t.Fatal(err)
	}
	restarted, err := loadCredentials(v, testInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.adoptStoredGeneration(time.Now()); err != nil {
		t.Fatal(err)
	}
	if restarted.current == nil || !restarted.current.Leaf.Equal(g.Leaf) || restarted.issuer != creds.issuer {
		t.Fatal("restart did not adopt the published generation")
	}
}

func TestRequireInstanceIDRejectsMalformedExtension(t *testing.T) {
	key, _ := testKey(t)
	malformed := pkix.Extension{Id: armtls.OIDSandboxID, Value: []byte{0x05, 0x00}}
	chain, err := newTestCA(t).issue(&key.PublicKey, "", time.Hour, malformed)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := certutil.ParseCertificatePEM([]byte(chain))
	if err != nil {
		t.Fatal(err)
	}
	if err := requireInstanceID(leaf, testInstanceID); err == nil || !strings.Contains(err.Error(), "leaf instance ID") {
		t.Fatalf("requireInstanceID = %v", err)
	}
}
