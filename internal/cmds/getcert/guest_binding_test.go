package getcert

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

// guestIssuerBinding reads the public CA binding retained after withdrawal.
// The caller serializes it with credential publication and owns the verified
// guest volume. An empty result means no issuer record exists; malformed or
// unprotected records are errors. No credential private key is read.
func guestIssuerBinding(root *os.Root) (string, error) {
	if root == nil {
		return "", errors.New("guest issuer binding requires a volume root")
	}
	if err := requireGuestRoot(root); err != nil {
		return "", err
	}
	info, err := root.Lstat(issuerRecordName)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() != 65 {
		return "", errors.New("guest issuer binding is not a protected fingerprint record")
	}
	bound, err := loadIssuerRecord(credentialVolume{root: root})
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(string(bound))
	if err != nil || hex.EncodeToString(raw) != string(bound) {
		return "", fmt.Errorf("guest issuer binding is not a canonical fingerprint")
	}
	return string(bound), nil
}

func TestGuestIssuerBindingRefusesMissingRoot(t *testing.T) {
	if _, err := guestIssuerBinding(nil); err == nil {
		t.Fatal("nil volume read a binding")
	}
}

func TestGuestIssuerBindingRetainsPublicIdentityAfterWithdrawal(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("C8S_REQUIRE_NFT") == "1" {
			t.Fatal("issuer binding custody requires root")
		}
		t.Skip("issuer binding custody requires root")
	}
	root, err := os.OpenRoot(ramBackedDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if binding, err := guestIssuerBinding(root); err != nil || binding != "" {
		t.Fatalf("fresh volume binding = %q, %v", binding, err)
	}
	volume := credentialVolume{root: root, leafName: "tls.crt", keyName: "tls.key", caName: "ca.crt"}
	want := issuerKeyID(strings.Repeat("ab", 32))
	if err := writeIssuerRecord(volume, want); err != nil {
		t.Fatal(err)
	}
	if err := withdrawGeneration(volume); err != nil {
		t.Fatal(err)
	}
	if binding, err := guestIssuerBinding(root); err != nil || binding != string(want) {
		t.Fatalf("withdrawal lost public issuer identity: %q, %v", binding, err)
	}
	for _, malformed := range []string{"bad\n", strings.Repeat("z", 64) + "\n", strings.Repeat("AB", 32) + "\n", strings.Repeat("a", 1024)} {
		if err := root.WriteFile(issuerRecordName, []byte(malformed), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := guestIssuerBinding(root); err == nil {
			t.Fatal("malformed issuer record was accepted")
		}
	}
	if err := writeIssuerRecord(volume, want); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod(issuerRecordName, 0664); err != nil {
		t.Fatal(err)
	}
	if _, err := guestIssuerBinding(root); err == nil {
		t.Fatal("writable issuer record was accepted")
	}
	if err := root.Remove(issuerRecordName); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("missing", issuerRecordName); err != nil {
		t.Fatal(err)
	}
	if _, err := guestIssuerBinding(root); err == nil {
		t.Fatal("dangling issuer link was treated as a never-issued volume")
	}
}
