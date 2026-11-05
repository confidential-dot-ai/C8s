package getcert

import (
	"os"
	"strings"
	"testing"
)

func TestGuestIssuerBindingRefusesMissingRoot(t *testing.T) {
	if _, err := GuestIssuerBinding(nil); err == nil {
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
	if binding, err := GuestIssuerBinding(root); err != nil || binding != "" {
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
	if binding, err := GuestIssuerBinding(root); err != nil || binding != string(want) {
		t.Fatalf("withdrawal lost public issuer identity: %q, %v", binding, err)
	}
	for _, malformed := range []string{"bad\n", strings.Repeat("z", 64) + "\n", strings.Repeat("AB", 32) + "\n", strings.Repeat("a", 1024)} {
		if err := root.WriteFile(issuerRecordName, []byte(malformed), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := GuestIssuerBinding(root); err == nil {
			t.Fatal("malformed issuer record was accepted")
		}
	}
	if err := writeIssuerRecord(volume, want); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod(issuerRecordName, 0664); err != nil {
		t.Fatal(err)
	}
	if _, err := GuestIssuerBinding(root); err == nil {
		t.Fatal("writable issuer record was accepted")
	}
	if err := root.Remove(issuerRecordName); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("missing", issuerRecordName); err != nil {
		t.Fatal(err)
	}
	if _, err := GuestIssuerBinding(root); err == nil {
		t.Fatal("dangling issuer link was treated as a never-issued volume")
	}
}
